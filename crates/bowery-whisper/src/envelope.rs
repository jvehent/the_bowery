//! Envelope sealing and opening with Ed25519 signatures.
//!
//! A sealed envelope is the protobuf-encoded [`WhisperEnvelope`] carrying a
//! signature over `domain || sender_fingerprint || nonce_be || ts_be ||
//! payload`. The verifier resolves the sender's verifying key via a
//! [`FingerprintResolver`] (typically the pinned-neighbors store), validates
//! the signature, gates on clock skew, runs the replay guard, and finally
//! decodes the inner [`WhisperPayload`].

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bowery_crypto::{Fingerprint, Identity};
use bowery_proto::{CANONICAL_SIG_DOMAIN, WhisperEnvelope, WhisperPayload};
use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message as _;
use thiserror::Error;

use crate::replay::{Replay, ReplayGuard};

const FINGERPRINT_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const DEFAULT_SKEW: Duration = Duration::from_mins(5);

#[derive(Debug, Error)]
pub enum Error {
    #[error("envelope failed to decode: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("envelope sender_fingerprint is {0} bytes; expected {FINGERPRINT_LEN}")]
    BadFingerprintLen(usize),

    #[error("envelope signature is {0} bytes; expected {SIGNATURE_LEN}")]
    BadSignatureLen(usize),

    #[error("unknown sender fingerprint")]
    UnknownSender,

    #[error("signature verification failed")]
    BadSignature,

    #[error(
        "envelope timestamp differs from local time by {diff_ms} ms (skew window is {skew_ms} ms)"
    )]
    ClockSkew { diff_ms: u64, skew_ms: u64 },

    #[error("local clock is before unix epoch")]
    LocalClockBeforeEpoch,

    #[error("payload failed to decode: {0}")]
    PayloadDecode(prost::DecodeError),

    #[error("replay rejected: {0}")]
    Replay(#[from] Replay),
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// Resolves a sender fingerprint to its pinned verifying key.
///
/// In the agent this is backed by the TOFU `known_neighbors` store; tests
/// use [`StaticResolver`].
pub trait FingerprintResolver: Send + Sync {
    fn resolve(&self, fp: &Fingerprint) -> Option<VerifyingKey>;
}

/// `HashMap`-backed resolver. Useful for tests and one-shot operator
/// commands where the set of valid senders is known up front.
#[derive(Debug, Default, Clone)]
pub struct StaticResolver {
    keys: HashMap<Fingerprint, VerifyingKey>,
}

impl StaticResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a verifying key. Returns the fingerprint it was indexed under.
    pub fn insert(&mut self, vk: VerifyingKey) -> Fingerprint {
        let fp = Fingerprint::from_verifying_key(&vk);
        self.keys.insert(fp, vk);
        fp
    }
}

impl FingerprintResolver for StaticResolver {
    fn resolve(&self, fp: &Fingerprint) -> Option<VerifyingKey> {
        self.keys.get(fp).copied()
    }
}

impl<T: FingerprintResolver + ?Sized> FingerprintResolver for Arc<T> {
    fn resolve(&self, fp: &Fingerprint) -> Option<VerifyingKey> {
        (**self).resolve(fp)
    }
}

/// Resolver that consults two backing stores in order. Useful for
/// agents that need to accept signatures from both pinned peer agents
/// (`KnownNeighbors`) and configured operators (a [`StaticResolver`]
/// built from `[operators]` config), without conflating the two stores.
#[derive(Debug, Clone)]
pub struct CompositeResolver<A, B> {
    primary: A,
    secondary: B,
}

impl<A, B> CompositeResolver<A, B> {
    pub fn new(primary: A, secondary: B) -> Self {
        Self { primary, secondary }
    }
}

impl<A: FingerprintResolver, B: FingerprintResolver> FingerprintResolver
    for CompositeResolver<A, B>
{
    fn resolve(&self, fp: &Fingerprint) -> Option<VerifyingKey> {
        self.primary
            .resolve(fp)
            .or_else(|| self.secondary.resolve(fp))
    }
}

// ---------------------------------------------------------------------------
// Sealer
// ---------------------------------------------------------------------------

/// Holds the local identity and produces signed envelopes.
///
/// Nonces are seeded from the wall clock at construction so they remain
/// monotonic across process restarts as long as the clock advances.
#[derive(Debug)]
pub struct Sealer {
    identity: Arc<Identity>,
    next_nonce: AtomicU64,
}

impl Sealer {
    pub fn new(identity: Arc<Identity>) -> Self {
        Self {
            identity,
            next_nonce: AtomicU64::new(current_ms().unwrap_or(1)),
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.identity.verifying_key()
    }

    /// Seal a payload addressed to `recipient_fp`. The recipient's
    /// fingerprint is included in the signing input (NOT on the
    /// wire), so an envelope signed for host A cannot be replayed
    /// against host B even if both pin the same sender. See
    /// `bowery_proto::CANONICAL_SIG_DOMAIN` for the full input
    /// shape.
    pub fn seal_for(&self, recipient_fp: &Fingerprint, payload: &WhisperPayload) -> Vec<u8> {
        let nonce = self.next_nonce.fetch_add(1, Ordering::Relaxed);
        let ts = current_ms().unwrap_or(0);
        let payload_bytes = payload.encode_to_vec();
        let fp = self.identity.fingerprint();
        let sig = self.identity.sign(&signing_input(
            recipient_fp.as_bytes(),
            fp.as_bytes(),
            nonce,
            ts,
            &payload_bytes,
        ));
        let env = WhisperEnvelope {
            sender_fingerprint: fp.as_bytes().to_vec(),
            nonce,
            ts_unix_ms: ts,
            payload: payload_bytes,
            signature: sig.to_bytes().to_vec(),
        };
        env.encode_to_vec()
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedEnvelope {
    pub sender: Fingerprint,
    pub nonce: u64,
    pub ts_unix_ms: u64,
    pub payload: WhisperPayload,
}

/// Opens incoming envelope bytes, performing all the checks listed at the
/// module top.
///
/// Holds the receiver's own fingerprint so it can verify the
/// recipient-binding signature (Phase-8 H1). An envelope signed for a
/// different recipient produces `BadSignature` here — no separate
/// "wrong recipient" error variant, since the recipient binding is
/// embedded in the signing input rather than carried on the wire.
#[derive(Debug)]
pub struct Verifier<R> {
    resolver: R,
    self_fp: Fingerprint,
    skew: Duration,
    replay: Mutex<ReplayGuard>,
}

impl<R: FingerprintResolver> Verifier<R> {
    /// Build a verifier with the receiver's own fingerprint. The
    /// `self_fp` is used to construct the signing input that the
    /// envelope's signature must match — an envelope addressed to a
    /// different fingerprint will fail with `BadSignature`.
    pub fn new(resolver: R, self_fp: Fingerprint) -> Self {
        Self::with_skew(resolver, self_fp, DEFAULT_SKEW)
    }

    pub fn with_skew(resolver: R, self_fp: Fingerprint, skew: Duration) -> Self {
        Self {
            resolver,
            self_fp,
            skew,
            replay: Mutex::new(ReplayGuard::new()),
        }
    }

    pub fn open(&self, bytes: &[u8]) -> Result<VerifiedEnvelope, Error> {
        let env = WhisperEnvelope::decode(bytes)?;

        if env.sender_fingerprint.len() != FINGERPRINT_LEN {
            return Err(Error::BadFingerprintLen(env.sender_fingerprint.len()));
        }
        if env.signature.len() != SIGNATURE_LEN {
            return Err(Error::BadSignatureLen(env.signature.len()));
        }

        let mut fp_arr = [0u8; FINGERPRINT_LEN];
        fp_arr.copy_from_slice(&env.sender_fingerprint);
        let sender = Fingerprint::from_bytes(fp_arr);

        let vk = self.resolver.resolve(&sender).ok_or(Error::UnknownSender)?;

        let mut sig_arr = [0u8; SIGNATURE_LEN];
        sig_arr.copy_from_slice(&env.signature);
        let sig = Signature::from_bytes(&sig_arr);

        // The signing input includes our own fingerprint as the
        // recipient. An envelope addressed to a different recipient
        // produces BadSignature here — Phase-8 H1 defense against
        // cross-recipient replay attacks.
        let canonical = signing_input(
            self.self_fp.as_bytes(),
            sender.as_bytes(),
            env.nonce,
            env.ts_unix_ms,
            &env.payload,
        );
        // Strict mode rejects malleable s and small-order/torsion R components
        // (per RFC 8032 §5.1.7) so a captured envelope can't be turned into a
        // second, distinct-bytes envelope that verifies under the same key.
        vk.verify_strict(&canonical, &sig)
            .map_err(|_| Error::BadSignature)?;

        let local_ms = current_ms().ok_or(Error::LocalClockBeforeEpoch)?;
        let diff_ms = local_ms.abs_diff(env.ts_unix_ms);
        let skew_max = u64::try_from(self.skew.as_millis()).unwrap_or(u64::MAX);
        if diff_ms > skew_max {
            return Err(Error::ClockSkew {
                diff_ms,
                skew_ms: skew_max,
            });
        }

        // Recover from a poisoned mutex rather than panic. The replay
        // guard's per-sender bitmap+highest state is monotone (forward
        // jumps clear bits, in-window holes are set-once), so even if a
        // previous holder panicked mid-update, the inner state is still
        // a valid prefix of the intended one — at worst we accept one
        // duplicate from an in-flight nonce. Panicking here would let a
        // single thread crash bring down the whole whisper layer for
        // every connected peer.
        self.replay
            .lock()
            .unwrap_or_else(|poison| {
                tracing::error!("replay guard mutex was poisoned; recovering");
                poison.into_inner()
            })
            .check_and_record(sender, env.nonce)?;

        let payload =
            WhisperPayload::decode(env.payload.as_slice()).map_err(Error::PayloadDecode)?;

        Ok(VerifiedEnvelope {
            sender,
            nonce: env.nonce,
            ts_unix_ms: env.ts_unix_ms,
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn current_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

/// Construct the bytes Ed25519 signs over for a whisper envelope.
///
/// Shape: `domain || recipient_fp || sender_fp || nonce_be || ts_be || payload`.
///
/// Both fingerprints are 32 bytes. `recipient_fp` is provided by the
/// caller (Sealer takes it as a parameter; Verifier passes its own
/// `self_fp`). It is not on the wire — including it on both sides of
/// the canonical input means a sender can't forge an envelope a
/// different receiver will accept, even if both pin the same sender
/// (Phase-8 H1).
fn signing_input(
    recipient_fp: &[u8; FINGERPRINT_LEN],
    sender_fp: &[u8; FINGERPRINT_LEN],
    nonce: u64,
    ts: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CANONICAL_SIG_DOMAIN.len() + 32 + 32 + 8 + 8 + payload.len());
    buf.extend_from_slice(CANONICAL_SIG_DOMAIN);
    buf.extend_from_slice(recipient_fp);
    buf.extend_from_slice(sender_fp);
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf.extend_from_slice(&ts.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn paired() -> (Arc<Identity>, Sealer, Verifier<StaticResolver>) {
        // For tests, "self-talks-to-self" — the same identity is both
        // sender and recipient. Real callers thread distinct fps.
        let identity = Arc::new(Identity::generate());
        let mut resolver = StaticResolver::new();
        resolver.insert(identity.verifying_key());
        let fp = identity.fingerprint();
        (
            identity.clone(),
            Sealer::new(identity),
            Verifier::new(resolver, fp),
        )
    }

    /// Test helper: the `recipient_fp` for self-talks-to-self test
    /// flows.
    fn self_recipient(sealer: &Sealer) -> Fingerprint {
        sealer.fingerprint()
    }

    #[test]
    fn roundtrip_heartbeat() {
        let (_id, sealer, verifier) = paired();
        let payload = WhisperPayload::heartbeat("0.0.1");
        let bytes = sealer.seal_for(&self_recipient(&sealer), &payload);
        let opened = verifier.open(&bytes).unwrap();
        assert_eq!(opened.sender, sealer.fingerprint());
        assert_eq!(opened.payload, payload);
    }

    #[test]
    fn rejects_unknown_sender() {
        let identity = Arc::new(Identity::generate());
        let sealer = Sealer::new(identity);
        // Verifier doesn't know the sender; its self_fp is some unrelated
        // fingerprint (a fresh identity).
        let stranger_fp = Identity::generate().fingerprint();
        let verifier = Verifier::new(StaticResolver::new(), stranger_fp);
        let bytes = sealer.seal_for(
            &self_recipient(&sealer),
            &WhisperPayload::heartbeat("0.0.1"),
        );
        assert!(matches!(verifier.open(&bytes), Err(Error::UnknownSender)));
    }

    #[test]
    fn rejects_tampered_payload() {
        let (_id, sealer, verifier) = paired();
        let bytes = sealer.seal_for(
            &self_recipient(&sealer),
            &WhisperPayload::heartbeat("0.0.1"),
        );
        let mut env = WhisperEnvelope::decode(bytes.as_slice()).unwrap();
        env.payload = WhisperPayload::heartbeat("0.0.2").encode_to_vec();
        let bytes = env.encode_to_vec();
        assert!(matches!(verifier.open(&bytes), Err(Error::BadSignature)));
    }

    #[test]
    fn rejects_tampered_nonce() {
        let (_id, sealer, verifier) = paired();
        let bytes = sealer.seal_for(
            &self_recipient(&sealer),
            &WhisperPayload::heartbeat("0.0.1"),
        );
        let mut env = WhisperEnvelope::decode(bytes.as_slice()).unwrap();
        env.nonce = env.nonce.wrapping_add(1);
        let bytes = env.encode_to_vec();
        assert!(matches!(verifier.open(&bytes), Err(Error::BadSignature)));
    }

    #[test]
    fn rejects_bad_fingerprint_length() {
        let (_id, sealer, verifier) = paired();
        let bytes = sealer.seal_for(&self_recipient(&sealer), &WhisperPayload::heartbeat("x"));
        let mut env = WhisperEnvelope::decode(bytes.as_slice()).unwrap();
        env.sender_fingerprint.truncate(16);
        let bytes = env.encode_to_vec();
        assert!(matches!(
            verifier.open(&bytes),
            Err(Error::BadFingerprintLen(16))
        ));
    }

    #[test]
    fn rejects_bad_signature_length() {
        let (_id, sealer, verifier) = paired();
        let bytes = sealer.seal_for(&self_recipient(&sealer), &WhisperPayload::heartbeat("x"));
        let mut env = WhisperEnvelope::decode(bytes.as_slice()).unwrap();
        env.signature.truncate(32);
        let bytes = env.encode_to_vec();
        assert!(matches!(
            verifier.open(&bytes),
            Err(Error::BadSignatureLen(32))
        ));
    }

    #[test]
    fn rejects_clock_skew() {
        let identity = Arc::new(Identity::generate());
        let mut resolver = StaticResolver::new();
        resolver.insert(identity.verifying_key());
        let fp = identity.fingerprint();
        let verifier = Verifier::with_skew(resolver, fp, Duration::from_millis(100));

        // Forge an envelope with a timestamp 10 minutes in the past, signed
        // correctly by the same identity. The skew window is 100 ms, so it
        // must be rejected.
        let nonce = 1u64;
        let past_ts = current_ms().unwrap().saturating_sub(10 * 60_000);
        let payload_bytes = WhisperPayload::heartbeat("x").encode_to_vec();
        // Self-talks-to-self: recipient_fp == sender_fp.
        let canonical = signing_input(fp.as_bytes(), fp.as_bytes(), nonce, past_ts, &payload_bytes);
        let sig = identity.sign(&canonical);

        let env = WhisperEnvelope {
            sender_fingerprint: fp.as_bytes().to_vec(),
            nonce,
            ts_unix_ms: past_ts,
            payload: payload_bytes,
            signature: sig.to_bytes().to_vec(),
        };
        let bytes = env.encode_to_vec();
        assert!(matches!(
            verifier.open(&bytes),
            Err(Error::ClockSkew { .. })
        ));
    }

    #[test]
    fn replay_of_same_envelope_is_rejected() {
        let (_id, sealer, verifier) = paired();
        let bytes = sealer.seal_for(
            &self_recipient(&sealer),
            &WhisperPayload::heartbeat("0.0.1"),
        );
        verifier.open(&bytes).unwrap();
        assert!(matches!(verifier.open(&bytes), Err(Error::Replay(_))));
    }

    #[test]
    fn nonces_are_strictly_increasing() {
        let identity = Arc::new(Identity::generate());
        let sealer = Sealer::new(identity);
        let a = WhisperEnvelope::decode(
            sealer
                .seal_for(
                    &self_recipient(&sealer),
                    &WhisperPayload::heartbeat("0.0.1"),
                )
                .as_slice(),
        )
        .unwrap();
        let b = WhisperEnvelope::decode(
            sealer
                .seal_for(
                    &self_recipient(&sealer),
                    &WhisperPayload::heartbeat("0.0.1"),
                )
                .as_slice(),
        )
        .unwrap();
        assert!(b.nonce > a.nonce);
    }

    /// Phase-8 hardening: confirm `verify_strict` rejects a malleable
    /// signature — one with `s' = s + L` (curve order). The lenient
    /// `Verifier::verify` path used to accept this, letting an attacker
    /// turn a captured envelope into a second, distinct-bytes envelope.
    #[test]
    fn rejects_malleable_signature() {
        // Add the curve order L (little-endian) to the lower-half `s` of
        // the signature. The result is still a structurally valid Ed25519
        // signature that verifies under lenient mode, but `verify_strict`
        // rejects it because `s >= L`.
        const ED25519_ORDER_LE: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];

        let (_id, sealer, verifier) = paired();
        let bytes = sealer.seal_for(
            &self_recipient(&sealer),
            &WhisperPayload::heartbeat("0.0.1"),
        );
        let mut env = WhisperEnvelope::decode(bytes.as_slice()).unwrap();

        let mut carry: u16 = 0;
        for (s_dst, l_src) in env.signature[32..].iter_mut().zip(ED25519_ORDER_LE.iter()) {
            let sum = u16::from(*s_dst) + u16::from(*l_src) + carry;
            *s_dst = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        let mangled = env.encode_to_vec();
        assert!(matches!(verifier.open(&mangled), Err(Error::BadSignature)));
    }
}
