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
use ed25519_dalek::{Signature, Verifier as DalekVerifier, VerifyingKey};
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
#[derive(Debug, Default)]
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

    /// Seal a payload into bytes ready for transmission.
    pub fn seal(&self, payload: &WhisperPayload) -> Vec<u8> {
        let nonce = self.next_nonce.fetch_add(1, Ordering::Relaxed);
        let ts = current_ms().unwrap_or(0);
        let payload_bytes = payload.encode_to_vec();
        let fp = self.identity.fingerprint();
        let sig = self
            .identity
            .sign(&signing_input(fp.as_bytes(), nonce, ts, &payload_bytes));
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEnvelope {
    pub sender: Fingerprint,
    pub nonce: u64,
    pub ts_unix_ms: u64,
    pub payload: WhisperPayload,
}

/// Opens incoming envelope bytes, performing all the checks listed at the
/// module top.
#[derive(Debug)]
pub struct Verifier<R> {
    resolver: R,
    skew: Duration,
    replay: Mutex<ReplayGuard>,
}

impl<R: FingerprintResolver> Verifier<R> {
    pub fn new(resolver: R) -> Self {
        Self::with_skew(resolver, DEFAULT_SKEW)
    }

    pub fn with_skew(resolver: R, skew: Duration) -> Self {
        Self {
            resolver,
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

        let canonical = signing_input(sender.as_bytes(), env.nonce, env.ts_unix_ms, &env.payload);
        vk.verify(&canonical, &sig)
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

        self.replay
            .lock()
            .expect("replay guard poisoned")
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

fn signing_input(fp: &[u8; FINGERPRINT_LEN], nonce: u64, ts: u64, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CANONICAL_SIG_DOMAIN.len() + 32 + 8 + 8 + payload.len());
    buf.extend_from_slice(CANONICAL_SIG_DOMAIN);
    buf.extend_from_slice(fp);
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
        let identity = Arc::new(Identity::generate());
        let mut resolver = StaticResolver::new();
        resolver.insert(identity.verifying_key());
        (
            identity.clone(),
            Sealer::new(identity),
            Verifier::new(resolver),
        )
    }

    #[test]
    fn roundtrip_heartbeat() {
        let (_id, sealer, verifier) = paired();
        let payload = WhisperPayload::heartbeat("0.0.1");
        let bytes = sealer.seal(&payload);
        let opened = verifier.open(&bytes).unwrap();
        assert_eq!(opened.sender, sealer.fingerprint());
        assert_eq!(opened.payload, payload);
    }

    #[test]
    fn rejects_unknown_sender() {
        let identity = Arc::new(Identity::generate());
        let sealer = Sealer::new(identity);
        let verifier = Verifier::new(StaticResolver::new());
        let bytes = sealer.seal(&WhisperPayload::heartbeat("0.0.1"));
        assert!(matches!(verifier.open(&bytes), Err(Error::UnknownSender)));
    }

    #[test]
    fn rejects_tampered_payload() {
        let (_id, sealer, verifier) = paired();
        let bytes = sealer.seal(&WhisperPayload::heartbeat("0.0.1"));
        let mut env = WhisperEnvelope::decode(bytes.as_slice()).unwrap();
        env.payload = WhisperPayload::heartbeat("0.0.2").encode_to_vec();
        let bytes = env.encode_to_vec();
        assert!(matches!(verifier.open(&bytes), Err(Error::BadSignature)));
    }

    #[test]
    fn rejects_tampered_nonce() {
        let (_id, sealer, verifier) = paired();
        let bytes = sealer.seal(&WhisperPayload::heartbeat("0.0.1"));
        let mut env = WhisperEnvelope::decode(bytes.as_slice()).unwrap();
        env.nonce = env.nonce.wrapping_add(1);
        let bytes = env.encode_to_vec();
        assert!(matches!(verifier.open(&bytes), Err(Error::BadSignature)));
    }

    #[test]
    fn rejects_bad_fingerprint_length() {
        let (_id, sealer, verifier) = paired();
        let bytes = sealer.seal(&WhisperPayload::heartbeat("x"));
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
        let bytes = sealer.seal(&WhisperPayload::heartbeat("x"));
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
        let verifier = Verifier::with_skew(resolver, Duration::from_millis(100));

        // Forge an envelope with a timestamp 10 minutes in the past, signed
        // correctly by the same identity. The skew window is 100 ms, so it
        // must be rejected.
        let nonce = 1u64;
        let past_ts = current_ms().unwrap().saturating_sub(10 * 60_000);
        let payload_bytes = WhisperPayload::heartbeat("x").encode_to_vec();
        let fp = identity.fingerprint();
        let canonical = signing_input(fp.as_bytes(), nonce, past_ts, &payload_bytes);
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
        let bytes = sealer.seal(&WhisperPayload::heartbeat("0.0.1"));
        verifier.open(&bytes).unwrap();
        assert!(matches!(verifier.open(&bytes), Err(Error::Replay(_))));
    }

    #[test]
    fn nonces_are_strictly_increasing() {
        let identity = Arc::new(Identity::generate());
        let sealer = Sealer::new(identity);
        let a =
            WhisperEnvelope::decode(sealer.seal(&WhisperPayload::heartbeat("0.0.1")).as_slice())
                .unwrap();
        let b =
            WhisperEnvelope::decode(sealer.seal(&WhisperPayload::heartbeat("0.0.1")).as_slice())
                .unwrap();
        assert!(b.nonce > a.nonce);
    }
}
