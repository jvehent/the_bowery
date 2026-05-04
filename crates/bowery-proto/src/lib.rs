//! Wire-format messages for The Bowery's whispering protocol.
//!
//! Defined directly via `prost` derive macros (no `protoc` build dep).
//! The corresponding `.proto` IDL is documented in
//! [`DESIGN.md`](../../DESIGN.md) §8.4 and is the source of truth for
//! field tags; the Rust definitions here must stay in sync.
//!
//! Phase 1a populates only [`Heartbeat`]. Other payload variants are
//! defined as empty placeholders and gain fields in later phases.

#![allow(clippy::doc_markdown)]

use prost::Message as ProstMessage;
use prost::Oneof;

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// The outer envelope carried by every whisper message.
///
/// Field meanings:
/// - `sender_fingerprint`: SHA-256(verifying_key) of the sender (32 bytes).
/// - `nonce`: per-sender monotonic nonce (used by the receiver's replay guard).
/// - `ts_unix_ms`: send timestamp, ms since Unix epoch (for skew gating).
/// - `payload`: a `WhisperPayload`, encoded with prost. Phase 1a transmits
///   plaintext; Phase 5 wraps this in ChaCha20-Poly1305 ciphertext.
/// - `signature`: Ed25519 signature over a canonical concatenation of the
///   four fields above (see [`crate::CANONICAL_SIG_DOMAIN`]).
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct WhisperEnvelope {
    #[prost(bytes = "vec", tag = "1")]
    pub sender_fingerprint: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub nonce: u64,
    #[prost(uint64, tag = "3")]
    pub ts_unix_ms: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub signature: Vec<u8>,
}

/// Domain-separation prefix for envelope signatures.
///
/// Every signed message is `domain || sender_fingerprint || nonce_be ||
/// ts_be || payload`, where `domain` is this constant. The prefix prevents
/// cross-protocol signature reuse if Bowery keys are ever loaded into other
/// protocols by mistake.
pub const CANONICAL_SIG_DOMAIN: &[u8] = b"bowery/whisper/envelope/v1";

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

/// The inner payload, with one variant per message type.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct WhisperPayload {
    #[prost(oneof = "Body", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub body: Option<Body>,
}

#[derive(Clone, PartialEq, Eq, Oneof)]
pub enum Body {
    #[prost(message, tag = "1")]
    Question(Question),
    #[prost(message, tag = "2")]
    Answer(Answer),
    #[prost(message, tag = "3")]
    Alert(Alert),
    #[prost(message, tag = "4")]
    OperatorCommand(OperatorCommand),
    #[prost(message, tag = "5")]
    OperatorResult(OperatorResult),
    #[prost(message, tag = "6")]
    Heartbeat(Heartbeat),
    #[prost(message, tag = "7")]
    NeighborOp(NeighborOp),
}

// ---------------------------------------------------------------------------
// Variants
// ---------------------------------------------------------------------------

/// Liveness ping. Sent at a configurable interval between paired peers.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Heartbeat {
    /// Sender's `bowery-agent` semantic-version string (e.g. `"0.0.1"`).
    #[prost(string, tag = "1")]
    pub agent_version: String,
}

// ---------------------------------------------------------------------------
// Question / Answer — Phase 5 whisper Q&A.
// ---------------------------------------------------------------------------

/// Phase-5 whisper question: "have you seen something matching this
/// tier-1 fingerprint?"
///
/// Tier-1 fingerprints are 64-bit truncations of `SHA256(domain ||
/// tier2_sha256)`; see `bowery_whisper::fingerprint`. They permit
/// collisions by design — peers can confirm or deny a *fuzzy* match
/// without leaking the underlying hash to anyone who hasn't already
/// independently observed it. Tier-2 (the full sha256) is exchanged
/// inside the encrypted whisper envelope only after both sides have
/// agreed the tier-1 hint is worth following up on.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Question {
    /// 16-byte episode id (typically uuid v4) the asker uses to
    /// correlate this question with the verdict that prompted it. We
    /// don't trust it — the asker could re-use it across questions —
    /// but it's a useful aggregation key in operator dashboards.
    #[prost(bytes = "vec", tag = "1")]
    pub episode_id: Vec<u8>,

    /// 8-byte tier-1 fingerprint of the artifact in question.
    #[prost(bytes = "vec", tag = "2")]
    pub tier1_fp: Vec<u8>,

    /// Hard deadline for responses, in milliseconds since the asker's
    /// wall clock. Responders drop this question if their local clock
    /// is past `ttl_ms` (with some skew tolerance applied separately
    /// at envelope-verification time).
    #[prost(uint64, tag = "3")]
    pub ttl_ms: u64,

    /// Optional short human-readable note (kept under 64 bytes by
    /// convention; over-long values may be truncated by responders for
    /// log-bloat reasons). Empty string means "no note".
    #[prost(string, tag = "4")]
    pub note: String,
}

/// Phase-5 whisper answer to a [`Question`]. Echoes the asker's
/// `episode_id` and `tier1_fp` so multiplexed askers can demux without
/// state-tracking, and so a malicious peer can't confuse one query with
/// another by replying out-of-order.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Answer {
    #[prost(bytes = "vec", tag = "1")]
    pub episode_id: Vec<u8>,

    #[prost(bytes = "vec", tag = "2")]
    pub tier1_fp: Vec<u8>,

    /// How many times the responder has independently observed something
    /// matching this tier-1 fingerprint. Zero means "never seen".
    #[prost(uint64, tag = "3")]
    pub seen_count: u64,

    /// First / last seen, milliseconds since unix epoch. Zero if
    /// `seen_count == 0` (no observations).
    #[prost(uint64, tag = "4")]
    pub first_seen_unix_ms: u64,

    #[prost(uint64, tag = "5")]
    pub last_seen_unix_ms: u64,

    /// Optional short note (rationale, role-tag of the responding host,
    /// etc.). Over 256 bytes is truncated by the asker.
    #[prost(string, tag = "6")]
    pub note: String,
}

// Placeholders — populated in later phases.

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Alert {}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct OperatorCommand {}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct OperatorResult {}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct NeighborOp {}

// ---------------------------------------------------------------------------
// Bloom advert — published to the mesh KV (chitchat), not via envelope.
// ---------------------------------------------------------------------------

/// A periodic "what tier-1 fingerprints have I seen" advert, gossiped
/// through the mesh KV. Encoded as protobuf for compactness and
/// schema-evolution; the KV value is base64'd by the mesh layer if
/// needed for transport.
///
/// Privacy trade-off: this leaks a coarse view of every host's
/// observation set in the public KV. Two mitigations:
/// 1. Tier-1 fingerprints are 64-bit and intentionally collidable.
/// 2. Bloom filters add a second layer of indistinguishability — a
///    "yes" set-membership in the filter is consistent with collisions
///    on top of collisions.
///
/// Tier-2 (the full sha256) only travels through the encrypted whisper
/// envelope, after both sides agree the tier-1 hint is worth chasing.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct BloomAdvert {
    /// Monotonic epoch counter. Receivers keep only the highest epoch
    /// from any given peer; lower-epoch adverts are stale.
    #[prost(uint64, tag = "1")]
    pub epoch: u64,

    /// Filter size in bits. Must equal `bits.len() * 8`.
    #[prost(uint32, tag = "2")]
    pub bit_count: u32,

    /// Number of hash positions per insert. Bounded at sender side; the
    /// receiver should reject impossibly large values.
    #[prost(uint32, tag = "3")]
    pub k: u32,

    /// Raw filter bytes (length = `bit_count / 8`).
    #[prost(bytes = "vec", tag = "4")]
    pub bits: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

impl WhisperPayload {
    pub fn heartbeat(agent_version: impl Into<String>) -> Self {
        Self {
            body: Some(Body::Heartbeat(Heartbeat {
                agent_version: agent_version.into(),
            })),
        }
    }

    pub fn question(q: Question) -> Self {
        Self {
            body: Some(Body::Question(q)),
        }
    }

    pub fn answer(a: Answer) -> Self {
        Self {
            body: Some(Body::Answer(a)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_roundtrip() {
        let original = WhisperPayload::heartbeat("0.0.1");
        let bytes = original.encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        assert_eq!(original, decoded);
        match decoded.body {
            Some(Body::Heartbeat(hb)) => assert_eq!(hb.agent_version, "0.0.1"),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn question_roundtrip() {
        let q = Question {
            episode_id: vec![0xab; 16],
            tier1_fp: vec![0xcd; 8],
            ttl_ms: 60_000,
            note: "binary scored 0.83".into(),
        };
        let original = WhisperPayload::question(q.clone());
        let bytes = original.encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        match decoded.body {
            Some(Body::Question(got)) => assert_eq!(got, q),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn answer_roundtrip() {
        let a = Answer {
            episode_id: vec![0xab; 16],
            tier1_fp: vec![0xcd; 8],
            seen_count: 3,
            first_seen_unix_ms: 1_700_000_000_000,
            last_seen_unix_ms: 1_700_000_300_000,
            note: "common across web tier".into(),
        };
        let original = WhisperPayload::answer(a.clone());
        let bytes = original.encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        match decoded.body {
            Some(Body::Answer(got)) => assert_eq!(got, a),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn bloom_advert_roundtrip() {
        let advert = BloomAdvert {
            epoch: 7,
            bit_count: 1024,
            k: 6,
            bits: vec![0xff; 128],
        };
        let bytes = advert.encode_to_vec();
        let decoded = BloomAdvert::decode(bytes.as_slice()).unwrap();
        assert_eq!(advert, decoded);
    }

    #[test]
    fn empty_envelope_roundtrip() {
        let env = WhisperEnvelope {
            sender_fingerprint: vec![0u8; 32],
            nonce: 42,
            ts_unix_ms: 1_700_000_000_000,
            payload: WhisperPayload::heartbeat("0.0.1").encode_to_vec(),
            signature: vec![0u8; 64],
        };
        let bytes = env.encode_to_vec();
        let decoded = WhisperEnvelope::decode(bytes.as_slice()).unwrap();
        assert_eq!(env, decoded);
    }
}
