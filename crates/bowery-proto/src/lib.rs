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

// Placeholders — populated in later phases.

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Question {}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Answer {}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Alert {}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct OperatorCommand {}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct OperatorResult {}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct NeighborOp {}

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
