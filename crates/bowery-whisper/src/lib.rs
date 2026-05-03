//! The Bowery whispering protocol.
//!
//! Phase 1a scope: envelope sealing/opening with Ed25519 signatures, a
//! per-sender sliding-window replay guard, and a `FingerprintResolver`
//! abstraction for callers to plug in their pinned-neighbor store.
//!
//! Phase 1b adds the QUIC transport. Phase 5 wraps payloads in
//! ChaCha20-Poly1305 ciphertext keyed by an X25519 ECDH session key.

mod envelope;
mod replay;
pub mod tls;
pub mod transport;

pub use envelope::{
    Error, FingerprintResolver, Sealer, StaticResolver, VerifiedEnvelope, Verifier,
};
pub use replay::ReplayGuard;
