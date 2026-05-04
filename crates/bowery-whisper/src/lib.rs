//! The Bowery whispering protocol.
//!
//! Phase 1a scope: envelope sealing/opening with Ed25519 signatures, a
//! per-sender sliding-window replay guard, and a `FingerprintResolver`
//! abstraction for callers to plug in their pinned-neighbor store.
//!
//! Phase 1b adds the QUIC transport. Phase 5 wraps payloads in
//! ChaCha20-Poly1305 ciphertext keyed by an X25519 ECDH session key.

mod envelope;
pub mod fingerprint;
pub mod known_neighbors;
pub mod qa;
mod replay;
pub mod tls;
pub mod transport;

pub use envelope::{
    CompositeResolver, Error, FingerprintResolver, Sealer, StaticResolver, VerifiedEnvelope,
    Verifier,
};
pub use fingerprint::{BloomError, BloomFilter, Tier1Fingerprint};
pub use replay::ReplayGuard;
