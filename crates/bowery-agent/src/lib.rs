//! The Bowery agent runtime, exposed as a library so it can be embedded
//! in tests and tools without going through the binary.
//!
//! Phase 1c surface: build an [`Agent`] from a [`Config`] and an
//! [`Identity`], let it gossip into the mesh, accept QUIC connections,
//! TOFU-pin neighbors, and exchange Heartbeats. Drop or call
//! [`Agent::shutdown`] to stop it.

pub mod agent;
pub mod config;
pub mod whisper_qa;

pub use agent::{Agent, AgentError, AgentEvent};
pub use config::Config;
pub use whisper_qa::{PeerSighting, WhisperContext};
