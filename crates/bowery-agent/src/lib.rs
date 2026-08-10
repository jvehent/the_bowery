//! The Bowery agent runtime, exposed as a library so it can be embedded
//! in tests and tools without going through the binary.
//!
//! Phase 1c surface: build an [`Agent`] from a [`Config`] and an
//! [`Identity`], let it gossip into the mesh, accept QUIC connections,
//! TOFU-pin neighbors, and exchange Heartbeats. Drop or call
//! [`Agent::shutdown`] to stop it.

pub mod agent;
mod bloom_publisher;
pub mod config;
mod eventlog_writer;
pub mod inbox;
pub mod monitor;
pub mod response_bpf;
pub mod sql_tables;
pub mod whisper_qa;
pub mod yara_store;

pub use agent::{Agent, AgentError, AgentEvent};
pub use config::Config;
pub use inbox::AlertInbox;
pub use whisper_qa::{PeerSighting, WhisperContext};
