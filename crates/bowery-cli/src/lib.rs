//! Library API for the operator CLI.
//!
//! Exposes the same operations the `bowery` binary uses, so the
//! ncurses console (and any future operator-facing tool) can call
//! them directly without re-implementing wire-format plumbing or
//! peer-manifest handling.
//!
//! Module layout:
//!
//! - [`alerts`] — long-poll the agent inbox via `Subscribe`.
//! - [`audit`] — verify a Phase-7 audit log's hash chain.
//! - [`doctor`] — read-only host-readiness check (BPF-LSM, BTF…).
//! - [`exec`] — issue `OperatorCommand::Sql` queries.
//! - [`model`] — the curated GGUF model registry + downloader.
//! - [`peers`] — read/write `~/.bowery/peers.toml`.
//!
//! The binary at `src/main.rs` wires these into clap subcommands;
//! `bowery-console` will wire them into ratatui panes.

pub mod alerts;
pub mod audit;
pub mod doctor;
pub mod exec;
pub mod model;
pub mod peers;
