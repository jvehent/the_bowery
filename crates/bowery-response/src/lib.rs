//! The Bowery's Phase-7 response engine.
//!
//! This crate is the policy-and-execution layer that sits between the
//! LLM analyzer (which produces `suggested_actions`) and the actual
//! kernel-side machinery that blocks or kills (BPF-LSM hooks, signal
//! delivery, etc.). It is deliberately split into three pieces:
//!
//! - **[`Action`]** — the typed action enum. New action ids are added
//!   here first; everything else flows from this.
//! - **[`ResponsePolicy`]** — the operator-controlled gate. Today it
//!   answers "may I execute *any* instance of this action id without
//!   operator approval?" Later phases will add per-host conditions,
//!   ttl-bounded standing authorisations, rate limits, and signed
//!   updates.
//! - **[`ResponseEngine`]** — the execution interface. Implementations
//!   range from [`NoopEngine`] (records the request, never executes —
//!   the default, observe-only) to a future BPF-LSM-backed engine
//!   that actually flips kernel-side bitmaps to block exec / open /
//!   connect.
//!
//! The agent calls `engine.execute(&action).await` whenever the LLM
//! produces a verdict whose `suggested_actions` list contains an
//! action id the policy permits. Engines are responsible for being
//! safe under a stuck or hostile policy file: the layered design
//! means you can ship the agent with `NoopEngine` everywhere first,
//! validate end-to-end signal flow, and only then turn the executor
//! on for a small subset of hosts.

pub mod action;
pub mod engine;
pub mod policy;
pub mod process_kill;

pub use action::{Action, ActionError, ActionOutcome};
pub use engine::{NoopEngine, ResponseEngine};
pub use policy::ResponsePolicy;
pub use process_kill::ProcessKillEngine;
