//! Phase 3 of The Bowery's pipeline: pre-filter rules, baseline scoring,
//! episode aggregation, and role-vector computation.
//!
//! Conceptually this is the layer that turns raw events into something a
//! later phase (LLM analyzer, response engine) can act on. See
//! [`DESIGN.md`](../../DESIGN.md) §5 for the pipeline diagram.
//!
//! Today's surface is intentionally small — Phase 2 only emits
//! [`bowery_events::Event::ProcessExec`] through the agent — but each
//! abstraction ([`Episode`], [`Rule`], [`BinaryScorer`], [`RoleVector`]) is
//! shaped to grow as more event types come online.

#![allow(clippy::doc_markdown)]

pub mod analyzer;
pub mod attack;
pub mod beacon;
pub mod defense;
pub mod episode;
pub mod escalation;
pub mod file_watch;
pub mod injection;
pub mod invocation;
pub mod kmod;
pub mod lineage;
pub mod mass_write;
pub mod peer_select;
pub mod provenance;
pub mod role;
pub mod rule;
pub mod score;
pub mod suppress;

pub use analyzer::{Analyzer, Verdict};
pub use attack::{Coverage, TECHNIQUES, Technique};
pub use beacon::{Beacon, BeaconTracker};
pub use episode::Episode;
pub use escalation::{DiscoveryBurst, DiscoveryTracker, EscalationHit, uid_transition};
pub use mass_write::{MassWriteBurst, MassWriteTracker};
pub use peer_select::{DEFAULT_FANOUT, DEFAULT_MIN_SIMILARITY, rank_by_similarity};
pub use role::{ROLE_VECTOR_DIMS, RoleFeatures, RoleVector};
pub use rule::{OperatorProcessRule, Rule, RuleHit, RuleSeverity};
pub use score::{BinaryScore, BinaryScorer};
pub use suppress::{AlertSuppressor, Decision as SuppressDecision};
