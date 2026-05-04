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
pub mod episode;
pub mod peer_select;
pub mod role;
pub mod rule;
pub mod score;

pub use analyzer::{Analyzer, Verdict};
pub use episode::Episode;
pub use peer_select::{DEFAULT_FANOUT, DEFAULT_MIN_SIMILARITY, rank_by_similarity};
pub use role::{ROLE_VECTOR_DIMS, RoleFeatures, RoleVector};
pub use rule::{Rule, RuleHit, RuleSeverity};
pub use score::{BinaryScore, BinaryScorer};
