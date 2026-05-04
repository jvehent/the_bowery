//! Typed action surface.
//!
//! Action ids on the wire (in `LlmVerdict.suggested_actions`) are
//! strings the LLM was prompted to choose from. This module turns
//! those strings into typed [`Action`]s that the engine can pattern-
//! match on.
//!
//! When a new action id is introduced, the workflow is:
//! 1. Add a variant to [`Action`].
//! 2. Update [`Action::id`] and [`Action::from_id`] to round-trip.
//! 3. Update the LLM prompt (`bowery-llm/src/prompt.rs`) so the model
//!    knows the id is allowed.
//! 4. Update [`ResponsePolicy`](crate::policy::ResponsePolicy)'s
//!    default-deny stance: operators have to add the new id to
//!    `allowed_actions` to opt in.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A concrete action the engine has been asked to execute.
///
/// Phase 7 v1 only carries `KillProcess`; later commits add the
/// blocking variants once the BPF-LSM hooks land. Splitting them out
/// at the type level (rather than carrying a generic `args: Vec<String>`)
/// means new actions go through code review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// Send `SIGKILL` to a specific pid. Idempotent: killing a
    /// non-existent pid yields [`ActionOutcome::AlreadyGone`].
    KillProcess {
        pid: u32,
        /// The episode id this action was decided for. Carried so
        /// audit trails can correlate the action with the verdict
        /// that motivated it.
        episode_id: String,
    },
    // Future variants — keep this comment up to date as Phase 7
    // progresses:
    //   BlockExec    { sha256: [u8; 32], ttl: Duration }
    //   BlockOpen    { path: PathBuf, ttl: Duration }
    //   BlockConnect { addr: IpAddr, port: u16, ttl: Duration }
    //   QuarantineHost { ttl: Duration }
}

impl Action {
    /// Stable string identifier. Matches the `suggested_actions`
    /// values the LLM emits and the entries operators put in
    /// `[response] allowed_actions`.
    pub fn id(&self) -> &'static str {
        match self {
            Action::KillProcess { .. } => "kill_process",
        }
    }

    /// All action ids the engine knows how to execute today. Used by
    /// policy parsing to reject typos in `allowed_actions` early.
    pub fn known_ids() -> &'static [&'static str] {
        &["kill_process"]
    }
}

/// Outcome of a single action execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ActionOutcome {
    /// The engine actually performed the action (signal sent, BPF map
    /// updated, etc.). Carries `at_unix_ms` so audit logs are easy to
    /// correlate.
    Executed { at_unix_ms: u64 },
    /// The engine accepted the request but did nothing because the
    /// target was already in the desired state — e.g. the pid we
    /// were asked to kill had already exited.
    AlreadyGone,
    /// The engine accepted the request but suppressed it (policy
    /// denial, not-yet-implemented executor, dry-run mode, etc.).
    /// `reason` is short, human-readable, and stable enough for ops
    /// dashboards to group on.
    Suppressed { reason: String },
}

impl ActionOutcome {
    pub fn executed_now() -> Self {
        let at_unix_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        Self::Executed { at_unix_ms }
    }

    pub fn suppressed(reason: impl Into<String>) -> Self {
        Self::Suppressed {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ActionError {
    #[error("kill_process: signal delivery failed for pid {pid}: {reason}")]
    KillFailed { pid: u32, reason: String },

    #[error("action `{0}` is not implemented in this engine")]
    Unimplemented(&'static str),

    #[error("action input rejected: {0}")]
    Invalid(String),
}

/// Convert an LLM-emitted action id (with the verdict's episode id
/// for traceability) into a typed action. Returns `None` for ids
/// that don't currently round-trip — older models are easy to
/// surprise with imagined ids, and we want to drop those silently
/// rather than crash.
///
/// `pid` is taken from the originating event; callers that don't
/// have one (e.g. per-host policy actions like `quarantine_host`)
/// can pass 0 once those variants exist.
pub fn from_id(id: &str, episode_id: &str, pid: Option<u32>) -> Option<Action> {
    match id {
        "kill_process" => Some(Action::KillProcess {
            pid: pid?,
            episode_id: episode_id.to_string(),
        }),
        _ => None,
    }
}

/// Convenience for tests and audit-log filters.
pub fn _suppress_unused_duration() -> Duration {
    Duration::ZERO
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_roundtrips_through_from_id() {
        let action = from_id("kill_process", "ep-x", Some(42)).unwrap();
        assert_eq!(action.id(), "kill_process");
        match action {
            Action::KillProcess { pid, episode_id } => {
                assert_eq!(pid, 42);
                assert_eq!(episode_id, "ep-x");
            }
        }
    }

    #[test]
    fn from_id_drops_unknown_actions() {
        assert!(from_id("isolate_host", "ep", Some(1)).is_none());
        assert!(from_id("page_oncall", "ep", Some(1)).is_none());
    }

    #[test]
    fn kill_process_requires_pid() {
        assert!(from_id("kill_process", "ep", None).is_none());
    }

    #[test]
    fn known_ids_lists_kill_process() {
        assert!(Action::known_ids().contains(&"kill_process"));
    }

    #[test]
    fn outcome_executed_now_carries_a_timestamp() {
        let o = ActionOutcome::executed_now();
        match o {
            ActionOutcome::Executed { at_unix_ms } => assert!(at_unix_ms > 0),
            other => panic!("expected Executed, got {other:?}"),
        }
    }
}
