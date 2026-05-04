//! Pluggable execution surface for [`Action`]s.
//!
//! The agent calls [`ResponseEngine::execute`] every time the LLM's
//! verdict carries a `suggested_actions` entry whose id maps to a
//! known [`Action`] *and* the [`ResponsePolicy`] permits it. The
//! engine is responsible for the actual side-effect: signal delivery,
//! BPF map updates, audit-log writes, etc.
//!
//! Phase 7 v1 ships [`NoopEngine`] only — it accepts the request,
//! emits a `Suppressed { reason: "noop engine" }` outcome, and
//! returns. The agent's startup logs make it obvious that no
//! enforcement is happening; turning it on means swapping the engine
//! type in `Agent::start_with_llm`. A `ProcessKillEngine` (real
//! `kill(2)`) and a `BpfLsmEngine` (kernel-side blocking) land in
//! follow-up commits.

use async_trait::async_trait;

use crate::action::{Action, ActionError, ActionOutcome};
use crate::policy::ResponsePolicy;

/// Anything that can take an [`Action`] and try to make it real.
///
/// Implementations should:
/// - Be idempotent: re-executing the same action against an
///   already-finalised target (pid that already exited, BPF entry
///   already set) returns [`ActionOutcome::AlreadyGone`] rather than
///   an error.
/// - Be cheap when the policy denies: callers pre-check with
///   [`ResponseEngine::policy`], but defence in depth — engines
///   should *also* short-circuit denied actions.
#[async_trait]
pub trait ResponseEngine: Send + Sync {
    /// Execute (or suppress) `action`. Errors only when the
    /// underlying syscall / kernel hook fails in an unexpected way;
    /// "already gone", "policy says no", and "we don't implement
    /// this" are all `Ok` outcomes carrying a discriminator.
    async fn execute(&self, action: &Action) -> Result<ActionOutcome, ActionError>;

    /// The policy this engine is gating on. Callers consult it
    /// before constructing the action to skip the typed-conversion
    /// work entirely when the id is denied.
    fn policy(&self) -> &ResponsePolicy;

    /// Stable identifier for logs / dashboards (`"noop"`,
    /// `"process-kill"`, `"bpf-lsm"`).
    fn name(&self) -> &'static str;
}

/// Observe-only engine. Records every request as `Suppressed` and
/// never touches the host. The default — and the right choice for
/// any host where the operator hasn't yet validated the LLM's
/// `suggested_actions` quality.
pub struct NoopEngine {
    policy: ResponsePolicy,
}

impl NoopEngine {
    pub fn new(policy: ResponsePolicy) -> Self {
        Self { policy }
    }
}

impl std::fmt::Debug for NoopEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopEngine")
            .field("policy.disabled", &self.policy.disabled)
            .field("policy.allowed_actions", &self.policy.allowed_actions.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ResponseEngine for NoopEngine {
    async fn execute(&self, action: &Action) -> Result<ActionOutcome, ActionError> {
        if !self.policy.permits(action.id()) {
            return Ok(ActionOutcome::suppressed("policy denied"));
        }
        Ok(ActionOutcome::suppressed("observe-only engine"))
    }

    fn policy(&self) -> &ResponsePolicy {
        &self.policy
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kill_action() -> Action {
        Action::KillProcess {
            pid: 4242,
            episode_id: "ep-1".into(),
        }
    }

    #[tokio::test]
    async fn noop_engine_with_default_policy_denies() {
        let eng = NoopEngine::new(ResponsePolicy::default());
        let outcome = eng.execute(&kill_action()).await.unwrap();
        assert!(matches!(
            outcome,
            ActionOutcome::Suppressed { reason } if reason == "policy denied"
        ));
    }

    #[tokio::test]
    async fn noop_engine_with_permissive_policy_still_observes_only() {
        let policy = ResponsePolicy {
            allowed_actions: vec!["kill_process".into()],
            disabled: false,
        };
        let eng = NoopEngine::new(policy);
        let outcome = eng.execute(&kill_action()).await.unwrap();
        assert!(matches!(
            outcome,
            ActionOutcome::Suppressed { reason } if reason == "observe-only engine"
        ));
    }

    #[tokio::test]
    async fn noop_engine_disabled_policy_denies_everything() {
        let policy = ResponsePolicy {
            allowed_actions: vec!["kill_process".into()],
            disabled: true,
        };
        let eng = NoopEngine::new(policy);
        let outcome = eng.execute(&kill_action()).await.unwrap();
        assert!(matches!(
            outcome,
            ActionOutcome::Suppressed { reason } if reason == "policy denied"
        ));
    }

    #[test]
    fn name_returns_stable_identifier() {
        let eng = NoopEngine::new(ResponsePolicy::default());
        assert_eq!(eng.name(), "noop");
    }
}
