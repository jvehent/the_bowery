//! Enforcement, fully decided and deliberately not carried out.
//!
//! # The question this answers
//!
//! Arming an EDR is a step operators are right to be slow about: the
//! failure mode is killing production, and nothing in an observe-only
//! deployment tells you what *would* have happened. The choice was
//! between running blind and running armed, and most people sensibly
//! choose blind forever.
//!
//! Dry run is the missing middle. Every gate runs — policy, deny-list,
//! action construction, whatever the wrapped engine would consult — and
//! the last step is skipped. What lands in the audit log is the exact
//! set of actions arming this host would have taken, on this host's real
//! traffic, with no risk of taking them.
//!
//! # Why this is not `NoopEngine`
//!
//! [`crate::NoopEngine`] answers a different question. It reports
//! `Suppressed`, which means *a gate said no* — and that is the opposite
//! of what a dry run finds. An operator evaluating enforcement would
//! read their own approved actions as policy rejections and conclude the
//! policy was working when it had in fact approved every one of them.
//!
//! So this reports [`ActionOutcome::WouldExecute`], naming the engine
//! that was standing by. `Suppressed` continues to mean refused, and the
//! two never blur.
//!
//! # What it still does
//!
//! It wraps a **real** engine and consults its policy, so a dry run is
//! only as informative as the configuration behind it. Running dry over
//! a deny-all policy correctly reports nothing, because nothing would
//! have happened.

use async_trait::async_trait;

use crate::action::{Action, ActionError, ActionOutcome};
use crate::engine::ResponseEngine;
use crate::policy::ResponsePolicy;

/// Wraps an engine and reports what it would have done.
pub struct DryRunEngine {
    inner: Box<dyn ResponseEngine>,
}

impl std::fmt::Debug for DryRunEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DryRunEngine")
            .field("wrapping", &self.inner.name())
            .finish()
    }
}

impl DryRunEngine {
    #[must_use]
    pub fn new(inner: Box<dyn ResponseEngine>) -> Self {
        Self { inner }
    }

    /// The engine that would have carried the action out.
    #[must_use]
    pub fn wrapped(&self) -> &'static str {
        self.inner.name()
    }
}

#[async_trait]
impl ResponseEngine for DryRunEngine {
    async fn execute(&self, action: &Action) -> Result<ActionOutcome, ActionError> {
        // The policy gate is the wrapped engine's, and it runs for real:
        // a dry run over a deny-all policy must report nothing, because
        // nothing would have happened. Only the final effect is skipped.
        if !self.inner.policy().permits(action.id()) {
            return Ok(ActionOutcome::suppressed(format!(
                "policy does not permit {} (dry run)",
                action.id()
            )));
        }
        Ok(ActionOutcome::would_execute(self.inner.name()))
    }

    fn policy(&self) -> &ResponsePolicy {
        self.inner.policy()
    }

    fn name(&self) -> &'static str {
        "dry-run"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopEngine;
    use crate::process_kill::ProcessKillEngine;

    fn allowing(ids: &[&str]) -> ResponsePolicy {
        ResponsePolicy {
            allowed_actions: ids.iter().map(|s| (*s).to_string()).collect(),
            disabled: false,
            block_exec_deny_list: Vec::new(),
        }
    }

    fn kill() -> Action {
        Action::KillProcess {
            pid: 4242,
            episode_id: "ep-1".into(),
        }
    }

    /// The distinction the whole module exists for: an approved action
    /// reads as "would have run", never as "was refused".
    #[tokio::test]
    async fn an_approved_action_reports_would_execute_not_suppressed() {
        let engine = DryRunEngine::new(Box::new(ProcessKillEngine::new(allowing(&[
            "kill_process",
        ]))));
        let outcome = engine.execute(&kill()).await.expect("dry run");
        assert!(
            matches!(&outcome, ActionOutcome::WouldExecute { would, .. } if would == "process-kill"),
            "got {outcome:?}"
        );
        assert!(
            !outcome.changed_the_host(),
            "a dry run must never change the host"
        );
    }

    /// A dry run over a deny-all policy reports nothing, because nothing
    /// would have happened. Reporting "would execute" here would tell an
    /// operator their policy was about to act when it was not.
    #[tokio::test]
    async fn a_denied_action_still_reads_as_denied() {
        let engine = DryRunEngine::new(Box::new(ProcessKillEngine::new(allowing(&[]))));
        let outcome = engine.execute(&kill()).await.expect("dry run");
        assert!(
            matches!(outcome, ActionOutcome::Suppressed { .. }),
            "{outcome:?}"
        );
    }

    /// The pid is real and belongs to this test process; the point is
    /// that nothing is signalled. If the dry run leaked through, the
    /// test binary would die.
    #[tokio::test]
    async fn nothing_reaches_the_host() {
        let me = std::process::id();
        let engine = DryRunEngine::new(Box::new(ProcessKillEngine::new(allowing(&[
            "kill_process",
        ]))));
        let outcome = engine
            .execute(&Action::KillProcess {
                pid: me,
                episode_id: "ep-self".into(),
            })
            .await
            .expect("dry run");
        assert!(matches!(outcome, ActionOutcome::WouldExecute { .. }));
        // Still here.
        assert_eq!(std::process::id(), me);
    }

    #[test]
    fn it_names_the_engine_it_stands_in_for() {
        let engine = DryRunEngine::new(Box::new(NoopEngine::new(allowing(&[]))));
        assert_eq!(engine.name(), "dry-run");
        assert_eq!(engine.wrapped(), "noop");
    }
}
