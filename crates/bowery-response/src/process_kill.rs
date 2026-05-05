//! `kill(2)`-backed [`ResponseEngine`].
//!
//! Phase-7's first executor that actually changes host state. On
//! `Action::KillProcess { pid, .. }`, the engine consults the policy
//! and — if permitted — sends `SIGKILL` to `pid`. The contract is:
//!
//! - **Policy denied** → [`ActionOutcome::Suppressed`] with reason
//!   `"policy denied"`.
//! - **Successful signal delivery** → [`ActionOutcome::Executed`]
//!   with the wall-clock send time.
//! - **`ESRCH`** (no such process — typically the target already
//!   exited between LLM inference and signal delivery) →
//!   [`ActionOutcome::AlreadyGone`]. This is *not* an error: the
//!   contract for `KillProcess` is "ensure pid is dead by the time
//!   we return", and an already-dead pid satisfies it.
//! - **Any other errno** (`EPERM` is the typical one when the agent
//!   wasn't started with `CAP_KILL`) → [`ActionError::KillFailed`].
//!
//! The engine is intentionally narrow: no rate limiting, no sleep-
//! and-retry, no polling for actual termination. Phase 8 hardening
//! adds those once we have audit data showing how often they matter
//! in production.

use async_trait::async_trait;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tracing::{info, warn};

use crate::action::{Action, ActionError, ActionOutcome};
use crate::engine::ResponseEngine;
use crate::policy::ResponsePolicy;

/// `SIGKILL`-on-permitted-action engine.
#[derive(Debug)]
pub struct ProcessKillEngine {
    policy: ResponsePolicy,
}

impl ProcessKillEngine {
    pub fn new(policy: ResponsePolicy) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl ResponseEngine for ProcessKillEngine {
    async fn execute(&self, action: &Action) -> Result<ActionOutcome, ActionError> {
        if !self.policy.permits(action.id()) {
            return Ok(ActionOutcome::suppressed("policy denied"));
        }
        match action {
            Action::KillProcess { pid, episode_id } => {
                let pid_i32 = i32::try_from(*pid)
                    .map_err(|_| ActionError::Invalid(format!("pid {pid} doesn't fit in i32")))?;
                let target = Pid::from_raw(pid_i32);
                match kill(target, Signal::SIGKILL) {
                    Ok(()) => {
                        info!(
                            episode = %episode_id,
                            pid = pid,
                            "process_kill: SIGKILL delivered"
                        );
                        Ok(ActionOutcome::executed_now())
                    }
                    Err(nix::errno::Errno::ESRCH) => {
                        info!(
                            episode = %episode_id,
                            pid = pid,
                            "process_kill: target already gone (ESRCH)"
                        );
                        Ok(ActionOutcome::AlreadyGone)
                    }
                    Err(e) => {
                        warn!(
                            episode = %episode_id,
                            pid = pid,
                            error = %e,
                            "process_kill: signal delivery failed"
                        );
                        Err(ActionError::KillFailed {
                            pid: *pid,
                            reason: e.to_string(),
                        })
                    }
                }
            }
            Action::BlockExec { .. } => Ok(ActionOutcome::suppressed(
                "process-kill engine doesn't implement block_exec; switch to bpf-lsm",
            )),
        }
    }

    fn policy(&self) -> &ResponsePolicy {
        &self.policy
    }

    fn name(&self) -> &'static str {
        "process-kill"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn permissive_policy() -> ResponsePolicy {
        ResponsePolicy {
            allowed_actions: vec!["kill_process".into()],
            disabled: false,
            block_exec_deny_list: vec![],
        }
    }

    fn kill_action(pid: u32) -> Action {
        Action::KillProcess {
            pid,
            episode_id: "test-episode".into(),
        }
    }

    /// Spawn a long-running child we own. Returns the `Child` so the
    /// test can wait on it after the engine kills it. We use `sleep`
    /// (universally available on Linux test hosts) rather than
    /// `nix::unistd::pause()` to keep the test self-contained.
    fn spawn_sleeper() -> std::process::Child {
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    #[tokio::test]
    async fn kills_a_real_child() {
        let mut child = spawn_sleeper();
        let pid = child.id();

        let engine = ProcessKillEngine::new(permissive_policy());
        let outcome = engine.execute(&kill_action(pid)).await.unwrap();
        assert!(
            matches!(outcome, ActionOutcome::Executed { .. }),
            "expected Executed, got {outcome:?}"
        );

        // The child should now be reapable. SIGKILL → status() reports
        // a non-zero exit / killed-by-signal — either way it's not
        // `success()`.
        let status = child.wait().expect("wait child");
        assert!(!status.success(), "child {pid} should have been killed");
    }

    #[tokio::test]
    async fn already_gone_when_target_already_exited() {
        // Spawn a short-lived child, wait for it to exit, then ask
        // the engine to kill that pid. Linux re-uses pids slowly
        // enough that this is reliable on a test host.
        let mut child = Command::new("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        child.wait().expect("wait true");

        let engine = ProcessKillEngine::new(permissive_policy());
        let outcome = engine.execute(&kill_action(pid)).await.unwrap();
        assert!(
            matches!(outcome, ActionOutcome::AlreadyGone),
            "expected AlreadyGone, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn policy_denies_kill_on_default_config() {
        let engine = ProcessKillEngine::new(ResponsePolicy::default());
        // pid=1 (init) — but the policy denies, so we never actually
        // try to signal it. Belt and braces.
        let outcome = engine.execute(&kill_action(1)).await.unwrap();
        assert!(
            matches!(
                outcome,
                ActionOutcome::Suppressed { ref reason } if reason == "policy denied"
            ),
            "expected Suppressed/policy-denied, got {outcome:?}"
        );
    }

    #[test]
    fn name_is_process_kill() {
        let engine = ProcessKillEngine::new(ResponsePolicy::default());
        assert_eq!(engine.name(), "process-kill");
    }
}
