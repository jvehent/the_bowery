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

/// Pids we will never signal regardless of LLM verdict / operator policy.
/// `0` is "process group / current session" sentinel for `kill(2)`,
/// `1` is `init` (typically systemd), `2` is `kthreadd` (kernel thread
/// supervisor). Killing any of these is at best a self-inflicted host
/// reboot and at worst a kernel panic.
const FORBIDDEN_PIDS: &[u32] = &[0, 1, 2];

/// Read the comm of `pid` from `/proc/<pid>/comm`. Returns `None` on
/// any I/O error (process gone, permissions, /proc unavailable). The
/// caller treats `None` as "we don't know what this pid is right now",
/// which composes naturally with the `AlreadyGone` short-circuit.
fn pid_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())
}

/// `SIGKILL`-on-permitted-action engine.
#[derive(Debug)]
pub struct ProcessKillEngine {
    policy: ResponsePolicy,
    /// pid of the agent process. We refuse to SIGKILL ourselves
    /// regardless of LLM verdict. Captured at construction time
    /// (`std::process::id()`).
    self_pid: u32,
}

impl ProcessKillEngine {
    pub fn new(policy: ResponsePolicy) -> Self {
        Self {
            policy,
            self_pid: std::process::id(),
        }
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
                // Forbidden-pid skip-list: 0 (kill(2)'s "current group"
                // sentinel), 1 (init), 2 (kthreadd), and the agent's own
                // pid. None of these ever should be signalled, regardless
                // of LLM verdict.
                if FORBIDDEN_PIDS.contains(pid) || *pid == self.self_pid {
                    warn!(
                        episode = %episode_id,
                        pid = pid,
                        "process_kill: refusing to SIGKILL forbidden pid"
                    );
                    return Ok(ActionOutcome::suppressed(
                        "pid is on the kill_process forbidden list (init / kthreadd / agent self)",
                    ));
                }
                // Defense-in-depth against pid recycling: between exec
                // event capture and SIGKILL the pid may have been reused
                // by an unrelated process. Read /proc/<pid>/comm and
                // refuse if the comm landed on the BlockExec deny-list
                // (sshd, systemd, etc.) — same critical-service set we
                // protect against the BPF-LSM-engine spoof attack. This
                // doesn't fully close the race (process could re-exec
                // again between this read and kill), but it catches the
                // common case where pid landed in a long-lived service.
                if let Some(current_comm) = pid_comm(*pid)
                    && !self.policy.permits_block_exec_comm(&current_comm)
                {
                    warn!(
                        episode = %episode_id,
                        pid = pid,
                        comm = %current_comm,
                        "process_kill: refusing SIGKILL on critical-service comm \
                         (likely pid-reuse race or comm spoof)"
                    );
                    return Ok(ActionOutcome::suppressed(
                        "pid currently maps to a comm on the critical-service deny-list",
                    ));
                }
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

    /// Phase-8 hardening (H10): refuse to SIGKILL pid 1 (init) even
    /// under permissive policy. The pid is forbidden on the engine
    /// side regardless of what the LLM verdict said.
    #[tokio::test]
    async fn refuses_to_kill_pid_one() {
        let engine = ProcessKillEngine::new(permissive_policy());
        let outcome = engine.execute(&kill_action(1)).await.unwrap();
        assert!(
            matches!(
                outcome,
                ActionOutcome::Suppressed { ref reason } if reason.contains("forbidden")
            ),
            "expected forbidden-pid suppression, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn refuses_to_kill_kthreadd() {
        let engine = ProcessKillEngine::new(permissive_policy());
        let outcome = engine.execute(&kill_action(2)).await.unwrap();
        assert!(matches!(
            outcome,
            ActionOutcome::Suppressed { ref reason } if reason.contains("forbidden")
        ));
    }

    #[tokio::test]
    async fn refuses_to_kill_zero_pid_sentinel() {
        let engine = ProcessKillEngine::new(permissive_policy());
        let outcome = engine.execute(&kill_action(0)).await.unwrap();
        assert!(matches!(
            outcome,
            ActionOutcome::Suppressed { ref reason } if reason.contains("forbidden")
        ));
    }

    #[tokio::test]
    async fn refuses_to_kill_agent_self() {
        let engine = ProcessKillEngine::new(permissive_policy());
        let self_pid = std::process::id();
        let outcome = engine.execute(&kill_action(self_pid)).await.unwrap();
        assert!(matches!(
            outcome,
            ActionOutcome::Suppressed { ref reason } if reason.contains("forbidden")
        ));
    }
}
