//! Phase-7 BPF-LSM-backed [`ResponseEngine`].
//!
//! Wraps a [`BpfBlocker`] and translates `Action::BlockExec` into
//! `BLOCKED_COMMS` map insertions. The kernel-side LSM hook
//! (`block_exec` in `crates/bowery-ebpf/src/main.rs`) consults that
//! map on every `bprm_check_security` and returns `EPERM` for
//! matches.
//!
//! Lives in `bowery-agent` rather than `bowery-response` because the
//! `BpfBlocker` import would drag aya + the BPF loader's whole
//! dep graph into a crate whose entire point is to be lightweight
//! enough to import from tests and CLI tools.
//!
//! Locking: `BpfBlocker` map operations need `&mut self` (aya's
//! `HashMap::insert/remove` borrows the underlying `MapData`
//! mutably). We wrap it in a `tokio::sync::Mutex` so concurrent
//! `execute()` calls serialise correctly. Lock hold time is
//! microseconds (a single bpf syscall), so contention is irrelevant
//! at realistic action rates.

use std::sync::Arc;

use async_trait::async_trait;
use bowery_ebpf_loader::BpfBlocker;
use bowery_response::{Action, ActionError, ActionOutcome, ResponseEngine, ResponsePolicy};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// `BpfBlocker`-backed engine. Implements `block_exec` via the
/// kernel-side `BLOCKED_COMMS` map; suppresses `kill_process` (use
/// the `process-kill` engine for that).
pub struct BpfLsmEngine {
    policy: ResponsePolicy,
    blocker: Arc<Mutex<BpfBlocker>>,
}

impl BpfLsmEngine {
    pub fn new(policy: ResponsePolicy, blocker: BpfBlocker) -> Self {
        Self {
            policy,
            blocker: Arc::new(Mutex::new(blocker)),
        }
    }
}

impl std::fmt::Debug for BpfLsmEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BpfLsmEngine")
            .field("policy.disabled", &self.policy.disabled)
            .field("policy.allowed_actions", &self.policy.allowed_actions.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ResponseEngine for BpfLsmEngine {
    async fn execute(&self, action: &Action) -> Result<ActionOutcome, ActionError> {
        if !self.policy.permits(action.id()) {
            return Ok(ActionOutcome::suppressed("policy denied"));
        }
        match action {
            Action::BlockExec { comm, episode_id } => {
                // Critical-comm protection. An attacker can call
                // prctl(PR_SET_NAME, "sshd") to spoof their comm; if we
                // add "sshd" to BLOCKED_COMMS the kernel hook then EPERM's
                // every legitimate sshd exec. Default-deny on a list of
                // process names whose loss would brick the host.
                if !self.policy.permits_block_exec_comm(comm) {
                    warn!(
                        episode = %episode_id,
                        comm = %comm,
                        "bpf-lsm: refusing to block protected comm"
                    );
                    return Ok(ActionOutcome::suppressed(
                        "comm is on the BlockExec deny-list (critical-service protection)",
                    ));
                }
                let mut blocker = self.blocker.lock().await;
                match blocker.block_comm(comm) {
                    Ok(()) => {
                        info!(
                            episode = %episode_id,
                            comm = %comm,
                            "bpf-lsm: comm added to BLOCKED_COMMS"
                        );
                        Ok(ActionOutcome::executed_now())
                    }
                    Err(e) => {
                        warn!(
                            episode = %episode_id,
                            comm = %comm,
                            error = %e,
                            "bpf-lsm: BLOCKED_COMMS insert failed"
                        );
                        Err(ActionError::Invalid(format!("block_comm: {e}")))
                    }
                }
            }
            Action::KillProcess { .. } => Ok(ActionOutcome::suppressed(
                "bpf-lsm engine doesn't implement kill_process; switch to process-kill",
            )),
        }
    }

    fn policy(&self) -> &ResponsePolicy {
        &self.policy
    }

    fn name(&self) -> &'static str {
        "bpf-lsm"
    }
}
