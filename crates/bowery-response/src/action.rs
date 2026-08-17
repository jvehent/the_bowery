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
    /// Add `comm` to the kernel-side LSM blocklist so any subsequent
    /// `execve` from a task whose `comm` matches gets `EPERM`.
    /// Implemented by the `BpfLsmEngine` via `BLOCKED_COMMS` (see
    /// `bowery-ebpf/src/main.rs`). Idempotent: re-adding an entry is
    /// a no-op.
    BlockExec {
        /// The 1–15 character process name to block. Truncated /
        /// nul-padded to 16 bytes by the kernel-facing layer.
        comm: String,
        episode_id: String,
    },
    /// Forbid execution of a specific **file**, identified by the
    /// `(dev, ino)` pair the kernel knows it by.
    ///
    /// What `BlockExec` should always have been. `comm` is 16 bytes any
    /// process sets with `prctl`, so a comm blocklist is bypassable by
    /// renaming yourself and *weaponisable* by naming yourself `sshd` —
    /// the agent then locks out the real one. An inode names the file:
    /// a rename keeps it, a copy gets a new one, and neither is under
    /// the attacker's control after the fact.
    ///
    /// `path` is carried for the audit trail only. It is what the
    /// inode was resolved *from*, never what the kernel matches on.
    BlockExecByInode {
        dev: u64,
        ino: u64,
        path: String,
        episode_id: String,
    },
    // Future variants — keep this comment up to date as Phase 7
    // progresses:
    //   BlockOpen      { path: PathBuf,    ttl: Duration }
    //   BlockConnect   { addr: IpAddr,     port: u16, ttl: Duration }
    //   QuarantineHost { ttl: Duration }
}

impl Action {
    /// Stable string identifier. Matches the `suggested_actions`
    /// values the LLM emits and the entries operators put in
    /// `[response] allowed_actions`.
    pub fn id(&self) -> &'static str {
        match self {
            Action::KillProcess { .. } => "kill_process",
            Action::BlockExec { .. } => "block_exec",
            Action::BlockExecByInode { .. } => "block_exec_by_inode",
        }
    }

    /// All action ids the engine knows how to execute today. Used by
    /// policy parsing to reject typos in `allowed_actions` early.
    pub fn known_ids() -> &'static [&'static str] {
        &["kill_process", "block_exec", "block_exec_by_inode"]
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
    /// The engine *attempted* the action and it FAILED (e.g. `kill(2)`
    /// returned EPERM because the agent lacks `CAP_KILL`). Distinct from
    /// `Suppressed`: the action was not deliberately withheld — the host
    /// state was NOT changed and containment did NOT happen. Operators must
    /// be able to tell a genuine enforcement failure apart from a policy
    /// suppression (in `bowery_audit` this is `outcome_kind = "failed"`),
    /// or a silently-failing kill reads as successful containment.
    Failed { reason: String },
    /// Dry run: the action passed every gate and **would** have been
    /// executed, but enforcement is not armed.
    ///
    /// Deliberately not `Suppressed`. Those are opposite facts: a
    /// suppression means a gate said no, and reading a dry run as one
    /// would tell an operator evaluating enforcement that their policy
    /// rejected the action when in fact it approved it. `would` names
    /// the engine that was standing by, so the audit trail says what
    /// arming the host would actually have done.
    WouldExecute { would: String, at_unix_ms: u64 },
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

    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            reason: reason.into(),
        }
    }

    pub fn would_execute(would: impl Into<String>) -> Self {
        let at_unix_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        Self::WouldExecute {
            would: would.into(),
            at_unix_ms,
        }
    }

    /// Did the host actually change?
    ///
    /// The question an operator reading an audit trail is really
    /// asking, and one that four of five variants answer "no" to.
    #[must_use]
    pub fn changed_the_host(&self) -> bool {
        matches!(self, Self::Executed { .. })
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
///
/// `comm` is the 1–15 character process name from the originating
/// event, used by `block_exec`. When absent, `block_exec` is
/// dropped (we don't have a sensible default to block).
pub fn from_id(id: &str, episode_id: &str, pid: Option<u32>, comm: Option<&str>) -> Option<Action> {
    match id {
        "kill_process" => Some(Action::KillProcess {
            pid: pid?,
            episode_id: episode_id.to_string(),
        }),
        "block_exec" => Some(Action::BlockExec {
            comm: comm?.to_string(),
            episode_id: episode_id.to_string(),
        }),
        // `block_exec_by_inode` is deliberately absent: it needs a path
        // to stat, and resolving one here would mean trusting whatever
        // string reached this function. Callers build it with
        // `block_exec_by_inode_for`, which is where the refusal to
        // unexecutable a critical system binary lives.
        _ => None,
    }
}

/// Paths whose execution must never be blocked, whatever a verdict
/// says.
///
/// The inode key removes the *spoofing* problem — an attacker cannot
/// make their file share `sshd`'s inode — but it does not remove the
/// *targeting* one: a verdict that names `/usr/sbin/sshd` would block
/// the real `sshd`, and now unspoofably. This is the same protection
/// `DEFAULT_BLOCK_EXEC_DENY_LIST` gives the comm path, keyed on the
/// thing that actually gets resolved.
///
/// Prefix-matched so a distribution's own layout variations
/// (`/usr/lib/systemd/systemd` and friends) are covered without
/// enumerating every helper.
const PROTECTED_EXEC_PREFIXES: &[&str] = &[
    "/usr/sbin/sshd",
    "/usr/lib/openssh/",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/login",
    "/bin/login",
    "/usr/lib/systemd/",
    "/lib/systemd/",
    "/usr/bin/systemctl",
    "/sbin/init",
    "/usr/sbin/init",
    // The agent itself. Blocking your own binary means no restart and
    // no way to undo the block without single-user mode.
    "/usr/bin/bowery-agent",
    "/usr/bin/bowery",
];

/// Is this a path the agent must refuse to make unexecutable?
#[must_use]
pub fn is_protected_exec_path(path: &str) -> bool {
    PROTECTED_EXEC_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Build a [`Action::BlockExecByInode`] for `path`, resolving the inode
/// the kernel knows it by.
///
/// Deliberately not reachable from [`from_id`]: it needs a real path to
/// `stat`, and this is where the refusal to unexecutable a critical
/// binary lives. Returns `None` when the path is protected or cannot be
/// stat'd — a block that cannot be resolved must not become a block on
/// something else.
#[must_use]
pub fn block_exec_by_inode_for(path: &str, episode_id: &str) -> Option<Action> {
    if is_protected_exec_path(path) {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let md = std::fs::metadata(path).ok()?;
        Some(Action::BlockExecByInode {
            dev: md.dev(),
            ino: md.ino(),
            path: path.to_string(),
            episode_id: episode_id.to_string(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, episode_id);
        None
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
    fn failed_outcome_is_distinct_from_suppressed_in_audit_kind() {
        // `bowery_audit` derives `outcome_kind` from the serde `outcome`
        // tag. A genuine enforcement failure must NOT read as "suppressed"
        // (a deliberate withholding) or the operator can't tell that
        // containment silently failed.
        let failed = serde_json::to_value(ActionOutcome::failed("EPERM")).unwrap();
        assert_eq!(failed.get("outcome").unwrap(), "failed");
        assert_eq!(failed.get("reason").unwrap(), "EPERM");

        let suppressed = serde_json::to_value(ActionOutcome::suppressed("policy denied")).unwrap();
        assert_eq!(suppressed.get("outcome").unwrap(), "suppressed");
        assert_ne!(
            failed.get("outcome").unwrap(),
            suppressed.get("outcome").unwrap()
        );
    }

    #[test]
    fn id_roundtrips_through_from_id() {
        let action = from_id("kill_process", "ep-x", Some(42), None).unwrap();
        assert_eq!(action.id(), "kill_process");
        match action {
            Action::KillProcess { pid, episode_id } => {
                assert_eq!(pid, 42);
                assert_eq!(episode_id, "ep-x");
            }
            other => panic!("expected KillProcess, got {other:?}"),
        }
    }

    #[test]
    fn from_id_drops_unknown_actions() {
        assert!(from_id("isolate_host", "ep", Some(1), None).is_none());
        assert!(from_id("page_oncall", "ep", Some(1), None).is_none());
    }

    #[test]
    fn kill_process_requires_pid() {
        assert!(from_id("kill_process", "ep", None, None).is_none());
    }

    #[test]
    fn block_exec_requires_comm() {
        assert!(from_id("block_exec", "ep", Some(1), None).is_none());
    }

    #[test]
    fn block_exec_roundtrips() {
        let action = from_id("block_exec", "ep-y", None, Some("nc")).unwrap();
        assert_eq!(action.id(), "block_exec");
        match action {
            Action::BlockExec { comm, episode_id } => {
                assert_eq!(comm, "nc");
                assert_eq!(episode_id, "ep-y");
            }
            other => panic!("expected BlockExec, got {other:?}"),
        }
    }

    /// The inode key removes spoofing, not targeting. An attacker who
    /// can influence a verdict could name sshd and now block it
    /// *unspoofably*, which is strictly worse than the comm path it
    /// replaces.
    #[test]
    fn critical_binaries_can_never_be_made_unexecutable() {
        for p in [
            "/usr/sbin/sshd",
            "/usr/lib/openssh/sshd-session",
            "/usr/bin/sudo",
            "/bin/su",
            "/usr/lib/systemd/systemd",
            "/usr/bin/bowery-agent",
        ] {
            assert!(is_protected_exec_path(p), "{p} must be protected");
            assert!(
                block_exec_by_inode_for(p, "ep-1").is_none(),
                "{p} must never yield a block action"
            );
        }
    }

    #[test]
    fn an_ordinary_binary_resolves_to_its_inode() {
        // Resolve something that certainly exists and is not protected.
        let tmp = std::env::temp_dir().join("bowery-block-inode-test");
        std::fs::write(&tmp, b"x").unwrap();
        let path = tmp.display().to_string();
        let action = block_exec_by_inode_for(&path, "ep-1").expect("resolves");
        match action {
            Action::BlockExecByInode {
                dev, ino, path: p, ..
            } => {
                assert!(ino > 0, "a real file has a real inode");
                assert!(dev > 0);
                assert_eq!(p, path, "the path is carried for the audit trail");
                assert_eq!(
                    action_id_of(&Action::BlockExecByInode {
                        dev,
                        ino,
                        path: p,
                        episode_id: "e".into()
                    }),
                    "block_exec_by_inode"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let _ = std::fs::remove_file(&tmp);
    }

    fn action_id_of(a: &Action) -> &'static str {
        a.id()
    }

    /// A path that does not exist must yield nothing. Resolving it to
    /// some fallback inode would block an unrelated file.
    #[test]
    fn an_unresolvable_path_yields_no_action() {
        assert!(block_exec_by_inode_for("/definitely/not/here", "ep-1").is_none());
    }

    /// It cannot be built from an id alone — there is no path to stat,
    /// and inventing one would skip the protection above.
    #[test]
    fn it_is_not_constructible_from_an_id() {
        assert!(from_id("block_exec_by_inode", "ep", Some(1), Some("x")).is_none());
    }

    #[test]
    fn known_ids_lists_all_known() {
        let ids = Action::known_ids();
        assert!(ids.contains(&"kill_process"));
        assert!(ids.contains(&"block_exec"));
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
