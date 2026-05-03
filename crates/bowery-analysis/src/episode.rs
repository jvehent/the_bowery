//! Behavioral episodes — bounded clusters of related events.
//!
//! Phase 3 (limited to ProcessExec) treats every exec as its own episode.
//! When ProcessExit / FileOpen / NetworkConnect are wired in, we'll group
//! them by process tree and time window. The Episode type is shaped now
//! so callers don't have to refactor when that arrives.

use std::time::SystemTime;

use bowery_events::{Event, ProcessExec};

/// A bounded time-window aggregation rooted at a process.
///
/// Phase 3: one ProcessExec per Episode. Future phases append related
/// events (file opens, network connects, exit) to `events`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Episode {
    /// Stable ID for log correlation. Phase 3 derives this from `(pid, ts)`.
    pub id: String,
    /// Wall-clock timestamp of the rooting event.
    pub started_at: SystemTime,
    /// The exec that started this episode.
    pub root: ProcessExec,
    /// Additional events captured within the episode window. Phase 3 is
    /// always empty; reserved for future event types.
    pub events: Vec<Event>,
}

impl Episode {
    /// Build an episode from a single ProcessExec.
    pub fn from_exec(exec: ProcessExec) -> Self {
        let id = format!("ep-{}-{}", exec.pid, system_time_nanos(exec.ts));
        Self {
            id,
            started_at: exec.ts,
            root: exec,
            events: Vec::new(),
        }
    }
}

fn system_time_nanos(t: SystemTime) -> u128 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn exec(pid: u32, ts: SystemTime) -> ProcessExec {
        ProcessExec {
            pid,
            ppid: 1,
            uid: 1000,
            comm: "bash".into(),
            exe_path: Some(PathBuf::from("/bin/bash")),
            args: vec!["bash".into()],
            ts,
        }
    }

    #[test]
    fn id_is_deterministic_per_root() {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let a = Episode::from_exec(exec(42, now));
        let b = Episode::from_exec(exec(42, now));
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn distinct_pids_get_distinct_ids() {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let a = Episode::from_exec(exec(1, now));
        let b = Episode::from_exec(exec(2, now));
        assert_ne!(a.id, b.id);
    }
}
