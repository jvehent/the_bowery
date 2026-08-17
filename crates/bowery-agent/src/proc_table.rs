//! A small, recent pid → exe map, so a process that has already exited
//! can still be named.
//!
//! # The gap this fills
//!
//! Everything that judges a file access needs to know *which binary*
//! did it, and `comm` cannot answer: it is 16 bytes any process sets
//! with `prctl`. The real answer is `/proc/<pid>/exe`, which is read
//! after the fact — and for the processes that matter most, the read
//! loses a race it cannot win.
//!
//! On a live host, `unix_chkpwd` was the last remaining source of
//! credential-read noise. It runs for milliseconds: PAM forks it, it
//! reads `/etc/shadow`, it exits. By the time the agent looked,
//! `/proc/<pid>/exe` was gone, so the sanctioned-reader check could not
//! establish that the reader was a packaged `unix_chkpwd` and — failing
//! closed, correctly — raised the alert.
//!
//! # Why not query the event log
//!
//! The agent already records every exec with a resolved `exe_path`, so
//! joining `file_open` against `exec` by pid looks like the obvious fix.
//! It is not: [`crate::eventlog_writer::EventLogHandle`] records through
//! an `mpsc` drained by a writer task, so the exec row is usually **not
//! committed yet** when the file-open for that same pid is processed.
//! The lookup would race, and would lose precisely for the short-lived
//! processes it exists to catch.
//!
//! This table is filled synchronously from the same pipeline task that
//! dispatches both events, in channel order, so the exec is always
//! recorded before the file access that follows it.
//!
//! # Why it is bounded conservatively
//!
//! A wrong answer here can only ever *grant* an exemption, which is the
//! dangerous direction: it turns a finding into silence. Two bounds
//! matter.
//!
//! **A TTL**, because a pid can be reused by a process that `fork`s
//! without `exec`ing — such a child inherits its parent's exe, so the
//! recorded path would name the wrong binary and nothing would overwrite
//! it. An exec for the same pid *does* overwrite, so the window for this
//! is short and the TTL closes it.
//!
//! **A cap**, so a fork storm cannot grow it without limit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// How long a recorded exec is allowed to answer for its pid.
///
/// Short on purpose — see the module docs on fork-without-exec reuse.
/// Long enough to cover any plausible gap between a process starting and
/// the file access it was started to perform.
pub const DEFAULT_TTL: Duration = Duration::from_mins(5);

/// Recent execs, so an exited process can still be named.
#[derive(Debug)]
pub struct ProcTable {
    inner: Mutex<HashMap<u32, (PathBuf, SystemTime)>>,
    ttl: Duration,
    max_tracked: usize,
}

impl Default for ProcTable {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

impl ProcTable {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            // A busy host has a few thousand live processes; this bounds
            // a fork storm rather than a real workload.
            max_tracked: 8192,
        }
    }

    /// Remember that `pid` exec'd `exe` at `ts`.
    pub fn record(&self, pid: u32, exe: &Path, ts: SystemTime) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if guard.len() >= self.max_tracked && !guard.contains_key(&pid) {
            // Cheaper than tracking recency, and losing the table only
            // costs us the fallback: /proc is still tried first, and a
            // miss alerts rather than exempting.
            guard.clear();
        }
        guard.insert(pid, (exe.to_path_buf(), ts));
    }

    /// The binary `pid` was running at `at`, if we saw it exec.
    ///
    /// `None` when the pid is unknown, when the record has aged past the
    /// TTL, or when the exec happened *after* the moment being asked
    /// about — a later exec cannot explain an earlier access, and
    /// answering with it would attribute a file read to a binary that
    /// had not started yet.
    #[must_use]
    pub fn exe_at(&self, pid: u32, at: SystemTime) -> Option<PathBuf> {
        let guard = self.inner.lock().ok()?;
        let (exe, ts) = guard.get(&pid)?;
        if *ts > at {
            return None;
        }
        if at.duration_since(*ts).ok()? > self.ttl {
            return None;
        }
        Some(exe.clone())
    }

    /// Forget a pid that has exited.
    ///
    /// Not required for correctness — the TTL covers it — but it closes
    /// the reuse window as soon as the kernel tells us, rather than
    /// minutes later.
    pub fn forget(&self, pid: u32) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(&pid);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// The case that motivated this: PAM forks `unix_chkpwd`, it reads
    /// `/etc/shadow`, it exits, and `/proc/<pid>/exe` is gone before the
    /// agent looks.
    #[test]
    fn an_exited_process_can_still_be_named() {
        let t = ProcTable::default();
        t.record(4242, Path::new("/usr/sbin/unix_chkpwd"), at(1000));
        assert_eq!(
            t.exe_at(4242, at(1001)),
            Some(PathBuf::from("/usr/sbin/unix_chkpwd"))
        );
    }

    /// A later exec must not explain an earlier access: the binary had
    /// not started yet.
    #[test]
    fn an_exec_after_the_access_does_not_answer_for_it() {
        let t = ProcTable::default();
        t.record(4242, Path::new("/usr/sbin/unix_chkpwd"), at(1000));
        assert_eq!(t.exe_at(4242, at(999)), None);
    }

    /// A pid reused by a process that forked without exec'ing inherits
    /// its parent's binary, and nothing would overwrite the stale
    /// record. The TTL is what bounds that, and a wrong answer here
    /// grants an exemption — the direction that turns a finding into
    /// silence.
    #[test]
    fn a_record_expires_so_a_reused_pid_cannot_inherit_an_exemption() {
        let t = ProcTable::new(Duration::from_mins(5));
        t.record(4242, Path::new("/usr/sbin/unix_chkpwd"), at(1000));
        assert!(t.exe_at(4242, at(1000 + 299)).is_some());
        assert!(
            t.exe_at(4242, at(1000 + 301)).is_none(),
            "past the TTL the table must stop answering"
        );
    }

    #[test]
    fn a_later_exec_for_the_same_pid_replaces_the_earlier_one() {
        let t = ProcTable::default();
        t.record(4242, Path::new("/bin/sh"), at(1000));
        t.record(4242, Path::new("/usr/bin/curl"), at(1001));
        assert_eq!(
            t.exe_at(4242, at(1002)),
            Some(PathBuf::from("/usr/bin/curl"))
        );
    }

    #[test]
    fn an_unknown_pid_answers_nothing() {
        let t = ProcTable::default();
        assert_eq!(t.exe_at(999, at(1000)), None);
    }

    #[test]
    fn an_exited_pid_can_be_forgotten_immediately() {
        let t = ProcTable::default();
        t.record(4242, Path::new("/bin/sh"), at(1000));
        t.forget(4242);
        assert_eq!(t.exe_at(4242, at(1001)), None);
    }

    #[test]
    fn tracking_is_bounded() {
        let t = ProcTable::default();
        for pid in 0..20_000 {
            t.record(pid, Path::new("/bin/sh"), at(1000));
        }
        assert!(t.len() <= 8192);
    }
}
