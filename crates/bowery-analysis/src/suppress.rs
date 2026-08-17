//! Collapsing a repeated finding into one alert that says how often it
//! repeated.
//!
//! # The failure this exists to fix
//!
//! A live three-host fleet produced 63 alerts in 24 minutes. Sixty-one
//! were the same handful of facts restated: `sshd` read
//! `/etc/ssh/ssh_host_rsa_key`, over and over. Two mechanisms produced
//! that flood, and they need different answers.
//!
//! Most of it was the *same finding about the same binary*, which is
//! what this module collapses. `sshd` opens each host key more than once
//! per connection, and each open was its own alert — the very same pid
//! read the very same file twice in the same second and the operator got
//! told twice.
//!
//! (The rest was `sshd` doing its job at all, which suppression is the
//! wrong tool for. Repeating a benign finding more quietly is still
//! repeating it; that one is answered by not raising it — see
//! [`crate::file_watch::reader_is_sanctioned`].)
//!
//! # Why the count has to travel with the alert
//!
//! Silently dropping repeats would trade one failure for a worse one.
//! "`sshd` read a host key" and "`sshd` read a host key 4,000 times in
//! the last hour" are different events, and the second is the
//! interesting one. So a suppressed run is never discarded — it is
//! folded into the next report, which states how many it stands for.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What to do with a finding that just fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Raise it. `folded` is how many occurrences were suppressed since
    /// the last report — `0` on a first sighting, and the alert should
    /// say so when it is not.
    Report { folded: usize },
    /// Already reported inside the window; counted, not raised.
    Suppress,
}

/// What identifies "the same finding" for suppression.
///
/// The reader's **exe** is part of the key, not just the rule and the
/// path. Two different binaries reading `/etc/shadow` are two findings
/// however alike they look, and collapsing them would let a noisy
/// legitimate reader provide cover for a quiet illegitimate one.
type Key = (&'static str, String, String);

struct Entry {
    reported_at: Instant,
    folded: usize,
}

/// One report per key per window, carrying the count it stands for.
pub struct AlertSuppressor {
    inner: Mutex<HashMap<Key, Entry>>,
    window: Duration,
    max_tracked: usize,
}

impl std::fmt::Debug for AlertSuppressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertSuppressor")
            .field("window", &self.window)
            .field("max_tracked", &self.max_tracked)
            .finish_non_exhaustive()
    }
}

impl AlertSuppressor {
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window,
            // A host has a bounded number of (rule, path, reader) shapes;
            // this caps a pathological one rather than a real one.
            max_tracked: 4096,
        }
    }

    /// Record an occurrence and decide whether to raise it.
    ///
    /// `exe` is the reader's resolved binary, or `None` when
    /// `/proc/<pid>/exe` could not be read. Unknown readers share one
    /// bucket: they cannot be told apart, and giving each its own key
    /// would defeat suppression exactly where the noise is worst — a
    /// storm of short-lived processes is the case where every exe lookup
    /// loses its race.
    pub fn observe(
        &self,
        rule_id: &'static str,
        path: &str,
        exe: Option<&str>,
        now: Instant,
    ) -> Decision {
        let key = (
            rule_id,
            path.to_string(),
            exe.unwrap_or_default().to_string(),
        );
        let Ok(mut guard) = self.inner.lock() else {
            // A poisoned lock must not silence detection. Reporting is
            // the safe direction.
            return Decision::Report { folded: 0 };
        };
        if guard.len() >= self.max_tracked && !guard.contains_key(&key) {
            // Cheaper than tracking recency. Clearing over-reports for
            // one window, which is the right way to be wrong.
            guard.clear();
        }
        match guard.get_mut(&key) {
            None => {
                guard.insert(
                    key,
                    Entry {
                        reported_at: now,
                        folded: 0,
                    },
                );
                Decision::Report { folded: 0 }
            }
            Some(entry) if now.duration_since(entry.reported_at) >= self.window => {
                let folded = entry.folded;
                entry.reported_at = now;
                entry.folded = 0;
                Decision::Report { folded }
            }
            Some(entry) => {
                entry.folded += 1;
                Decision::Suppress
            }
        }
    }
}

/// The clause an alert adds when it stands for more than itself.
///
/// Empty when it stands only for itself, so the ordinary alert reads
/// exactly as it did before.
#[must_use]
pub fn folded_note(folded: usize, window: Duration) -> String {
    if folded == 0 {
        return String::new();
    }
    let secs = window.as_secs();
    let span = if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    };
    format!(
        " ({folded} further occurrence{} in the preceding {span}, folded into this one)",
        if folded == 1 { "" } else { "s" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = "cred.read_shadow";
    const PATH: &str = "/etc/shadow";
    const SSHD: Option<&str> = Some("/usr/sbin/sshd");

    #[test]
    fn the_first_sighting_always_reports() {
        let s = AlertSuppressor::new(Duration::from_hours(1));
        assert_eq!(
            s.observe(RULE, PATH, SSHD, Instant::now()),
            Decision::Report { folded: 0 }
        );
    }

    /// The exact shape seen on the fleet: one pid, one file, two opens,
    /// one second apart, two alerts.
    #[test]
    fn a_repeat_inside_the_window_is_folded_not_raised() {
        let s = AlertSuppressor::new(Duration::from_hours(1));
        let t = Instant::now();
        assert!(matches!(
            s.observe(RULE, PATH, SSHD, t),
            Decision::Report { .. }
        ));
        assert_eq!(
            s.observe(RULE, PATH, SSHD, t + Duration::from_secs(1)),
            Decision::Suppress
        );
    }

    /// Suppressed occurrences are counted, never discarded: "read a host
    /// key" and "read a host key 4,000 times" are different events.
    #[test]
    fn the_next_report_states_how_many_it_stands_for() {
        let s = AlertSuppressor::new(Duration::from_mins(10));
        let t = Instant::now();
        s.observe(RULE, PATH, SSHD, t);
        for i in 1..=7 {
            s.observe(RULE, PATH, SSHD, t + Duration::from_secs(i));
        }
        assert_eq!(
            s.observe(RULE, PATH, SSHD, t + Duration::from_mins(11)),
            Decision::Report { folded: 7 }
        );
    }

    #[test]
    fn the_count_resets_after_it_has_been_reported() {
        let s = AlertSuppressor::new(Duration::from_mins(10));
        let t = Instant::now();
        s.observe(RULE, PATH, SSHD, t);
        s.observe(RULE, PATH, SSHD, t + Duration::from_secs(1));
        assert_eq!(
            s.observe(RULE, PATH, SSHD, t + Duration::from_mins(11)),
            Decision::Report { folded: 1 }
        );
        assert_eq!(
            s.observe(RULE, PATH, SSHD, t + Duration::from_mins(22)),
            Decision::Report { folded: 0 }
        );
    }

    /// The case that makes the exe part of the key load-bearing: a noisy
    /// legitimate reader must never provide cover for a quiet
    /// illegitimate one.
    #[test]
    fn a_different_reader_of_the_same_file_is_a_different_finding() {
        let s = AlertSuppressor::new(Duration::from_hours(1));
        let t = Instant::now();
        s.observe(RULE, PATH, SSHD, t);
        assert_eq!(
            s.observe(RULE, PATH, Some("/tmp/harvest"), t + Duration::from_secs(1)),
            Decision::Report { folded: 0 },
            "an unrelated binary must not inherit sshd's suppression"
        );
    }

    #[test]
    fn a_different_path_is_a_different_finding() {
        let s = AlertSuppressor::new(Duration::from_hours(1));
        let t = Instant::now();
        s.observe(
            "cred.read_ssh_host_key",
            "/etc/ssh/ssh_host_rsa_key",
            SSHD,
            t,
        );
        assert_eq!(
            s.observe(
                "cred.read_ssh_host_key",
                "/etc/ssh/ssh_host_ed25519_key",
                SSHD,
                t
            ),
            Decision::Report { folded: 0 }
        );
    }

    #[test]
    fn the_note_is_empty_when_the_alert_stands_only_for_itself() {
        assert_eq!(folded_note(0, Duration::from_hours(1)), "");
        assert!(folded_note(1, Duration::from_hours(1)).contains("1 further occurrence "));
        assert!(folded_note(9, Duration::from_hours(1)).contains("9 further occurrences"));
    }

    #[test]
    fn tracking_is_bounded() {
        let s = AlertSuppressor::new(Duration::from_hours(1));
        let t = Instant::now();
        for i in 0..10_000 {
            s.observe(RULE, &format!("/etc/shadow{i}"), SSHD, t);
        }
        assert!(s.inner.lock().unwrap().len() <= 4096);
    }
}
