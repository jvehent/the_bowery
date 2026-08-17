//! Privilege transitions, and the reconnaissance that usually precedes
//! them.
//!
//! Two detections that need no new sensor — the uid is already on every
//! exec event, and the parent's is one `/proc` read away.
//!
//! # Why the *sanctioned* path has to be exempt
//!
//! Becoming root is not suspicious; Linux provides `sudo`, `su`,
//! `pkexec` and `doas` precisely so people can. What is suspicious is
//! reaching uid 0 **without** going through one of them, because that
//! means the escalation came from somewhere else: an exploit, a
//! misconfigured service, a setuid binary nobody shipped.
//!
//! The exemption is anchored on package provenance rather than on a
//! name, because a name is attacker-controlled. A binary called `sudo`
//! that no package owns is the thing this is looking for, not the thing
//! it should ignore.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::provenance::Provenance;

/// A privilege escalation worth reporting.
#[derive(Debug, Clone, PartialEq)]
pub struct EscalationHit {
    pub rule_id: &'static str,
    pub why: String,
    pub severity: f32,
}

/// Did a process reach root without using a sanctioned path?
///
/// `child_uid` is the real uid the new process runs as; `parent_uid` is
/// the real uid of whatever started it. `provenance` describes the
/// binary being executed.
///
/// `None` when nothing happened, when the parent was already root, or
/// when the escalation went through a packaged setuid helper — which is
/// what `sudo` is *for*, and alerting on it would fire on every
/// administrative action a human takes.
#[must_use]
pub fn uid_transition(
    child_uid: u32,
    parent_uid: Option<u32>,
    provenance: Provenance,
    exe_is_setuid: bool,
) -> Option<EscalationHit> {
    // Only a transition *to* root is interesting. Dropping privileges is
    // what well-behaved daemons do on startup.
    if child_uid != 0 {
        return None;
    }
    // Unknown parent means no transition can be established. Reporting
    // one anyway would alert on every root process whose parent had
    // already exited.
    let parent_uid = parent_uid?;
    if parent_uid == 0 {
        return None;
    }

    // The sanctioned path: a setuid-root binary the distribution ships.
    // `sudo`, `su`, `pkexec`, `newgrp`, `doas`. Anchored on provenance,
    // not on the name, because the name is attacker-controlled — a
    // binary *called* sudo that no package owns is the finding, not the
    // exemption.
    if exe_is_setuid && provenance == Provenance::PackagedIntact {
        return None;
    }

    let (rule_id, severity, detail) = if exe_is_setuid {
        (
            "privesc.uid_transition_untrusted_setuid",
            0.95,
            "through a setuid binary that is not a packaged, unmodified one",
        )
    } else {
        (
            "privesc.uid_transition_no_helper",
            0.9,
            "without going through any setuid helper at all, which means the privilege \
             came from somewhere other than the sanctioned path",
        )
    };
    Some(EscalationHit {
        rule_id,
        severity,
        why: format!(
            "a process owned by uid {parent_uid} started something running as root {detail}"
        ),
    })
}

// ---------------------------------------------------------------------------
// Discovery bursts
// ---------------------------------------------------------------------------

/// Commands that answer "where am I and what can I reach from here".
///
/// Every one of them is run constantly by ordinary shell users and by
/// scripts, which is exactly why a single execution means nothing. What
/// distinguishes reconnaissance is the *burst*: several different ones,
/// from the same parent, in seconds.
///
/// Matched against the basename only, so each entry is a bare command
/// name — `sudo -l` would never match and is deliberately absent.
const RECON: &[&str] = &[
    // Who am I?
    "whoami",
    "id",
    "groups",
    "logname",
    // Where am I?
    "hostname",
    "uname",
    "lsb_release",
    "hostnamectl",
    "dmidecode",
    "lscpu",
    // Who else is here?
    "w",
    "who",
    "users",
    "last",
    "lastlog",
    "finger",
    // What is running?
    "ps",
    "pstree",
    "top",
    "lsof",
    "systemctl",
    "service",
    // What can I reach?
    "netstat",
    "ss",
    "ifconfig",
    "ip",
    "route",
    "arp",
    "iptables",
    "nft",
    "dig",
    "nslookup",
    "host",
    // What is on disk?
    "mount",
    "df",
    "lsblk",
    "blkid",
    "findmnt",
    // What is installed, and what runs later?
    "dpkg",
    "rpm",
    "apt",
    "yum",
    "crontab",
    "getent",
    "getcap",
    "sestatus",
];

/// A run of reconnaissance from one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryBurst {
    pub parent_pid: u32,
    /// The distinct recon commands seen, in order of first sighting.
    pub commands: Vec<String>,
}

/// Watches for several different recon commands from one parent in a
/// short window.
///
/// Keyed on the **parent** rather than the process itself, because each
/// `whoami` is its own short-lived pid; what ties them together is the
/// shell or script that ran them.
#[derive(Debug)]
pub struct DiscoveryTracker {
    inner: Mutex<HashMap<u32, Vec<(Instant, String)>>>,
    window: Duration,
    threshold: usize,
    max_tracked: usize,
}

impl DiscoveryTracker {
    /// `threshold` distinct commands within `window` constitutes a
    /// burst.
    #[must_use]
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window,
            threshold: threshold.max(2),
            // Bounds a fork bomb's worth of distinct parents; a real
            // host has a handful running recon at once.
            max_tracked: 1024,
        }
    }

    /// Record an execution and report a burst if this completes one.
    ///
    /// Returns `Some` **once** per burst: the parent's history is
    /// cleared on report, so a shell that keeps running recon produces
    /// one alert per window rather than one per command.
    pub fn observe(
        &self,
        parent_pid: u32,
        exe_or_comm: &str,
        now: Instant,
    ) -> Option<DiscoveryBurst> {
        let name = exe_or_comm.rsplit('/').next().unwrap_or(exe_or_comm);
        if !RECON.contains(&name) {
            return None;
        }
        let mut guard = self.inner.lock().ok()?;
        if guard.len() >= self.max_tracked && !guard.contains_key(&parent_pid) {
            // Cheaper than tracking recency, and a cleared tracker
            // re-learns within one window.
            guard.clear();
        }
        let seen = guard.entry(parent_pid).or_default();
        seen.retain(|(at, _)| now.duration_since(*at) < self.window);
        if !seen.iter().any(|(_, n)| n == name) {
            seen.push((now, name.to_string()));
        }
        if seen.len() < self.threshold {
            return None;
        }
        let commands: Vec<String> = seen.iter().map(|(_, n)| n.clone()).collect();
        guard.remove(&parent_pid);
        Some(DiscoveryBurst {
            parent_pid,
            commands,
        })
    }
}

/// The rule id a discovery burst is reported under.
///
/// A burst has no per-rule variation, so unlike the file-watch tables
/// this is a single constant — but it still has to reach the ATT&CK map,
/// which is why it is named rather than inlined at the call site.
pub const DISCOVERY_RULE_ID: &str = "discovery.recon_burst";

/// Every rule id this module can produce.
#[must_use]
pub const fn rule_ids() -> &'static [&'static str] {
    &[
        "privesc.uid_transition_no_helper",
        "privesc.uid_transition_untrusted_setuid",
        DISCOVERY_RULE_ID,
    ]
}

/// Operator-facing text for a burst.
#[must_use]
pub fn discovery_rationale(burst: &DiscoveryBurst) -> String {
    format!(
        "reconnaissance: {} ran {} different discovery commands in quick succession ({}). \
         Each is ordinary alone; together and this fast they are someone working out what \
         this host is and what it can reach",
        burst.parent_pid,
        burst.commands.len(),
        burst.commands.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same guard as the other rule modules: the ATT&CK map is built
    /// from `rule_ids`, so it has to match what `uid_transition`
    /// actually returns.
    #[test]
    fn rule_ids_matches_what_uid_transition_can_return() {
        use std::collections::HashSet;
        let mut reachable = HashSet::new();
        for provenance in [
            Provenance::PackagedIntact,
            Provenance::PackagedModified,
            Provenance::Unpackaged,
            Provenance::Unknown,
        ] {
            for setuid in [true, false] {
                if let Some(hit) = uid_transition(0, Some(1000), provenance, setuid) {
                    reachable.insert(hit.rule_id);
                }
            }
        }
        reachable.insert(DISCOVERY_RULE_ID);
        let declared: HashSet<&str> = rule_ids().iter().copied().collect();
        assert_eq!(reachable, declared);
    }

    #[test]
    fn reaching_root_without_a_helper_is_a_finding() {
        let hit = uid_transition(0, Some(1000), Provenance::Unpackaged, false).expect("alert");
        assert_eq!(hit.rule_id, "privesc.uid_transition_no_helper");
        assert!(hit.why.contains("uid 1000"));
    }

    #[test]
    fn sudo_is_not_a_finding() {
        // The sanctioned path. Alerting here would fire on every
        // administrative action a human performs and teach them to
        // ignore the rule.
        assert!(uid_transition(0, Some(1000), Provenance::PackagedIntact, true).is_none());
    }

    #[test]
    fn a_setuid_binary_no_package_owns_is_not_exempt() {
        // The exemption is anchored on provenance, not on a name, so a
        // binary *called* sudo that arrived some other way is caught.
        let hit = uid_transition(0, Some(1000), Provenance::Unpackaged, true).expect("alert");
        assert_eq!(hit.rule_id, "privesc.uid_transition_untrusted_setuid");
        assert!(hit.severity > 0.9);
    }

    #[test]
    fn a_modified_packaged_setuid_helper_is_not_exempt_either() {
        assert!(uid_transition(0, Some(1000), Provenance::PackagedModified, true).is_some());
    }

    #[test]
    fn root_starting_root_is_not_a_transition() {
        assert!(uid_transition(0, Some(0), Provenance::Unpackaged, false).is_none());
    }

    #[test]
    fn dropping_privileges_is_not_a_transition() {
        // Daemons do this on startup; it is the opposite of escalation.
        assert!(uid_transition(1000, Some(0), Provenance::Unpackaged, false).is_none());
    }

    #[test]
    fn an_unknown_parent_reports_nothing() {
        // The parent exited before it could be read. Alerting anyway
        // would fire on every root process whose parent is gone, which
        // on a booting host is most of them.
        assert!(uid_transition(0, None, Provenance::Unpackaged, false).is_none());
    }

    #[test]
    fn one_recon_command_is_not_a_burst() {
        let t = DiscoveryTracker::new(Duration::from_mins(1), 4);
        let now = Instant::now();
        assert!(t.observe(100, "/usr/bin/whoami", now).is_none());
        assert!(t.observe(100, "id", now).is_none());
    }

    #[test]
    fn several_different_commands_from_one_parent_are() {
        let t = DiscoveryTracker::new(Duration::from_mins(1), 4);
        let now = Instant::now();
        for cmd in ["whoami", "id", "uname"] {
            assert!(t.observe(100, cmd, now).is_none());
        }
        let burst = t.observe(100, "/bin/netstat", now).expect("burst");
        assert_eq!(burst.parent_pid, 100);
        assert_eq!(burst.commands.len(), 4);
        assert!(discovery_rationale(&burst).contains("4 different"));
    }

    #[test]
    fn repeating_one_command_never_bursts() {
        // A script in a loop running `id` is not reconnaissance. Only
        // *distinct* commands count.
        let t = DiscoveryTracker::new(Duration::from_mins(1), 3);
        let now = Instant::now();
        for _ in 0..20 {
            assert!(t.observe(100, "id", now).is_none());
        }
    }

    #[test]
    fn different_parents_do_not_pool() {
        // Otherwise a busy host aggregates unrelated shells into a
        // phantom burst.
        let t = DiscoveryTracker::new(Duration::from_mins(1), 3);
        let now = Instant::now();
        assert!(t.observe(1, "whoami", now).is_none());
        assert!(t.observe(2, "id", now).is_none());
        assert!(t.observe(3, "uname", now).is_none());
    }

    #[test]
    fn a_burst_reports_once_then_starts_over() {
        // A shell that keeps poking around should produce one alert per
        // window, not one per command.
        let t = DiscoveryTracker::new(Duration::from_mins(1), 2);
        let now = Instant::now();
        assert!(t.observe(100, "whoami", now).is_none());
        assert!(t.observe(100, "id", now).is_some());
        assert!(
            t.observe(100, "uname", now).is_none(),
            "history was cleared"
        );
    }

    #[test]
    fn commands_outside_the_window_expire() {
        let t = DiscoveryTracker::new(Duration::from_mins(1), 2);
        let start = Instant::now();
        assert!(t.observe(100, "whoami", start).is_none());
        // Same parent, but two minutes later: not a burst.
        let later = start + Duration::from_mins(2);
        assert!(t.observe(100, "id", later).is_none());
    }
}
