//! Built-in watch sets for file writes.
//!
//! The kernel sensor reports every write-intent open. This decides which
//! of them are worth an operator's attention.
//!
//! # Why these are built in rather than configured
//!
//! The agent already has operator-configurable file watches, and they
//! covered nothing by default — an operator had to know in advance which
//! paths matter. That is backwards for the paths below: `/etc/ld.so.preload`
//! and `~/.ssh/authorized_keys` are how Linux hosts get persisted on,
//! and every deployment wants them watched. Configuration is for the
//! paths that are specific to *your* estate.
//!
//! # Matching, and what it deliberately misses
//!
//! **Absolute paths only.** `openat` resolves relative paths against a
//! dirfd that a kernel probe cannot follow, so a relative path is
//! recorded but never matched. Resolving it wrongly would be worse than
//! not matching: it would attribute a write to a file nobody touched.
//! [`is_matchable`] makes the gap countable rather than silent.
//!
//! **No suppression by process name.** A package upgrade writes systemd
//! units, and it is tempting to ignore writes from `dpkg` or `apt`. We
//! don't, for one reason: `comm` is attacker-controlled — it is 16 bytes
//! any process can set with `prctl` — so a suppression list keyed on it
//! is an instruction for how to evade the rule. The process name is
//! reported so a human can judge, never used to silence.
//!
//! That means routine package operations will produce hits. The
//! rationale says so, and the fix is fleet corroboration (a write every
//! host makes at the same moment is an upgrade) rather than a bypass
//! anyone can spell.

/// What a matched write is evidence of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileWatchCategory {
    /// Survives a reboot, or re-executes on a schedule or a login.
    Persistence,
    /// Grants or widens privilege.
    PrivilegeEscalation,
    /// Secrets, or the files that guard them.
    Credential,
    /// Blinds or rewrites the record.
    DefenseEvasion,
}

impl FileWatchCategory {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Persistence => "persistence",
            Self::PrivilegeEscalation => "privilege-escalation",
            Self::Credential => "credential-access",
            Self::DefenseEvasion => "defense-evasion",
        }
    }
}

/// A matched write.
#[derive(Debug, Clone, PartialEq)]
pub struct FileWatchHit {
    pub rule_id: &'static str,
    pub category: FileWatchCategory,
    /// What this path is for, in an operator's words — the alert has to
    /// explain itself to someone woken at 03:00 who does not know why
    /// `/etc/ld.so.preload` matters.
    pub why: &'static str,
    /// `[0,1]`, fed straight into the alert's suspicion.
    pub severity: f32,
}

/// How a rule matches a path.
#[derive(Debug, Clone, Copy)]
enum Match {
    /// Path starts with this. Directory rules end in `/` so
    /// `/etc/cron.daily` cannot be matched by `/etc/crontabs-mine`.
    Prefix(&'static str),
    /// Path is exactly this.
    Exact(&'static str),
    /// Path ends with this — the only way to catch a file in *any*
    /// user's home without enumerating homes.
    Suffix(&'static str),
}

struct Rule {
    id: &'static str,
    m: Match,
    category: FileWatchCategory,
    why: &'static str,
    severity: f32,
}

/// The watch set.
///
/// Ordered most-specific first: `/etc/ld.so.preload` before any broader
/// `/etc/` rule, so the reported reason is the sharpest one that applies.
const RULES: &[Rule] = &[
    // -- persistence: execution that outlives a session -----------------
    Rule {
        id: "persist.ld_preload",
        m: Match::Exact("/etc/ld.so.preload"),
        category: FileWatchCategory::Persistence,
        why: "every dynamically linked process on the host loads what this file names, \
              before main() runs. Writing it is a whole-system code-injection primitive \
              and has almost no legitimate use",
        severity: 0.97,
    },
    Rule {
        id: "persist.systemd_unit",
        m: Match::Prefix("/etc/systemd/system/"),
        category: FileWatchCategory::Persistence,
        why: "systemd units start at boot and can restart themselves. Also written by \
              package installs, so check the process and whether peers saw the same write",
        severity: 0.85,
    },
    Rule {
        id: "persist.systemd_unit_lib",
        m: Match::Prefix("/usr/lib/systemd/system/"),
        category: FileWatchCategory::Persistence,
        why: "distribution-owned systemd unit directory; normally only a package manager \
              writes here",
        severity: 0.85,
    },
    Rule {
        id: "persist.cron",
        m: Match::Prefix("/etc/cron"),
        category: FileWatchCategory::Persistence,
        why: "cron re-executes on a schedule, which is the cheapest durable foothold there is",
        severity: 0.9,
    },
    Rule {
        id: "persist.authorized_keys",
        m: Match::Suffix("/.ssh/authorized_keys"),
        category: FileWatchCategory::Persistence,
        why: "appending a public key here grants permanent passwordless login as that user, \
              and survives password changes",
        severity: 0.95,
    },
    Rule {
        id: "persist.pam",
        m: Match::Prefix("/etc/pam.d/"),
        category: FileWatchCategory::Persistence,
        why: "PAM decides how every authentication on the host succeeds; a module added \
              here can harvest or bypass credentials",
        severity: 0.93,
    },
    Rule {
        id: "persist.udev",
        m: Match::Prefix("/etc/udev/rules.d/"),
        category: FileWatchCategory::Persistence,
        why: "udev rules can run programs on device events, which is execution that no \
              service list shows",
        severity: 0.8,
    },
    Rule {
        id: "persist.shell_profile",
        m: Match::Prefix("/etc/profile.d/"),
        category: FileWatchCategory::Persistence,
        why: "sourced by every interactive login shell on the host",
        severity: 0.8,
    },
    Rule {
        id: "persist.user_rc",
        m: Match::Suffix("/.bashrc"),
        category: FileWatchCategory::Persistence,
        why: "sourced by every interactive shell that user opens, so a line here \
              re-executes on each login and survives reboots",
        severity: 0.7,
    },
    Rule {
        id: "persist.user_profile",
        m: Match::Suffix("/.bash_profile"),
        category: FileWatchCategory::Persistence,
        why: "sourced by that user's login shells; a common place to hide \
              re-execution that no service manager lists",
        severity: 0.7,
    },
    // -- privilege escalation -------------------------------------------
    Rule {
        id: "privesc.sudoers",
        m: Match::Prefix("/etc/sudoers"),
        category: FileWatchCategory::PrivilegeEscalation,
        why: "defines who may become root and with what password prompt; a single line \
              here is a permanent privilege grant",
        severity: 0.95,
    },
    // -- credential access ----------------------------------------------
    Rule {
        id: "cred.shadow",
        m: Match::Exact("/etc/shadow"),
        category: FileWatchCategory::Credential,
        why: "the password hash database. A write is either a password change or an \
              account being added or backdoored",
        severity: 0.9,
    },
    Rule {
        id: "cred.passwd",
        m: Match::Exact("/etc/passwd"),
        category: FileWatchCategory::Credential,
        why: "account database; a new uid-0 entry here is a classic backdoor",
        severity: 0.88,
    },
    Rule {
        id: "cred.ssh_private_key",
        m: Match::Suffix("/.ssh/id_rsa"),
        category: FileWatchCategory::Credential,
        why: "an SSH private key being written — key replacement, or a stolen key being \
              staged for use",
        severity: 0.85,
    },
    // -- defense evasion -------------------------------------------------
    Rule {
        id: "evade.auth_log",
        m: Match::Prefix("/var/log/auth"),
        category: FileWatchCategory::DefenseEvasion,
        why: "the authentication log. Writes from anything but the logging daemon suggest \
              the record of a login is being edited",
        severity: 0.85,
    },
    Rule {
        id: "evade.wtmp",
        m: Match::Prefix("/var/log/wtmp"),
        category: FileWatchCategory::DefenseEvasion,
        why: "login history; truncating it is how a session is removed from `last`",
        severity: 0.85,
    },
];

/// Can this path be matched at all?
///
/// Only absolute paths. A relative one came from an `openat` against a
/// dirfd the probe could not resolve, and guessing would attribute a
/// write to a file nobody touched.
#[must_use]
pub fn is_matchable(path: &str) -> bool {
    path.starts_with('/')
}

/// Classify a write. `None` means nothing in the watch set applies.
#[must_use]
pub fn classify(path: &str) -> Option<FileWatchHit> {
    if !is_matchable(path) {
        return None;
    }
    RULES
        .iter()
        .find(|r| match r.m {
            Match::Prefix(p) => path.starts_with(p),
            Match::Exact(p) => path == p,
            Match::Suffix(p) => path.ends_with(p),
        })
        .map(|r| FileWatchHit {
            rule_id: r.id,
            category: r.category,
            why: r.why,
            severity: r.severity,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_the_classic_persistence_paths() {
        for (path, id) in [
            ("/etc/ld.so.preload", "persist.ld_preload"),
            ("/etc/systemd/system/evil.service", "persist.systemd_unit"),
            ("/etc/cron.d/backdoor", "persist.cron"),
            ("/etc/crontab", "persist.cron"),
            ("/root/.ssh/authorized_keys", "persist.authorized_keys"),
            (
                "/home/julien/.ssh/authorized_keys",
                "persist.authorized_keys",
            ),
            ("/etc/pam.d/sshd", "persist.pam"),
            ("/etc/sudoers.d/oops", "privesc.sudoers"),
            ("/etc/shadow", "cred.shadow"),
            ("/var/log/auth.log", "evade.auth_log"),
        ] {
            let hit = classify(path).unwrap_or_else(|| panic!("{path} should match"));
            assert_eq!(hit.rule_id, id, "{path}");
        }
    }

    #[test]
    fn suffix_rules_catch_any_users_home() {
        // The only way to watch every home without enumerating them.
        assert!(classify("/home/alice/.ssh/authorized_keys").is_some());
        assert!(classify("/var/lib/postgres/.ssh/authorized_keys").is_some());
    }

    #[test]
    fn ordinary_writes_do_not_match() {
        for path in [
            "/tmp/build-output.o",
            "/var/lib/bowery/events.db",
            "/home/julien/notes.md",
            "/proc/self/oom_score_adj",
        ] {
            assert!(classify(path).is_none(), "{path} should not match");
        }
    }

    #[test]
    fn a_directory_rule_cannot_be_matched_by_a_similar_name() {
        // `/etc/systemd/system/` ends in a slash on purpose. Without it,
        // `/etc/systemd/system-evil` would match the unit rule.
        let hit = classify("/etc/systemd/system-not-a-unit-dir/x");
        assert!(hit.is_none(), "got {hit:?}");
    }

    #[test]
    fn relative_paths_never_match() {
        // They come from an openat against a dirfd the kernel probe
        // cannot resolve. Matching one would attribute a write to a file
        // nobody touched.
        assert!(!is_matchable("etc/shadow"));
        assert!(classify("etc/shadow").is_none());
        assert!(classify("../../etc/ld.so.preload").is_none());
    }

    #[test]
    fn the_most_specific_rule_wins() {
        // /etc/ld.so.preload must not be reported as some generic /etc
        // rule; the operator needs the sharpest reason.
        assert_eq!(
            classify("/etc/ld.so.preload").unwrap().rule_id,
            "persist.ld_preload"
        );
    }

    #[test]
    fn every_rule_has_a_usable_severity_and_explanation() {
        for r in RULES {
            assert!(
                (0.0..=1.0).contains(&r.severity),
                "{} severity out of range",
                r.id
            );
            // The alert has to explain itself to someone who does not
            // already know why the path matters.
            assert!(r.why.len() > 40, "{} needs a real explanation", r.id);
            assert!(r.id.contains('.'), "{} should be namespaced", r.id);
        }
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate rule id");
    }
}
