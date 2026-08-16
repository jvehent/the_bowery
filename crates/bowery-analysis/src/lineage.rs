//! What spawned what.
//!
//! The oldest detection in the book — *"nginx spawned a shell"* — needs
//! no new sensor and no new data: it is one comparison between a process
//! and its parent. This agent could not express it, which is why
//! `process_lineage` sat in the baseline schema being neither written
//! nor read.
//!
//! # Why the parent is the whole signal
//!
//! Every binary named below is legitimate somewhere. `sh` is not
//! suspicious. `curl` is not suspicious. What is suspicious is *who
//! asked*: a web server has no reason to start an interactive shell, and
//! a cron job that fetches a script from the network is either a deploy
//! or an intrusion, and you want to know which. Rules keyed on the child
//! alone would either miss all of this or alert on every shell on the
//! host.
//!
//! # What this deliberately does not do
//!
//! **No ancestry beyond one hop.** A webshell that does
//! `nginx → sh → curl` is caught at the first hop; tracking the full
//! tree would need a process table that survives exits, which is a
//! larger change than the detection is worth today.
//!
//! **`comm` is attacker-controlled**, as everywhere else. A parent that
//! renames itself evades these rules. That is an argument for adding
//! path-based ancestry later, not for skipping the rule: the attacker
//! who knows to rename their shell is a different one from the attacker
//! running an off-the-shelf webshell, and both exist.

/// Programs that serve the network and have no business starting shells.
///
/// Matched on `comm`, which the kernel truncates to 15 characters — so
/// entries here must be the truncated form, not the full name.
const NETWORK_SERVICES: &[&str] = &[
    "nginx",
    "apache2",
    "httpd",
    "php-fpm",
    "lighttpd",
    "node",
    "java",
    "tomcat",
    "postgres",
    "mysqld",
    "mariadbd",
    "redis-server",
    "memcached",
    "mongod",
    "smbd",
    "vsftpd",
    "proftpd",
    "exim4",
    "postfix",
];

/// Interactive shells.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "fish"];

/// Things that fetch from, or listen on, the network.
const NETWORK_TOOLS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ftp", "tftp",
];

/// Interpreters — the second half of most download-and-run chains.
const INTERPRETERS: &[&str] = &["python3", "python", "perl", "ruby", "php", "lua"];

/// Schedulers and init paths, whose children run unattended.
const SCHEDULERS: &[&str] = &["cron", "crond", "atd", "anacron", "systemd"];

#[derive(Debug, Clone, PartialEq)]
pub struct LineageHit {
    pub rule_id: &'static str,
    pub why: &'static str,
    pub severity: f32,
}

fn base_name(path_or_comm: &str) -> &str {
    path_or_comm.rsplit('/').next().unwrap_or(path_or_comm)
}

fn in_set(name: &str, set: &[&str]) -> bool {
    set.contains(&name)
}

/// Judge a parent→child pair.
///
/// `child` may be a full path or a bare comm; only the final component
/// is compared. Returns the first matching rule, ordered most severe
/// first.
#[must_use]
pub fn classify(parent_comm: &str, child: &str) -> Option<LineageHit> {
    let parent = base_name(parent_comm.trim());
    let child = base_name(child.trim());
    if parent.is_empty() || child.is_empty() {
        return None;
    }

    // A network service starting a shell. The canonical shape of a
    // webshell or an exploited service, and one almost no legitimate
    // configuration produces.
    if in_set(parent, NETWORK_SERVICES) && in_set(child, SHELLS) {
        return Some(LineageHit {
            rule_id: "lineage.service_spawned_shell",
            why: "a network-facing service started an interactive shell — the shape of a \
                  webshell or an exploited service, and something almost no legitimate \
                  configuration does",
            severity: 0.95,
        });
    }

    // A service reaching for the network directly: staging a payload.
    if in_set(parent, NETWORK_SERVICES) && in_set(child, NETWORK_TOOLS) {
        return Some(LineageHit {
            rule_id: "lineage.service_spawned_downloader",
            why: "a network-facing service started a download tool, which is how a \
                  foothold fetches its second stage",
            severity: 0.9,
        });
    }

    // A service starting an interpreter. Legitimate for some stacks
    // (CGI, a PHP worker pool), so scored below the shell case.
    if in_set(parent, NETWORK_SERVICES) && in_set(child, INTERPRETERS) {
        return Some(LineageHit {
            rule_id: "lineage.service_spawned_interpreter",
            why: "a network-facing service started a script interpreter; legitimate for \
                  some CGI stacks, so confirm this is one of yours",
            severity: 0.75,
        });
    }

    // Unattended work reaching for the network. Deploys look like this
    // too, which is exactly why an operator should see it.
    if in_set(parent, SCHEDULERS) && in_set(child, NETWORK_TOOLS) {
        return Some(LineageHit {
            rule_id: "lineage.scheduled_downloader",
            why: "a scheduled task fetched from the network with nobody watching — either \
                  a deploy step or a foothold refreshing itself",
            severity: 0.8,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_webshell_is_caught() {
        let hit = classify("nginx", "/bin/sh").expect("nginx → sh must alert");
        assert_eq!(hit.rule_id, "lineage.service_spawned_shell");
        assert!(hit.severity > 0.9);
    }

    #[test]
    fn a_full_path_or_a_bare_comm_both_work() {
        assert!(classify("nginx", "/usr/bin/bash").is_some());
        assert!(classify("nginx", "bash").is_some());
        assert!(classify("/usr/sbin/nginx", "bash").is_some());
    }

    #[test]
    fn sshd_starting_a_shell_is_normal_and_must_not_alert() {
        // The single most important negative. sshd exists to start
        // shells; alerting on it would fire on every login and teach an
        // operator to ignore the whole rule set.
        assert!(classify("sshd", "/bin/bash").is_none());
        assert!(classify("login", "/bin/bash").is_none());
        assert!(classify("systemd", "/bin/bash").is_none());
    }

    #[test]
    fn ordinary_shell_use_does_not_alert() {
        assert!(classify("bash", "/usr/bin/ls").is_none());
        assert!(classify("bash", "/usr/bin/curl").is_none());
        assert!(classify("make", "/usr/bin/cc").is_none());
    }

    #[test]
    fn a_service_fetching_a_payload_is_caught() {
        let hit = classify("apache2", "/usr/bin/curl").unwrap();
        assert_eq!(hit.rule_id, "lineage.service_spawned_downloader");
    }

    #[test]
    fn a_scheduled_download_is_flagged_but_ranked_below_a_shell() {
        let sched = classify("cron", "/usr/bin/wget").unwrap();
        let shell = classify("nginx", "sh").unwrap();
        assert_eq!(sched.rule_id, "lineage.scheduled_downloader");
        assert!(
            sched.severity < shell.severity,
            "a deploy step must not outrank a webshell"
        );
    }

    #[test]
    fn an_interpreter_from_a_service_ranks_below_a_shell() {
        // CGI stacks do this legitimately, so it must not be the loudest
        // thing in the file.
        let interp = classify("nginx", "python3").unwrap();
        assert!(interp.severity < classify("nginx", "sh").unwrap().severity);
    }

    #[test]
    fn empty_or_unknown_parents_do_not_alert() {
        // ppid enrichment can lose a race with the parent exiting; an
        // unknown parent must produce no verdict rather than a wrong one.
        assert!(classify("", "/bin/sh").is_none());
        assert!(classify("nginx", "").is_none());
        assert!(classify("some-unknown-daemon", "/bin/sh").is_none());
    }

    #[test]
    fn every_rule_explains_itself_and_is_ranked() {
        for (parent, child) in [
            ("nginx", "sh"),
            ("nginx", "curl"),
            ("nginx", "python3"),
            ("cron", "wget"),
        ] {
            let hit = classify(parent, child).unwrap();
            assert!(
                hit.why.len() > 40,
                "{} needs a real explanation",
                hit.rule_id
            );
            assert!((0.0..=1.0).contains(&hit.severity));
            assert!(hit.rule_id.starts_with("lineage."));
        }
    }
}
