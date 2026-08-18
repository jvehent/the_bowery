//! Turning the host's defences off.
//!
//! Every family in the IoT corpus reaches for the firewall — `iptables
//! -A` appears fourteen times across the Mirai relatives and `iptables
//! -F` twice — and today `iptables` and `nft` sit in the *discovery*
//! list, treated as reconnaissance. A lone `iptables -F` is therefore
//! invisible unless four other recon commands happen to accompany it,
//! which is a strange thing for "someone flushed the firewall" to
//! require.
//!
//! The sensor has carried the arguments all along. This reads them.
//!
//! # Why only the wholesale acts
//!
//! `iptables -A` is what Docker, libvirt, fail2ban, Kubernetes and `ufw`
//! itself do continuously, and a rule that fires on adding a rule would
//! be the loudest wrong rule in the agent — the mistake this project has
//! now made three times and writes down each time.
//!
//! So the conjunction is *wholesale*: flushing every chain, changing a
//! default policy, tearing down a whole ruleset, disabling the firewall,
//! stopping the audit daemon, putting the mandatory-access-control
//! system into permissive mode. Those are qualitatively different from
//! editing one rule, and legitimate software almost never does them
//! outside of a deliberate administrative action.
//!
//! The distinction is in the arguments and nowhere else:
//!
//! - `iptables -F` flushes everything. `iptables -F DOCKER` flushes one
//!   chain Docker owns, and Docker does it routinely — so a chain
//!   operand disqualifies the finding.
//! - `systemctl stop auditd` is one of these. `systemctl is-active
//!   auditd` is not, and is what monitoring does all day. The verb has
//!   to be read, not just the target.
//!
//! # What it cannot see
//!
//! A process that speaks netlink directly — which is all `iptables` is
//! doing underneath — never execs anything and is invisible here. This
//! catches the shell-command form, which is what the corpus shows and
//! what a foothold with a shell reaches for, not the shape of a
//! purpose-built implant.

/// A defence that was switched off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefenseHit {
    pub rule_id: &'static str,
    pub why: String,
    /// Reported as the verdict's suspicion.
    pub severity_pct: u8,
}

impl DefenseHit {
    #[must_use]
    pub fn severity(&self) -> f32 {
        f32::from(self.severity_pct) / 100.0
    }
}

pub const FIREWALL_RULE_ID: &str = "defense_evasion.firewall_flushed";
pub const SERVICE_RULE_ID: &str = "defense_evasion.security_service_stopped";
pub const MAC_RULE_ID: &str = "defense_evasion.mac_disabled";

/// Every rule id this module can produce.
#[must_use]
pub const fn rule_ids() -> &'static [&'static str] {
    &[FIREWALL_RULE_ID, SERVICE_RULE_ID, MAC_RULE_ID]
}

/// Services whose job is watching or restricting this host.
///
/// Stopping one is a different act from stopping a web server, which is
/// why the target is matched and not just the verb.
const SECURITY_SERVICES: &[&str] = &[
    "auditd",
    "apparmor",
    "snapd.apparmor",
    "firewalld",
    "ufw",
    "nftables",
    "iptables",
    "ip6tables",
    "netfilter-persistent",
    "selinux",
    "selinux-autorelabel",
    "falco",
    "falcod",
    "osqueryd",
    "wazuh-agent",
    "clamav-daemon",
    "clamav-freshclam",
    "fail2ban",
    "aide",
    "rsyslog",
    "systemd-journald",
    "sysstat",
];

/// The verbs that take a service away.
const STOPPING_VERBS: &[&str] = &["stop", "disable", "mask", "kill"];

/// Reduce a unit name to the service it belongs to.
///
/// Strips the type suffix so `auditd.service` matches `auditd`, and the
/// instance of a templated unit so `falco@node1.service` matches
/// `falco` — systemd's own idiom, and one an attacker would otherwise
/// slip past a list of bare names.
fn unit_stem(unit: &str) -> &str {
    let mut stem = unit;
    for suffix in [".service", ".socket", ".timer", ".target"] {
        if let Some(s) = stem.strip_suffix(suffix) {
            stem = s;
            break;
        }
    }
    match stem.split_once('@') {
        Some((template, _instance)) => template,
        None => stem,
    }
}

/// The command's own name, without its directory.
fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Read an exec as an attempt to switch a defence off.
///
/// `program` is the resolved executable path or the command name; `args`
/// is the full argument vector *including* argv\[0\], as the sensor
/// reports it.
#[must_use]
pub fn classify(program: &str, args: &[String]) -> Option<DefenseHit> {
    // argv[0] is the program itself; the operands are what follow.
    let operands: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let name = base_name(program);
    match name {
        // Note `iptables-restore` is deliberately absent: it reloads a
        // saved ruleset, which is how a firewall is *applied*, not torn
        // down. It falls through to the catch-all below.
        "iptables" | "ip6tables" | "iptables-legacy" | "ip6tables-legacy" => iptables(&operands),
        "nft" => nft(&operands),
        "ufw" => ufw(&operands),
        "firewall-cmd" => firewall_cmd(&operands),
        "systemctl" | "service" => service_control(name, &operands),
        "setenforce" => setenforce(&operands),
        "aa-disable" | "aa-teardown" => Some(DefenseHit {
            rule_id: MAC_RULE_ID,
            why: format!(
                "{name} was run, which unloads AppArmor profiles and removes the \
                 confinement they were enforcing"
            ),
            severity_pct: 90,
        }),
        _ => None,
    }
}

fn iptables(operands: &[&str]) -> Option<DefenseHit> {
    let mut it = operands.iter().peekable();
    while let Some(arg) = it.next() {
        // A flush with no chain operand empties every chain in the
        // table. With one, it empties that chain — which is Docker
        // rebuilding its own, several times a day.
        if *arg == "-F" || *arg == "--flush" {
            let targeted = it.peek().is_some_and(|next| !next.starts_with('-'));
            if !targeted {
                return Some(DefenseHit {
                    rule_id: FIREWALL_RULE_ID,
                    why: "iptables was flushed with no chain named, which empties every \
                          chain in the table and leaves the host with no packet filter"
                        .to_string(),
                    severity_pct: 90,
                });
            }
        }
        // Default policy ACCEPT on a filter chain: everything not
        // explicitly denied is now allowed.
        if *arg == "-P" || *arg == "--policy" {
            let chain = it.next();
            let policy = it.peek().copied();
            if policy.is_some_and(|p| p.eq_ignore_ascii_case("ACCEPT")) {
                return Some(DefenseHit {
                    rule_id: FIREWALL_RULE_ID,
                    why: format!(
                        "the default policy for the {} chain was set to ACCEPT, so \
                         anything not explicitly denied now passes",
                        chain.copied().unwrap_or("filter")
                    ),
                    severity_pct: 85,
                });
            }
        }
    }
    None
}

fn nft(operands: &[&str]) -> Option<DefenseHit> {
    let joined = operands.join(" ");
    if joined.contains("flush ruleset") {
        return Some(DefenseHit {
            rule_id: FIREWALL_RULE_ID,
            why: "the entire nftables ruleset was flushed, which leaves the host with \
                  no packet filter at all"
                .to_string(),
            severity_pct: 90,
        });
    }
    if joined.contains("delete table") {
        return Some(DefenseHit {
            rule_id: FIREWALL_RULE_ID,
            why: "an nftables table was deleted, removing every chain and rule it held".to_string(),
            severity_pct: 85,
        });
    }
    None
}

fn ufw(operands: &[&str]) -> Option<DefenseHit> {
    let verb = operands.iter().find(|a| !a.starts_with('-'))?;
    match *verb {
        "disable" => Some(DefenseHit {
            rule_id: FIREWALL_RULE_ID,
            why: "the host firewall was disabled with `ufw disable`".to_string(),
            severity_pct: 90,
        }),
        "reset" => Some(DefenseHit {
            rule_id: FIREWALL_RULE_ID,
            why: "`ufw reset` was run, which deletes every rule and disables the firewall"
                .to_string(),
            severity_pct: 90,
        }),
        _ => None,
    }
}

fn firewall_cmd(operands: &[&str]) -> Option<DefenseHit> {
    if operands.contains(&"--panic-off") {
        return None; // restores traffic; not a teardown
    }
    operands
        .contains(&"--set-default-zone=trusted")
        .then(|| DefenseHit {
            rule_id: FIREWALL_RULE_ID,
            why: "firewalld's default zone was set to `trusted`, which accepts all \
                  traffic that is not otherwise matched"
                .to_string(),
            severity_pct: 85,
        })
}

fn service_control(name: &str, operands: &[&str]) -> Option<DefenseHit> {
    // `systemctl stop auditd` and `service auditd stop` put the verb and
    // the unit in opposite orders.
    let positional: Vec<&str> = operands
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .collect();
    let (verb, units): (&str, &[&str]) = if name == "service" {
        // service <unit> <verb>
        match positional.as_slice() {
            [unit, verb, ..] => (verb, std::slice::from_ref(unit)),
            _ => return None,
        }
    } else {
        match positional.split_first() {
            Some((verb, rest)) => (verb, rest),
            None => return None,
        }
    };
    if !STOPPING_VERBS.contains(&verb) {
        return None;
    }
    let hit = units
        .iter()
        .map(|u| unit_stem(u))
        .find(|stem| SECURITY_SERVICES.contains(stem))?;
    Some(DefenseHit {
        rule_id: SERVICE_RULE_ID,
        why: format!(
            "`{hit}` was told to {verb}. That service is part of how this host defends \
             or records itself, so stopping it removes evidence or protection rather \
             than a workload"
        ),
        severity_pct: 90,
    })
}

fn setenforce(operands: &[&str]) -> Option<DefenseHit> {
    let mode = operands.first()?;
    (*mode == "0" || mode.eq_ignore_ascii_case("permissive")).then(|| DefenseHit {
        rule_id: MAC_RULE_ID,
        why: "SELinux was put into permissive mode, which keeps it logging while it \
              stops enforcing anything"
            .to_string(),
        severity_pct: 90,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn hit(program: &str, argv: &[&str]) -> Option<DefenseHit> {
        classify(program, &args(argv))
    }

    #[test]
    fn a_bare_flush_empties_every_chain_and_is_a_finding() {
        let h = hit("/usr/sbin/iptables", &["iptables", "-F"]).expect("flush");
        assert_eq!(h.rule_id, FIREWALL_RULE_ID);
        assert!(h.why.contains("no chain named"));
    }

    /// Docker rebuilds its own chain several times a day. Firing on that
    /// would make this the loudest wrong rule in the agent.
    #[test]
    fn flushing_one_named_chain_is_not_a_finding() {
        assert_eq!(hit("iptables", &["iptables", "-F", "DOCKER"]), None);
        assert_eq!(hit("iptables", &["iptables", "-F", "FORWARD"]), None);
    }

    /// Adding and deleting individual rules is what firewall management
    /// *is*, and every tool on the host does it.
    #[test]
    fn ordinary_rule_management_is_not_a_finding() {
        for argv in [
            vec![
                "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT",
            ],
            vec!["iptables", "-D", "INPUT", "1"],
            vec!["iptables", "-I", "FORWARD", "-j", "DOCKER"],
            vec!["iptables", "-L", "-n"],
            vec!["iptables", "-S"],
        ] {
            assert_eq!(hit("iptables", &argv), None, "{argv:?}");
        }
    }

    #[test]
    fn a_default_accept_policy_is_a_finding_but_drop_is_not() {
        assert!(hit("iptables", &["iptables", "-P", "INPUT", "ACCEPT"]).is_some());
        assert_eq!(hit("iptables", &["iptables", "-P", "INPUT", "DROP"]), None);
    }

    #[test]
    fn flushing_the_nftables_ruleset_is_a_finding() {
        assert_eq!(
            hit("/usr/sbin/nft", &["nft", "flush", "ruleset"]).map(|h| h.rule_id),
            Some(FIREWALL_RULE_ID)
        );
        assert_eq!(hit("nft", &["nft", "list", "ruleset"]), None);
    }

    #[test]
    fn disabling_ufw_is_a_finding_and_allowing_a_port_is_not() {
        assert!(hit("ufw", &["ufw", "disable"]).is_some());
        assert!(hit("ufw", &["ufw", "reset"]).is_some());
        assert_eq!(hit("ufw", &["ufw", "allow", "22/tcp"]), None);
        assert_eq!(hit("ufw", &["ufw", "status"]), None);
    }

    /// The verb has to be read. `systemctl` ran hundreds of times on the
    /// fleet this was measured against, and every one was `is-active`,
    /// `daemon-reload`, `show` or `restart`.
    #[test]
    fn stopping_a_security_service_is_a_finding_and_querying_one_is_not() {
        assert_eq!(
            hit("systemctl", &["systemctl", "stop", "auditd"]).map(|h| h.rule_id),
            Some(SERVICE_RULE_ID)
        );
        assert!(hit("systemctl", &["systemctl", "disable", "apparmor.service"]).is_some());
        assert!(hit("systemctl", &["systemctl", "mask", "firewalld"]).is_some());
        for argv in [
            vec!["systemctl", "is-active", "--quiet", "auditd"],
            vec!["systemctl", "daemon-reload"],
            vec!["systemctl", "show", "auditd", "-p", "ActiveState"],
            vec!["systemctl", "restart", "auditd"],
            vec!["systemctl", "status", "apparmor"],
        ] {
            assert_eq!(hit("systemctl", &argv), None, "{argv:?}");
        }
    }

    /// Stopping a workload is not this.
    /// A templated unit is still the service it templates.
    #[test]
    fn a_templated_security_unit_is_stemmed_to_its_template() {
        assert!(hit("systemctl", &["systemctl", "stop", "falco@node1.service"]).is_some());
        assert!(hit("systemctl", &["systemctl", "stop", "auditd@main"]).is_some());
        // And a template that is not a security service still is not.
        assert_eq!(
            hit("systemctl", &["systemctl", "stop", "nginx@a.service"]),
            None
        );
    }

    #[test]
    fn stopping_an_ordinary_service_is_not_a_finding() {
        assert_eq!(hit("systemctl", &["systemctl", "stop", "nginx"]), None);
        assert_eq!(hit("systemctl", &["systemctl", "stop", "postgresql"]), None);
    }

    /// `service` puts the unit before the verb.
    #[test]
    fn the_sysv_wrapper_is_read_in_its_own_order() {
        assert!(hit("service", &["service", "auditd", "stop"]).is_some());
        assert_eq!(hit("service", &["service", "auditd", "status"]), None);
        assert_eq!(hit("service", &["service", "nginx", "stop"]), None);
    }

    #[test]
    fn putting_selinux_in_permissive_mode_is_a_finding() {
        assert_eq!(
            hit("setenforce", &["setenforce", "0"]).map(|h| h.rule_id),
            Some(MAC_RULE_ID)
        );
        assert!(hit("setenforce", &["setenforce", "Permissive"]).is_some());
        // Turning it back on is not.
        assert_eq!(hit("setenforce", &["setenforce", "1"]), None);
    }

    #[test]
    fn unloading_apparmor_is_a_finding() {
        assert_eq!(
            hit("/usr/sbin/aa-teardown", &["aa-teardown"]).map(|h| h.rule_id),
            Some(MAC_RULE_ID)
        );
    }

    #[test]
    fn an_unrelated_program_is_never_a_finding() {
        assert_eq!(hit("/usr/bin/curl", &["curl", "-F", "x"]), None);
        assert_eq!(hit("/bin/ls", &["ls", "-F"]), None);
    }

    /// Every id `classify` can return must be declared, or it vanishes
    /// from the ATT&CK map and the detection counters.
    #[test]
    fn rule_ids_matches_what_classify_can_return() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for (prog, argv) in [
            ("iptables", vec!["iptables", "-F"]),
            ("nft", vec!["nft", "flush", "ruleset"]),
            ("ufw", vec!["ufw", "disable"]),
            ("systemctl", vec!["systemctl", "stop", "auditd"]),
            ("setenforce", vec!["setenforce", "0"]),
            ("aa-teardown", vec!["aa-teardown"]),
        ] {
            if let Some(h) = hit(prog, &argv) {
                seen.insert(h.rule_id);
            }
        }
        let declared: HashSet<&str> = rule_ids().iter().copied().collect();
        assert_eq!(seen, declared, "declared ids and reachable ids disagree");
    }

    #[test]
    fn every_finding_explains_itself_and_is_ranked() {
        let h = hit("iptables", &["iptables", "-F"]).expect("hit");
        assert!(h.why.len() > 40, "the rationale is what an operator reads");
        assert!(h.severity() > 0.8 && h.severity() <= 1.0);
    }
}
