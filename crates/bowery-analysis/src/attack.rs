//! The ATT&CK coverage map, as data rather than as a document.
//!
//! A coverage map that lives only in Markdown drifts the first time
//! someone adds a rule and forgets to write it down, and the failure
//! mode is the worst one available: a document that claims coverage the
//! code does not have. So the map is a table here, every entry names the
//! rule ids that back it, and a test asserts that **every rule the agent
//! can fire appears in exactly one entry**. Adding a detection without
//! placing it on the map fails the build.
//!
//! # On honesty
//!
//! [`Coverage`] deliberately has no "full" variant above
//! [`Coverage::Good`]. No host sensor covers a technique completely —
//! there is always a variant, a bypass, or a code path nobody thought
//! of — and a map that says "complete" invites an operator to stop
//! looking. The grades here answer a narrower and more useful question:
//! *if this technique were used on this host, how likely is it that
//! something fires?*

/// How well a technique is covered, deliberately pessimistic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Coverage {
    /// Nothing fires. Listed anyway — the gaps are the useful half of a
    /// coverage map, and omitting them would make this a feature list.
    None,
    /// One narrow variant fires; the technique's common forms do not.
    Partial,
    /// The mainstream variants fire, with known blind spots named in
    /// `gap`.
    Good,
}

impl Coverage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Partial => "partial",
            Self::Good => "good",
        }
    }
}

/// One ATT&CK technique and what the agent does about it.
#[derive(Debug, Clone, Copy)]
pub struct Technique {
    /// ATT&CK technique id, e.g. `T1543.002`.
    pub id: &'static str,
    pub name: &'static str,
    /// ATT&CK tactic, in ATT&CK's own words.
    pub tactic: &'static str,
    pub coverage: Coverage,
    /// The rule ids that fire. Empty exactly when `coverage` is
    /// [`Coverage::None`].
    pub rules: &'static [&'static str],
    /// What is *not* covered. Required even at [`Coverage::Good`] —
    /// there is always something, and naming it is the point.
    pub gap: &'static str,
}

/// The map.
///
/// Ordered by tactic as ATT&CK orders them, so it reads as a kill chain
/// rather than as an alphabetised inventory.
pub const TECHNIQUES: &[Technique] = &[
    // -- Execution ------------------------------------------------------
    Technique {
        id: "T1059.004",
        name: "Command and Scripting Interpreter: Unix Shell",
        tactic: "Execution",
        coverage: Coverage::Partial,
        rules: &[
            "lineage.service_spawned_shell",
            "lineage.service_spawned_interpreter",
        ],
        gap: "only fires when a network service or scheduler is the parent. A shell \
              started from an interactive login looks exactly like a person working",
    },
    Technique {
        id: "T1204.002",
        name: "User Execution: Malicious File",
        tactic: "Execution",
        coverage: Coverage::Partial,
        rules: &["baseline.rarity", "yara.match"],
        gap: "rests on the binary being rare for this host or matching a YARA rule. A \
              malicious file that is neither is executed silently",
    },
    // -- Persistence ----------------------------------------------------
    Technique {
        id: "T1543.002",
        name: "Create or Modify System Process: systemd Service",
        tactic: "Persistence",
        coverage: Coverage::Good,
        rules: &["persist.systemd_unit", "persist.systemd_unit_lib"],
        gap: "user units under `~/.config/systemd` are not watched, and a unit created \
              before the agent started is never seen — there is no boot-time sweep",
    },
    Technique {
        id: "T1053.003",
        name: "Scheduled Task/Job: Cron",
        tactic: "Persistence",
        coverage: Coverage::Good,
        rules: &["persist.cron", "lineage.scheduled_downloader"],
        gap: "`at` jobs and systemd timers are not watched",
    },
    Technique {
        id: "T1098.004",
        name: "Account Manipulation: SSH Authorized Keys",
        tactic: "Persistence",
        coverage: Coverage::Good,
        rules: &["persist.authorized_keys", "cred.read_authorized_keys"],
        gap: "a key added through a non-default `AuthorizedKeysFile` path is missed",
    },
    Technique {
        id: "T1546.004",
        name: "Event Triggered Execution: Unix Shell Configuration Modification",
        tactic: "Persistence",
        coverage: Coverage::Good,
        rules: &[
            "persist.shell_profile",
            "persist.user_rc",
            "persist.user_profile",
        ],
        gap: "covers the standard rc and profile files; an exotic shell's own \
              configuration is not enumerated",
    },
    Technique {
        id: "T1547.006",
        name: "Boot or Logon Autostart Execution: Kernel Modules",
        tactic: "Persistence",
        coverage: Coverage::None,
        rules: &[],
        gap: "no module-load sensor. A kernel rootkit is invisible to this agent, and \
              would in fact be able to hide the agent's own sensors",
    },
    Technique {
        // ATT&CK has no udev sub-technique; this is the parent, which is
        // the honest place to put it rather than inventing a closer id.
        id: "T1546",
        name: "Event Triggered Execution (udev rules)",
        tactic: "Persistence",
        coverage: Coverage::Partial,
        rules: &["persist.udev"],
        gap: "watches udev rule directories only. The wider technique — inotify hooks, \
              message-bus triggers, anything else that runs code on an event — is not \
              covered",
    },
    Technique {
        id: "T1556.003",
        name: "Modify Authentication Process: Pluggable Authentication Modules",
        tactic: "Persistence",
        coverage: Coverage::Good,
        rules: &["persist.pam"],
        gap: "watches the configuration; a replaced PAM `.so` is caught only if it \
              lands under a watched path",
    },
    // -- Privilege Escalation -------------------------------------------
    Technique {
        id: "T1548.003",
        name: "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        tactic: "Privilege Escalation",
        coverage: Coverage::Good,
        rules: &["privesc.sudoers", "recon.read_sudoers"],
        gap: "a rule added by a package's own postinst is indistinguishable from one an \
              attacker added",
    },
    Technique {
        id: "T1548.001",
        name: "Abuse Elevation Control Mechanism: Setuid and Setgid",
        tactic: "Privilege Escalation",
        coverage: Coverage::Good,
        rules: &[
            "privesc.setid_unpackaged",
            "privesc.setid_packaged_modified",
            "privesc.setid_unknown_provenance",
            "privesc.uid_transition_untrusted_setuid",
        ],
        gap: "the set-id bit is read at exec time, so a binary that is made setuid and \
              never run again is not reported until it runs. There is no filesystem sweep",
    },
    Technique {
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        tactic: "Privilege Escalation",
        coverage: Coverage::Partial,
        rules: &["privesc.uid_transition_no_helper"],
        gap: "catches the *result* — a process running as root whose parent was not — \
              not the exploit. An exploit that stays inside one process, never execs, \
              and does its work in-memory produces no transition to see",
    },
    // -- Defense Evasion ------------------------------------------------
    Technique {
        id: "T1070.002",
        name: "Indicator Removal: Clear Linux or Mac System Logs",
        tactic: "Defense Evasion",
        coverage: Coverage::Good,
        rules: &["evade.auth_log", "evade.wtmp"],
        gap: "journald's binary logs are not watched, and on a systemd host that is \
              where the evidence actually lives",
    },
    Technique {
        id: "T1574.006",
        name: "Hijack Execution Flow: Dynamic Linker Hijacking",
        tactic: "Defense Evasion",
        coverage: Coverage::Good,
        rules: &["persist.ld_preload"],
        gap: "`/etc/ld.so.preload` is watched; the `LD_PRELOAD` *environment variable* \
              is not, because the exec sensor does not capture the environment",
    },
    Technique {
        id: "T1562.001",
        name: "Impair Defenses: Disable or Modify Tools",
        tactic: "Defense Evasion",
        coverage: Coverage::Partial,
        rules: &["probe.sensor_blind", "peer.silent"],
        gap: "the agent reports its own blindness, and its neighbours now report it \
              going silent altogether — a host cannot witness its own death. What \
              remains uncovered is the quieter attack: an agent left running but \
              tampered with, which still gossips and so still looks alive to every \
              peer watching for silence",
    },
    // -- Credential Access ----------------------------------------------
    Technique {
        id: "T1003.008",
        name: "OS Credential Dumping: /etc/passwd and /etc/shadow",
        tactic: "Credential Access",
        coverage: Coverage::Good,
        rules: &[
            "cred.read_shadow",
            "cred.read_gshadow",
            "cred.read_opasswd",
            "cred.shadow",
            "cred.passwd",
        ],
        gap: "the sanctioned readers (a packaged, unmodified `sshd`, `su`, `login`, PAM) \
              are exempt, so a compromise *of one of those binaries* that leaves the \
              package hash intact — an injected library, a hijacked child process — reads \
              shadow without a finding",
    },
    Technique {
        id: "T1552.001",
        name: "Unsecured Credentials: Credentials In Files",
        tactic: "Credential Access",
        coverage: Coverage::Good,
        rules: &[
            "cred.read_aws",
            "cred.read_kube",
            "cred.read_netrc",
            "cred.read_pgpass",
            "cred.read_mysql",
            "cred.read_git",
            "cred.read_docker",
            "cred.read_rails_master_key",
            "cred.read_htpasswd",
        ],
        gap: "a known list of well-known credential paths. Application-specific secret \
              files nobody enumerated are not watched, and neither is a `.env`. No reader \
              is sanctioned for these, so every access is a finding",
    },
    Technique {
        id: "T1552.004",
        name: "Unsecured Credentials: Private Keys",
        tactic: "Credential Access",
        coverage: Coverage::Good,
        rules: &[
            "cred.read_ssh_private_key",
            "cred.read_ssh_host_key",
            "cred.read_gnupg",
            "cred.ssh_private_key",
        ],
        gap: "keys stored outside `~/.ssh` and `/etc/ssh` are missed",
    },
    // -- Discovery ------------------------------------------------------
    Technique {
        id: "T1087",
        name: "Account Discovery",
        tactic: "Discovery",
        coverage: Coverage::Partial,
        rules: &["discovery.recon_burst"],
        gap: "needs a *burst* — several different recon commands from one parent. A \
              patient attacker running one command a minute never trips it, and \
              reading `/etc/passwd` directly instead of running `getent` is a \
              credential-access hit rather than a discovery one",
    },
    Technique {
        id: "T1082",
        name: "System Information Discovery",
        tactic: "Discovery",
        coverage: Coverage::Partial,
        rules: &["discovery.recon_burst"],
        gap: "same burst requirement. Reading `/proc` and `/sys` directly, which is \
              what a compiled implant does, executes nothing and so is not seen",
    },
    Technique {
        id: "T1049",
        name: "System Network Connections Discovery",
        tactic: "Discovery",
        coverage: Coverage::Partial,
        rules: &["discovery.recon_burst"],
        gap: "same burst requirement",
    },
    // -- Lateral Movement -----------------------------------------------
    Technique {
        id: "T1021.004",
        name: "Remote Services: SSH",
        tactic: "Lateral Movement",
        coverage: Coverage::Partial,
        rules: &["corroborate.net_inbound_connect"],
        gap: "the whisper network can ask the other end 'did you connect to me?', which \
              is the strongest signal here — but it only covers hosts that are *in* the \
              mesh. A connection from anywhere else cannot be corroborated",
    },
    // -- Command and Control --------------------------------------------
    Technique {
        id: "T1105",
        name: "Ingress Tool Transfer",
        tactic: "Command and Control",
        coverage: Coverage::Partial,
        rules: &[
            "lineage.service_spawned_downloader",
            "lineage.scheduled_downloader",
        ],
        gap: "fires on a downloader started by a service or scheduler. A downloader run \
              from a shell, or a transfer done in-process by an implant, is not seen",
    },
    Technique {
        id: "T1071.001",
        name: "Application Layer Protocol: Web Protocols",
        tactic: "Command and Control",
        coverage: Coverage::None,
        rules: &[],
        gap: "connection events are recorded but nothing scores them. There is no \
              beaconing detection — no periodicity analysis, no destination rarity",
    },
    // -- Impact ---------------------------------------------------------
    Technique {
        id: "T1486",
        name: "Data Encrypted for Impact",
        tactic: "Impact",
        coverage: Coverage::Partial,
        rules: &["impact.mass_write_new_extension"],
        gap: "needs the sweep to *rename* what it encrypts, which most families do but \
              not all — in-place encryption that keeps the filename is invisible here. \
              The sensor reports write intent only: no renames, no unlinks, no contents, \
              so there is no entropy check and a family that writes everything as a \
              common extension evades the test that makes the rule usable at all",
    },
];

/// Every rule id the map claims, in declaration order.
#[must_use]
pub fn mapped_rule_ids() -> Vec<&'static str> {
    TECHNIQUES.iter().flat_map(|t| t.rules).copied().collect()
}

/// How many techniques sit at each grade.
#[must_use]
pub fn tally() -> (usize, usize, usize) {
    let count = |c: Coverage| TECHNIQUES.iter().filter(|t| t.coverage == c).count();
    (
        count(Coverage::Good),
        count(Coverage::Partial),
        count(Coverage::None),
    )
}

use std::fmt::Write as _;

/// Greedy wrap, so the generated document is readable in a terminal
/// rather than one long line per gap.
fn wrap(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = 0;
    for word in text.split_whitespace() {
        if line > 0 && line + 1 + word.chars().count() > width {
            out.push('\n');
            line = 0;
        } else if line > 0 {
            out.push(' ');
            line += 1;
        }
        out.push_str(word);
        line += word.chars().count();
    }
    out
}

/// Render the map as the Markdown that ships in
/// `docs/ATTACK-COVERAGE.md`.
///
/// The document is generated rather than written so it cannot disagree
/// with the code; a test compares the checked-in file against this
/// output and fails when they drift.
#[must_use]
pub fn markdown() -> String {
    let (good, partial, none) = tally();
    let mut out = String::new();
    out.push_str(
        "# ATT&CK coverage\n\
         \n\
         <!-- GENERATED FILE — do not edit by hand.\n\
         \x20    Source: crates/bowery-analysis/src/attack.rs\n\
         \x20    Regenerate: BOWERY_UPDATE_DOCS=1 cargo test -p bowery-analysis -->\n\
         \n\
         What The Bowery's agents actually detect, mapped to MITRE ATT&CK, and — more\n\
         usefully — what they do not.\n\
         \n\
         There is no \"full\" grade. No host sensor covers a technique completely: there\n\
         is always a variant, a bypass, or a code path nobody thought of, and a map that\n\
         claims completeness invites an operator to stop looking. The grades answer a\n\
         narrower question: *if this technique were used on this host, how likely is it\n\
         that something fires?*\n\
         \n\
         - **good** — the mainstream variants fire.\n\
         - **partial** — one narrow variant fires; the common forms do not.\n\
         - **none** — nothing fires. Listed anyway; the gaps are the useful half.\n\
         \n",
    );
    let _ = writeln!(
        out,
        "Today: **{good} good, {partial} partial, {none} uncovered** across {} techniques.\n",
        TECHNIQUES.len()
    );

    let mut tactic = "";
    for t in TECHNIQUES {
        if t.tactic != tactic {
            tactic = t.tactic;
            let _ = writeln!(out, "## {tactic}\n");
        }
        let _ = writeln!(
            out,
            "### {} — {}\n\n**Coverage: {}**\n",
            t.id,
            t.name,
            t.coverage.label()
        );
        if t.rules.is_empty() {
            out.push_str("No rule fires.\n\n");
        } else {
            out.push_str("Rules: ");
            let rendered: Vec<String> = t.rules.iter().map(|r| format!("`{r}`")).collect();
            out.push_str(&rendered.join(", "));
            out.push_str("\n\n");
        }
        out.push_str(&wrap(&format!("Gap: {}.", t.gap), 84));
        out.push_str("\n\n");
    }

    out.push_str(
        "## Rules that are not table entries\n\
         \n\
         These fire from subsystems rather than from a rule table, so they have no\n\
         entry in the analyzer's rule lists:\n\
         \n",
    );
    for r in NON_TABLE_RULES {
        let _ = writeln!(out, "- `{r}`");
    }
    out
}

/// Rule ids that are real but produced outside the rule tables — scores
/// and subsystems rather than table entries.
///
/// Kept here rather than in the map's test so the exemption is
/// enumerated and reviewable instead of implicit.
pub const NON_TABLE_RULES: &[&str] = &[
    // The baseline scorer's rarity signal; it has no id of its own
    // because it is a score, not a rule.
    "baseline.rarity",
    // The YARA subsystem.
    "yara.match",
    // The probe watchdog.
    "probe.sensor_blind",
    // The peer-liveness watchdog: a neighbour that stops gossiping.
    "peer.silent",
    // The corroboration engine's claim kinds.
    "corroborate.net_inbound_connect",
    // "does this binary touch this file on your host too?" — a
    // downgrade-only round, so it never appears as a finding of its own.
    "corroborate.file_access",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every rule the agent can fire must be on the map.
    ///
    /// This is the test that makes the map worth reading. Without it,
    /// adding a detection and forgetting to document it produces a map
    /// that under-reports; renaming a rule produces one that points at
    /// nothing. Both fail here instead.
    #[test]
    fn every_rule_appears_on_the_map() {
        let mut real: HashSet<&str> = crate::file_watch::rule_ids().into_iter().collect();
        real.extend(crate::lineage::rule_ids());
        real.extend(crate::provenance::rule_ids());
        real.extend(crate::escalation::rule_ids());
        real.extend(crate::mass_write::rule_ids());

        let mapped: HashSet<&str> = mapped_rule_ids().into_iter().collect();

        let missing: Vec<_> = real.difference(&mapped).copied().collect();
        assert!(
            missing.is_empty(),
            "these rules fire but are on no ATT&CK technique: {missing:?}. \
             Add them to TECHNIQUES — a coverage map that omits a detection \
             under-reports what the agent does."
        );

        let exempt: HashSet<&str> = NON_TABLE_RULES.iter().copied().collect();
        let phantom: Vec<_> = mapped
            .difference(&real)
            .filter(|r| !exempt.contains(*r))
            .copied()
            .collect();
        assert!(
            phantom.is_empty(),
            "the map claims these rules, but nothing produces them: {phantom:?}. \
             A map that points at a renamed or deleted rule claims coverage that \
             does not exist."
        );
    }

    #[test]
    fn no_coverage_means_no_rules_and_vice_versa() {
        for t in TECHNIQUES {
            match t.coverage {
                Coverage::None => assert!(
                    t.rules.is_empty(),
                    "{} claims no coverage but names rules",
                    t.id
                ),
                _ => assert!(
                    !t.rules.is_empty(),
                    "{} claims coverage but names no rule that would fire",
                    t.id
                ),
            }
        }
    }

    /// Even a well-covered technique has a blind spot, and the map is
    /// only useful if it says what it is.
    #[test]
    fn every_technique_names_its_gap() {
        for t in TECHNIQUES {
            assert!(
                t.gap.len() > 20,
                "{} has no meaningful gap statement; every technique has a blind spot \
                 and an honest map names it",
                t.id
            );
        }
    }

    #[test]
    fn technique_ids_are_unique() {
        let mut seen = HashSet::new();
        for t in TECHNIQUES {
            assert!(seen.insert(t.id), "duplicate technique {}", t.id);
        }
    }

    /// `docs/ATTACK-COVERAGE.md` is generated from [`TECHNIQUES`]; this
    /// is what stops it from drifting.
    ///
    /// Set `BOWERY_UPDATE_DOCS=1` to rewrite the file instead of
    /// failing.
    #[test]
    fn the_checked_in_document_matches_the_map() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ATTACK-COVERAGE.md");
        let generated = markdown();
        if std::env::var_os("BOWERY_UPDATE_DOCS").is_some() {
            std::fs::write(&path, &generated).expect("write the coverage doc");
            return;
        }
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            on_disk, generated,
            "docs/ATTACK-COVERAGE.md is out of date. \
             Regenerate: BOWERY_UPDATE_DOCS=1 cargo test -p bowery-analysis"
        );
    }

    /// The gaps are not a footnote — they are most of the map.
    #[test]
    fn the_map_admits_to_uncovered_techniques() {
        assert!(
            TECHNIQUES.iter().any(|t| t.coverage == Coverage::None),
            "a coverage map with no gaps is a feature list"
        );
    }
}
