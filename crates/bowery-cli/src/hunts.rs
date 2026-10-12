//! Curated incident-response hunts.
//!
//! A hunt is a question an operator asks the *whole fleet* at once,
//! with the one or two details that change per incident left as
//! parameters. They are kept here rather than in the browser so the
//! terminal and the web console ask identical questions, and so one
//! test can hold them to the schema.
//!
//! # Why these are parameterised templates and not a query builder
//!
//! The field picker in the Query pane can express "these columns of
//! that table, filtered". None of the questions below are that shape:
//! they are joins against a baseline, time windows, `GROUP BY` with a
//! `HAVING`, and prefix matches across several columns at once. A
//! builder that could express them would be a SQL editor with extra
//! steps, so a hunt renders to SQL the operator can read and edit
//! before it runs.
//!
//! # Keeping them true
//!
//! The catalogue's column lists drifted from the agent's real schema
//! and nobody noticed until a browser read both — `bowery_events` was
//! missing `local_addr`, `bowery_alerts` was missing `peers_familiar`.
//! A list of SQL templates is the same hazard with a worse failure: a
//! hunt that errors is discovered mid-incident. So every hunt here is
//! executed against a live agent by `scripts/integration-sql-test.sh`,
//! which is the only check that can catch a column that no longer
//! exists.

use std::collections::BTreeMap;

/// What kind of value a parameter takes.
///
/// Drives the input the console renders, and whether the value is
/// quoted when the template is filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// Free text, substituted inside quotes.
    Text,
    /// A bare number, substituted without quotes.
    ///
    /// Rejected unless it parses, because a template that puts
    /// arbitrary text where SQL expects a number produces a syntax
    /// error at the worst possible moment.
    Number,
}

#[derive(Debug, Clone, Copy)]
pub struct Param {
    /// The `{key}` the template substitutes.
    pub key: &'static str,
    pub label: &'static str,
    pub default: &'static str,
    pub kind: ParamKind,
    /// One line of guidance, shown beside the input.
    pub hint: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct Hunt {
    pub id: &'static str,
    pub name: &'static str,
    /// What this answers, and when an operator would want it.
    pub about: &'static str,
    /// Loose grouping for the console's list.
    pub group: &'static str,
    /// The primary table, so the hunt can be checked against the
    /// catalogue without parsing SQL.
    pub table: &'static str,
    pub sql: &'static str,
    pub params: &'static [Param],
}

impl Hunt {
    /// Fill the template from `values`, falling back to each
    /// parameter's default.
    ///
    /// # Errors
    ///
    /// When a `Number` parameter is given something that is not one.
    /// Quoting a non-number into a numeric position would produce a
    /// query that fails on the agent rather than here, which is the
    /// wrong place to find out.
    pub fn render(&self, values: &BTreeMap<String, String>) -> Result<String, String> {
        let mut out = self.sql.to_string();
        for p in self.params {
            let raw = values
                .get(p.key)
                .map(String::as_str)
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(p.default);
            let filled = match p.kind {
                // Doubling the quote is the SQLite escape. The
                // operator can edit the rendered SQL freely, so this
                // is about generating something valid rather than
                // about holding a boundary — the agent's read-only
                // surface and its authorizer are what hold that.
                ParamKind::Text => raw.replace('\'', "''"),
                ParamKind::Number => {
                    let t = raw.trim();
                    if t.parse::<i64>().is_err() {
                        return Err(format!("{} must be a whole number, got {t:?}", p.label));
                    }
                    t.to_string()
                }
            };
            out = out.replace(&format!("{{{}}}", p.key), &filled);
        }
        Ok(out)
    }

    /// The parameters with their defaults, for a caller that wants to
    /// render without collecting input first.
    #[must_use]
    pub fn defaults(&self) -> BTreeMap<String, String> {
        self.params
            .iter()
            .map(|p| (p.key.to_string(), p.default.to_string()))
            .collect()
    }
}

#[must_use]
pub fn by_id(id: &str) -> Option<&'static Hunt> {
    HUNTS.iter().find(|h| h.id == id)
}

const HOURS: Param = Param {
    key: "hours",
    label: "window (hours)",
    default: "24",
    kind: ParamKind::Number,
    hint: "how far back to look; the event log's retention is the real ceiling",
};

const LIMIT: Param = Param {
    key: "limit",
    label: "rows",
    default: "100",
    kind: ParamKind::Number,
    hint: "per agent, not fleet-wide",
};

pub const HUNTS: &[Hunt] = &[
    // -- Sweeps: "does anyone have this?" -----------------------------
    Hunt {
        id: "ioc-hash",
        name: "Sweep for a file hash",
        about: "Has any host ever executed this binary? The baseline records every hash \
                that has run, with when it was first and last seen and how often — so a \
                hit tells you which host, and a count of one tells you it ran once.",
        group: "indicator sweeps",
        table: "bowery_baseline_binaries",
        sql: "SELECT sha256_hex, exe_path, pkg, seen_count, \
              datetime(first_seen_unix, 'unixepoch') AS first_seen, \
              datetime(last_seen_unix, 'unixepoch') AS last_seen \
              FROM bowery_baseline_binaries \
              WHERE sha256_hex LIKE '{sha}%' \
              LIMIT {limit}",
        params: &[
            Param {
                key: "sha",
                label: "sha256 (prefix ok)",
                default: "",
                kind: ParamKind::Text,
                hint: "lowercase hex; a prefix matches, so the first 12 characters are enough",
            },
            LIMIT,
        ],
    },
    Hunt {
        id: "ioc-path",
        name: "Sweep for a path",
        about: "Any event touching this path — executed, read, written. The place to \
                start when a report names a file and you need to know which of your \
                hosts has seen it.",
        group: "indicator sweeps",
        table: "bowery_events",
        sql: "SELECT datetime(ts_unix_ms/1000, 'unixepoch') AS when_utc, kind, pid, comm, \
              exe_path, path, file_op \
              FROM bowery_events \
              WHERE (path LIKE '%{needle}%' OR exe_path LIKE '%{needle}%') \
                AND ts_unix_ms > (strftime('%s','now') - {hours}*3600) * 1000 \
              ORDER BY ts_unix_ms DESC LIMIT {limit}",
        params: &[
            Param {
                key: "needle",
                label: "path or filename",
                default: "",
                kind: ParamKind::Text,
                hint: "substring match against both the subject path and the acting binary",
            },
            HOURS,
            LIMIT,
        ],
    },
    Hunt {
        id: "ioc-address",
        name: "Sweep for a network peer",
        about: "Has anything here talked to this address? Aggregated destinations give \
                you first seen, last seen and a count per host, which is what tells a \
                one-off resolution apart from a channel.",
        group: "indicator sweeps",
        table: "bowery_net_destinations",
        sql: "SELECT addr, port, seen_count, \
              datetime(first_seen_unix, 'unixepoch') AS first_seen, \
              datetime(last_seen_unix, 'unixepoch') AS last_seen \
              FROM bowery_net_destinations \
              WHERE addr LIKE '%{addr}%' \
              ORDER BY seen_count DESC LIMIT {limit}",
        params: &[
            Param {
                key: "addr",
                label: "address",
                default: "",
                kind: ParamKind::Text,
                hint: "substring, so a /24 can be swept as 203.0.113.",
            },
            LIMIT,
        ],
    },
    // -- Execution ----------------------------------------------------
    Hunt {
        id: "exec-writable",
        name: "Execution from a writable path",
        about: "Anything that ran out of /tmp, /dev/shm or /var/tmp. Not inherently \
                malicious — build systems and installers live there — but it is where \
                a dropped payload runs from, and the list is usually short enough to \
                read.",
        group: "execution",
        table: "bowery_events",
        sql: "SELECT datetime(ts_unix_ms/1000, 'unixepoch') AS when_utc, pid, ppid, uid, \
              comm, exe_path, substr(args, 1, 120) AS args \
              FROM bowery_events \
              WHERE kind = 'exec' AND exe_path LIKE '{prefix}%' \
                AND ts_unix_ms > (strftime('%s','now') - {hours}*3600) * 1000 \
              ORDER BY ts_unix_ms DESC LIMIT {limit}",
        params: &[
            Param {
                key: "prefix",
                label: "path prefix",
                default: "/tmp/",
                kind: ParamKind::Text,
                hint: "try /dev/shm/ and /var/tmp/ too; one prefix per run",
            },
            HOURS,
            LIMIT,
        ],
    },
    Hunt {
        id: "exec-rare",
        name: "Binaries this host barely knows",
        about: "Hashes with a low sighting count, newest first. Rarity is the weakest \
                signal on its own and the best starting point when you have no \
                indicator: it is a list of what is unusual *for this host*, which is \
                not the same as unusual.",
        group: "execution",
        table: "bowery_baseline_binaries",
        sql: "SELECT exe_path, pkg, seen_count, substr(sha256_hex, 1, 16) AS sha, \
              datetime(first_seen_unix, 'unixepoch') AS first_seen \
              FROM bowery_baseline_binaries \
              WHERE seen_count <= {max_seen} \
              ORDER BY first_seen_unix DESC LIMIT {limit}",
        params: &[
            Param {
                key: "max_seen",
                label: "seen at most",
                default: "2",
                kind: ParamKind::Number,
                hint: "1 means it has run exactly once",
            },
            LIMIT,
        ],
    },
    Hunt {
        id: "exec-no-exe",
        name: "Running from a deleted binary",
        about: "Execs the agent could not resolve to a file on disk. A process whose \
                binary was unlinked after launch looks exactly like this — and so does \
                a short-lived child the agent lost the race with, so read it as a lead \
                rather than a finding.",
        group: "execution",
        table: "bowery_events",
        sql: "SELECT datetime(ts_unix_ms/1000, 'unixepoch') AS when_utc, pid, ppid, uid, \
              comm, substr(args, 1, 120) AS args \
              FROM bowery_events \
              WHERE kind = 'exec' AND (exe_path IS NULL OR exe_path = '') \
                AND ts_unix_ms > (strftime('%s','now') - {hours}*3600) * 1000 \
              ORDER BY ts_unix_ms DESC LIMIT {limit}",
        params: &[HOURS, LIMIT],
    },
    Hunt {
        id: "exec-by-parent",
        name: "What a process started",
        about: "Children of a named parent. The question you ask once you have one \
                suspicious process and want the rest of the session around it.",
        group: "execution",
        table: "bowery_events",
        sql: "SELECT datetime(ts_unix_ms/1000, 'unixepoch') AS when_utc, pid, ppid, uid, \
              comm, exe_path, substr(args, 1, 120) AS args \
              FROM bowery_events \
              WHERE kind = 'exec' AND (comm = '{parent}' OR exe_path LIKE '%/{parent}') \
                AND ts_unix_ms > (strftime('%s','now') - {hours}*3600) * 1000 \
              ORDER BY ts_unix_ms DESC LIMIT {limit}",
        params: &[
            Param {
                key: "parent",
                label: "process name",
                default: "bash",
                kind: ParamKind::Text,
                hint: "matched against comm and the binary's basename",
            },
            HOURS,
            LIMIT,
        ],
    },
    // -- Credentials and sensitive files -------------------------------
    Hunt {
        id: "cred-reads",
        name: "Who read the credential files",
        about: "Attributed reads of the password databases, keys and token files the \
                agent watches. Every row names the binary, which is the whole point: \
                `sshd` reading a host key is its job and a shell reading it is not.",
        group: "credentials",
        table: "bowery_events",
        sql: "SELECT datetime(ts_unix_ms/1000, 'unixepoch') AS when_utc, comm, exe_path, \
              path, file_op \
              FROM bowery_events \
              WHERE kind = 'file_access' AND path LIKE '%{needle}%' \
                AND ts_unix_ms > (strftime('%s','now') - {hours}*3600) * 1000 \
              ORDER BY ts_unix_ms DESC LIMIT {limit}",
        params: &[
            Param {
                key: "needle",
                label: "path contains",
                default: "shadow",
                kind: ParamKind::Text,
                hint: "shadow, id_rsa, credentials, .netrc, authorized_keys …",
            },
            HOURS,
            LIMIT,
        ],
    },
    Hunt {
        id: "persistence-writes",
        name: "Writes to persistence paths",
        about: "Changes under the directories that survive a reboot — units, cron, \
                shell profiles, authorized_keys. A foothold has to land in one of them \
                to come back, so this is the shortest list worth reading after a \
                confirmed intrusion.",
        group: "persistence",
        table: "bowery_events",
        sql: "SELECT datetime(ts_unix_ms/1000, 'unixepoch') AS when_utc, kind, comm, \
              exe_path, path, file_op \
              FROM bowery_events \
              WHERE path LIKE '{prefix}%' AND file_op IS NOT NULL AND file_op <> 'read' \
                AND ts_unix_ms > (strftime('%s','now') - {hours}*3600) * 1000 \
              ORDER BY ts_unix_ms DESC LIMIT {limit}",
        params: &[
            Param {
                key: "prefix",
                label: "path prefix",
                default: "/etc/systemd/",
                kind: ParamKind::Text,
                hint: "/etc/cron, /etc/systemd/, /root/.ssh/, /etc/ld.so",
            },
            HOURS,
            LIMIT,
        ],
    },
    Hunt {
        id: "persist-cron",
        name: "Scheduled jobs, as the host has them now",
        about: "Live crontab contents per host. Read against what you expect rather \
                than against yesterday — the agent sees cron *files* change, but a job \
                added before it started is only visible here.",
        group: "persistence",
        table: "crontab",
        sql: "SELECT user, minute, hour, day_of_month, month, day_of_week, \
              substr(command, 1, 140) AS command, path \
              FROM crontab LIMIT {limit}",
        params: &[LIMIT],
    },
    Hunt {
        id: "persist-units",
        name: "Systemd units and what they launch",
        about: "Every unit with its ExecStart. The same reasoning as cron: a unit \
                installed before the agent started leaves no event, and this is the \
                only place it shows up.",
        group: "persistence",
        table: "systemd_units",
        sql: "SELECT name, type, substr(exec_start, 1, 140) AS exec_start, path \
              FROM systemd_units \
              WHERE exec_start LIKE '%{needle}%' LIMIT {limit}",
        params: &[
            Param {
                key: "needle",
                label: "ExecStart contains",
                default: "",
                kind: ParamKind::Text,
                hint: "blank lists everything; try /tmp or a binary name",
            },
            LIMIT,
        ],
    },
    // -- Network ------------------------------------------------------
    Hunt {
        id: "net-listening",
        name: "What is listening",
        about: "Every listening socket with the uid behind it. Compare against the \
                services you meant to run; a listener owned by an unexpected user is \
                the shape of a backdoor.",
        group: "network",
        table: "listening_ports",
        sql: "SELECT protocol, family, address, port, uid FROM listening_ports \
              ORDER BY port LIMIT {limit}",
        params: &[LIMIT],
    },
    Hunt {
        id: "net-beacon",
        name: "Beacon candidates",
        about: "Destinations contacted many times, busiest first. Periodicity is not \
                measured here — NTP, package mirrors and every monitoring agent look \
                like this — so the useful column is `first_seen`: a destination this \
                host has only known since the incident is the interesting one.",
        group: "network",
        table: "bowery_net_destinations",
        sql: "SELECT addr, port, seen_count, \
              datetime(first_seen_unix, 'unixepoch') AS first_seen, \
              datetime(last_seen_unix, 'unixepoch') AS last_seen \
              FROM bowery_net_destinations \
              WHERE seen_count >= {min_count} \
              ORDER BY seen_count DESC LIMIT {limit}",
        params: &[
            Param {
                key: "min_count",
                label: "contacted at least",
                default: "20",
                kind: ParamKind::Number,
                hint: "raise it on a chatty host",
            },
            LIMIT,
        ],
    },
    Hunt {
        id: "net-inbound",
        name: "Who connected in",
        about: "Inbound connections with the local port they reached. `local_addr` is \
                which of this host's addresses they arrived on, which matters on a \
                box with both a tailnet and a LAN.",
        group: "network",
        table: "bowery_events",
        sql: "SELECT datetime(ts_unix_ms/1000, 'unixepoch') AS when_utc, dst_addr AS source, \
              local_addr, local_port, comm, exe_path \
              FROM bowery_events \
              WHERE kind = 'connect' AND direction = 'in' \
                AND ts_unix_ms > (strftime('%s','now') - {hours}*3600) * 1000 \
              ORDER BY ts_unix_ms DESC LIMIT {limit}",
        params: &[HOURS, LIMIT],
    },
    // -- Host state ---------------------------------------------------
    Hunt {
        id: "host-logins",
        name: "Who is logged in, and who was",
        about: "Current sessions. Run the `last` table alongside it for history — a \
                session that ended is not in here, and the one you care about usually \
                has.",
        group: "host state",
        table: "logged_in_users",
        sql: "SELECT user, tty, host, pid, datetime(login_time, 'unixepoch') AS login_utc \
              FROM logged_in_users LIMIT {limit}",
        params: &[LIMIT],
    },
    Hunt {
        id: "host-login-history",
        name: "Login history",
        about: "The wtmp record. Worth pairing with the `evade.wtmp` detection: if \
                that has fired, this table is the thing that was being edited.",
        group: "host state",
        table: "last",
        sql: "SELECT user, tty, host, pid, type, datetime(time_unix, 'unixepoch') AS when_utc \
              FROM last WHERE user LIKE '%{user}%' \
              ORDER BY time_unix DESC LIMIT {limit}",
        params: &[
            Param {
                key: "user",
                label: "user contains",
                default: "",
                kind: ParamKind::Text,
                hint: "blank for everyone",
            },
            LIMIT,
        ],
    },
    Hunt {
        id: "host-accounts",
        name: "Accounts that can log in",
        about: "Users with a real shell, uid first. An added account is the least \
                subtle persistence there is and the easiest to miss, because nothing \
                about it looks like an event.",
        group: "host state",
        table: "users",
        sql: "SELECT uid, gid, username, shell, directory, gecos FROM users \
              WHERE shell NOT LIKE '%nologin' AND shell NOT LIKE '%false' \
              ORDER BY uid LIMIT {limit}",
        params: &[LIMIT],
    },
    Hunt {
        id: "host-modules",
        name: "Loaded kernel modules",
        about: "What is in the kernel right now. The agent reports modules it watched \
                *load*; anything resident before it started, or loaded while it was \
                down, only appears here.",
        group: "host state",
        table: "kernel_modules",
        sql: "SELECT name, size, used_by_count, status FROM kernel_modules \
              WHERE name LIKE '%{needle}%' ORDER BY name LIMIT {limit}",
        params: &[
            Param {
                key: "needle",
                label: "name contains",
                default: "",
                kind: ParamKind::Text,
                hint: "blank lists everything",
            },
            LIMIT,
        ],
    },
    // -- The agent's own view -----------------------------------------
    Hunt {
        id: "agent-alerts",
        name: "What each host has alerted on",
        about: "The live inboxes across the fleet, highest suspicion first. Includes \
                the neighbourhood's verdict and the local model's reading when either \
                ran.",
        group: "the agent's view",
        table: "bowery_alerts",
        sql: "SELECT rule_id, suspicion, exe_path, substr(rationale, 1, 120) AS why, \
              peers_asked, peers_unseen, peers_familiar, \
              substr(model_explanation, 1, 100) AS model \
              FROM bowery_alerts WHERE suspicion >= {min_suspicion} \
              ORDER BY suspicion DESC, ts_unix_ms DESC LIMIT {limit}",
        params: &[
            Param {
                key: "min_suspicion",
                label: "suspicion at least",
                default: "0",
                kind: ParamKind::Number,
                hint: "0 shows everything, including findings already damped",
            },
            LIMIT,
        ],
    },
    Hunt {
        id: "agent-blind",
        name: "Is anyone blind",
        about: "Sensor self-attestation per host. Run this first, every time: a quiet \
                host and a blind one produce the same empty result from every other \
                hunt here, and this is the only table that tells them apart.",
        group: "the agent's view",
        table: "bowery_probe_status",
        sql: "SELECT probe, watching, attached, emitted, parse_failed, kernel_drops, \
              stopped_reason FROM bowery_probe_status ORDER BY probe",
        params: &[],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_hunt_is_a_select_against_a_catalogued_table() {
        let known = crate::catalog::table_names();
        for h in HUNTS {
            let sql = h.render(&h.defaults()).expect("defaults must render");
            let upper = sql.trim_start().to_ascii_uppercase();
            assert!(upper.starts_with("SELECT"), "{}: not a SELECT", h.id);
            assert!(
                !sql.contains(';'),
                "{}: a hunt is one statement, not several",
                h.id
            );
            assert!(
                known.contains(&h.table),
                "{}: table {} is not in the catalogue",
                h.id,
                h.table
            );
            assert!(
                sql.contains(h.table),
                "{}: declares table {} but never queries it",
                h.id,
                h.table
            );
        }
    }

    /// A placeholder nobody substitutes reaches the agent verbatim and
    /// fails there, which is the wrong place to find out.
    #[test]
    fn every_placeholder_has_a_parameter_and_every_parameter_is_used() {
        for h in HUNTS {
            for p in h.params {
                assert!(
                    h.sql.contains(&format!("{{{}}}", p.key)),
                    "{}: parameter {} is never used",
                    h.id,
                    p.key
                );
            }
            let rendered = h.render(&h.defaults()).expect("defaults must render");
            assert!(
                !rendered.contains('{') && !rendered.contains('}'),
                "{}: unsubstituted placeholder in {rendered}",
                h.id
            );
        }
    }

    #[test]
    fn ids_names_and_groups_are_usable() {
        let mut ids: Vec<&str> = HUNTS.iter().map(|h| h.id).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate hunt id");
        for h in HUNTS {
            assert!(!h.name.is_empty(), "{}: no name", h.id);
            assert!(h.about.len() > 40, "{}: say what it answers", h.id);
            assert!(!h.group.is_empty(), "{}: no group", h.id);
            assert!(by_id(h.id).is_some(), "{} is not findable by id", h.id);
        }
    }

    /// A quote in a value must not end the string it sits in.
    #[test]
    fn a_quote_in_a_value_is_escaped_rather_than_closing_the_literal() {
        let h = by_id("ioc-path").expect("hunt");
        let mut v = h.defaults();
        v.insert("needle".into(), "o'brien".into());
        let sql = h.render(&v).expect("render");
        assert!(sql.contains("o''brien"), "got {sql}");
        // And the quotes still balance, which is what actually matters.
        assert_eq!(sql.matches('\'').count() % 2, 0, "unbalanced quotes: {sql}");
    }

    /// A number position must not accept text.
    ///
    /// Not a security boundary — the operator can edit the rendered
    /// SQL — but failing here names the parameter, where failing on
    /// the agent says only `sql_error`.
    #[test]
    fn a_numeric_parameter_refuses_text_and_says_which_one() {
        let h = by_id("exec-rare").expect("hunt");
        let mut v = h.defaults();
        v.insert("max_seen".into(), "lots".into());
        let err = h.render(&v).expect_err("must refuse");
        assert!(err.contains("seen at most"), "got {err}");
        assert!(err.contains("whole number"), "got {err}");
    }

    /// An empty value falls back to the default rather than rendering
    /// a hole.
    #[test]
    fn a_blank_value_uses_the_default() {
        let h = by_id("exec-writable").expect("hunt");
        let mut v = h.defaults();
        v.insert("prefix".into(), "   ".into());
        let sql = h.render(&v).expect("render");
        assert!(sql.contains("'/tmp/%'"), "got {sql}");
    }

    /// The first hunt an operator should run has to need no input.
    #[test]
    fn the_blindness_check_takes_no_parameters() {
        let h = by_id("agent-blind").expect("hunt");
        assert!(
            h.params.is_empty(),
            "a hunt you run before you know anything cannot require input"
        );
    }
}
