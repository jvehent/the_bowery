//! What you can ask, and how to ask it.
//!
//! The SQL surface is the most capable thing here and the least
//! discoverable: an operator faces an empty prompt and has to already
//! know that `bowery_events` exists, that it holds `kind='exec'` rows,
//! and that `ts_unix_ms` is milliseconds. Knowing SQL does not help
//! with any of that.
//!
//! So this is the schema an operator needs, plus queries that answer
//! the questions people actually arrive with. The console renders it
//! into the Query pane's idle screen — the moment somebody is looking
//! for something to type — and `bowery tables` prints it.
//!
//! # Kept honest
//!
//! Every table named here is cross-checked against the agent's real
//! registry by a test in `bowery-agent` (which owns the registry and
//! has this crate as a dev-dependency). A catalogue that drifts from
//! the schema is worse than none: it sends an operator to a table that
//! no longer exists and reads as the tool being broken.

/// One queryable table or view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    pub name: &'static str,
    /// What it holds, in the terms someone would go looking for it.
    pub about: &'static str,
    /// The columns worth knowing; not exhaustive for the wide ones.
    pub columns: &'static str,
}

/// A question, and the query that answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Example {
    /// Phrased as the question, not as a description of the SQL.
    pub question: &'static str,
    pub sql: &'static str,
}

pub const TABLES: &[Table] = &[
    Table {
        name: "bowery_events",
        about: "every observed host event, append-only and persisted — the only place \
                process exits, network connects and file opens are kept",
        columns: "seq, ts_unix_ms, kind, pid, ppid, uid, comm, exe_path, args, exit_code, \
                  dst_addr, dst_port, local_port, direction, path, file_op, open_flags",
    },
    Table {
        name: "bowery_alerts",
        about: "the agent's live inbox — bounded and 72h, so use the operator-side \
                archive (`bowery alerts history`) for anything older",
        columns: "originator_fp_hex, episode_id, rule_id, exe_sha256_hex, exe_path, suspicion, rationale, ts_unix_ms, backend, confirmed, peers_asked, peers_unseen, peers_seen, peers_refused",
    },
    Table {
        name: "bowery_baseline_binaries",
        about: "every binary hash this host has executed, with first/last seen, a count, \
                and what the hash was: path, size, owning package, platform. Descriptor \
                columns are NULL for hashes first seen before they existed, which means \
                'not recorded' and never 'not packaged'",
        columns: "sha256_hex, first_seen_unix, last_seen_unix, seen_count, exe_path, \
                  size_bytes, pkg, platform",
    },
    Table {
        name: "bowery_detections",
        about: "the detection rules this agent has compiled in, and how often each fired",
        columns: "rule_id, fired, fired_since_install, last_fired_unix_ms, since_unix_ms",
    },
    Table {
        name: "bowery_corroboration_status",
        about: "why the cross-host corroboration rounds produced what they did, per claim \
                kind. A rule at zero fires may mean nothing happened or that every claim \
                was dropped before anyone could be asked — `no_audience` is the difference",
        columns: "kind, raised, no_audience, deduped, shed, rounds, corroborated, denied, \
                  refused, no_reply",
    },
    Table {
        name: "bowery_probe_status",
        about: "sensor self-attestation: attached, emitted, parse failures, kernel drops. \
                Where you look to tell a quiet host from a blind one",
        columns: "probe, watching, attached, emitted, parse_failed, kernel_drops, last_event_unix_ms, stopped_reason, object_path, object_sha256",
    },
    Table {
        name: "bowery_silences",
        about: "silences in force, with the pattern each covers and who signed it",
        columns: "id, rule_id, exe_sha256_hex, exe_path, host_fp_hex, weight, reason, operator_fp_hex, issued_unix_ms, expires_unix_ms, matched, last_matched_unix_ms",
    },
    Table {
        name: "bowery_audit",
        about: "what the response engine did, or would have done",
        columns: "seq, ts_unix_ms, episode_id, action_id, outcome_kind",
    },
    Table {
        name: "bowery_peers",
        about: "pinned neighbours this agent knows, by fingerprint",
        columns: "fingerprint_hex",
    },
    Table {
        name: "bowery_mesh_peers",
        about: "live gossip view of the mesh — who is up, and what role they claim",
        columns: "fingerprint_hex, whisper_addr, agent_version, platform, comparable, pinned, \
                  has_role_vector, has_bloom_advert, grant_state",
    },
    Table {
        name: "bowery_net_destinations",
        about: "outbound destinations seen, aggregated — for 'who does this host talk to'",
        columns: "dst_key, addr, port, first_seen_unix, last_seen_unix, seen_count",
    },
    Table {
        name: "bowery_monitor_rules",
        about: "operator-configured file watches and process detections",
        columns: "kind, rule_id, pattern, ops, severity",
    },
    Table {
        name: "bowery_yara_rules",
        about: "YARA rules loaded, and whether each compiled",
        columns: "rule_id, bytes, received_unix, source_operator_fp, request_id",
    },
    Table {
        name: "bowery_revocations",
        about: "revoked peer identities, so a burned key stays burned",
        columns: "fingerprint_hex, issued_unix_ms, reason, operator_fp_hex",
    },
    Table {
        name: "bowery_eventlog_status",
        about: "event log health: how far back it reaches, and whether it has gaps",
        columns: "recording, queryable, path, rows, oldest_ts_unix_ms, newest_ts_unix_ms, highest_seq, dropped, write_failed, last_error",
    },
    // ---- live host state, read at query time ----
    Table {
        name: "processes",
        about: "processes running right now, read from /proc at query time",
        columns: "pid, ppid, uid, gid, name, cmdline, exe_path, start_time_unix, state, \
                  threads, rss_bytes, vsize_bytes",
    },
    Table {
        name: "listening_ports",
        about: "what is listening, and which uid owns it",
        columns: "protocol, family, address, port, uid, inode",
    },
    Table {
        name: "process_open_sockets",
        about: "open sockets per process — joins to `processes` on pid to name a connection",
        columns: "pid, fd, family, protocol, local_address, local_port, remote_address, \
                  remote_port, state, inode",
    },
    Table {
        name: "crontab",
        about: "scheduled jobs across user and system crontabs — a classic persistence spot",
        columns: "minute, hour, day_of_month, month, day_of_week, user, command, path",
    },
    Table {
        name: "systemd_units",
        about: "unit files and what each executes — the other classic persistence spot",
        columns: "name, type, description, exec_start, path",
    },
    Table {
        name: "users",
        about: "local accounts from /etc/passwd",
        columns: "username, uid, gid, gecos, directory, shell",
    },
    Table {
        name: "logged_in_users",
        about: "who is logged in now",
        columns: "user, tty, host, pid, login_time",
    },
    Table {
        name: "last",
        about: "login history from wtmp",
        columns: "user, tty, host, pid, type, time_unix",
    },
    Table {
        name: "kernel_modules",
        about: "loaded modules — where a rootkit would have to appear",
        columns: "name, size, used_by_count, used_by, status, address",
    },
    Table {
        name: "interfaces",
        about: "network interfaces and their state",
        columns: "name, mac, mtu, operstate, flags",
    },
    Table {
        name: "mounts",
        about: "mounted filesystems and their options",
        columns: "mount_id, parent_id, device, fs_type, mount_point, mount_options",
    },
    Table {
        name: "os_version",
        about: "distribution and release",
        columns: "id, name, version, version_id, codename, build_id, pretty_name",
    },
    Table {
        name: "system_info",
        about: "hostname, CPU, memory, kernel version",
        columns: "hostname, uuid, cpu_brand, cpu_count, cpu_logical_cores, hardware_model, \
                  hardware_vendor, board_model, physical_memory_bytes, kernel_version",
    },
];

pub const EXAMPLES: &[Example] = &[
    Example {
        question: "What ran recently?",
        sql: "SELECT ts_unix_ms, pid, uid, exe_path, args FROM bowery_events \
              WHERE kind = 'exec' ORDER BY seq DESC LIMIT 50",
    },
    Example {
        question: "What ran in the last hour, as readable time?",
        sql: "SELECT datetime(ts_unix_ms/1000,'unixepoch') AS t, exe_path, args \
              FROM bowery_events WHERE kind = 'exec' \
              AND ts_unix_ms > (strftime('%s','now') - 3600) * 1000 ORDER BY seq DESC",
    },
    Example {
        question: "Does any host have this program, whatever its build?",
        sql: "SELECT pkg, exe_path, platform, COUNT(*) AS builds, SUM(seen_count) AS execs \
              FROM bowery_baseline_binaries WHERE pkg IS NOT NULL \
              GROUP BY pkg, exe_path ORDER BY builds DESC LIMIT 50",
    },
    Example {
        question: "Which binaries has nothing described? (recorded before descriptors, or unpackaged)",
        sql: "SELECT sha256_hex, seen_count FROM bowery_baseline_binaries \
              WHERE exe_path IS NULL ORDER BY seen_count DESC LIMIT 50",
    },
    Example {
        question: "Has this binary ever run here before?",
        sql: "SELECT b.sha256_hex, b.seen_count, \
              datetime(b.first_seen_unix,'unixepoch') AS first_seen, e.exe_path \
              FROM bowery_baseline_binaries b JOIN bowery_events e \
              ON e.kind = 'exec' AND e.exe_path LIKE '%curl%' GROUP BY b.sha256_hex LIMIT 20",
    },
    Example {
        question: "What has only ever run once? (the shape of a one-shot payload)",
        sql: "SELECT sha256_hex, datetime(first_seen_unix,'unixepoch') AS seen \
              FROM bowery_baseline_binaries WHERE seen_count = 1 \
              ORDER BY first_seen_unix DESC LIMIT 50",
    },
    Example {
        question: "Is this host actually being monitored?",
        sql: "SELECT probe, watching, attached, emitted, parse_failed, kernel_drops, \
              stopped_reason, datetime(last_event_unix_ms/1000,'unixepoch') AS last_event \
              FROM bowery_probe_status",
    },
    Example {
        question: "Is corroboration doing anything, or is there nobody to ask?",
        sql: "SELECT kind, raised, no_audience, rounds, corroborated, denied \
              FROM bowery_corroboration_status ORDER BY raised DESC",
    },
    Example {
        question: "Can this mesh actually corroborate itself?",
        sql: "SELECT platform, COUNT(*) AS peers, SUM(comparable) AS can_compare \
              FROM bowery_mesh_peers GROUP BY platform",
    },
    Example {
        question: "Which detections have never fired? (coverage you do not have)",
        sql: "SELECT rule_id, fired, fired_since_install FROM bowery_detections \
              WHERE fired_since_install = 0 ORDER BY rule_id",
    },
    Example {
        question: "Who does this host talk to?",
        sql: "SELECT addr, port, seen_count, \
              datetime(last_seen_unix,'unixepoch') AS last_seen \
              FROM bowery_net_destinations ORDER BY seen_count DESC LIMIT 50",
    },
    Example {
        question: "What did this process do? (pivot from an alert's pid)",
        sql: "SELECT seq, ts_unix_ms, kind, path, dst_addr, dst_port, args \
              FROM bowery_events WHERE pid = 1234 ORDER BY seq",
    },
    Example {
        question: "What ran as root that was not started by root?",
        sql: "SELECT e.ts_unix_ms, e.pid, e.uid, e.exe_path, e.args FROM bowery_events e \
              WHERE e.kind = 'exec' AND e.uid = 0 ORDER BY e.seq DESC LIMIT 50",
    },
    Example {
        question: "What files has anything opened for write under /etc?",
        sql: "SELECT ts_unix_ms, pid, comm, path, file_op FROM bowery_events \
              WHERE kind = 'file_open' AND path LIKE '/etc/%' ORDER BY seq DESC LIMIT 50",
    },
    Example {
        question: "What is currently silenced, and why?",
        sql: "SELECT id, rule_id, exe_path, weight, reason, matched, \
              datetime(expires_unix_ms/1000,'unixepoch') AS expires FROM bowery_silences",
    },
    Example {
        question: "How far back does this host's history actually reach?",
        sql: "SELECT recording, queryable, rows, dropped, \
              datetime(oldest_ts_unix_ms/1000,'unixepoch') AS oldest, \
              datetime(newest_ts_unix_ms/1000,'unixepoch') AS newest \
              FROM bowery_eventlog_status",
    },
    Example {
        question: "What is listening, and who owns it?",
        sql: "SELECT l.protocol, l.address, l.port, l.uid, p.name, p.exe_path \
              FROM listening_ports l LEFT JOIN process_open_sockets s ON s.local_port = l.port \
              LEFT JOIN processes p ON p.pid = s.pid ORDER BY l.port",
    },
    Example {
        question: "What persistence is configured on this host?",
        sql: "SELECT user, command, path FROM crontab \
              UNION ALL SELECT 'systemd', exec_start, path FROM systemd_units \
              WHERE exec_start IS NOT NULL AND exec_start <> ''",
    },
    Example {
        question: "Which running process is rare on this host? (join live to history)",
        sql: "SELECT p.pid, p.exe_path, COUNT(e.seq) AS execs FROM processes p \
              LEFT JOIN bowery_events e ON e.kind = 'exec' AND e.exe_path = p.exe_path \
              GROUP BY p.pid, p.exe_path HAVING execs <= 2 ORDER BY execs LIMIT 50",
    },
    Example {
        question: "Which accounts have a real shell?",
        sql: "SELECT username, uid, directory, shell FROM users \
              WHERE shell NOT LIKE '%nologin' AND shell NOT LIKE '%false'",
    },
    Example {
        question: "Who logged in recently?",
        sql: "SELECT user, host, tty, datetime(time_unix,'unixepoch') AS t FROM last \
              ORDER BY time_unix DESC LIMIT 30",
    },
];

/// Table names the catalogue claims exist. Used by the agent-side test
/// that keeps this honest.
#[must_use]
pub fn table_names() -> Vec<&'static str> {
    TABLES.iter().map(|t| t.name).collect()
}

/// Every catalogued table an example's SQL mentions.
///
/// Matches against the catalogue rather than scanning for identifiers,
/// so column names and SQL keywords cannot be mistaken for tables. The
/// drift this catches is an example pointing at a table that has been
/// renamed or dropped.
#[must_use]
pub fn tables_referenced_by_examples() -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for ex in EXAMPLES {
        let sql = ex.sql;
        for t in TABLES {
            if found.contains(&t.name) {
                continue;
            }
            // Word-boundary check: `processes` must not match inside
            // `process_open_sockets`.
            if sql.match_indices(t.name).any(|(i, _)| {
                let after = sql[i + t.name.len()..].chars().next();
                let before = sql[..i].chars().next_back();
                !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
                    && !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            }) {
                found.push(t.name);
            }
        }
    }
    found
}

/// Plain-text rendering for `bowery tables`.
#[must_use]
pub fn render() -> String {
    use std::fmt::Write as _;
    let mut out = String::from("Queryable tables\n\n");
    for t in TABLES {
        let _ = writeln!(
            out,
            "  {}\n    {}\n    columns: {}\n",
            t.name, t.about, t.columns
        );
    }
    out.push_str("Example queries\n\n");
    for ex in EXAMPLES {
        let _ = writeln!(out, "  {}\n    {}\n", ex.question, squash(ex.sql));
    }
    out.push_str(
        "Run these with `bowery sql --agent-addr <addr> …` or in the console's Query pane.\n\
         The console lists them on its idle screen; `:schema <table>` asks the agent for\n\
         the live column list, which is authoritative if this drifts.\n",
    );
    out
}

/// Collapse the whitespace a multi-line `&str` literal leaves behind.
#[must_use]
pub fn squash(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_example_references_a_catalogued_table() {
        let known = table_names();
        for t in tables_referenced_by_examples() {
            assert!(
                known.contains(&t),
                "example query uses {t:?}, which the catalogue does not list"
            );
        }
    }

    #[test]
    fn the_catalogue_has_no_duplicates() {
        let mut names = table_names();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "a table is listed twice");
    }

    /// An example that does not parse as a SELECT is a trap: it is
    /// offered as a starting point and the agent's authorizer will
    /// reject anything else.
    #[test]
    fn every_example_is_a_select() {
        for ex in EXAMPLES {
            let sql = squash(ex.sql);
            assert!(
                sql.to_ascii_uppercase().starts_with("SELECT"),
                "{:?} is not a SELECT: {sql}",
                ex.question
            );
            assert!(!sql.contains("  "), "unsquashed whitespace in {sql:?}");
        }
    }

    /// Questions are the index an operator scans; two entries with the
    /// same question means one is unreachable.
    #[test]
    fn example_questions_are_distinct() {
        let mut qs: Vec<&str> = EXAMPLES.iter().map(|e| e.question).collect();
        qs.sort_unstable();
        let before = qs.len();
        qs.dedup();
        assert_eq!(before, qs.len(), "duplicate question in the examples");
    }
}
