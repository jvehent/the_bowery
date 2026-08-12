//! Phase-9 bonus tables — agent-state-aware SQL views that
//! `bowery-tables` can't carry directly because it has no
//! dependency on the agent crate.
//!
//! Each table impl holds an `Arc` to the agent state it observes
//! (`KnownNeighbors`, `Baseline`, `AlertInbox`, audit-log path)
//! and re-reads it on every query. That trade-off — no caching,
//! re-walk per query — is the same as the rest of the Phase-9
//! tables; agents have small state so the per-query cost is
//! microseconds.
//!
//! These tables are deliberately Bowery-specific: they expose the
//! agent's own awareness of the mesh (peers it has pinned, alerts
//! it has emitted, the audit-log envelope chain) — exactly the
//! questions a generic host-state SQL surface can't answer.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use bowery_baseline::Baseline;
use bowery_mesh::PeerInfo;
use bowery_tables::{BoweryTable, TableError};
use bowery_whisper::known_neighbors::KnownNeighbors;
use rusqlite::{Connection, params};
use tokio::sync::watch;
use tracing::warn;

use base64::prelude::Engine as _;
use bowery_whisper::FingerprintResolver as _;

use crate::inbox::AlertInbox;
use crate::monitor::{MonitorRules, file_op_label, severity_label};
use crate::yara_store::YaraStore;

// ---------------------------------------------------------------------------
// bowery_peers — fingerprints currently pinned in KnownNeighbors.
// ---------------------------------------------------------------------------

/// `bowery_peers` table — one row per pinned peer in the agent's
/// `KnownNeighbors` store. Operators use this to ask the relay
/// "who could you fan a query out to?" without dialing the mesh
/// gossip layer directly.
#[derive(Debug)]
pub struct BoweryPeersTable {
    kn: Arc<KnownNeighbors>,
}

impl BoweryPeersTable {
    pub fn new(kn: Arc<KnownNeighbors>) -> Self {
        Self { kn }
    }
}

impl BoweryTable for BoweryPeersTable {
    fn name(&self) -> &'static str {
        "bowery_peers"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_peers (
                fingerprint_hex TEXT
            );",
        )?;
        let mut stmt = conn.prepare("INSERT INTO bowery_peers (fingerprint_hex) VALUES (?1)")?;
        for fp in self.kn.fingerprints() {
            stmt.execute(params![fp.to_string()])?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bowery_monitor_rules — the operator's configured file + process rules.
// ---------------------------------------------------------------------------

/// `bowery_monitor_rules` table — one row per operator-configured
/// monitoring rule, so an operator can ask an agent "what are you
/// actually watching?" over SQL instead of reading its config file
/// (and can fan that question across the fleet with `--fanout`).
///
/// `kind` is `file` or `process`. `pattern` is the watched path for a
/// file rule, or the `key=value` matchers (joined by ` AND `) for a
/// process rule. `ops` is the comma-separated change classes for a
/// file rule and empty for a process rule.
#[derive(Debug)]
pub struct BoweryMonitorRulesTable {
    rules: Arc<MonitorRules>,
}

impl BoweryMonitorRulesTable {
    pub fn new(rules: Arc<MonitorRules>) -> Self {
        Self { rules }
    }
}

impl BoweryTable for BoweryMonitorRulesTable {
    fn name(&self) -> &'static str {
        "bowery_monitor_rules"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_monitor_rules (
                kind      TEXT,
                rule_id   TEXT,
                pattern   TEXT,
                ops       TEXT,
                severity  TEXT
            );",
        )?;
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_monitor_rules (kind, rule_id, pattern, ops, severity)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for r in self.rules.file_rules() {
            let ops = r
                .ops
                .iter()
                .map(|o| file_op_label(*o))
                .collect::<Vec<_>>()
                .join(",");
            stmt.execute(params![
                "file",
                r.id,
                r.path.display().to_string(),
                ops,
                severity_label(r.severity),
            ])?;
        }
        for r in self.rules.process_rules() {
            let mut parts: Vec<String> = Vec::new();
            if let Some(v) = &r.exe_prefix {
                parts.push(format!("exe_prefix={v}"));
            }
            if let Some(v) = &r.comm {
                parts.push(format!("comm={v}"));
            }
            if let Some(v) = &r.arg_substr {
                parts.push(format!("arg_substr={v}"));
            }
            stmt.execute(params![
                "process",
                r.id,
                parts.join(" AND "),
                "",
                severity_label(r.severity),
            ])?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bowery_yara_rules — operator-distributed YARA rules this agent holds.
// ---------------------------------------------------------------------------

/// `bowery_yara_rules` table — one row per YARA rule this agent has
/// stored, whether pushed directly by an operator or received by mesh
/// propagation.
///
/// Fleet use: `SELECT rule_id FROM bowery_yara_rules` with `--fanout`
/// answers "did my rule actually reach every agent?" — the practical way
/// to confirm a distribution converged.
#[derive(Debug)]
pub struct BoweryYaraRulesTable {
    store: Arc<YaraStore>,
}

impl BoweryYaraRulesTable {
    pub fn new(store: Arc<YaraStore>) -> Self {
        Self { store }
    }
}

impl BoweryTable for BoweryYaraRulesTable {
    fn name(&self) -> &'static str {
        "bowery_yara_rules"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_yara_rules (
                rule_id            TEXT,
                bytes              INTEGER,
                received_unix      INTEGER,
                source_operator_fp TEXT,
                request_id         TEXT
            );",
        )?;
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_yara_rules
                (rule_id, bytes, received_unix, source_operator_fp, request_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for r in self.store.list() {
            stmt.execute(params![
                r.rule_id,
                i64::try_from(r.bytes_len).unwrap_or(i64::MAX),
                i64::try_from(r.received_unix).unwrap_or(i64::MAX),
                r.source_operator_fp,
                r.request_id,
            ])?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bowery_mesh_peers — everything the agent has DISCOVERED over the
// chitchat mesh, whether or not it has been pinned.
// ---------------------------------------------------------------------------

/// `bowery_mesh_peers` table — one row per live peer the agent
/// currently sees in the gossip mesh. This is the *discovery* view,
/// distinct from `bowery_peers` (the *pinned* set): a peer shows up
/// here as soon as gossip carries its state, and the `pinned` column
/// says whether it also made it into `KnownNeighbors`.
///
/// Diagnostic use: to check whether agent A can reach agent B over
/// the mesh, query this on A — if B's fingerprint appears, gossip is
/// flowing A↔B. A peer that's `pinned = 0` was discovered *after* the
/// bootstrap window closed (so A sees it but won't trust it for
/// fan-out); an empty table means A has discovered no peers at all
/// (no seeds, wrong `advertise_addr`, or the mesh port isn't
/// reachable).
#[derive(Debug)]
pub struct BoweryMeshPeersTable {
    peers_rx: watch::Receiver<Vec<PeerInfo>>,
    kn: Arc<KnownNeighbors>,
    /// `None` leaves `grant_state` as `unchecked` — used by callers that
    /// have no operator key set to verify against.
    enrollment: Option<GrantCheck>,
}

impl BoweryMeshPeersTable {
    pub fn new(peers_rx: watch::Receiver<Vec<PeerInfo>>, kn: Arc<KnownNeighbors>) -> Self {
        Self {
            peers_rx,
            kn,
            enrollment: None,
        }
    }

    /// Enable grant evaluation for the `grant_state` column.
    #[must_use]
    pub fn with_enrollment(mut self, check: GrantCheck) -> Self {
        self.enrollment = Some(check);
        self
    }
}

impl BoweryTable for BoweryMeshPeersTable {
    fn name(&self) -> &'static str {
        "bowery_mesh_peers"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_mesh_peers (
                fingerprint_hex   TEXT,
                whisper_addr      TEXT,
                agent_version     TEXT,
                pinned            INTEGER,
                has_role_vector   INTEGER,
                has_bloom_advert  INTEGER,
                grant_state       TEXT
            );",
        )?;
        // Snapshot the pinned set once so we don't re-lock KnownNeighbors
        // per row. The mesh peer list is a cheap watch-channel borrow.
        let pinned = self.kn.fingerprints();
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_mesh_peers
                (fingerprint_hex, whisper_addr, agent_version, pinned,
                 has_role_vector, has_bloom_advert, grant_state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for peer in self.peers_rx.borrow().iter() {
            let is_pinned = i64::from(pinned.contains(&peer.fingerprint));
            let has_role = i64::from(peer.role_vector.is_some());
            let has_bloom = i64::from(peer.bloom_advert.is_some());
            stmt.execute(params![
                peer.fingerprint.to_string(),
                peer.whisper_addr.to_string(),
                peer.agent_version,
                is_pinned,
                has_role,
                has_bloom,
                grant_state(peer, self.enrollment.as_ref()),
            ])?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bowery_baseline_binaries — every binary the agent's baseline observed.
// ---------------------------------------------------------------------------

/// `bowery_baseline_binaries` table — one row per distinct
/// SHA-256 in the agent's baseline store, with first/last-seen
/// timestamps and the cumulative observation count. The baseline
/// is the agent's local memory of "have I seen this before?";
/// surfacing it as SQL lets operators ask "which binaries have I
/// only seen on this one host?" by joining across fan-out.
#[derive(Debug)]
pub struct BoweryBaselineBinariesTable {
    baseline: Arc<Baseline>,
}

impl BoweryBaselineBinariesTable {
    pub fn new(baseline: Arc<Baseline>) -> Self {
        Self { baseline }
    }
}

impl BoweryTable for BoweryBaselineBinariesTable {
    fn name(&self) -> &'static str {
        "bowery_baseline_binaries"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_baseline_binaries (
                sha256_hex      TEXT,
                first_seen_unix INTEGER,
                last_seen_unix  INTEGER,
                seen_count      INTEGER
            );",
        )?;
        // SECURITY-AUDIT-PHASE9 F-9: snapshot the binaries first so
        // the baseline mutex isn't held during our per-row INSERTs.
        // Snapshot errors fall back to "no rows" rather than failing
        // the whole query — same best-effort policy as everywhere
        // else in `bowery-tables`.
        let snapshot = self.baseline.snapshot_binaries().unwrap_or_default();
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_baseline_binaries (sha256_hex, first_seen_unix, last_seen_unix, seen_count)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for rec in &snapshot {
            let sha_hex = hex_lower(&rec.sha256);
            let first = unix_secs(rec.first_seen);
            let last = unix_secs(rec.last_seen);
            let count = i64::try_from(rec.seen_count).unwrap_or(i64::MAX);
            let _ = stmt.execute(params![sha_hex, first, last, count]);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bowery_alerts — alerts currently in the agent's inbox.
// ---------------------------------------------------------------------------

/// `bowery_alerts` table — one row per alert in the agent's
/// inbox, identical schema to the [`bowery_proto::Alert`] message
/// the operator's `bowery alerts tail` would receive. Surfaces
/// the inbox over SQL so operators can run queries like "every
/// alert with suspicion >= 0.95 across the fleet" via fan-out.
#[derive(Debug)]
pub struct BoweryAlertsTable {
    inbox: Arc<AlertInbox>,
}

impl BoweryAlertsTable {
    pub fn new(inbox: Arc<AlertInbox>) -> Self {
        Self { inbox }
    }
}

impl BoweryTable for BoweryAlertsTable {
    fn name(&self) -> &'static str {
        "bowery_alerts"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_alerts (
                originator_fp_hex TEXT,
                episode_id        TEXT,
                exe_sha256_hex    TEXT,
                exe_path          TEXT,
                suspicion         REAL,
                rationale         TEXT,
                ts_unix_ms        INTEGER,
                backend           TEXT,
                confirmed         INTEGER,
                peers_asked       INTEGER,
                peers_unseen      INTEGER,
                peers_seen        INTEGER
            );",
        )?;
        let (alerts, _) = self.inbox.read_since(0, usize::MAX);
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_alerts (originator_fp_hex, episode_id, exe_sha256_hex,
                                         exe_path, suspicion, rationale, ts_unix_ms, backend,
                                         confirmed, peers_asked, peers_unseen, peers_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;
        for a in alerts {
            let originator_hex = hex_lower(&a.originator_fp);
            let ts: i64 = i64::try_from(a.ts_unix_ms).unwrap_or(i64::MAX);
            stmt.execute(params![
                originator_hex,
                a.episode_id,
                a.exe_sha256_hex,
                a.exe_path,
                f64::from(a.suspicion),
                a.rationale,
                ts,
                a.backend,
                // Absent confirmation renders as NULL rather than 0 so
                // "no whisper round ran" is distinguishable from "the
                // round ran and did not confirm".
                a.confirmation.map(|c| i64::from(c.confirmed)),
                a.confirmation.map(|c| i64::from(c.peers_asked)),
                a.confirmation.map(|c| i64::from(c.peers_unseen)),
                a.confirmation.map(|c| i64::from(c.peers_seen)),
            ])?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bowery_audit — the response engine's signed audit-log envelopes.
// ---------------------------------------------------------------------------

/// `bowery_audit` table — one row per line in the agent's audit
/// log (when [`response.audit_log_path`](crate::config::ResponseConfig)
/// is configured). Each row carries the fields an operator would
/// otherwise have to grep + jq out of the JSONL file:
///
/// - `seq` — Phase-8 hash-chain sequence number
/// - `ts_unix_ms` — wall clock at action attempt
/// - `episode_id` — analyzer episode the action belongs to
/// - `action_id` — `kill_process` / `block_exec` / etc.
/// - `outcome_kind` — `executed` / `dry_run` / `suppressed_*`
///
/// Parsing is best-effort: malformed lines are skipped silently.
/// `audit_log_path` not configured → table queryable but empty.
#[derive(Debug)]
pub struct BoweryAuditTable {
    log_path: Option<PathBuf>,
}

impl BoweryAuditTable {
    pub fn new(log_path: Option<PathBuf>) -> Self {
        Self { log_path }
    }
}

/// Hard cap on the audit log bytes any single query will read.
/// SECURITY-AUDIT-PHASE9 F-12: prior implementation called
/// `fs::read_to_string` with no cap, so an audit log grown to
/// many MB-to-GB would OOM the agent on every query (and was
/// reachable via fanout — one operator query × N peers).
///
/// 64 MiB is well above any realistic short-term operator-question
/// volume; longer-horizon forensics should be done with `bowery
/// audit verify` against the file directly, not via SQL.
const MAX_AUDIT_BYTES: u64 = 64 * 1024 * 1024;

impl BoweryTable for BoweryAuditTable {
    fn name(&self) -> &'static str {
        "bowery_audit"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        use std::io::{BufRead, BufReader, Read};

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_audit (
                seq          INTEGER,
                ts_unix_ms   INTEGER,
                episode_id   TEXT,
                action_id    TEXT,
                outcome_kind TEXT
            );",
        )?;
        let Some(path) = self.log_path.as_ref() else {
            return Ok(());
        };
        let Ok(file) = std::fs::File::open(path) else {
            return Ok(());
        };
        // Cap the reader at MAX_AUDIT_BYTES so an operator query
        // can't read a multi-GB audit log into memory. The line
        // straddling the cap will hit EOF mid-record and json-parse
        // fail — silently skipped, same as any malformed line.
        let reader = BufReader::new(file.take(MAX_AUDIT_BYTES));
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_audit (seq, ts_unix_ms, episode_id, action_id, outcome_kind)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for line in reader.lines() {
            // I/O errors during a streaming read mean the file is
            // changing under us or we hit our byte cap mid-line —
            // either way, stop cleanly. The rows we already
            // inserted are still queryable.
            let Ok(line) = line else {
                break;
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let seq = value.get("seq").and_then(serde_json::Value::as_i64);
            let ts = value.get("ts_unix_ms").and_then(serde_json::Value::as_i64);
            let episode = value
                .get("episode_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let action = value
                .get("action_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            // outcome can be a string or an object {kind, ...}; try both.
            let outcome_kind = match value.get("outcome") {
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                Some(serde_json::Value::Object(map)) => map
                    .get("kind")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                _ => value
                    .get("outcome_kind")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
            };
            stmt.execute(params![seq, ts, episode, action, outcome_kind])?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// How this agent would judge a peer's membership grant *right now*.
///
/// This is the pre-flight for switching `enrollment` from `tofu` to
/// `grant`: flipping the policy while any peer reads anything other than
/// `valid` partitions the mesh, because those peers stop being pinnable.
/// Reported as text rather than a boolean so the reason is actionable —
/// `absent` means the peer hasn't been issued a grant, while
/// `invalid: …` means it has one that this agent rejects.
fn grant_state(peer: &PeerInfo, enrollment: Option<&GrantCheck>) -> String {
    let Some(check) = enrollment else {
        return "unchecked".to_string();
    };
    let Some(encoded) = peer.membership_grant.as_deref() else {
        return "absent".to_string();
    };
    let Ok(raw) = base64::prelude::BASE64_STANDARD.decode(encoded.as_bytes()) else {
        return "invalid: not base64".to_string();
    };
    let Ok(grant) = <bowery_proto::MembershipGrant as prost::Message>::decode(raw.as_slice())
    else {
        return "invalid: undecodable".to_string();
    };
    let operators = check.operators.clone();
    let resolve = move |fp: &bowery_crypto::Fingerprint| operators.resolve(fp);
    match bowery_whisper::mesh_trust::verify_grant(
        &grant,
        &peer.fingerprint,
        &check.cluster_id,
        &resolve,
        SystemTime::now(),
    ) {
        Ok(()) => "valid".to_string(),
        Err(e) => format!("invalid: {e}"),
    }
}

/// The subset of enrollment state the SQL view needs to judge a grant.
#[derive(Debug)]
pub struct GrantCheck {
    pub cluster_id: String,
    pub operators: Arc<bowery_whisper::StaticResolver>,
}

// ---------------------------------------------------------------------------
// bowery_net_destinations — every endpoint this host has contacted.
// ---------------------------------------------------------------------------

/// `bowery_net_destinations` — one row per endpoint this agent has ever
/// made an outbound connection to, with a count and first/last seen.
///
/// Under `--fanout` this is the **fleet-wide connection graph**, which
/// is what makes lateral movement visible at all: the two halves of a
/// hop live on different hosts, and neither is remarkable alone.
///
/// ```sql
/// -- who in the fleet has ever talked to this endpoint?
/// SELECT _agent_name, seen_count, first_seen_unix
/// FROM bowery_net_destinations WHERE dst_key = '10.0.0.5:22';
///
/// -- endpoints exactly one host has ever contacted
/// SELECT dst_key, COUNT(*) AS hosts FROM bowery_net_destinations
/// GROUP BY dst_key HAVING hosts = 1;
/// ```
#[derive(Debug)]
pub struct BoweryNetDestinationsTable {
    baseline: Arc<Baseline>,
}

impl BoweryNetDestinationsTable {
    pub fn new(baseline: Arc<Baseline>) -> Self {
        Self { baseline }
    }
}

impl BoweryTable for BoweryNetDestinationsTable {
    fn name(&self) -> &'static str {
        "bowery_net_destinations"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_net_destinations (
                dst_key         TEXT,
                addr            TEXT,
                port            INTEGER,
                first_seen_unix INTEGER,
                last_seen_unix  INTEGER,
                seen_count      INTEGER
            );",
        )?;
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_net_destinations
                (dst_key, addr, port, first_seen_unix, last_seen_unix, seen_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        // Snapshot first so the baseline mutex isn't held across our
        // INSERTs (SECURITY-AUDIT-PHASE9 F-9); a snapshot error falls
        // back to no rows, the same best-effort policy as every other
        // table here.
        let snapshot = self
            .baseline
            .snapshot_net_destinations()
            .unwrap_or_default();
        for r in &snapshot {
            let _ = stmt.execute(params![
                r.dst_key,
                r.addr,
                i64::from(r.port),
                unix_secs(r.first_seen),
                unix_secs(r.last_seen),
                i64::try_from(r.seen_count).unwrap_or(i64::MAX),
            ]);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bowery_revocations — identities an operator has ejected from the mesh.
// ---------------------------------------------------------------------------

/// `bowery_revocations` — one row per revoked agent identity.
///
/// Fleet-wide with `--fanout`, this answers the question that actually
/// matters after ejecting a compromised host: *did the revocation
/// reach everyone?* An agent that never received it still trusts the
/// revoked peer.
#[derive(Debug)]
pub struct BoweryRevocationsTable {
    store: Arc<bowery_whisper::mesh_trust::RevocationStore>,
}

impl BoweryRevocationsTable {
    pub fn new(store: Arc<bowery_whisper::mesh_trust::RevocationStore>) -> Self {
        Self { store }
    }
}

impl BoweryTable for BoweryRevocationsTable {
    fn name(&self) -> &'static str {
        "bowery_revocations"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_revocations (
                fingerprint_hex   TEXT,
                issued_unix_ms    INTEGER,
                reason            TEXT,
                operator_fp_hex   TEXT
            );",
        )?;
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_revocations
                (fingerprint_hex, issued_unix_ms, reason, operator_fp_hex)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for e in self.store.entries() {
            stmt.execute(params![
                e.fingerprint,
                i64::try_from(e.issued_unix_ms).unwrap_or(i64::MAX),
                e.reason,
                e.operator_fp,
            ])?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bowery_events — the append-only local history.
// ---------------------------------------------------------------------------

/// `bowery_events` — one row per observed host event, in append order.
///
/// This is the table that turns "an alert fired at 14:32" into "here is
/// what the host was doing at 14:32", and it is the only place
/// `ProcessExit` / `NetworkConnect` / `FileOpen` are retained at all —
/// the analyzer has no scoring path for them, so before this they were
/// collected by the eBPF loader and discarded.
///
/// Unlike every other table here, this one does **not** copy its rows
/// into the query connection. The event log is already a `SQLite` file,
/// so it is `ATTACH`ed read-only and exposed as a view: queries run
/// against its real indexes, and a multi-million-row history costs
/// nothing to register. Materialising it the way `bowery_peers` does
/// would mean copying the entire log on every query.
///
/// The attach is read-only (`mode=ro`) as defence in depth. The
/// SELECT-only authorizer already rejects writes at query time, but
/// `register` runs *before* that authorizer is installed, so the file
/// itself is what enforces it here.
#[derive(Debug)]
pub struct BoweryEventsTable {
    log: Option<Arc<bowery_eventlog::EventLog>>,
}

/// Columns mirrored from the event log's own schema, so the view is a
/// straight passthrough and the two can't drift into different names.
const EVENTS_COLUMNS: &str = "seq, ts_unix_ms, kind, pid, ppid, uid, comm, exe_path, args, \
                              exit_code, net_family, dst_addr, dst_port, local_port, local_addr, direction, \
                              path, file_op, open_flags";

const EVENTS_EMPTY_DDL: &str = "CREATE TABLE IF NOT EXISTS bowery_events (
    seq          INTEGER,
    ts_unix_ms   INTEGER,
    kind         TEXT,
    pid          INTEGER,
    ppid         INTEGER,
    uid          INTEGER,
    comm         TEXT,
    exe_path     TEXT,
    args         TEXT,
    exit_code    INTEGER,
    net_family   TEXT,
    dst_addr     TEXT,
    dst_port     INTEGER,
    local_port   INTEGER,
    local_addr   TEXT,
    direction    TEXT,
    path         TEXT,
    file_op      TEXT,
    open_flags   INTEGER
);";

impl BoweryEventsTable {
    pub fn new(log: Option<Arc<bowery_eventlog::EventLog>>) -> Self {
        Self { log }
    }

    /// Path to attach, or `None` when there is nothing attachable.
    ///
    /// An in-memory log belongs to another connection and cannot be
    /// reached from here; that is a real limitation of `path =
    /// ":memory:"`, and `bowery_eventlog_status.queryable` reports it
    /// rather than leaving an operator to wonder why history is empty.
    fn attachable_path(&self) -> Option<PathBuf> {
        let log = self.log.as_ref()?;
        let path = log.path();
        if path.as_os_str() == ":memory:" {
            return None;
        }
        path.is_file().then(|| path.to_path_buf())
    }
}

impl BoweryTable for BoweryEventsTable {
    fn name(&self) -> &'static str {
        "bowery_events"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        let Some(path) = self.attachable_path() else {
            // Register the shape even with no data behind it, so a query
            // written against a recording host doesn't error out against
            // one that isn't recording — it just returns no rows.
            conn.execute_batch(EVENTS_EMPTY_DDL)?;
            return Ok(());
        };
        let uri = format!("file:{}?mode=ro", path.display());
        if let Err(e) = conn.execute("ATTACH DATABASE ?1 AS bowery_eventlog_db", params![uri]) {
            // Degrade to the empty shape rather than failing the whole
            // query: one unreadable history file must not take down
            // every other table in the same statement.
            warn!(error = %e, path = %path.display(), "event log attach failed; bowery_events will be empty");
            conn.execute_batch(EVENTS_EMPTY_DDL)?;
            return Ok(());
        }
        // A TEMP view, not a plain one: SQLite refuses to let a view in
        // `main` reference an attached database ("view ... cannot
        // reference objects in database ..."), and the `temp` schema is
        // the documented exemption. It also resolves first for an
        // unqualified `bowery_events`, which is how operators write it.
        conn.execute_batch(&format!(
            "CREATE TEMP VIEW IF NOT EXISTS bowery_events AS
             SELECT {EVENTS_COLUMNS} FROM bowery_eventlog_db.events;"
        ))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bowery_eventlog_status — coverage telemetry for the history itself.
// ---------------------------------------------------------------------------

/// `bowery_eventlog_status` — is this host actually recording?
///
/// A silent sensor is the EDR failure that matters most: an empty
/// `bowery_events` looks identical whether the host was quiet or stopped
/// recording an hour ago. This table makes the difference queryable, and
/// fleet-wide with `--fanout`:
///
/// ```sql
/// SELECT _agent_name, recording, queryable, dropped, newest_ts_unix_ms
/// FROM bowery_eventlog_status
/// ```
///
/// `dropped` is the count of events shed because the writer queue was
/// full — a non-zero value means the history has holes, and roughly
/// where.
#[derive(Debug)]
pub struct BoweryEventLogStatusTable {
    log: Option<Arc<bowery_eventlog::EventLog>>,
    dropped: Option<Arc<std::sync::atomic::AtomicU64>>,
    health: Option<Arc<crate::eventlog_writer::WriteHealth>>,
}

impl BoweryEventLogStatusTable {
    pub fn new(
        log: Option<Arc<bowery_eventlog::EventLog>>,
        dropped: Option<Arc<std::sync::atomic::AtomicU64>>,
    ) -> Self {
        Self {
            log,
            dropped,
            health: None,
        }
    }

    /// Attach write-failure reporting. Without it the view can say
    /// "recording" while every write is failing — which is exactly what
    /// happened, and exactly what this table exists to prevent.
    #[must_use]
    pub(crate) fn with_health(mut self, health: Arc<crate::eventlog_writer::WriteHealth>) -> Self {
        self.health = Some(health);
        self
    }
}

impl BoweryTable for BoweryEventLogStatusTable {
    fn name(&self) -> &'static str {
        "bowery_eventlog_status"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bowery_eventlog_status (
                recording          INTEGER,
                queryable          INTEGER,
                path               TEXT,
                rows               INTEGER,
                oldest_ts_unix_ms  INTEGER,
                newest_ts_unix_ms  INTEGER,
                highest_seq        INTEGER,
                dropped            INTEGER,
                write_failed       INTEGER,
                last_error         TEXT
            );",
        )?;

        let dropped = self
            .dropped
            .as_ref()
            .map_or(0, |d| d.load(std::sync::atomic::Ordering::Relaxed));
        let (write_failed, last_error) = self.health.as_ref().map_or((0, None), |h| {
            (
                h.failed.load(std::sync::atomic::Ordering::Relaxed),
                h.last_error.lock().ok().and_then(|g| g.clone()),
            )
        });

        let (recording, queryable, path, stats) = match &self.log {
            Some(log) => {
                let p = log.path().to_path_buf();
                // Queryable and recording are genuinely different: an
                // in-memory log records fine but no query connection can
                // reach it.
                let queryable = p.as_os_str() != ":memory:" && p.is_file();
                (true, queryable, p.display().to_string(), log.stats().ok())
            }
            None => (false, false, String::new(), None),
        };
        let stats = stats.unwrap_or_default();

        conn.execute(
            "INSERT INTO bowery_eventlog_status
                (recording, queryable, path, rows, oldest_ts_unix_ms,
                 newest_ts_unix_ms, highest_seq, dropped, write_failed, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                i64::from(recording),
                i64::from(queryable),
                path,
                i64::try_from(stats.rows).unwrap_or(i64::MAX),
                stats
                    .oldest_ts_unix_ms
                    .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                stats
                    .newest_ts_unix_ms
                    .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                i64::try_from(stats.highest_seq).unwrap_or(i64::MAX),
                i64::try_from(dropped).unwrap_or(i64::MAX),
                i64::try_from(write_failed).unwrap_or(i64::MAX),
                last_error,
            ],
        )?;
        Ok(())
    }
}
