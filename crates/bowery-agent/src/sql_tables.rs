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
//! questions a third-party query surface like sysquery can never
//! answer.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use bowery_baseline::Baseline;
use bowery_tables::{BoweryTable, TableError};
use bowery_whisper::known_neighbors::KnownNeighbors;
use rusqlite::{Connection, params};

use crate::inbox::AlertInbox;

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
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_baseline_binaries (sha256_hex, first_seen_unix, last_seen_unix, seen_count)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        // for_each_binary returns Result<()>; treat any internal error
        // as "stop walking" rather than failing the whole query —
        // baseline reads happen on a hot path and a corrupt row
        // shouldn't break unrelated queries.
        let _ = self.baseline.for_each_binary(|rec| {
            let sha_hex = hex_lower(&rec.sha256);
            let first = unix_secs(rec.first_seen);
            let last = unix_secs(rec.last_seen);
            let count = i64::try_from(rec.seen_count).unwrap_or(i64::MAX);
            // Best-effort: ignore per-row insert errors so one bad
            // row doesn't kill the table.
            let _ = stmt.execute(params![sha_hex, first, last, count]);
        });
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
                backend           TEXT
            );",
        )?;
        let (alerts, _) = self.inbox.read_since(0, usize::MAX);
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_alerts (originator_fp_hex, episode_id, exe_sha256_hex,
                                         exe_path, suspicion, rationale, ts_unix_ms, backend)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
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

impl BoweryTable for BoweryAuditTable {
    fn name(&self) -> &'static str {
        "bowery_audit"
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
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
        let Ok(contents) = std::fs::read_to_string(path) else {
            return Ok(());
        };
        let mut stmt = conn.prepare(
            "INSERT INTO bowery_audit (seq, ts_unix_ms, episode_id, action_id, outcome_kind)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for line in contents.lines() {
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
