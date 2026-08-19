//! Operator-side alert archive — the durable record of what the fleet
//! reported.
//!
//! # Why this exists, and why it is not on the agents
//!
//! An agent's inbox is a **bounded, in-memory ring with a 72-hour TTL**
//! that dies with the process. That is the right shape for a delivery
//! buffer and the wrong shape for a record: an alert older than three
//! days is gone, and so is every alert on a host that restarted.
//!
//! The security consequence is the one that decides where this lives.
//! An attacker who roots a monitored host can erase every alert *about
//! themselves* — not by defeating anything, but by waiting three days
//! or restarting a service. A record kept only on the machine it
//! accuses is a record that machine's owner can revoke. So the archive
//! is written on the operator's box, from alerts that already arrived
//! and verified over the signed operator transport.
//!
//! It is fed by whatever polls: the console while it is open, and
//! `bowery notify` on its timer — which already drained every agent in
//! the manifest and then threw the alerts away once the mail was sent.
//!
//! # What it does not claim
//!
//! Alerts are verified **at poll time**, by the operator transport,
//! against the agent's pinned key. The signature is not retained per
//! row, so this is the operator's own contemporaneous record and not a
//! re-verifiable chain of custody. Treating it as evidence against a
//! determined insider with access to this box would be overclaiming,
//! and the distinction matters enough to say out loud.
//!
//! # Every version is kept
//!
//! One episode legitimately produces several alerts: the pre-filter
//! raises one, the LLM refines it, a whisper quorum confirms it, and a
//! `file.access` corroboration can supersede it *downward*. The inbox
//! has no update path, so superseding is how a verdict changes.
//!
//! Consumers that want "the current verdict" collapse by episode — but
//! the archive keeps every version, because how a verdict moved is
//! usually the interesting part. "Raised at 0.9, downgraded to 0.3 when
//! four peers said they all do that" is a different story from "0.3",
//! and only one of them is recoverable if the archive stores the last
//! write. [`LATEST_VIEW`] does the collapsing for normal browsing.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bowery_proto::Alert;
use rusqlite::{Connection, OptionalExtension, params};

/// Default location, alongside the peer manifest and notify cursors.
///
/// # Errors
///
/// If the home directory cannot be determined.
pub fn default_path() -> Result<PathBuf> {
    let home =
        std::env::var_os("HOME").context("HOME is not set; pass an explicit archive path")?;
    Ok(PathBuf::from(home).join(".bowery").join("alerts.db"))
}

/// Collapses to the newest row per (agent, episode).
///
/// `MAX(ts_unix_ms)` picks the winner, matching the rule the inbox and
/// `bowery notify` already use: a later alert for an episode replaces
/// its predecessor.
///
/// **An empty `episode_id` is not an identity.** Alerts that carry one
/// are unrelated to each other, so grouping on it would collapse every
/// unkeyed alert an agent ever raised into a single row — silently, and
/// in the direction of showing an operator less than happened. They are
/// passed through untouched instead.
const LATEST_VIEW: &str = "CREATE VIEW IF NOT EXISTS alerts_latest AS
     SELECT * FROM alerts
     WHERE episode_id = ''
        OR (agent_fp, episode_id, ts_unix_ms) IN (
            SELECT agent_fp, episode_id, MAX(ts_unix_ms)
            FROM alerts WHERE episode_id <> ''
            GROUP BY agent_fp, episode_id
        )";

/// Selected in this order by [`Archive::query`]; [`Row::from_sql`]
/// reads them back by index, so the two must stay in step.
const SELECT_COLUMNS: &str = "agent_fp, agent_name, episode_id, ts_unix_ms, archived_ms, \
                              rule_id, suspicion, exe_path, exe_sha256, rationale, backend, \
                              confirmed, peers_asked, peers_unseen, peers_seen, \
                              peers_incomparable, peers_familiar, context_json";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS alerts (
    agent_fp        TEXT    NOT NULL,
    agent_name      TEXT,
    episode_id      TEXT    NOT NULL,
    ts_unix_ms      INTEGER NOT NULL,
    archived_ms     INTEGER NOT NULL,
    rule_id         TEXT,
    suspicion       REAL    NOT NULL,
    exe_path        TEXT,
    exe_sha256      TEXT,
    rationale       TEXT,
    backend         TEXT,
    confirmed       INTEGER,
    peers_asked     INTEGER,
    peers_unseen    INTEGER,
    peers_seen      INTEGER,
    peers_incomparable INTEGER,
    peers_familiar  INTEGER,
    peers_no_reply  INTEGER,
    peers_refused   INTEGER,
    quorum          INTEGER,
    context_json    TEXT    NOT NULL DEFAULT '{}',
    actions_json    TEXT    NOT NULL DEFAULT '[]',
    PRIMARY KEY (agent_fp, episode_id, ts_unix_ms)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS alerts_by_time  ON alerts (ts_unix_ms DESC);
CREATE INDEX IF NOT EXISTS alerts_by_rule  ON alerts (rule_id, ts_unix_ms DESC);
CREATE INDEX IF NOT EXISTS alerts_by_sha   ON alerts (exe_sha256);
";

/// A local `SQLite` file holding every alert this operator has seen.
#[derive(Debug)]
pub struct Archive {
    conn: Connection,
    path: PathBuf,
}

impl Archive {
    /// Open (creating if absent), and apply the schema.
    ///
    /// # Errors
    ///
    /// If the parent directory cannot be created, or `SQLite` refuses the
    /// file or the schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating archive directory {}", parent.display()))?;
        }
        let conn = Connection::open(&path)
            .with_context(|| format!("opening alert archive {}", path.display()))?;
        // WAL so a console reading and a notify run writing don't lock
        // each other out — the two are expected to overlap.
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("enabling WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .context("setting synchronous")?;
        conn.execute_batch(SCHEMA).context("applying schema")?;
        conn.execute_batch(LATEST_VIEW)
            .context("creating alerts_latest")?;
        Ok(Self { conn, path })
    }

    /// In-memory archive, for tests.
    ///
    /// # Errors
    ///
    /// If `SQLite` refuses the schema.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory archive")?;
        conn.execute_batch(SCHEMA).context("applying schema")?;
        conn.execute_batch(LATEST_VIEW)
            .context("creating alerts_latest")?;
        Ok(Self {
            conn,
            path: PathBuf::from(":memory:"),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Archive a batch, returning how many rows were newly stored.
    ///
    /// Idempotent: re-polling the same alerts (a reset cursor, an
    /// overlapping notify run, a console opened twice) must not
    /// duplicate or overwrite. `INSERT OR IGNORE` on the natural key is
    /// what makes it safe for every caller to archive everything it
    /// sees without coordinating.
    ///
    /// `agent_name` is resolved from the peer manifest at archive time
    /// and stored alongside the fingerprint, so renaming a host later
    /// does not rewrite what an old alert said it was.
    ///
    /// # Errors
    ///
    /// If the transaction cannot be prepared or committed.
    pub fn record(&mut self, alerts: &[Alert], agent_name: Option<&str>) -> Result<usize> {
        let now = now_unix_ms();
        let tx = self.conn.transaction().context("beginning archive write")?;
        let mut stored = 0usize;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT OR IGNORE INTO alerts (
                        agent_fp, agent_name, episode_id, ts_unix_ms, archived_ms,
                        rule_id, suspicion, exe_path, exe_sha256, rationale, backend,
                        confirmed, peers_asked, peers_unseen, peers_seen,
                        peers_no_reply, peers_refused, peers_incomparable, peers_familiar,
                        quorum, context_json, actions_json
                     ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
                )
                .context("preparing archive insert")?;
            for a in alerts {
                let c = a.confirmation;
                stored += stmt
                    .execute(params![
                        hex_lower(&a.originator_fp),
                        agent_name,
                        a.episode_id,
                        a.ts_unix_ms,
                        now,
                        empty_to_null(&a.rule_id),
                        f64::from(a.suspicion),
                        empty_to_null(&a.exe_path),
                        empty_to_null(&a.exe_sha256_hex),
                        empty_to_null(&a.rationale),
                        empty_to_null(&a.backend),
                        c.map(|c| i64::from(c.confirmed)),
                        c.map(|c| c.peers_asked),
                        c.map(|c| c.peers_unseen),
                        c.map(|c| c.peers_seen),
                        c.map(|c| c.peers_no_reply),
                        c.map(|c| c.peers_refused),
                        c.map(|c| c.peers_incomparable),
                        c.map(|c| c.peers_familiar),
                        c.map(|c| c.quorum),
                        context_json(a),
                        actions_json(a),
                    ])
                    .context("inserting alert")?;
            }
        }
        tx.commit().context("committing archive write")?;
        Ok(stored)
    }

    /// Rows matching `filter`, newest first.
    ///
    /// # Errors
    ///
    /// If the query fails.
    pub fn query(&self, filter: &Filter) -> Result<Vec<Row>> {
        let source = if filter.all_versions {
            "alerts"
        } else {
            "alerts_latest"
        };
        let mut sql = format!("SELECT {SELECT_COLUMNS} FROM {source} WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(since) = filter.since_unix_ms {
            sql.push_str(" AND ts_unix_ms >= ?");
            args.push(Box::new(since));
        }
        if let Some(until) = filter.until_unix_ms {
            sql.push_str(" AND ts_unix_ms <= ?");
            args.push(Box::new(until));
        }
        if let Some(min) = filter.min_suspicion {
            sql.push_str(" AND suspicion >= ?");
            args.push(Box::new(min));
        }
        if let Some(rule) = &filter.rule_id {
            sql.push_str(" AND rule_id = ?");
            args.push(Box::new(rule.clone()));
        }
        if let Some(agent) = &filter.agent {
            sql.push_str(" AND (agent_fp = ? OR agent_name = ?)");
            args.push(Box::new(agent.clone()));
            args.push(Box::new(agent.clone()));
        }
        if filter.confirmed_only {
            sql.push_str(" AND confirmed = 1");
        }
        // Free-text across the fields an operator actually recalls a
        // finding by. The rationale is in there because a week later it
        // is remembered as "that thing about the watchdog", not by rule
        // id or episode hash.
        if let Some(text) = &filter.text {
            const COLUMNS: [&str; 6] = [
                "exe_path",
                "rationale",
                "rule_id",
                "episode_id",
                "exe_sha256",
                "context_json",
            ];
            let clause = COLUMNS
                .iter()
                .map(|c| format!("{c} LIKE ? ESCAPE '\\'"))
                .collect::<Vec<_>>()
                .join(" OR ");
            let _ = write!(sql, " AND ({clause})");
            let pattern = format!("%{}%", escape_like(text));
            for _ in 0..COLUMNS.len() {
                args.push(Box::new(pattern.clone()));
            }
        }

        sql.push_str(" ORDER BY ts_unix_ms DESC LIMIT ?");
        args.push(Box::new(i64::try_from(filter.limit).unwrap_or(i64::MAX)));

        let params: Vec<&dyn rusqlite::ToSql> =
            args.iter().map(std::convert::AsRef::as_ref).collect();
        let mut stmt = self.conn.prepare(&sql).context("preparing archive query")?;
        let rows = stmt
            .query_map(params.as_slice(), Row::from_sql)
            .context("running archive query")?
            .collect::<Result<Vec<_>, _>>()
            .context("reading archive rows")?;
        Ok(rows)
    }

    /// Newest archived alert timestamp for an agent, or 0.
    ///
    /// Lets a poller resume where it left off instead of re-fetching a
    /// whole retention window on every start.
    ///
    /// # Errors
    ///
    /// If the query fails.
    pub fn cursor_for(&self, agent_fp_hex: &str) -> Result<u64> {
        let ts: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(ts_unix_ms) FROM alerts WHERE agent_fp = ?1",
                params![agent_fp_hex.to_ascii_lowercase()],
                |r| r.get(0),
            )
            .optional()
            .context("reading archive cursor")?
            .flatten();
        Ok(ts.unwrap_or(0).try_into().unwrap_or(0))
    }

    /// Total rows and distinct episodes.
    ///
    /// # Errors
    ///
    /// If the query fails.
    pub fn stats(&self) -> Result<Stats> {
        let (rows, episodes, agents, oldest, newest) = self
            .conn
            .query_row(
                "SELECT COUNT(*), COUNT(DISTINCT episode_id), COUNT(DISTINCT agent_fp), \
                 COALESCE(MIN(ts_unix_ms),0), COALESCE(MAX(ts_unix_ms),0) FROM alerts",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .context("reading archive stats")?;
        Ok(Stats {
            rows,
            episodes,
            agents,
            oldest_unix_ms: oldest,
            newest_unix_ms: newest,
        })
    }

    /// Drop rows older than `before_unix_ms`, returning how many went.
    ///
    /// Never called automatically. The archive exists precisely because
    /// the agent-side store forgets; adding a second silent forgetting
    /// would defeat it. An operator who wants a bound asks for one.
    ///
    /// # Errors
    ///
    /// If the delete fails.
    pub fn prune(&self, before_unix_ms: u64) -> Result<usize> {
        let n = self
            .conn
            .execute(
                "DELETE FROM alerts WHERE ts_unix_ms < ?1",
                params![before_unix_ms],
            )
            .context("pruning archive")?;
        Ok(n)
    }
}

/// What to select. All fields are AND-ed; `None` means "no constraint".
#[derive(Debug, Clone)]
pub struct Filter {
    pub since_unix_ms: Option<u64>,
    pub until_unix_ms: Option<u64>,
    pub min_suspicion: Option<f64>,
    pub rule_id: Option<String>,
    /// Fingerprint hex or operator-assigned name.
    pub agent: Option<String>,
    pub confirmed_only: bool,
    /// Substring across path, rationale, rule, episode, hash, context.
    pub text: Option<String>,
    /// Keep superseded versions instead of collapsing per episode.
    pub all_versions: bool,
    pub limit: usize,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            since_unix_ms: None,
            until_unix_ms: None,
            min_suspicion: None,
            rule_id: None,
            agent: None,
            confirmed_only: false,
            text: None,
            all_versions: false,
            limit: 500,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub agent_fp: String,
    pub agent_name: Option<String>,
    pub episode_id: String,
    pub ts_unix_ms: u64,
    pub archived_ms: u64,
    pub rule_id: Option<String>,
    pub suspicion: f64,
    pub exe_path: Option<String>,
    pub exe_sha256: Option<String>,
    pub rationale: Option<String>,
    pub backend: Option<String>,
    pub confirmed: Option<bool>,
    pub peers_asked: Option<u32>,
    pub peers_unseen: Option<u32>,
    pub peers_seen: Option<u32>,
    /// Peers that answered but could not be compared against. `NULL`
    /// from a row archived before the field existed — which is not the
    /// same as zero, and the distinction is the point of the field.
    pub peers_incomparable: Option<u32>,
    /// Peers that had the same program at a different build. `NULL`
    /// from a row archived before the field existed.
    pub peers_familiar: Option<u32>,
    pub context_json: String,
}

impl Row {
    fn from_sql(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            agent_fp: r.get(0)?,
            agent_name: r.get(1)?,
            episode_id: r.get(2)?,
            ts_unix_ms: r.get::<_, i64>(3)?.try_into().unwrap_or(0),
            archived_ms: r.get::<_, i64>(4)?.try_into().unwrap_or(0),
            rule_id: r.get(5)?,
            suspicion: r.get(6)?,
            exe_path: r.get(7)?,
            exe_sha256: r.get(8)?,
            rationale: r.get(9)?,
            backend: r.get(10)?,
            confirmed: r.get::<_, Option<i64>>(11)?.map(|v| v != 0),
            peers_asked: opt_u32(r, 12)?,
            peers_unseen: opt_u32(r, 13)?,
            peers_seen: opt_u32(r, 14)?,
            peers_incomparable: opt_u32(r, 15)?,
            peers_familiar: opt_u32(r, 16)?,
            context_json: r.get(17)?,
        })
    }

    /// Rebuild the `Alert` this row was archived from.
    ///
    /// Lossy in one direction only: `suggested_actions` is not selected
    /// back (nothing renders it), and the fingerprint is re-derived from
    /// hex. Everything an operator acts on — episode, rule, hash, path,
    /// score, confirmation counts, context — round-trips, which is what
    /// lets archived history reuse the same rendering, pivots and
    /// silence flow as a live alert instead of a parallel set.
    #[must_use]
    pub fn to_alert(&self) -> Alert {
        Alert {
            originator_fp: hex_decode(&self.agent_fp),
            rule_id: self.rule_id.clone().unwrap_or_default(),
            episode_id: self.episode_id.clone(),
            exe_sha256_hex: self.exe_sha256.clone().unwrap_or_default(),
            exe_path: self.exe_path.clone().unwrap_or_default(),
            #[allow(clippy::cast_possible_truncation)]
            suspicion: self.suspicion as f32,
            rationale: self.rationale.clone().unwrap_or_default(),
            suggested_actions: Vec::new(),
            ts_unix_ms: self.ts_unix_ms,
            backend: self.backend.clone().unwrap_or_default(),
            confirmation: self
                .confirmed
                .map(|confirmed| bowery_proto::AlertConfirmation {
                    peers_asked: self.peers_asked.unwrap_or(0),
                    peers_unseen: self.peers_unseen.unwrap_or(0),
                    peers_seen: self.peers_seen.unwrap_or(0),
                    peers_no_reply: 0,
                    peers_refused: 0,
                    peers_incomparable: self.peers_incomparable.unwrap_or(0),
                    peers_familiar: self.peers_familiar.unwrap_or(0),
                    quorum: 0,
                    confirmed,
                }),
            context: parse_context(&self.context_json),
        }
    }

    /// The operator-assigned name when known, else a short fingerprint.
    #[must_use]
    pub fn agent_label(&self) -> String {
        self.agent_name
            .clone()
            .unwrap_or_else(|| self.agent_fp.chars().take(12).collect::<String>())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub rows: u64,
    pub episodes: u64,
    pub agents: u64,
    pub oldest_unix_ms: u64,
    pub newest_unix_ms: u64,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A nullable count, widened from `SQLite`'s only integer type.
fn opt_u32(r: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Option<u32>> {
    Ok(r.get::<_, Option<i64>>(idx)?
        .map(|v| u32::try_from(v).unwrap_or(0)))
}

/// Neutralise `LIKE` metacharacters so a search term is taken
/// literally.
///
/// Without this, a rationale search for `100%` becomes "100 followed by
/// anything" and an operator searching for `_` matches every row. That
/// is a silent widening in a box whose entire job is narrowing — the
/// wrong direction to fail in when the question is "did this happen".
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn empty_to_null(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// Parse an even-length lowercase hex string back to bytes. A row that
/// somehow holds a malformed fingerprint yields an empty vec rather
/// than failing the whole view — the alert is still worth showing.
fn hex_decode(s: &str) -> Vec<u8> {
    if !s.len().is_multiple_of(2) {
        return Vec::new();
    }
    let bytes: Option<Vec<u8>> = s
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect();
    bytes.unwrap_or_default()
}

/// Context attributes back out of the stored JSON object.
fn parse_context(json: &str) -> Vec<bowery_proto::Attribute> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    map.into_iter()
        .map(|(key, value)| bowery_proto::Attribute {
            key,
            value: value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_string),
        })
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Context attributes as a JSON object. Hand-rolled to avoid pulling a
/// serialiser in for two string fields; values are escaped for JSON,
/// which is the only structure they could otherwise forge.
fn context_json(a: &Alert) -> String {
    let mut out = String::from("{");
    for (i, attr) in a.context.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{}:{}",
            json_string(&attr.key),
            json_string(&attr.value)
        );
    }
    out.push('}');
    out
}

fn actions_json(a: &Alert) -> String {
    let mut out = String::from("[");
    for (i, s) in a.suggested_actions.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&json_string(s));
    }
    out.push(']');
    out
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_proto::{AlertConfirmation, Attribute};

    fn alert(fp: u8, episode: &str, ts: u64, suspicion: f32) -> Alert {
        Alert {
            originator_fp: vec![fp; 32],
            rule_id: "cred.read_netrc".into(),
            episode_id: episode.into(),
            exe_sha256_hex: "ab".repeat(32),
            exe_path: "/tmp/payload".into(),
            suspicion,
            rationale: "exec from world-writable path".into(),
            suggested_actions: vec!["isolate".into()],
            ts_unix_ms: ts,
            backend: "test".into(),
            confirmation: None,
            context: vec![Attribute {
                key: "argv".into(),
                value: "./payload --quiet".into(),
            }],
        }
    }

    /// Every poller archives everything it sees, on purpose — the
    /// console and `bowery notify` overlap, and a cursor resets whenever
    /// either restarts. That is only safe if re-recording is a no-op.
    #[test]
    fn recording_the_same_alert_twice_stores_it_once() {
        let mut a = Archive::open_in_memory().unwrap();
        let batch = vec![alert(1, "ep-1", 1000, 0.9)];
        assert_eq!(a.record(&batch, Some("otter1")).unwrap(), 1);
        assert_eq!(
            a.record(&batch, Some("otter1")).unwrap(),
            0,
            "second is a no-op"
        );
        assert_eq!(a.stats().unwrap().rows, 1);
    }

    /// An episode's verdict moves: the pre-filter raises it, the LLM
    /// refines it, a quorum confirms it, corroboration can downgrade it.
    /// The archive keeps every step; the default view shows the last.
    #[test]
    fn superseding_alerts_are_kept_but_collapse_by_default() {
        let mut a = Archive::open_in_memory().unwrap();
        a.record(
            &[
                alert(1, "ep-1", 1000, 0.9),
                alert(1, "ep-1", 2000, 0.3), // mesh said everyone does that
            ],
            Some("otter1"),
        )
        .unwrap();

        let latest = a.query(&Filter::default()).unwrap();
        assert_eq!(latest.len(), 1, "collapsed to one row per episode");
        assert!(
            (latest[0].suspicion - 0.3).abs() < 1e-6,
            "the newest verdict wins, got {}",
            latest[0].suspicion
        );

        let all = a
            .query(&Filter {
                all_versions: true,
                ..Filter::default()
            })
            .unwrap();
        assert_eq!(all.len(), 2, "the downgrade's history must survive");
        assert!(
            (all[1].suspicion - 0.9).abs() < 1e-6,
            "the original 0.9 is what makes the downgrade legible"
        );
    }

    /// The collapse keys on episode id, and an alert can arrive
    /// without one. Grouping those together would fold every unkeyed
    /// alert from a host into one row — a silent, unbounded loss in the
    /// direction of showing less than happened.
    #[test]
    fn alerts_without_an_episode_id_never_collapse_together() {
        let mut a = Archive::open_in_memory().unwrap();
        let mut first = alert(1, "", 1000, 0.7);
        first.exe_path = "/usr/bin/first".into();
        let mut second = alert(1, "", 2000, 0.8);
        second.exe_path = "/usr/bin/second".into();
        let mut third = alert(1, "", 3000, 0.9);
        third.exe_path = "/usr/bin/third".into();
        a.record(&[first, second, third], Some("otter1")).unwrap();

        let rows = a.query(&Filter::default()).unwrap();
        assert_eq!(
            rows.len(),
            3,
            "unkeyed alerts are not versions of each other"
        );
        // And keyed alerts must still collapse alongside them.
        a.record(
            &[alert(1, "ep-1", 4000, 0.5), alert(1, "ep-1", 5000, 0.6)],
            Some("otter1"),
        )
        .unwrap();
        assert_eq!(a.query(&Filter::default()).unwrap().len(), 4);
    }

    /// Two hosts can produce the same episode id; the fingerprint is
    /// half the key, so one must not evict the other.
    #[test]
    fn the_same_episode_id_on_two_agents_is_two_alerts() {
        let mut a = Archive::open_in_memory().unwrap();
        a.record(&[alert(1, "ep-collide", 1000, 0.9)], Some("otter1"))
            .unwrap();
        a.record(&[alert(2, "ep-collide", 1000, 0.5)], Some("legolas"))
            .unwrap();
        assert_eq!(a.stats().unwrap().rows, 2);
        assert_eq!(a.stats().unwrap().agents, 2);
    }

    #[test]
    fn filters_narrow_by_rule_agent_score_and_time() {
        let mut a = Archive::open_in_memory().unwrap();
        let mut low = alert(1, "ep-low", 1000, 0.2);
        low.rule_id = "net.beacon".into();
        let mut high = alert(2, "ep-high", 5000, 0.95);
        high.rule_id = "cred.read_aws".into();
        a.record(&[low], Some("otter1")).unwrap();
        a.record(&[high], Some("legolas")).unwrap();

        let by_rule = a
            .query(&Filter {
                rule_id: Some("cred.read_aws".into()),
                ..Filter::default()
            })
            .unwrap();
        assert_eq!(by_rule.len(), 1);
        assert_eq!(by_rule[0].episode_id, "ep-high");

        // An agent is addressable by the name an operator gave it, not
        // just by 64 hex characters nobody remembers.
        let by_name = a
            .query(&Filter {
                agent: Some("legolas".into()),
                ..Filter::default()
            })
            .unwrap();
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].agent_label(), "legolas");

        let by_score = a
            .query(&Filter {
                min_suspicion: Some(0.5),
                ..Filter::default()
            })
            .unwrap();
        assert_eq!(by_score.len(), 1);

        let by_time = a
            .query(&Filter {
                since_unix_ms: Some(2000),
                ..Filter::default()
            })
            .unwrap();
        assert_eq!(by_time.len(), 1);
        assert_eq!(by_time[0].episode_id, "ep-high");
    }

    /// A week later a finding is remembered as "that thing about the
    /// watchdog", not by rule id — so search has to reach the prose.
    #[test]
    fn free_text_search_reaches_rationale_path_and_context() {
        let mut a = Archive::open_in_memory().unwrap();
        let mut w = alert(1, "ep-w", 1000, 0.8);
        w.rationale = "write-intent open of /dev/watchdog0 disarms the reboot".into();
        w.exe_path = "/usr/bin/dd".into();
        a.record(&[w], Some("otter1")).unwrap();
        a.record(&[alert(1, "ep-other", 2000, 0.8)], Some("otter1"))
            .unwrap();

        for needle in ["watchdog", "/usr/bin/dd", "--quiet"] {
            let hits = a
                .query(&Filter {
                    text: Some(needle.into()),
                    ..Filter::default()
                })
                .unwrap();
            assert!(!hits.is_empty(), "{needle:?} found nothing");
        }
        // `--quiet` lives only in a context attribute, and only on the
        // other alert, so it must not match the watchdog one.
        let ctx = a
            .query(&Filter {
                text: Some("watchdog".into()),
                ..Filter::default()
            })
            .unwrap();
        assert_eq!(ctx.len(), 1, "search must narrow, not match everything");
    }

    /// Search is a narrowing tool. `%` and `_` are `LIKE` wildcards, so
    /// without escaping, a term like `100%` quietly matches far more
    /// than it should and a bare `_` matches everything — failing in
    /// the one direction a search box must not.
    #[test]
    fn a_wildcard_in_a_search_term_is_taken_literally() {
        let mut a = Archive::open_in_memory().unwrap();
        let mut odd = alert(1, "ep-1", 1000, 0.8);
        odd.rationale = "cpu at 100% sustained".into();
        a.record(&[odd], Some("otter1")).unwrap();
        let mut plain = alert(1, "ep-2", 2000, 0.8);
        plain.rationale = "cpu at 1004 sustained".into();
        a.record(&[plain], Some("otter1")).unwrap();

        let hits = a
            .query(&Filter {
                text: Some("100%".into()),
                ..Filter::default()
            })
            .unwrap();
        assert_eq!(hits.len(), 1, "the % must match a literal %, not anything");
        assert_eq!(hits[0].episode_id, "ep-1");

        // `_` is LIKE's single-character wildcard: unescaped, `1_04`
        // matches the literal `1004` in the other row. Escaped, it
        // matches only a real underscore, and there is none here.
        let underscore = a
            .query(&Filter {
                text: Some("1_04".into()),
                ..Filter::default()
            })
            .unwrap();
        assert!(
            underscore.is_empty(),
            "_ matched {} row(s) as a wildcard",
            underscore.len()
        );

        // The value is bound, not interpolated, so a quote is data.
        let quoted = a
            .query(&Filter {
                text: Some("' OR 1=1 --".into()),
                ..Filter::default()
            })
            .unwrap();
        assert!(quoted.is_empty(), "a quote must be data, not syntax");
    }

    #[test]
    fn a_cursor_resumes_per_agent_and_is_zero_when_unknown() {
        let mut a = Archive::open_in_memory().unwrap();
        a.record(
            &[alert(1, "ep-1", 1000, 0.9), alert(1, "ep-2", 7000, 0.9)],
            Some("otter1"),
        )
        .unwrap();
        a.record(&[alert(2, "ep-3", 3000, 0.9)], Some("legolas"))
            .unwrap();

        assert_eq!(a.cursor_for(&"01".repeat(32)).unwrap(), 7000);
        assert_eq!(a.cursor_for(&"02".repeat(32)).unwrap(), 3000);
        assert_eq!(a.cursor_for(&"ff".repeat(32)).unwrap(), 0, "unknown agent");
    }

    /// Context values are attacker-influenced and land in a JSON blob a
    /// consumer will parse. A quote in an argv must not forge structure.
    #[test]
    fn context_json_escapes_what_the_host_controls() {
        let mut a = Archive::open_in_memory().unwrap();
        let mut hostile = alert(1, "ep-1", 1000, 0.9);
        hostile.context = vec![Attribute {
            key: "argv".into(),
            value: "sh -c \"echo\\\" \n\t hi".into(),
        }];
        a.record(&[hostile], Some("otter1")).unwrap();
        let row = &a.query(&Filter::default()).unwrap()[0];
        assert!(!row.context_json.contains('\n'), "raw newline in JSON");
        assert!(row.context_json.contains("\\n"), "newline must be escaped");
        assert!(row.context_json.contains("\\\""), "quote must be escaped");
        let parsed: serde_json::Value =
            serde_json::from_str(&row.context_json).expect("context must be valid JSON");
        assert_eq!(parsed["argv"], "sh -c \"echo\\\" \n\t hi");
    }

    #[test]
    fn confirmation_counts_survive_the_round_trip() {
        let mut a = Archive::open_in_memory().unwrap();
        let mut c = alert(1, "ep-1", 1000, 0.9);
        c.confirmation = Some(AlertConfirmation {
            peers_asked: 5,
            peers_unseen: 4,
            peers_seen: 1,
            peers_no_reply: 0,
            peers_refused: 0,
            peers_incomparable: 0,
            peers_familiar: 0,
            quorum: 2,
            confirmed: true,
        });
        a.record(&[c], Some("otter1")).unwrap();
        let row = &a.query(&Filter::default()).unwrap()[0];
        assert_eq!(row.confirmed, Some(true));
        assert_eq!(row.peers_unseen, Some(4));
        assert_eq!(row.peers_seen, Some(1));

        let only_confirmed = a
            .query(&Filter {
                confirmed_only: true,
                ..Filter::default()
            })
            .unwrap();
        assert_eq!(only_confirmed.len(), 1);
    }

    /// An alert with no whisper round must read as "no round ran", not
    /// as "the round found nothing" — the distinction the whole quorum
    /// design turns on.
    #[test]
    fn an_unasked_alert_records_null_not_zero() {
        let mut a = Archive::open_in_memory().unwrap();
        a.record(&[alert(1, "ep-1", 1000, 0.9)], Some("otter1"))
            .unwrap();
        let row = &a.query(&Filter::default()).unwrap()[0];
        assert_eq!(row.confirmed, None, "must not read as 'not confirmed'");
        assert_eq!(row.peers_asked, None);

        // And such an alert must not be swept up by a confirmed filter.
        assert!(
            a.query(&Filter {
                confirmed_only: true,
                ..Filter::default()
            })
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn an_archive_survives_reopening_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("alerts.db");
        {
            let mut a = Archive::open(&path).unwrap();
            a.record(&[alert(1, "ep-1", 1000, 0.9)], Some("otter1"))
                .unwrap();
        }
        let reopened = Archive::open(&path).unwrap();
        assert_eq!(reopened.stats().unwrap().rows, 1, "durability is the point");
    }

    #[test]
    fn prune_drops_only_what_is_older() {
        let mut a = Archive::open_in_memory().unwrap();
        a.record(
            &[alert(1, "ep-old", 1000, 0.9), alert(1, "ep-new", 9000, 0.9)],
            Some("otter1"),
        )
        .unwrap();
        assert_eq!(a.prune(5000).unwrap(), 1);
        let left = a.query(&Filter::default()).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].episode_id, "ep-new");
    }
}

// ---------------------------------------------------------------------------
// `bowery alerts history` rendering
// ---------------------------------------------------------------------------

/// Everything `bowery alerts history` was asked for.
///
/// The bool count is the shape of the command line, not a state
/// machine — each is an independent flag the operator either passed or
/// did not.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct HistoryArgs {
    pub path: PathBuf,
    pub query: Option<String>,
    pub min_suspicion: Option<f64>,
    pub rule: Option<String>,
    pub agent: Option<String>,
    pub confirmed: bool,
    pub since: Option<std::time::Duration>,
    pub all_versions: bool,
    pub limit: usize,
    pub json: bool,
    pub stats: bool,
}

impl HistoryArgs {
    #[must_use]
    pub fn filter(&self) -> Filter {
        Filter {
            since_unix_ms: self.since.map(|d| {
                let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
                now_unix_ms().saturating_sub(ms)
            }),
            until_unix_ms: None,
            min_suspicion: self.min_suspicion,
            rule_id: self.rule.clone(),
            agent: self.agent.clone(),
            confirmed_only: self.confirmed,
            text: self.query.clone(),
            all_versions: self.all_versions,
            limit: self.limit,
        }
    }
}

/// `2026-08-19 01:25:01Z`, or the raw value if it is not a sane time.
#[must_use]
pub fn format_ts(ms: u64) -> String {
    let secs = i64::try_from(ms / 1000).unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(secs).map_or_else(
        |_| ms.to_string(),
        |t| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            )
        },
    )
}

/// One row per line, or one JSON object per line.
#[must_use]
pub fn render(rows: &[Row], json: bool) -> String {
    let mut out = String::new();
    for r in rows {
        if json {
            let _ = writeln!(
                out,
                "{{\"ts_unix_ms\":{},\"archived_ms\":{},\"agent\":{},\"agent_fp\":{},\
                 \"episode_id\":{},\"rule_id\":{},\"suspicion\":{:.4},\"exe_path\":{},\
                 \"exe_sha256\":{},\"confirmed\":{},\"peers_unseen\":{},\"peers_asked\":{},\
                 \"peers_incomparable\":{},\"rationale\":{},\"context\":{}}}",
                r.ts_unix_ms,
                r.archived_ms,
                json_string(&r.agent_label()),
                json_string(&r.agent_fp),
                json_string(&r.episode_id),
                r.rule_id.as_deref().map_or("null".into(), json_string),
                r.suspicion,
                r.exe_path.as_deref().map_or("null".into(), json_string),
                r.exe_sha256.as_deref().map_or("null".into(), json_string),
                r.confirmed.map_or("null".into(), |c| c.to_string()),
                r.peers_unseen.map_or("null".into(), |v| v.to_string()),
                r.peers_asked.map_or("null".into(), |v| v.to_string()),
                r.peers_incomparable
                    .map_or("null".into(), |v| v.to_string()),
                r.rationale.as_deref().map_or("null".into(), json_string),
                r.context_json,
            );
        } else {
            // The confirmation marker distinguishes three states, not
            // two: confirmed, asked-and-not-confirmed, and never asked.
            // A blank where "no round ran" belongs would read as a
            // negative verdict.
            // Four states, not three. `?` is a round that ran and could
            // compare nothing — distinct from one that compared and
            // found nothing, which is what `·` means.
            let conf = match (r.confirmed, r.peers_unseen, r.peers_asked) {
                (Some(true), Some(u), Some(t)) => format!("✓{u}/{t}"),
                (Some(false), Some(0), Some(t)) if r.peers_incomparable.is_some_and(|n| n > 0) => {
                    format!("?0/{t}")
                }
                (Some(false), Some(u), Some(t)) => format!("·{u}/{t}"),
                _ => String::new(),
            };
            let _ = writeln!(
                out,
                "{ts}  {sus:>4.2}  {conf:<6}  {agent:<12}  {rule:<32}  {ep}",
                ts = format_ts(r.ts_unix_ms),
                sus = r.suspicion,
                agent = truncate(&r.agent_label(), 12),
                rule = truncate(r.rule_id.as_deref().unwrap_or("-"), 32),
                ep = r.episode_id,
            );
            if let Some(p) = &r.exe_path {
                let _ = writeln!(out, "    exe  {p}");
            }
            if let Some(w) = &r.rationale {
                let _ = writeln!(out, "    why  {w}");
            }
        }
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    s.chars().take(n.saturating_sub(1)).chain(['…']).collect()
}

/// Human summary of what the archive covers.
///
/// Printed with `--stats`, and on an empty result — because "no rows"
/// and "nothing is being archived" look identical otherwise, and the
/// difference is whether the operator has a monitoring gap.
#[must_use]
pub fn render_stats(s: &Stats, path: &Path) -> String {
    if s.rows == 0 {
        return format!(
            "archive {} is empty.\nIt fills as `bowery notify` or the console polls; \
             if neither has run, there is nothing recorded yet — which is not the same \
             as nothing having happened.\n",
            path.display()
        );
    }
    format!(
        "archive  {}\nrows     {} ({} episode(s) across {} agent(s))\ncovering {} .. {}\n",
        path.display(),
        s.rows,
        s.episodes,
        s.agents,
        format_ts(s.oldest_unix_ms),
        format_ts(s.newest_unix_ms),
    )
}

#[cfg(test)]
mod roundtrip_tests {
    use super::*;
    use bowery_proto::{AlertConfirmation, Attribute};

    /// Archived history reuses the live alert rendering, pivots and
    /// silence flow, so a row has to come back as the alert it was.
    #[test]
    fn an_alert_survives_the_archive_round_trip() {
        let original = Alert {
            originator_fp: vec![0x3a; 32],
            rule_id: "cred.read_aws".into(),
            episode_id: "ep-7f3a91".into(),
            exe_sha256_hex: "9f".repeat(32),
            exe_path: "/tmp/.x/harvest".into(),
            suspicion: 0.92,
            rationale: "read ~/.aws/credentials".into(),
            suggested_actions: vec![],
            ts_unix_ms: 1_755_400_000_000,
            backend: "llama-cpp/qwen3-0.6b".into(),
            confirmation: Some(AlertConfirmation {
                peers_asked: 3,
                peers_unseen: 3,
                peers_seen: 0,
                peers_no_reply: 0,
                peers_refused: 0,
                peers_incomparable: 0,
                peers_familiar: 0,
                quorum: 2,
                confirmed: true,
            }),
            context: vec![Attribute {
                key: "argv".into(),
                value: "./harvest --quiet".into(),
            }],
        };
        let mut a = Archive::open_in_memory().unwrap();
        a.record(std::slice::from_ref(&original), Some("otter1"))
            .unwrap();
        let back = a.query(&Filter::default()).unwrap()[0].to_alert();

        assert_eq!(back.originator_fp, original.originator_fp, "fingerprint");
        assert_eq!(back.episode_id, original.episode_id);
        assert_eq!(back.rule_id, original.rule_id);
        assert_eq!(back.exe_path, original.exe_path);
        assert_eq!(back.exe_sha256_hex, original.exe_sha256_hex);
        assert_eq!(back.rationale, original.rationale);
        assert_eq!(back.ts_unix_ms, original.ts_unix_ms);
        assert!((back.suspicion - original.suspicion).abs() < 1e-6);
        assert_eq!(back.context, original.context, "context attributes");
        let c = back.confirmation.expect("confirmation");
        assert!(c.confirmed);
        assert_eq!(c.peers_unseen, 3);
    }

    /// The pivots key off these fields, and an empty one silently
    /// disables a pivot rather than erroring.
    #[test]
    fn a_sparse_alert_round_trips_without_inventing_fields() {
        let sparse = Alert {
            originator_fp: vec![0x01; 32],
            episode_id: "ep-bare".into(),
            suspicion: 0.4,
            ts_unix_ms: 1000,
            ..Default::default()
        };
        let mut a = Archive::open_in_memory().unwrap();
        a.record(&[sparse], None).unwrap();
        let back = a.query(&Filter::default()).unwrap()[0].to_alert();
        assert_eq!(back.exe_path, "");
        assert_eq!(back.rule_id, "");
        assert_eq!(back.exe_sha256_hex, "");
        assert!(back.context.is_empty());
        assert!(
            back.confirmation.is_none(),
            "no round ran, not 'not confirmed'"
        );
    }

    /// An agent with no manifest entry must still be attributable.
    #[test]
    fn an_unnamed_agent_falls_back_to_a_short_fingerprint() {
        let mut a = Archive::open_in_memory().unwrap();
        a.record(
            &[Alert {
                originator_fp: vec![0xab; 32],
                episode_id: "ep-1".into(),
                ts_unix_ms: 1,
                ..Default::default()
            }],
            None,
        )
        .unwrap();
        let row = &a.query(&Filter::default()).unwrap()[0];
        assert_eq!(row.agent_label(), "abababababab");
    }
}
