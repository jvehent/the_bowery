//! Append-only per-agent event log — the local history behind
//! "what happened on this host between 14:20 and 14:40?".
//!
//! The baseline ([`bowery_baseline`]) stores *aggregates*: how many
//! times a sha has been seen, which parent spawned which child. That
//! answers "is this normal here?" but cannot reconstruct a timeline,
//! because the individual observations are folded away on write. This
//! store keeps the observations themselves.
//!
//! # Append-only, with a policy pruner
//!
//! The recording path only ever `INSERT`s — nothing updates or deletes a
//! row that has been written. The single exception is [`EventLog::prune`],
//! which drops the *oldest* rows to honour the retention policy. That is
//! a deliberate distinction: an operator can trust that a row they read
//! was never edited, while disk stays bounded. It is not tamper-proof
//! against a root-level attacker on the host — `seq` is monotonic so a
//! deletion is detectable as a gap, and making that evidence durable
//! means witnessing the chain off-box (see `DESIGN.md`).
//!
//! # Why its own `SQLite` file
//!
//! Separate from the baseline because the two have opposite profiles:
//! the baseline is small, hot, and read on every exec; the event log is
//! large, write-heavy, and read only during an investigation. Splitting
//! them keeps event-write volume from thrashing the baseline's page
//! cache, lets retention differ, and — most usefully — lets the SQL
//! surface `ATTACH` this file read-only and query it with real indexes
//! instead of copying it row by row.
//!
//! # Schema shape
//!
//! One wide table rather than a table per event kind. A timeline query
//! is the dominant access pattern (`WHERE ts_unix_ms BETWEEN ? AND ?
//! ORDER BY seq`), and that is a single scan over one table with one
//! index instead of a five-way `UNION ALL`. The cost is NULL columns for
//! fields that don't apply to a kind, which `SQLite` stores in ~1 byte
//! each.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use bowery_events::{Event, FileOp, NetFamily};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

/// `seq` is `INTEGER PRIMARY KEY AUTOINCREMENT` — monotonic across the
/// life of the file and never reused, even after pruning, so a gap in
/// `seq` means rows were removed. `AUTOINCREMENT` (rather than plain
/// rowid) is what guarantees non-reuse.
///
/// Indexes are deliberately few: every index is a write amplifier, and
/// this table's write rate is its defining constraint. `ts_unix_ms`
/// serves time-range queries (the dominant investigative access) and the
/// retention pruner. `kind` serves "show me all network connections".
/// Anything else falls back to a scan, which is the right trade for a
/// table that is written constantly and read rarely.
const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_unix_ms   INTEGER NOT NULL,
    kind         TEXT    NOT NULL,
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
    direction    TEXT,
    path         TEXT,
    file_op      TEXT,
    open_flags   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_unix_ms);
CREATE INDEX IF NOT EXISTS idx_events_kind_ts ON events(kind, ts_unix_ms);
";

#[derive(Debug, Error)]
pub enum Error {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error on event log path {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Kind discriminator written to the `kind` column.
///
/// These strings are an operator-facing API — they appear in every
/// `WHERE kind = '…'` an operator writes — so they are spelled out
/// explicitly rather than derived from the Rust variant names, which are
/// free to change.
pub const KIND_EXEC: &str = "exec";
pub const KIND_EXIT: &str = "exit";
pub const KIND_CONNECT: &str = "connect";
pub const KIND_FILE_OPEN: &str = "file_open";
pub const KIND_FILE_CHANGE: &str = "file_change";

/// Retention policy. Both bounds apply; whichever bites first wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Drop rows older than this many seconds. `0` disables the age bound.
    pub max_age_secs: u64,
    /// Drop oldest rows beyond this count. `0` disables the size bound.
    ///
    /// This is the bound that actually protects a small disk. Age alone
    /// is unbounded in the bad case — an exec storm can write more in an
    /// hour than a quiet week.
    pub max_rows: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            max_age_secs: 7 * 24 * 3600,
            max_rows: 500_000,
        }
    }
}

/// What the store currently holds. Surfaced over SQL so an operator can
/// tell "nothing happened" from "we stopped recording" — a silent sensor
/// is the failure mode that matters most in an EDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub rows: u64,
    pub oldest_ts_unix_ms: Option<u64>,
    pub newest_ts_unix_ms: Option<u64>,
    /// Highest `seq` ever assigned. Compared against `rows`, the
    /// difference is how many rows retention has reclaimed.
    pub highest_seq: u64,
}

/// Append-only event store.
#[derive(Debug)]
pub struct EventLog {
    inner: Mutex<Connection>,
    path: PathBuf,
}

impl EventLog {
    /// Open or create an event log at `path`, creating parent
    /// directories as needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| Error::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let conn = Connection::open(&path)?;
        Self::initialise(conn, path)
    }

    /// In-memory log, for tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::initialise(conn, PathBuf::from(":memory:"))
    }

    fn initialise(conn: Connection, path: PathBuf) -> Result<Self> {
        // `synchronous = NORMAL` under WAL: a crash can lose the last
        // few commits but cannot corrupt the file. For telemetry that is
        // the right trade — `FULL` would fsync per batch and make the
        // write rate a disk-latency problem, which on an SD-card-backed
        // Pi is the difference between usable and not.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        conn.execute_batch(SCHEMA_V1)?;
        Self::migrate(&conn)?;
        Ok(Self {
            inner: Mutex::new(conn),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Raw connection handle, for tests that need to corrupt the schema
    /// to exercise write-failure paths.
    #[doc(hidden)]
    pub fn conn_for_test(&self) -> &Mutex<Connection> {
        &self.inner
    }

    /// Add columns introduced after a log file was first created.
    ///
    /// `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table, so
    /// adding a column to `SCHEMA_V1` alone silently leaves every
    /// already-deployed agent on the old shape — and then every INSERT
    /// naming the new column fails, which stops history recording dead
    /// on exactly the hosts that have the most of it. That is not
    /// hypothetical: it happened.
    ///
    /// `ALTER TABLE ... ADD COLUMN` is metadata-only in `SQLite` for a
    /// nullable column with no default, so this is O(1) regardless of
    /// how many rows the log holds.
    fn migrate(conn: &Connection) -> Result<()> {
        // Columns added after the initial schema. Append here — never
        // reorder or remove, since the point is to reconcile with files
        // written by older builds.
        const ADDED: &[(&str, &str)] = &[("local_port", "INTEGER"), ("direction", "TEXT")];

        let mut present = std::collections::HashSet::new();
        {
            let mut stmt = conn.prepare("PRAGMA table_info(events)")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
            for name in rows {
                present.insert(name?);
            }
        }
        for (name, ty) in ADDED {
            if !present.contains(*name) {
                conn.execute_batch(&format!("ALTER TABLE events ADD COLUMN {name} {ty};"))?;
            }
        }
        Ok(())
    }

    /// Append a batch of events in one transaction.
    ///
    /// Batched rather than per-event because a transaction commit is the
    /// expensive part: at exec-storm rates, per-event commits dominate
    /// and the writer becomes the bottleneck that drops events.
    pub fn append_batch(&self, events: &[Event]) -> Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }
        let conn = self.inner.lock().expect("event log mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events
                    (ts_unix_ms, kind, pid, ppid, uid, comm, exe_path, args,
                     exit_code, net_family, dst_addr, dst_port, local_port, direction,
                     path, file_op, open_flags)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                         ?15, ?16, ?17)",
            )?;
            for event in events {
                let r = Row::from_event(event);
                stmt.execute(params![
                    r.ts_unix_ms,
                    r.kind,
                    r.pid,
                    r.ppid,
                    r.uid,
                    r.comm,
                    r.exe_path,
                    r.args,
                    r.exit_code,
                    r.net_family,
                    r.dst_addr,
                    r.dst_port,
                    r.local_port,
                    r.direction,
                    r.path,
                    r.file_op,
                    r.open_flags,
                ])?;
            }
        }
        tx.commit()?;
        Ok(events.len())
    }

    /// Enforce `retention`, dropping oldest-first. Returns how many rows
    /// were reclaimed.
    ///
    /// Runs on a timer rather than per-insert: a `DELETE` on every append
    /// would double the write cost and defeat the batching above.
    pub fn prune(&self, retention: Retention) -> Result<u64> {
        let conn = self.inner.lock().expect("event log mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let mut removed = 0u64;

        if retention.max_age_secs > 0 {
            let now_ms = now_unix_ms();
            let cutoff = now_ms.saturating_sub(retention.max_age_secs.saturating_mul(1000));
            let n = tx.execute(
                "DELETE FROM events WHERE ts_unix_ms < ?1",
                params![i64::try_from(cutoff).unwrap_or(i64::MAX)],
            )?;
            removed += n as u64;
        }

        if retention.max_rows > 0 {
            // Delete by `seq` rather than by timestamp: `seq` is the true
            // append order, and clock steps (NTP, a VM resuming) can make
            // `ts_unix_ms` non-monotonic. Trimming by time under a
            // backwards step would delete the wrong rows.
            let n = tx.execute(
                "DELETE FROM events WHERE seq <= (
                     SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?1
                 )",
                params![i64::try_from(retention.max_rows).unwrap_or(i64::MAX)],
            )?;
            removed += n as u64;
        }

        tx.commit()?;
        Ok(removed)
    }

    /// Current contents, for the coverage-telemetry SQL view.
    pub fn stats(&self) -> Result<Stats> {
        let conn = self.inner.lock().expect("event log mutex poisoned");
        let rows: u64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| {
            r.get::<_, i64>(0).map(|v| u64::try_from(v).unwrap_or(0))
        })?;
        let (oldest, newest): (Option<i64>, Option<i64>) = conn.query_row(
            "SELECT MIN(ts_unix_ms), MAX(ts_unix_ms) FROM events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        // `sqlite_sequence` only has a row once something has been
        // inserted, so a fresh log legitimately has no entry.
        let highest_seq: u64 = conn
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'events'",
                [],
                |r| r.get::<_, i64>(0).map(|v| u64::try_from(v).unwrap_or(0)),
            )
            .optional()?
            .unwrap_or(0);
        Ok(Stats {
            rows,
            oldest_ts_unix_ms: oldest.map(|v| u64::try_from(v).unwrap_or(0)),
            newest_ts_unix_ms: newest.map(|v| u64::try_from(v).unwrap_or(0)),
            highest_seq,
        })
    }

    /// Checkpoint the WAL into the main file.
    ///
    /// This is about bounding WAL growth, *not* visibility: a read-only
    /// attach does see un-checkpointed rows, because the reader shares
    /// the `-shm` index with the writer (same uid — the agent queries
    /// its own log in-process). `tests/attach_probe.rs` pins that
    /// behaviour, since the opposite would make the checkpoint interval
    /// a query-lag window.
    ///
    /// Without periodic checkpoints a busy agent's WAL grows unbounded
    /// between restarts, which is its own disk-exhaustion bug.
    pub fn checkpoint(&self) -> Result<()> {
        let conn = self.inner.lock().expect("event log mutex poisoned");
        conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
        Ok(())
    }
}

/// Flattened column values for one event.
struct Row {
    ts_unix_ms: i64,
    kind: &'static str,
    pid: Option<i64>,
    ppid: Option<i64>,
    uid: Option<i64>,
    comm: Option<String>,
    exe_path: Option<String>,
    args: Option<String>,
    exit_code: Option<i64>,
    net_family: Option<&'static str>,
    dst_addr: Option<String>,
    dst_port: Option<i64>,
    local_port: Option<i64>,
    direction: Option<&'static str>,
    path: Option<String>,
    file_op: Option<&'static str>,
    open_flags: Option<i64>,
}

impl Row {
    fn from_event(event: &Event) -> Self {
        let ts = system_time_to_unix_ms(event.timestamp());
        let mut r = Self {
            ts_unix_ms: ts,
            kind: KIND_EXEC,
            pid: None,
            ppid: None,
            uid: None,
            comm: None,
            exe_path: None,
            args: None,
            exit_code: None,
            net_family: None,
            dst_addr: None,
            dst_port: None,
            local_port: None,
            direction: None,
            path: None,
            file_op: None,
            open_flags: None,
        };
        match event {
            Event::ProcessExec(e) => {
                r.kind = KIND_EXEC;
                r.pid = Some(i64::from(e.pid));
                r.ppid = Some(i64::from(e.ppid));
                r.uid = Some(i64::from(e.uid));
                r.comm = Some(e.comm.clone());
                r.exe_path = e.exe_path.as_ref().map(|p| p.display().to_string());
                // Shell-ish joining, not a faithful re-quote: this column
                // is for reading and `LIKE` matching, and callers that
                // need exact argv should not round-trip through it.
                r.args = Some(e.args.join(" "));
            }
            Event::ProcessExit(e) => {
                r.kind = KIND_EXIT;
                r.pid = Some(i64::from(e.pid));
                r.exit_code = Some(i64::from(e.exit_code));
            }
            Event::NetworkConnect(e) => {
                r.kind = KIND_CONNECT;
                r.pid = Some(i64::from(e.pid));
                r.net_family = Some(match e.family {
                    NetFamily::V4 => "v4",
                    NetFamily::V6 => "v6",
                });
                r.dst_addr = Some(e.daddr.to_string());
                r.dst_port = Some(i64::from(e.dport));
                r.local_port = Some(i64::from(e.local_port));
                r.direction = Some(e.direction.label());
            }
            Event::FileOpen(e) => {
                r.kind = KIND_FILE_OPEN;
                r.pid = Some(i64::from(e.pid));
                r.path = Some(e.path.display().to_string());
                r.open_flags = Some(i64::from(e.flags));
            }
            Event::FileChange(e) => {
                r.kind = KIND_FILE_CHANGE;
                r.path = Some(e.path.display().to_string());
                r.file_op = Some(match e.op {
                    FileOp::Modify => "modify",
                    FileOp::Attrib => "attrib",
                    FileOp::Delete => "delete",
                    FileOp::Move => "move",
                    FileOp::Create => "create",
                });
            }
        }
        r
    }
}

fn system_time_to_unix_ms(ts: SystemTime) -> i64 {
    ts.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::Duration;

    use bowery_events::{FileChange, NetworkConnect, ProcessExec, ProcessExit};

    use super::*;

    fn exec_at(pid: u32, ts: SystemTime) -> Event {
        Event::ProcessExec(ProcessExec {
            pid,
            ppid: 1,
            uid: 0,
            comm: "sh".into(),
            exe_path: Some(PathBuf::from("/bin/sh")),
            args: vec!["-c".into(), "id".into()],
            ts,
        })
    }

    #[test]
    fn every_event_kind_round_trips_into_its_columns() {
        let log = EventLog::open_in_memory().unwrap();
        let now = SystemTime::now();
        let n = log
            .append_batch(&[
                exec_at(100, now),
                Event::ProcessExit(ProcessExit {
                    pid: 100,
                    exit_code: 3,
                    ts: now,
                }),
                Event::NetworkConnect(NetworkConnect {
                    pid: 100,
                    family: NetFamily::V4,
                    daddr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
                    dport: 4444,
                    local_port: 51000,
                    direction: bowery_events::NetDirection::Outbound,
                    ts: now,
                }),
                Event::FileChange(FileChange {
                    path: PathBuf::from("/etc/passwd"),
                    op: FileOp::Modify,
                    ts: now,
                }),
            ])
            .unwrap();
        assert_eq!(n, 4);

        let conn = log.inner.lock().unwrap();
        // The exec's fields.
        let (kind, comm, exe, args): (String, String, String, String) = conn
            .query_row(
                "SELECT kind, comm, exe_path, args FROM events WHERE pid = 100 AND kind = 'exec'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (kind.as_str(), comm.as_str(), exe.as_str()),
            ("exec", "sh", "/bin/sh")
        );
        assert_eq!(args, "-c id");

        // The connect — the signal that used to be collected and dropped.
        let (addr, port): (String, i64) = conn
            .query_row(
                "SELECT dst_addr, dst_port FROM events WHERE kind = 'connect'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((addr.as_str(), port), ("10.0.0.7", 4444));

        let exit_code: i64 = conn
            .query_row(
                "SELECT exit_code FROM events WHERE kind = 'exit'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(exit_code, 3);

        let (path, op): (String, String) = conn
            .query_row(
                "SELECT path, file_op FROM events WHERE kind = 'file_change'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((path.as_str(), op.as_str()), ("/etc/passwd", "modify"));
    }

    #[test]
    fn retention_by_age_drops_only_what_is_older_than_the_cutoff() {
        let log = EventLog::open_in_memory().unwrap();
        let now = SystemTime::now();
        let old = now - Duration::from_hours(1);
        log.append_batch(&[exec_at(1, old), exec_at(2, now)])
            .unwrap();

        let removed = log
            .prune(Retention {
                max_age_secs: 60,
                max_rows: 0,
            })
            .unwrap();
        assert_eq!(removed, 1, "only the hour-old row is past a 60s cutoff");
        let stats = log.stats().unwrap();
        assert_eq!(stats.rows, 1);
    }

    #[test]
    fn retention_by_rows_keeps_the_newest_and_trims_by_seq() {
        let log = EventLog::open_in_memory().unwrap();
        let now = SystemTime::now();
        let events: Vec<Event> = (0..10).map(|i| exec_at(i, now)).collect();
        log.append_batch(&events).unwrap();

        let removed = log
            .prune(Retention {
                max_age_secs: 0,
                max_rows: 4,
            })
            .unwrap();
        assert_eq!(removed, 6);

        let conn = log.inner.lock().unwrap();
        let kept: Vec<i64> = conn
            .prepare("SELECT pid FROM events ORDER BY seq")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(kept, vec![6, 7, 8, 9], "the newest 4 survive");
    }

    /// A backwards clock step (NTP correction, VM resume) must not make
    /// the size-based pruner delete the wrong rows — which is why it
    /// trims by `seq`, not by timestamp.
    #[test]
    fn row_retention_is_immune_to_a_backwards_clock_step() {
        let log = EventLog::open_in_memory().unwrap();
        let now = SystemTime::now();
        let future = now + Duration::from_hours(24);
        // Appended first but stamped *later* than the rows that follow.
        log.append_batch(&[exec_at(1, future), exec_at(2, now), exec_at(3, now)])
            .unwrap();

        log.prune(Retention {
            max_age_secs: 0,
            max_rows: 2,
        })
        .unwrap();

        let conn = log.inner.lock().unwrap();
        let kept: Vec<i64> = conn
            .prepare("SELECT pid FROM events ORDER BY seq")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(
            kept,
            vec![2, 3],
            "trimming follows append order, not the skewed timestamps"
        );
    }

    #[test]
    fn stats_expose_reclaimed_rows_as_a_seq_gap() {
        let log = EventLog::open_in_memory().unwrap();
        let now = SystemTime::now();
        log.append_batch(&(0..5).map(|i| exec_at(i, now)).collect::<Vec<_>>())
            .unwrap();
        log.prune(Retention {
            max_age_secs: 0,
            max_rows: 2,
        })
        .unwrap();

        let stats = log.stats().unwrap();
        assert_eq!(stats.rows, 2);
        assert_eq!(
            stats.highest_seq, 5,
            "seq must not be reused after a prune, so the gap stays visible"
        );
        assert!(stats.oldest_ts_unix_ms.is_some());
    }

    #[test]
    fn empty_log_reports_empty_stats_without_erroring() {
        let log = EventLog::open_in_memory().unwrap();
        let stats = log.stats().unwrap();
        assert_eq!(stats, Stats::default());
        assert_eq!(log.append_batch(&[]).unwrap(), 0);
        assert_eq!(log.prune(Retention::default()).unwrap(), 0);
    }

    #[test]
    fn reopening_a_file_backed_log_keeps_prior_rows() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("events.db");
        {
            let log = EventLog::open(&path).unwrap();
            log.append_batch(&[exec_at(42, SystemTime::now())]).unwrap();
            log.checkpoint().unwrap();
        }
        let log = EventLog::open(&path).unwrap();
        assert_eq!(
            log.stats().unwrap().rows,
            1,
            "history must survive a restart"
        );
    }
}

#[cfg(test)]
mod migration_tests {
    use std::path::PathBuf;
    use std::time::SystemTime;

    use bowery_events::{Event, NetDirection, NetFamily, NetworkConnect, ProcessExec};
    use rusqlite::Connection;

    use super::*;

    /// The pre-migration schema, verbatim: no `local_port`, no
    /// `direction`.
    const SCHEMA_BEFORE: &str = "
    CREATE TABLE IF NOT EXISTS events (
        seq          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_unix_ms   INTEGER NOT NULL,
        kind         TEXT    NOT NULL,
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
        path         TEXT,
        file_op      TEXT,
        open_flags   INTEGER
    );";

    /// Regression for a bug that reached a live host: adding a column to
    /// `SCHEMA_V1` does nothing to an existing file, because
    /// `CREATE TABLE IF NOT EXISTS` is a no-op there. Every subsequent
    /// INSERT then failed, and the agent with the longest history was
    /// the one that stopped recording.
    #[test]
    fn an_old_schema_log_migrates_and_keeps_accepting_writes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("events.db");

        // A log written by the previous build, with a row already in it.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_BEFORE).unwrap();
            conn.execute(
                "INSERT INTO events (ts_unix_ms, kind, pid, comm) VALUES (1, 'exec', 7, 'old')",
                [],
            )
            .unwrap();
        }

        let log = EventLog::open(&path).expect("opening an old-schema log must succeed");

        // The write that used to fail.
        log.append_batch(&[Event::NetworkConnect(NetworkConnect {
            pid: 0,
            family: NetFamily::V4,
            daddr: "10.0.0.42".parse().unwrap(),
            dport: 54321,
            local_port: 22,
            direction: NetDirection::Inbound,
            ts: SystemTime::now(),
        })])
        .expect("a migrated log must accept rows using the new columns");

        // Pre-existing history survives the migration.
        assert_eq!(log.stats().unwrap().rows, 2, "the old row must not be lost");

        let conn = log.inner.lock().unwrap();
        let (dir_label, lport): (String, i64) = conn
            .query_row(
                "SELECT direction, local_port FROM events WHERE kind = 'connect'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((dir_label.as_str(), lport), ("in", 22));
    }

    /// Migration runs on every open, so it must be a no-op the second
    /// time — `ALTER TABLE ADD COLUMN` errors on a duplicate.
    #[test]
    fn migration_is_idempotent_across_reopens() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("events.db");
        for _ in 0..3 {
            let log = EventLog::open(&path).expect("reopen must not fail");
            log.append_batch(&[Event::ProcessExec(ProcessExec {
                pid: 1,
                ppid: 1,
                uid: 0,
                comm: "t".into(),
                exe_path: Some(PathBuf::from("/bin/t")),
                args: vec![],
                ts: SystemTime::now(),
            })])
            .unwrap();
        }
        let log = EventLog::open(&path).unwrap();
        assert_eq!(log.stats().unwrap().rows, 3);
    }
}
