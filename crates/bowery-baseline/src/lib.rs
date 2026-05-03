//! SQLite-backed baseline store for The Bowery.
//!
//! Phase 2 surface: record observed binaries (by SHA-256) and parent→child
//! exec edges, query known-binary counts. Schema migrations via simple
//! `CREATE TABLE IF NOT EXISTS`. Subsequent phases add scoring helpers,
//! network peers, syscall-frequency aggregation, and TTL on episode rows
//! (see [`DESIGN.md`](../../DESIGN.md) §7).
//!
//! Concurrency: a single connection guarded by a `Mutex`. The agent's
//! pipeline calls into this from `tokio::task::spawn_blocking` so the
//! async runtime never blocks on `SQLite` I/O.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

const SCHEMA_V1: &str = r"
CREATE TABLE IF NOT EXISTS binaries (
    sha256 BLOB PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS process_lineage (
    parent_sha BLOB NOT NULL,
    child_sha BLOB NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(parent_sha, child_sha)
);

CREATE INDEX IF NOT EXISTS idx_lineage_child ON process_lineage(child_sha);
";

#[derive(Debug, Error)]
pub enum Error {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error on baseline path {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// Binary was new — first time we've seen this SHA.
    Inserted,
    /// Binary was already present; `seen_count` is its updated count.
    Updated { seen_count: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryRecord {
    pub sha256: [u8; 32],
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub seen_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageRecord {
    pub parent_sha: [u8; 32],
    pub child_sha: [u8; 32],
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub seen_count: u64,
}

/// Persistent baseline store.
#[derive(Debug)]
pub struct Baseline {
    inner: Mutex<Connection>,
    path: PathBuf,
}

impl Baseline {
    /// Open or create a baseline at `path`. Parent directories are created
    /// if missing. Schema is applied on every open.
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

    /// In-memory baseline. Only the schema is applied; nothing persists.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::initialise(conn, PathBuf::from(":memory:"))
    }

    fn initialise(conn: Connection, path: PathBuf) -> Result<Self> {
        // WAL is harmless for in-memory; apply unconditionally for parity.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        conn.execute_batch(SCHEMA_V1)?;
        Ok(Self {
            inner: Mutex::new(conn),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    // -----------------------------------------------------------------
    // binaries
    // -----------------------------------------------------------------

    /// Record an observation of a binary by its SHA-256. Increments
    /// `seen_count` and updates `last_seen` if already present, inserts
    /// otherwise.
    pub fn upsert_binary(&self, sha: &[u8; 32]) -> Result<UpsertOutcome> {
        let now = system_time_to_secs(SystemTime::now());
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let tx = conn.unchecked_transaction()?;

        let existing: Option<u64> = tx
            .query_row(
                "SELECT seen_count FROM binaries WHERE sha256 = ?1",
                params![&sha[..]],
                |row| row.get(0),
            )
            .optional()?;

        let outcome = if let Some(prev) = existing {
            tx.execute(
                "UPDATE binaries
                 SET last_seen = ?2, seen_count = seen_count + 1
                 WHERE sha256 = ?1",
                params![&sha[..], now],
            )?;
            UpsertOutcome::Updated {
                seen_count: prev + 1,
            }
        } else {
            tx.execute(
                "INSERT INTO binaries (sha256, first_seen, last_seen, seen_count)
                 VALUES (?1, ?2, ?2, 1)",
                params![&sha[..], now],
            )?;
            UpsertOutcome::Inserted
        };

        tx.commit()?;
        Ok(outcome)
    }

    pub fn get_binary(&self, sha: &[u8; 32]) -> Result<Option<BinaryRecord>> {
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let result = conn
            .query_row(
                "SELECT first_seen, last_seen, seen_count FROM binaries WHERE sha256 = ?1",
                params![&sha[..]],
                |row| {
                    Ok(BinaryRecord {
                        sha256: *sha,
                        first_seen: secs_to_system_time(row.get::<_, i64>(0)?),
                        last_seen: secs_to_system_time(row.get::<_, i64>(1)?),
                        seen_count: row.get::<_, u64>(2)?,
                    })
                },
            )
            .optional()?;
        Ok(result)
    }

    pub fn count_binaries(&self) -> Result<u64> {
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let count: u64 = conn.query_row("SELECT COUNT(*) FROM binaries", [], |row| row.get(0))?;
        Ok(count)
    }

    // -----------------------------------------------------------------
    // process lineage
    // -----------------------------------------------------------------

    pub fn record_lineage(
        &self,
        parent_sha: &[u8; 32],
        child_sha: &[u8; 32],
    ) -> Result<UpsertOutcome> {
        let now = system_time_to_secs(SystemTime::now());
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let tx = conn.unchecked_transaction()?;

        let existing: Option<u64> = tx
            .query_row(
                "SELECT seen_count FROM process_lineage
                 WHERE parent_sha = ?1 AND child_sha = ?2",
                params![&parent_sha[..], &child_sha[..]],
                |row| row.get(0),
            )
            .optional()?;

        let outcome = if let Some(prev) = existing {
            tx.execute(
                "UPDATE process_lineage
                 SET last_seen = ?3, seen_count = seen_count + 1
                 WHERE parent_sha = ?1 AND child_sha = ?2",
                params![&parent_sha[..], &child_sha[..], now],
            )?;
            UpsertOutcome::Updated {
                seen_count: prev + 1,
            }
        } else {
            tx.execute(
                "INSERT INTO process_lineage
                   (parent_sha, child_sha, first_seen, last_seen, seen_count)
                 VALUES (?1, ?2, ?3, ?3, 1)",
                params![&parent_sha[..], &child_sha[..], now],
            )?;
            UpsertOutcome::Inserted
        };

        tx.commit()?;
        Ok(outcome)
    }

    pub fn get_lineage(
        &self,
        parent_sha: &[u8; 32],
        child_sha: &[u8; 32],
    ) -> Result<Option<LineageRecord>> {
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let result = conn
            .query_row(
                "SELECT first_seen, last_seen, seen_count
                 FROM process_lineage
                 WHERE parent_sha = ?1 AND child_sha = ?2",
                params![&parent_sha[..], &child_sha[..]],
                |row| {
                    Ok(LineageRecord {
                        parent_sha: *parent_sha,
                        child_sha: *child_sha,
                        first_seen: secs_to_system_time(row.get::<_, i64>(0)?),
                        last_seen: secs_to_system_time(row.get::<_, i64>(1)?),
                        seen_count: row.get::<_, u64>(2)?,
                    })
                },
            )
            .optional()?;
        Ok(result)
    }

    pub fn count_lineage_edges(&self) -> Result<u64> {
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let count: u64 =
            conn.query_row("SELECT COUNT(*) FROM process_lineage", [], |row| row.get(0))?;
        Ok(count)
    }
}

fn system_time_to_secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn secs_to_system_time(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
    } else {
        UNIX_EPOCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn upsert_inserts_then_updates() {
        let baseline = Baseline::open_in_memory().unwrap();
        let s = sha(0xAA);

        let first = baseline.upsert_binary(&s).unwrap();
        assert_eq!(first, UpsertOutcome::Inserted);

        let second = baseline.upsert_binary(&s).unwrap();
        assert_eq!(second, UpsertOutcome::Updated { seen_count: 2 });

        let third = baseline.upsert_binary(&s).unwrap();
        assert_eq!(third, UpsertOutcome::Updated { seen_count: 3 });
    }

    #[test]
    fn get_binary_returns_record() {
        let baseline = Baseline::open_in_memory().unwrap();
        let s = sha(0x42);
        baseline.upsert_binary(&s).unwrap();
        baseline.upsert_binary(&s).unwrap();

        let rec = baseline.get_binary(&s).unwrap().expect("present");
        assert_eq!(rec.sha256, s);
        assert_eq!(rec.seen_count, 2);
        assert!(rec.first_seen <= rec.last_seen);
    }

    #[test]
    fn get_binary_returns_none_for_unknown() {
        let baseline = Baseline::open_in_memory().unwrap();
        assert!(baseline.get_binary(&sha(0)).unwrap().is_none());
    }

    #[test]
    fn count_binaries_grows() {
        let baseline = Baseline::open_in_memory().unwrap();
        assert_eq!(baseline.count_binaries().unwrap(), 0);
        baseline.upsert_binary(&sha(1)).unwrap();
        baseline.upsert_binary(&sha(2)).unwrap();
        baseline.upsert_binary(&sha(1)).unwrap(); // re-upsert
        assert_eq!(baseline.count_binaries().unwrap(), 2);
    }

    #[test]
    fn lineage_inserts_then_updates() {
        let baseline = Baseline::open_in_memory().unwrap();
        let parent = sha(0x10);
        let child = sha(0x20);

        let first = baseline.record_lineage(&parent, &child).unwrap();
        assert_eq!(first, UpsertOutcome::Inserted);

        let second = baseline.record_lineage(&parent, &child).unwrap();
        assert_eq!(second, UpsertOutcome::Updated { seen_count: 2 });

        let rec = baseline
            .get_lineage(&parent, &child)
            .unwrap()
            .expect("present");
        assert_eq!(rec.seen_count, 2);
    }

    #[test]
    fn distinct_lineage_edges_are_independent() {
        let baseline = Baseline::open_in_memory().unwrap();
        baseline.record_lineage(&sha(1), &sha(2)).unwrap();
        baseline.record_lineage(&sha(1), &sha(3)).unwrap();
        baseline.record_lineage(&sha(4), &sha(2)).unwrap();
        assert_eq!(baseline.count_lineage_edges().unwrap(), 3);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.db");
        let s = sha(0x99);

        {
            let baseline = Baseline::open(&path).unwrap();
            baseline.upsert_binary(&s).unwrap();
            baseline.upsert_binary(&s).unwrap();
        }

        let baseline = Baseline::open(&path).unwrap();
        let rec = baseline.get_binary(&s).unwrap().expect("persisted");
        assert_eq!(rec.seen_count, 2);
    }

    #[test]
    fn schema_creates_parent_dirs_on_first_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/path/baseline.db");
        let baseline = Baseline::open(&path).unwrap();
        baseline.upsert_binary(&sha(7)).unwrap();
        assert!(path.exists());
    }
}
