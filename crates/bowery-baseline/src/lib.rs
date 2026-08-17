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

-- Network destinations this host has ever contacted.
--
-- The peer analogue of `binaries`: the question 'has this host talked to
-- this endpoint before?' is answered the same way as 'has this host run
-- this binary before?', and -- asked across the mesh -- becomes 'has ANY
-- host in the fleet ever talked to it?'. A destination nobody has
-- contacted is the shape of C2 or exfil; an intra-fleet destination
-- nobody has contacted is the shape of lateral movement.
--
-- Keyed on the canonical addr:port text rather than a parsed tuple so
-- v4 and v6 share one table and the key is directly greppable by an
-- operator reading the SQL surface.
-- How often each detection rule has fired, across the life of this
-- install rather than since the last restart.
--
-- The in-memory counters answer only for the current process, and that
-- window misled twice in one session: a zero was read as a rule that had
-- never worked when the agent had simply restarted minutes earlier.
-- Whether a rule has ever fired since install is the question worth
-- asking, and it has to outlive the process.
--
-- CREATE TABLE IF NOT EXISTS means an existing baseline gains this table
-- on next start, with no migration step and no data loss.
CREATE TABLE IF NOT EXISTS detection_stats (
    rule_id    TEXT PRIMARY KEY,
    fired      INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS net_destinations (
    dst_key    TEXT PRIMARY KEY,
    addr       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 0
);
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

/// One endpoint this host has contacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetDestinationRecord {
    /// Canonical `addr:port`, and the key peers fingerprint for whisper
    /// rounds.
    pub dst_key: String,
    pub addr: String,
    pub port: u16,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub seen_count: u64,
}

/// Canonical text form of a destination. Single source of truth: the
/// asker's fingerprint and the responder's scan must agree byte for
/// byte or a whisper round silently matches nothing.
#[must_use]
pub fn destination_key(addr: &str, port: u16) -> String {
    format!("{addr}:{port}")
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

    /// Visit every binary record in the baseline. The callback runs
    /// while the connection mutex is held; keep it cheap (no blocking
    /// I/O, no async). Used by the Phase-5 whisper responder to
    /// aggregate sightings by tier-1 fingerprint without an extra
    /// schema column.
    ///
    /// **Caller must keep the visit callback cheap** — the mutex
    /// is held for the entire walk. Callers that need to do
    /// non-trivial per-row work (e.g. writing into a `SQLite`
    /// connection elsewhere) should use [`Self::snapshot_binaries`]
    /// instead, which collects into a Vec under the lock and
    /// releases the mutex before the caller iterates.
    /// Record an observation of an outbound connection to `addr:port`.
    ///
    /// Mirrors [`Self::upsert_binary`]: `Inserted` means this host has
    /// never contacted this endpoint before, which is the local half of
    /// the rarity signal.
    pub fn upsert_net_destination(&self, addr: &str, port: u16) -> Result<UpsertOutcome> {
        let key = destination_key(addr, port);
        let now = system_time_to_secs(SystemTime::now());
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let tx = conn.unchecked_transaction()?;

        let existing: Option<u64> = tx
            .query_row(
                "SELECT seen_count FROM net_destinations WHERE dst_key = ?1",
                params![&key],
                |row| row.get(0),
            )
            .optional()?;

        let outcome = if let Some(prev) = existing {
            tx.execute(
                "UPDATE net_destinations SET last_seen = ?2, seen_count = seen_count + 1
                 WHERE dst_key = ?1",
                params![&key, now],
            )?;
            UpsertOutcome::Updated {
                seen_count: prev.saturating_add(1),
            }
        } else {
            tx.execute(
                "INSERT INTO net_destinations
                    (dst_key, addr, port, first_seen, last_seen, seen_count)
                 VALUES (?1, ?2, ?3, ?4, ?4, 1)",
                params![&key, addr, i64::from(port), now],
            )?;
            UpsertOutcome::Inserted
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// Collect every recorded destination into a Vec.
    ///
    /// Fold in-memory fire counts into the durable totals.
    ///
    /// Called periodically and at shutdown rather than on every fire:
    /// a rule can fire thousands of times a day and a write per fire
    /// would put `SQLite` on the alert path for no benefit. Losing the
    /// last interval's counts on a hard kill is an acceptable trade for
    /// keeping detection off the disk.
    ///
    /// # Errors
    /// Propagates `SQLite` failures.
    pub fn add_detection_counts(&self, counts: &[(&str, u64, Option<u64>)]) -> Result<()> {
        if counts.is_empty() {
            return Ok(());
        }
        let now = system_time_to_secs(SystemTime::now());
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        for (rule_id, delta, last_ms) in counts {
            if *delta == 0 {
                // Still ensure the row exists: a rule that has never
                // fired must be a visible zero, not a missing row.
                tx.execute(
                    "INSERT OR IGNORE INTO detection_stats (rule_id, fired, first_seen, last_seen)
                     VALUES (?1, 0, ?2, ?2)",
                    params![rule_id, now],
                )?;
                continue;
            }
            let last = last_ms.map_or(now, |ms| i64::try_from(ms / 1000).unwrap_or(now));
            tx.execute(
                "INSERT INTO detection_stats (rule_id, fired, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(rule_id) DO UPDATE SET
                     fired = fired + excluded.fired,
                     last_seen = MAX(last_seen, excluded.last_seen)",
                params![
                    rule_id,
                    i64::try_from(*delta).unwrap_or(i64::MAX),
                    now,
                    last
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Durable per-rule totals: `(rule_id, fired, last_seen_unix_secs)`.
    ///
    /// # Errors
    /// Propagates `SQLite` failures.
    pub fn detection_counts(&self) -> Result<Vec<(String, u64, u64)>> {
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT rule_id, fired, last_seen FROM detection_stats ORDER BY rule_id")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                    u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// How long this host has known one destination, and how often it
    /// has contacted it.
    ///
    /// The novelty half of beacon scoring: regular outbound traffic is
    /// what NTP, package mirrors and monitoring agents look like, so
    /// periodicity alone is useless. What separates a beacon is that the
    /// endpoint is *new* — and answering that from the baseline is why
    /// no list of known-good destinations is needed, which would be both
    /// endless and an evasion target.
    ///
    /// # Errors
    /// Propagates `SQLite` failures.
    pub fn net_destination(&self, addr: &str, port: u16) -> Result<Option<NetDestinationRecord>> {
        let key = destination_key(addr, port);
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let rec = conn
            .query_row(
                "SELECT addr, port, first_seen, last_seen, seen_count
                 FROM net_destinations WHERE dst_key = ?1",
                params![key],
                |row| {
                    Ok(NetDestinationRecord {
                        dst_key: key.clone(),
                        addr: row.get(0)?,
                        port: u16::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                        first_seen: secs_to_system_time(row.get::<_, i64>(2)?),
                        last_seen: secs_to_system_time(row.get::<_, i64>(3)?),
                        seen_count: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                    })
                },
            )
            .optional()?;
        Ok(rec)
    }

    /// Preferred over [`Self::for_each_net_destination`] wherever the
    /// caller does real work per row: the visitor variant holds the
    /// baseline mutex for the whole walk, which is the shape of
    /// SECURITY-AUDIT-PHASE9 F-9 (the SQL view must not hold it across
    /// its own INSERTs).
    pub fn snapshot_net_destinations(&self) -> Result<Vec<NetDestinationRecord>> {
        let mut out = Vec::new();
        self.for_each_net_destination(|r| out.push(r.clone()))?;
        Ok(out)
    }

    /// Visit every recorded destination. Used by the whisper responder,
    /// which derives a tier-1 fingerprint per row and does no I/O.
    pub fn for_each_net_destination<F>(&self, mut visit: F) -> Result<()>
    where
        F: FnMut(&NetDestinationRecord),
    {
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT dst_key, addr, port, first_seen, last_seen, seen_count
             FROM net_destinations",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(NetDestinationRecord {
                dst_key: row.get(0)?,
                addr: row.get(1)?,
                port: u16::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                first_seen: secs_to_system_time(row.get(3)?),
                last_seen: secs_to_system_time(row.get(4)?),
                seen_count: row.get(5)?,
            })
        })?;
        for row in rows {
            visit(&row?);
        }
        Ok(())
    }

    pub fn for_each_binary<F>(&self, mut visit: F) -> Result<()>
    where
        F: FnMut(&BinaryRecord),
    {
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT sha256, first_seen, last_seen, seen_count FROM binaries")?;
        let rows = stmt.query_map([], |row| {
            let sha_blob: Vec<u8> = row.get(0)?;
            let mut sha = [0u8; 32];
            if sha_blob.len() == 32 {
                sha.copy_from_slice(&sha_blob);
            }
            Ok(BinaryRecord {
                sha256: sha,
                first_seen: secs_to_system_time(row.get::<_, i64>(1)?),
                last_seen: secs_to_system_time(row.get::<_, i64>(2)?),
                seen_count: row.get::<_, u64>(3)?,
            })
        })?;
        for row in rows {
            let rec = row?;
            visit(&rec);
        }
        Ok(())
    }

    /// Snapshot every binary into a Vec, releasing the mutex
    /// before returning so the caller can iterate without
    /// blocking concurrent baseline writers (the analyzer's
    /// `upsert_binary` path, the whisper-Q&A reader, etc.).
    ///
    /// SECURITY-AUDIT-PHASE9 F-9: `bowery-agent`'s SQL bonus
    /// table `bowery_baseline_binaries` previously held this
    /// mutex through every per-row INSERT into a per-query
    /// in-memory `SQLite`, blocking analyzer upserts for as long
    /// as the operator-supplied query took. Snapshotting first
    /// trades a transient ~40 bytes/record allocation for
    /// mutex-hold time bounded by the SELECT walk only.
    pub fn snapshot_binaries(&self) -> Result<Vec<BinaryRecord>> {
        let conn = self.inner.lock().expect("baseline mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT sha256, first_seen, last_seen, seen_count FROM binaries")?;
        let rows = stmt.query_map([], |row| {
            let sha_blob: Vec<u8> = row.get(0)?;
            let mut sha = [0u8; 32];
            if sha_blob.len() == 32 {
                sha.copy_from_slice(&sha_blob);
            }
            Ok(BinaryRecord {
                sha256: sha,
                first_seen: secs_to_system_time(row.get::<_, i64>(1)?),
                last_seen: secs_to_system_time(row.get::<_, i64>(2)?),
                seen_count: row.get::<_, u64>(3)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
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
mod net_destination_tests {
    use super::*;

    #[test]
    fn first_contact_is_inserted_and_repeats_increment() {
        let b = Baseline::open_in_memory().unwrap();
        assert_eq!(
            b.upsert_net_destination("203.0.113.9", 443).unwrap(),
            UpsertOutcome::Inserted,
            "first contact is the local half of the rarity signal"
        );
        assert_eq!(
            b.upsert_net_destination("203.0.113.9", 443).unwrap(),
            UpsertOutcome::Updated { seen_count: 2 }
        );

        let mut rows = Vec::new();
        b.for_each_net_destination(|r| rows.push(r.clone()))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].dst_key, "203.0.113.9:443");
        assert_eq!(rows[0].addr, "203.0.113.9");
        assert_eq!(rows[0].port, 443);
        assert_eq!(rows[0].seen_count, 2);
    }

    /// Port is part of the identity: SSH to a host you already talk to
    /// on 443 is a different fact, and collapsing them would hide
    /// exactly the lateral-movement case this exists for.
    #[test]
    fn the_same_address_on_a_different_port_is_a_different_destination() {
        let b = Baseline::open_in_memory().unwrap();
        b.upsert_net_destination("10.0.0.5", 443).unwrap();
        assert_eq!(
            b.upsert_net_destination("10.0.0.5", 22).unwrap(),
            UpsertOutcome::Inserted
        );
        let mut n = 0;
        b.for_each_net_destination(|_| n += 1).unwrap();
        assert_eq!(n, 2);
    }

    /// v6 addresses contain colons, so the canonical key must stay
    /// round-trippable through the fields it was built from — the
    /// asker fingerprints this string and the responder rebuilds it.
    #[test]
    fn v6_destinations_keep_address_and_port_separable() {
        let b = Baseline::open_in_memory().unwrap();
        b.upsert_net_destination("2001:db8::1", 8443).unwrap();
        let mut rows = Vec::new();
        b.for_each_net_destination(|r| rows.push(r.clone()))
            .unwrap();
        assert_eq!(rows[0].addr, "2001:db8::1");
        assert_eq!(rows[0].port, 8443);
        assert_eq!(
            rows[0].dst_key,
            destination_key("2001:db8::1", 8443),
            "the stored key must equal what an asker would fingerprint"
        );
    }

    #[test]
    fn destinations_survive_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("baseline.db");
        {
            let b = Baseline::open(&path).unwrap();
            b.upsert_net_destination("198.51.100.7", 53).unwrap();
        }
        let b = Baseline::open(&path).unwrap();
        assert_eq!(
            b.upsert_net_destination("198.51.100.7", 53).unwrap(),
            UpsertOutcome::Updated { seen_count: 2 },
            "a restart must not make every destination look new again"
        );
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
    fn for_each_binary_visits_every_row() {
        let baseline = Baseline::open_in_memory().unwrap();
        baseline.upsert_binary(&sha(1)).unwrap();
        baseline.upsert_binary(&sha(2)).unwrap();
        baseline.upsert_binary(&sha(2)).unwrap(); // bump count for sha(2)

        let mut seen: Vec<([u8; 32], u64)> = Vec::new();
        baseline
            .for_each_binary(|rec| seen.push((rec.sha256, rec.seen_count)))
            .unwrap();
        seen.sort_by_key(|(s, _)| *s);
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], (sha(1), 1));
        assert_eq!(seen[1], (sha(2), 2));
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

    // -----------------------------------------------------------------
    // Durable detection counters
    // -----------------------------------------------------------------

    #[test]
    fn counts_accumulate_across_drains() {
        let dir = tempfile::tempdir().unwrap();
        let b = Baseline::open(dir.path().join("b.db")).unwrap();
        b.add_detection_counts(&[("cred.read_shadow", 3, None)])
            .unwrap();
        b.add_detection_counts(&[("cred.read_shadow", 2, None)])
            .unwrap();
        let got = b.detection_counts().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, 5, "a second flush must add, not replace");
    }

    /// The whole reason this is on disk: a restart must not reset the
    /// answer to whether a rule has ever fired here.
    #[test]
    fn counts_survive_reopening_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.db");
        {
            let b = Baseline::open(&path).unwrap();
            b.add_detection_counts(&[("c2.beacon_new_destination", 4, None)])
                .unwrap();
        }
        let b = Baseline::open(&path).unwrap();
        assert_eq!(b.detection_counts().unwrap()[0].1, 4);
    }

    /// A rule that has never fired still gets a row, so its zero is
    /// visible rather than absent.
    #[test]
    fn a_never_fired_rule_is_still_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let b = Baseline::open(dir.path().join("b.db")).unwrap();
        b.add_detection_counts(&[("impact.mass_write_new_extension", 0, None)])
            .unwrap();
        let got = b.detection_counts().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, 0);
    }

    /// ...and a later zero must not wipe a real count.
    #[test]
    fn a_zero_flush_does_not_reset_an_existing_total() {
        let dir = tempfile::tempdir().unwrap();
        let b = Baseline::open(dir.path().join("b.db")).unwrap();
        b.add_detection_counts(&[("lineage.service_spawned_shell", 7, None)])
            .unwrap();
        b.add_detection_counts(&[("lineage.service_spawned_shell", 0, None)])
            .unwrap();
        assert_eq!(b.detection_counts().unwrap()[0].1, 7);
    }

    #[test]
    fn a_destination_lookup_reports_what_it_knows() {
        let dir = tempfile::tempdir().unwrap();
        let b = Baseline::open(dir.path().join("b.db")).unwrap();
        assert!(b.net_destination("10.0.0.9", 443).unwrap().is_none());
        b.upsert_net_destination("10.0.0.9", 443).unwrap();
        b.upsert_net_destination("10.0.0.9", 443).unwrap();
        let rec = b
            .net_destination("10.0.0.9", 443)
            .unwrap()
            .expect("known now");
        assert_eq!(rec.seen_count, 2);
        assert_eq!(rec.port, 443);
    }
}
