//! `processes` table — one row per live process on the host.
//!
//! Slice-2 implementation walks `/proc` eagerly via `procfs`,
//! materialising every visible PID into a temp table at registration
//! time. That's fine for hosts with hundreds-to-low-thousands of
//! processes (the common case) but it does mean an operator query
//! like `SELECT * FROM processes WHERE pid = 42` still reads the
//! whole tree. Slice 6+ will swap this for a `vtab` with
//! filter pushdown so single-PID queries skip the walk entirely.
//!
//! Columns are the operator-facing minimum: identity (`pid`,
//! `ppid`, `name`, `cmdline`, `exe_path`), ownership (`uid`, `gid`),
//! lifecycle (`start_time_unix`, `state`, `threads`), and footprint
//! (`rss_bytes`, `vsize_bytes`). RSS is converted from pages to
//! bytes so an operator can compare against memory thresholds
//! without knowing the host page size.
//!
//! Per-pid `procfs` reads can race with process exit (the pid
//! disappears between `all_processes()` and the field reads). We
//! treat any `ProcError` on a single pid as "skip this row" rather
//! than failing the whole query — operator tables are best-effort
//! snapshots.

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "processes";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS processes (
        pid              INTEGER,
        ppid             INTEGER,
        uid              INTEGER,
        gid              INTEGER,
        name             TEXT,
        cmdline          TEXT,
        exe_path         TEXT,
        start_time_unix  INTEGER,
        state            TEXT,
        threads          INTEGER,
        rss_bytes        INTEGER,
        vsize_bytes      INTEGER
    );
";

#[derive(Debug, Default)]
pub struct ProcessesTable {
    /// SECURITY-AUDIT-PHASE9 F-8 — Phase-9 final-4: `expose_cmdline`
    /// is OFF by default. argv routinely contains DB connection
    /// strings, API tokens, secrets passed via `--token=…` flags,
    /// and full paths under `$HOME`. With fanout, that data
    /// crosses to operators authorised on the relay but not
    /// necessarily on the peer. Operators who need cmdline must
    /// opt in per agent via `[sql] expose_cmdline = true`.
    expose_cmdline: bool,
}

impl ProcessesTable {
    pub fn new(expose_cmdline: bool) -> Self {
        Self { expose_cmdline }
    }
}

impl BoweryTable for ProcessesTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let rows = collect(self.expose_cmdline);
        let mut stmt = conn.prepare(
            "INSERT INTO processes (pid, ppid, uid, gid, name, cmdline, exe_path,
                                    start_time_unix, state, threads, rss_bytes, vsize_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.pid,
                r.ppid,
                r.uid,
                r.gid,
                r.name,
                r.cmdline,
                r.exe_path,
                r.start_time_unix,
                r.state,
                r.threads,
                r.rss_bytes,
                r.vsize_bytes,
            ])?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ProcRow {
    pid: i64,
    ppid: Option<i64>,
    uid: Option<i64>,
    gid: Option<i64>,
    name: Option<String>,
    cmdline: Option<String>,
    exe_path: Option<String>,
    start_time_unix: Option<i64>,
    state: Option<String>,
    threads: Option<i64>,
    rss_bytes: Option<i64>,
    vsize_bytes: Option<i64>,
}

fn collect(expose_cmdline: bool) -> Vec<ProcRow> {
    let Ok(iter) = procfs::process::all_processes() else {
        return Vec::new();
    };
    let boot_time = procfs::boot_time_secs().ok();
    let ticks = procfs::ticks_per_second();
    let page_size = procfs::page_size();
    let mut out = Vec::new();
    for proc in iter.flatten() {
        out.push(build_row(
            &proc,
            boot_time,
            ticks,
            page_size,
            expose_cmdline,
        ));
    }
    out
}

fn build_row(
    proc: &procfs::process::Process,
    boot_time: Option<u64>,
    ticks_per_second: u64,
    page_size: u64,
    expose_cmdline: bool,
) -> ProcRow {
    let pid = i64::from(proc.pid());
    let mut row = ProcRow {
        pid,
        ..Default::default()
    };
    if let Ok(stat) = proc.stat() {
        row.ppid = Some(i64::from(stat.ppid));
        row.name = Some(stat.comm.clone());
        row.state = Some(stat.state.to_string());
        row.threads = Some(stat.num_threads);
        row.vsize_bytes = i64::try_from(stat.vsize).ok();
        // stat.rss is in pages; convert to bytes for operator-friendliness.
        let rss_bytes = stat.rss.saturating_mul(page_size);
        row.rss_bytes = i64::try_from(rss_bytes).ok();
        row.start_time_unix = compute_start_time_unix(stat.starttime, boot_time, ticks_per_second);
    }
    if let Ok(status) = proc.status() {
        row.uid = Some(i64::from(status.ruid));
        row.gid = Some(i64::from(status.rgid));
    }
    if expose_cmdline && let Ok(cmdline) = proc.cmdline() {
        // /proc/<pid>/cmdline is NUL-separated argv; join with space
        // for human-readable display. Empty cmdline (kernel threads)
        // surfaces as NULL so operators can `WHERE cmdline IS NULL`.
        let joined = cmdline.join(" ");
        row.cmdline = if joined.is_empty() {
            None
        } else {
            Some(joined)
        };
    }
    if let Ok(exe) = proc.exe() {
        row.exe_path = exe.to_str().map(str::to_string);
    }
    row
}

/// `stat.starttime` is "clock ticks since boot". Convert to unix
/// seconds using the kernel's boot wall-clock anchor.
fn compute_start_time_unix(starttime: u64, boot_time: Option<u64>, ticks: u64) -> Option<i64> {
    let boot = boot_time?;
    if ticks == 0 {
        return None;
    }
    let secs_since_boot = starttime / ticks;
    let unix = boot.checked_add(secs_since_boot)?;
    i64::try_from(unix).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_at_least_self() {
        let conn = Connection::open_in_memory().unwrap();
        ProcessesTable::new(true).register(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM processes", [], |row| row.get(0))
            .unwrap();
        assert!(count > 0, "must observe at least the test process");
        // The current pid must be present.
        let my_pid = i64::from(std::process::id());
        let found: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM processes WHERE pid = ?1",
                params![my_pid],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(found, 1, "self pid must appear in processes");
    }

    #[test]
    fn self_row_has_expected_shape() {
        let conn = Connection::open_in_memory().unwrap();
        ProcessesTable::new(true).register(&conn).unwrap();
        let my_pid = i64::from(std::process::id());
        let (ppid, name, threads): (Option<i64>, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT ppid, name, threads FROM processes WHERE pid = ?1",
                params![my_pid],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(ppid.unwrap_or(0) > 0, "ppid resolves to a real parent");
        assert!(name.is_some(), "name resolves");
        assert!(threads.unwrap_or(0) >= 1, "self has at least one thread");
    }
}
