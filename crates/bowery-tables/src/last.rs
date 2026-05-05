//! `last` table — login history from `/var/log/wtmp`.
//!
//! Same record format as `utmp` — wtmp is the rolling history,
//! utmp is the current snapshot. We keep every record (login,
//! logout, boot, runlevel) and surface `ut_type` so operators can
//! filter:
//!
//! - `WHERE type = 7` for user logins
//! - `WHERE type = 8` for logouts
//! - `WHERE type = 2` for system boots
//!
//! Rows are read in file order, which is chronological — newest
//! at the bottom. Operators wanting "most recent first" should
//! `ORDER BY time_unix DESC`.

use std::fs;

use rusqlite::{Connection, params};

use crate::utmp::parse;
use crate::{BoweryTable, TableError};

const NAME: &str = "last";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS last (
        user       TEXT,
        tty        TEXT,
        host       TEXT,
        pid        INTEGER,
        type       INTEGER,
        time_unix  INTEGER
    );
";

#[derive(Debug)]
pub struct LastTable;

impl BoweryTable for LastTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let Ok(bytes) = fs::read("/var/log/wtmp") else {
            return Ok(());
        };
        let mut stmt = conn.prepare(
            "INSERT INTO last (user, tty, host, pid, type, time_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for rec in parse(&bytes) {
            let host = if rec.host.is_empty() {
                None
            } else {
                Some(rec.host)
            };
            let user = if rec.user.is_empty() {
                None
            } else {
                Some(rec.user)
            };
            let tty = if rec.line.is_empty() {
                None
            } else {
                Some(rec.line)
            };
            stmt.execute(params![
                user,
                tty,
                host,
                i64::from(rec.pid),
                i64::from(rec.ut_type),
                rec.time_unix,
            ])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_table() {
        let conn = Connection::open_in_memory().unwrap();
        LastTable.register(&conn).unwrap();
        let _: i64 = conn
            .query_row("SELECT COUNT(*) FROM last", [], |row| row.get(0))
            .unwrap();
    }
}
