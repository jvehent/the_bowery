//! `logged_in_users` table — currently active sessions from
//! `/var/run/utmp`.
//!
//! One row per `USER_PROCESS` record. Other `ut_type`s
//! (`BOOT_TIME`, `RUN_LVL`, `DEAD_PROCESS`, ...) are filtered out
//! since operators querying "who is logged in right now" want
//! human sessions, not bookkeeping markers.

use std::fs;

use rusqlite::{Connection, params};

use crate::utmp::{USER_PROCESS, parse};
use crate::{BoweryTable, TableError};

const NAME: &str = "logged_in_users";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS logged_in_users (
        user        TEXT,
        tty         TEXT,
        host        TEXT,
        pid         INTEGER,
        login_time  INTEGER
    );
";

#[derive(Debug)]
pub struct LoggedInUsersTable;

impl BoweryTable for LoggedInUsersTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        // utmp may be missing on minimal containers / systemd
        // user instances. Surface zero rows rather than failing.
        let Ok(bytes) = fs::read("/var/run/utmp") else {
            return Ok(());
        };
        let mut stmt = conn.prepare(
            "INSERT INTO logged_in_users (user, tty, host, pid, login_time)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for rec in parse(&bytes) {
            if rec.ut_type != USER_PROCESS {
                continue;
            }
            let host = if rec.host.is_empty() {
                None
            } else {
                Some(rec.host)
            };
            stmt.execute(params![
                rec.user,
                rec.line,
                host,
                i64::from(rec.pid),
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
        LoggedInUsersTable.register(&conn).unwrap();
        // Can't assert >= 1 — CI containers commonly have empty
        // utmp. Just confirm the table is queryable.
        let _: i64 = conn
            .query_row("SELECT COUNT(*) FROM logged_in_users", [], |row| row.get(0))
            .unwrap();
    }
}
