//! `users` table — parses `/etc/passwd`.
//!
//! One row per local account. NSS-only accounts (LDAP, SSSD,
//! AD-joined) are intentionally not surfaced — Bowery agents
//! shouldn't pull a directory service into the query path. If
//! that becomes load-bearing, a Slice-8 bonus table can layer
//! `getpwent`-backed enumeration on top.
//!
//! Format per `getpwent(3)`: `name:passwd:uid:gid:gecos:dir:shell`.
//! `passwd` is `x` on every modern distro (the real hash lives in
//! `/etc/shadow` which root-owned and not parsed here). Lines
//! starting with `+` or `-` (NIS) are ignored.

use std::fs;

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "users";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS users (
        username  TEXT,
        uid       INTEGER,
        gid       INTEGER,
        gecos     TEXT,
        directory TEXT,
        shell     TEXT
    );
";

#[derive(Debug)]
pub struct UsersTable;

impl BoweryTable for UsersTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        // If /etc/passwd is missing (extremely unusual) or
        // unreadable to the agent, surface zero rows rather
        // than failing every query.
        let Ok(contents) = fs::read_to_string("/etc/passwd") else {
            return Ok(());
        };
        let rows = parse_passwd(&contents);
        let mut stmt = conn.prepare(
            "INSERT INTO users (username, uid, gid, gecos, directory, shell)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.username,
                r.uid,
                r.gid,
                r.gecos,
                r.directory,
                r.shell
            ])?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct UserRow {
    username: Option<String>,
    uid: Option<i64>,
    gid: Option<i64>,
    gecos: Option<String>,
    directory: Option<String>,
    shell: Option<String>,
}

fn parse_passwd(contents: &str) -> Vec<UserRow> {
    let mut out = Vec::new();
    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip NIS markers — `+name`, `-name`, `+@netgroup`, `+::::`.
        if line.starts_with('+') || line.starts_with('-') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        out.push(UserRow {
            username: Some(fields[0].to_string()),
            uid: fields[2].parse().ok(),
            gid: fields[3].parse().ok(),
            gecos: Some(fields[4].to_string()),
            directory: Some(fields[5].to_string()),
            shell: Some(fields[6].to_string()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_passwd() {
        let raw = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# comment line
+@everyone
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
";
        let rows = parse_passwd(raw);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].username.as_deref(), Some("root"));
        assert_eq!(rows[0].uid, Some(0));
        assert_eq!(rows[0].shell.as_deref(), Some("/bin/bash"));
        assert_eq!(rows[2].uid, Some(65534));
    }

    #[test]
    fn registers_with_real_passwd() {
        let conn = Connection::open_in_memory().unwrap();
        UsersTable.register(&conn).unwrap();
        // Every Linux host has at least 'root'.
        let root: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE username = 'root' AND uid = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(root, 1, "root must always be present");
    }
}
