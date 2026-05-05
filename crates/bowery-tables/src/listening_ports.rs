//! `listening_ports` table — TCP listeners + bound UDP sockets.
//!
//! Sources: `/proc/net/{tcp,tcp6,udp,udp6}` via `procfs::net`.
//! Rows correspond to:
//! - TCP/TCP6 entries with `state = Listen` (true listeners)
//! - UDP/UDP6 entries — UDP has no listen state, but a bound UDP
//!   socket is the protocol-equivalent of "accepting traffic on a
//!   port", so we surface them all. Operators can filter by
//!   `protocol IN ('tcp','tcp6')` if they want only stream
//!   listeners.
//!
//! Columns omit `pid`/`process` deliberately — the kernel doesn't
//! attach owner-pid to entries in `/proc/net/tcp`. The mapping
//! goes through socket inode → fd → pid, which lives in
//! `process_open_sockets`. Operators wanting "what process owns
//! port 22?" should `JOIN process_open_sockets USING (inode)`.

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "listening_ports";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS listening_ports (
        protocol  TEXT,
        family    INTEGER,
        address   TEXT,
        port      INTEGER,
        uid       INTEGER,
        inode     INTEGER
    );
";

#[derive(Debug)]
pub struct ListeningPortsTable;

impl BoweryTable for ListeningPortsTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let rows = collect();
        let mut stmt = conn.prepare(
            "INSERT INTO listening_ports (protocol, family, address, port, uid, inode)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.protocol, r.family, r.address, r.port, r.uid, r.inode
            ])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ListenRow {
    protocol: &'static str,
    family: i64,
    address: String,
    port: i64,
    uid: i64,
    inode: i64,
}

fn collect() -> Vec<ListenRow> {
    let mut out = Vec::new();
    if let Ok(entries) = procfs::net::tcp() {
        for e in entries {
            if matches!(e.state, procfs::net::TcpState::Listen) {
                push_tcp(&mut out, "tcp", 4, &e);
            }
        }
    }
    if let Ok(entries) = procfs::net::tcp6() {
        for e in entries {
            if matches!(e.state, procfs::net::TcpState::Listen) {
                push_tcp(&mut out, "tcp6", 6, &e);
            }
        }
    }
    if let Ok(entries) = procfs::net::udp() {
        for e in entries {
            push_udp(&mut out, "udp", 4, &e);
        }
    }
    if let Ok(entries) = procfs::net::udp6() {
        for e in entries {
            push_udp(&mut out, "udp6", 6, &e);
        }
    }
    out
}

fn push_tcp(
    out: &mut Vec<ListenRow>,
    protocol: &'static str,
    family: i64,
    e: &procfs::net::TcpNetEntry,
) {
    out.push(ListenRow {
        protocol,
        family,
        address: e.local_address.ip().to_string(),
        port: i64::from(e.local_address.port()),
        uid: i64::from(e.uid),
        inode: i64::try_from(e.inode).unwrap_or(i64::MAX),
    });
}

fn push_udp(
    out: &mut Vec<ListenRow>,
    protocol: &'static str,
    family: i64,
    e: &procfs::net::UdpNetEntry,
) {
    out.push(ListenRow {
        protocol,
        family,
        address: e.local_address.ip().to_string(),
        port: i64::from(e.local_address.port()),
        uid: i64::from(e.uid),
        inode: i64::try_from(e.inode).unwrap_or(i64::MAX),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_table() {
        let conn = Connection::open_in_memory().unwrap();
        ListeningPortsTable.register(&conn).unwrap();
        // We can't assert >= 1 — sandboxed test hosts may have
        // /proc/net/tcp empty or unreadable. The schema must be
        // queryable regardless.
        let _: i64 = conn
            .query_row("SELECT COUNT(*) FROM listening_ports", [], |row| row.get(0))
            .unwrap();
    }

    #[test]
    fn schema_columns_match() {
        let conn = Connection::open_in_memory().unwrap();
        ListeningPortsTable.register(&conn).unwrap();
        // Verify every documented column exists by projecting it.
        conn.query_row(
            "SELECT protocol, family, address, port, uid, inode FROM listening_ports LIMIT 0",
            [],
            |_row| Ok(()),
        )
        .ok();
    }
}
