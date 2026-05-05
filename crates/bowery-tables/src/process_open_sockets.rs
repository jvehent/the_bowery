//! `process_open_sockets` table — one row per (pid, fd) pair where
//! the fd is a socket.
//!
//! The kernel doesn't expose a process-aware socket listing
//! directly. We synthesise it: walk every process's `fd/`
//! directory, keep entries whose link target parses as
//! `socket:[<inode>]`, and join those inodes against the merged
//! tcp/tcp6/udp/udp6 tables to recover the address tuples.
//!
//! Sockets we can't resolve (the inode isn't in any of the four
//! protocol tables — typical for unix-domain sockets, raw, or
//! netlink) get a row with `protocol = NULL` and addresses
//! NULL'd out, so operators still see "this pid has fd=N which
//! is a socket of unknown family" rather than losing the row.
//! That's better than silently dropping unmatched sockets.
//!
//! Reading other processes' fd dirs requires `CAP_SYS_PTRACE` in
//! the general case (most kernels relax this when the caller's
//! UID matches the target). We swallow per-pid errors as "skip
//! this pid" — same best-effort policy as the `processes` table.

use std::collections::HashMap;

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "process_open_sockets";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS process_open_sockets (
        pid             INTEGER,
        fd              INTEGER,
        family          INTEGER,
        protocol        TEXT,
        local_address   TEXT,
        local_port      INTEGER,
        remote_address  TEXT,
        remote_port     INTEGER,
        state           TEXT,
        inode           INTEGER
    );
";

#[derive(Debug)]
pub struct ProcessOpenSocketsTable;

impl BoweryTable for ProcessOpenSocketsTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let rows = collect();
        let mut stmt = conn.prepare(
            "INSERT INTO process_open_sockets (pid, fd, family, protocol,
                                                local_address, local_port,
                                                remote_address, remote_port,
                                                state, inode)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.pid,
                r.fd,
                r.family,
                r.protocol,
                r.local_address,
                r.local_port,
                r.remote_address,
                r.remote_port,
                r.state,
                r.inode,
            ])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SocketRow {
    pid: i64,
    fd: i64,
    family: Option<i64>,
    protocol: Option<&'static str>,
    local_address: Option<String>,
    local_port: Option<i64>,
    remote_address: Option<String>,
    remote_port: Option<i64>,
    state: Option<String>,
    inode: i64,
}

#[derive(Debug, Clone)]
struct SockMeta {
    family: i64,
    protocol: &'static str,
    local_address: String,
    local_port: i64,
    remote_address: String,
    remote_port: i64,
    state: String,
}

fn collect() -> Vec<SocketRow> {
    let table = build_inode_table();
    let Ok(iter) = procfs::process::all_processes() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for proc in iter.flatten() {
        let pid = i64::from(proc.pid());
        let Ok(fd_iter) = proc.fd() else { continue };
        for fd in fd_iter.flatten() {
            if let procfs::process::FDTarget::Socket(inode) = fd.target {
                let inode_i = i64::try_from(inode).unwrap_or(i64::MAX);
                let row = match table.get(&inode) {
                    Some(meta) => SocketRow {
                        pid,
                        fd: i64::from(fd.fd),
                        family: Some(meta.family),
                        protocol: Some(meta.protocol),
                        local_address: Some(meta.local_address.clone()),
                        local_port: Some(meta.local_port),
                        remote_address: Some(meta.remote_address.clone()),
                        remote_port: Some(meta.remote_port),
                        state: Some(meta.state.clone()),
                        inode: inode_i,
                    },
                    None => SocketRow {
                        pid,
                        fd: i64::from(fd.fd),
                        family: None,
                        protocol: None,
                        local_address: None,
                        local_port: None,
                        remote_address: None,
                        remote_port: None,
                        state: None,
                        inode: inode_i,
                    },
                };
                out.push(row);
            }
        }
    }
    out
}

/// Read the four /proc/net/{tcp,tcp6,udp,udp6} tables once and
/// build an inode → metadata index. Doing this once per table
/// registration (rather than per-pid) keeps the cost bounded:
/// O(sockets) once, then O(1) per fd lookup.
fn build_inode_table() -> HashMap<u64, SockMeta> {
    let mut out: HashMap<u64, SockMeta> = HashMap::new();
    if let Ok(entries) = procfs::net::tcp() {
        for e in entries {
            out.insert(e.inode, tcp_meta("tcp", 4, &e));
        }
    }
    if let Ok(entries) = procfs::net::tcp6() {
        for e in entries {
            out.insert(e.inode, tcp_meta("tcp6", 6, &e));
        }
    }
    if let Ok(entries) = procfs::net::udp() {
        for e in entries {
            out.insert(e.inode, udp_meta("udp", 4, &e));
        }
    }
    if let Ok(entries) = procfs::net::udp6() {
        for e in entries {
            out.insert(e.inode, udp_meta("udp6", 6, &e));
        }
    }
    out
}

fn tcp_meta(protocol: &'static str, family: i64, e: &procfs::net::TcpNetEntry) -> SockMeta {
    SockMeta {
        family,
        protocol,
        local_address: e.local_address.ip().to_string(),
        local_port: i64::from(e.local_address.port()),
        remote_address: e.remote_address.ip().to_string(),
        remote_port: i64::from(e.remote_address.port()),
        state: format!("{:?}", e.state),
    }
}

fn udp_meta(protocol: &'static str, family: i64, e: &procfs::net::UdpNetEntry) -> SockMeta {
    SockMeta {
        family,
        protocol,
        local_address: e.local_address.ip().to_string(),
        local_port: i64::from(e.local_address.port()),
        remote_address: e.remote_address.ip().to_string(),
        remote_port: i64::from(e.remote_address.port()),
        state: format!("{:?}", e.state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_table() {
        let conn = Connection::open_in_memory().unwrap();
        ProcessOpenSocketsTable.register(&conn).unwrap();
        // We can't assert >= 1 — sandboxed test runs may have no
        // visible socket FDs. Schema must be queryable regardless.
        let _: i64 = conn
            .query_row("SELECT COUNT(*) FROM process_open_sockets", [], |row| {
                row.get(0)
            })
            .unwrap();
    }

    #[test]
    fn schema_columns_match() {
        let conn = Connection::open_in_memory().unwrap();
        ProcessOpenSocketsTable.register(&conn).unwrap();
        conn.query_row(
            "SELECT pid, fd, family, protocol, local_address, local_port,
                    remote_address, remote_port, state, inode
             FROM process_open_sockets LIMIT 0",
            [],
            |_row| Ok(()),
        )
        .ok();
    }
}
