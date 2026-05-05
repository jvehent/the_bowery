//! `interfaces` table — network interface inventory from `/sys/class/net`.
//!
//! Slice 2 ships the link-layer view: name, MAC, MTU, operational
//! state, kernel flags. IP-address rows live in a future
//! `interface_addresses` table (slice 3 alongside the socket
//! tables) — they need a netlink `RTM_GETADDR` walk and don't
//! belong on the same row anyway since one interface can have
//! many addresses.
//!
//! `flags` is the raw hex from `/sys/class/net/<iface>/flags`
//! (kernel-side `IFF_*` bitmask); operators querying for "up"
//! interfaces are better served by `operstate = 'up'` since it
//! tracks the carrier, not just admin-up.

use std::fs;
use std::path::Path;

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "interfaces";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS interfaces (
        name      TEXT,
        mac       TEXT,
        mtu       INTEGER,
        operstate TEXT,
        flags     TEXT
    );
";

const SYS_NET: &str = "/sys/class/net";

#[derive(Debug)]
pub struct InterfacesTable;

impl BoweryTable for InterfacesTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let rows = collect();
        let mut stmt = conn.prepare(
            "INSERT INTO interfaces (name, mac, mtu, operstate, flags)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for r in rows {
            stmt.execute(params![r.name, r.mac, r.mtu, r.operstate, r.flags])?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct InterfaceRow {
    name: String,
    mac: Option<String>,
    mtu: Option<i64>,
    operstate: Option<String>,
    flags: Option<String>,
}

fn collect() -> Vec<InterfaceRow> {
    let Ok(entries) = fs::read_dir(SYS_NET) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let path = entry.path();
        out.push(InterfaceRow {
            name,
            mac: read_attr(&path, "address"),
            mtu: read_attr(&path, "mtu").and_then(|s| s.parse().ok()),
            operstate: read_attr(&path, "operstate"),
            flags: read_attr(&path, "flags"),
        });
    }
    out
}

fn read_attr(iface_dir: &Path, attr: &str) -> Option<String> {
    let path = iface_dir.join(attr);
    match fs::read_to_string(&path) {
        Ok(s) => {
            let s = s.trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_loopback() {
        let conn = Connection::open_in_memory().unwrap();
        InterfacesTable.register(&conn).unwrap();
        // Every Linux host has 'lo'.
        let lo: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM interfaces WHERE name = 'lo'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(lo, 1, "loopback must always be present");

        // Loopback must have a usable mtu (>= 1500 typically, but
        // any positive number is fine for the assertion).
        let mtu: Option<i64> = conn
            .query_row("SELECT mtu FROM interfaces WHERE name = 'lo'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(mtu.unwrap_or(0) > 0, "loopback mtu must resolve");
    }
}
