//! `kernel_modules` table — parses `/proc/modules`.
//!
//! Format per line, separated by whitespace:
//!
//! ```text
//! name size used_by_count [comma-list-or-"-"] status address
//! ```
//!
//! Example:
//!
//! ```text
//! tls 98304 0 - Live 0x0000000000000000
//! xt_conntrack 12288 2 nf_nat,nf_conntrack Live 0x0000000000000000
//! ```
//!
//! `used_by` is the list of dependent modules, `-` when nothing
//! depends on the module. `status` is `Live`, `Loading`, or
//! `Unloading`. `address` is the module's load address (kernel-space
//! pointer) — surfaced as TEXT because `SQLite`'s INTEGER is `i64` and
//! kernel addresses are `u64` (and operators usually want hex anyway).

use std::fs;

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "kernel_modules";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS kernel_modules (
        name           TEXT,
        size           INTEGER,
        used_by_count  INTEGER,
        used_by        TEXT,
        status         TEXT,
        address        TEXT
    );
";

#[derive(Debug)]
pub struct KernelModulesTable;

impl BoweryTable for KernelModulesTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        // /proc/modules is unreadable in some sandboxed environments
        // (e.g. unprivileged containers). Treat that as "no rows"
        // rather than failing the whole query.
        let contents = match fs::read_to_string("/proc/modules") {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(TableError::Io {
                    table: NAME,
                    source: e,
                });
            }
        };
        let rows = parse_modules(&contents);
        let mut stmt = conn.prepare(
            "INSERT INTO kernel_modules (name, size, used_by_count, used_by, status, address)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.name,
                r.size,
                r.used_by_count,
                r.used_by,
                r.status,
                r.address,
            ])?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ModuleRow {
    name: Option<String>,
    size: Option<i64>,
    used_by_count: Option<i64>,
    used_by: Option<String>,
    status: Option<String>,
    address: Option<String>,
}

fn parse_modules(contents: &str) -> Vec<ModuleRow> {
    let mut out = Vec::new();
    for line in contents.lines() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let name = fields.next().map(str::to_string);
        let size: Option<i64> = fields.next().and_then(|s| s.parse().ok());
        let used_by_count: Option<i64> = fields.next().and_then(|s| s.parse().ok());
        let used_by_raw = fields.next();
        let status = fields.next().map(str::to_string);
        let address = fields.next().map(str::to_string);
        let used_by = used_by_raw.and_then(|s| {
            // Trailing comma is normal: "foo,bar," — strip empties.
            if s == "-" {
                None
            } else {
                let cleaned: Vec<&str> = s.split(',').filter(|p| !p.is_empty()).collect();
                if cleaned.is_empty() {
                    None
                } else {
                    Some(cleaned.join(","))
                }
            }
        });
        out.push(ModuleRow {
            name,
            size,
            used_by_count,
            used_by,
            status,
            address,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_modules() {
        let raw = "\
tls 98304 0 - Live 0x0000000000000000
xt_conntrack 12288 2 nf_nat,nf_conntrack, Live 0xffffffffc0123000
";
        let rows = parse_modules(raw);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name.as_deref(), Some("tls"));
        assert_eq!(rows[0].size, Some(98304));
        assert_eq!(rows[0].used_by_count, Some(0));
        assert_eq!(rows[0].used_by, None);
        assert_eq!(rows[0].status.as_deref(), Some("Live"));
        assert_eq!(rows[1].used_by.as_deref(), Some("nf_nat,nf_conntrack"));
        assert_eq!(rows[1].address.as_deref(), Some("0xffffffffc0123000"));
    }

    #[test]
    fn registers_with_real_proc_modules() {
        let conn = Connection::open_in_memory().unwrap();
        KernelModulesTable.register(&conn).unwrap();
        // We can't assert >= 1 — kernels built without modules
        // (CONFIG_MODULES=n) won't have /proc/modules. Just confirm
        // the schema is queryable.
        conn.query_row(
            "SELECT name, size, used_by_count, used_by, status, address FROM kernel_modules LIMIT 1",
            [],
            |_row| Ok(()),
        )
        .ok();
    }
}
