//! `os_version` table — parses `/etc/os-release`.
//!
//! Every modern Linux distro ships an `/etc/os-release` shell-style
//! file with stable keys (`ID`, `NAME`, `VERSION`, `VERSION_ID`,
//! `VERSION_CODENAME`, `BUILD_ID`, `PRETTY_NAME`). The full schema
//! is documented at [systemd.io/OS_RELEASE](https://systemd.io/OS_RELEASE/);
//! we surface the common subset.
//!
//! Always one row. Missing keys arrive as `NULL` so operators can
//! distinguish "key absent in this distro" from "empty value".

use std::fs;
use std::path::Path;

use rusqlite::{Connection, params};
use tracing::warn;

use crate::{BoweryTable, TableError};

const NAME: &str = "os_version";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS os_version (
        id           TEXT,
        name         TEXT,
        version      TEXT,
        version_id   TEXT,
        codename     TEXT,
        build_id     TEXT,
        pretty_name  TEXT
    );
";

const OS_RELEASE_PATHS: &[&str] = &["/etc/os-release", "/usr/lib/os-release"];

#[derive(Debug)]
pub struct OsVersionTable;

impl BoweryTable for OsVersionTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let row = read_os_release().unwrap_or_default();
        conn.execute(
            "INSERT INTO os_version (id, name, version, version_id, codename, build_id, pretty_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.id,
                row.name,
                row.version,
                row.version_id,
                row.codename,
                row.build_id,
                row.pretty_name,
            ],
        )?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct OsRelease {
    id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    version_id: Option<String>,
    codename: Option<String>,
    build_id: Option<String>,
    pretty_name: Option<String>,
}

/// Parse the first os-release file we find. Returns `None` if neither
/// path is readable; never panics on malformed input — unrecognised
/// keys are dropped, malformed lines logged at warn level.
fn read_os_release() -> Option<OsRelease> {
    for candidate in OS_RELEASE_PATHS {
        if Path::new(candidate).is_file() {
            match fs::read_to_string(candidate) {
                Ok(contents) => return Some(parse_os_release(&contents)),
                Err(e) => warn!(path = candidate, error = %e, "read os-release failed"),
            }
        }
    }
    None
}

/// Shell-style key=value parser. Handles double- and single-quoted
/// values; unquoted values stop at the first whitespace.
fn parse_os_release(contents: &str) -> OsRelease {
    let mut out = OsRelease::default();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = unquote(value).to_string();
        match key {
            "ID" => out.id = Some(value),
            "NAME" => out.name = Some(value),
            "VERSION" => out.version = Some(value),
            "VERSION_ID" => out.version_id = Some(value),
            "VERSION_CODENAME" => out.codename = Some(value),
            "BUILD_ID" => out.build_id = Some(value),
            "PRETTY_NAME" => out.pretty_name = Some(value),
            _ => {} // ignore the long tail
        }
    }
    out
}

fn unquote(raw: &str) -> &str {
    let raw = raw.trim();
    if raw.len() >= 2 {
        let bytes = raw.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &raw[1..raw.len() - 1];
        }
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_os_release() {
        let raw = r#"
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
VERSION_ID="22.04"
VERSION_CODENAME=jammy
PRETTY_NAME="Ubuntu 22.04.3 LTS"
HOME_URL="https://www.ubuntu.com/"
"#;
        let parsed = parse_os_release(raw);
        assert_eq!(parsed.id.as_deref(), Some("ubuntu"));
        assert_eq!(parsed.name.as_deref(), Some("Ubuntu"));
        assert_eq!(parsed.version_id.as_deref(), Some("22.04"));
        assert_eq!(parsed.codename.as_deref(), Some("jammy"));
        assert!(parsed.pretty_name.unwrap().contains("Ubuntu"));
    }

    #[test]
    fn registers_one_row_with_full_schema() {
        let conn = Connection::open_in_memory().unwrap();
        OsVersionTable.register(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM os_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        // Column shape is stable.
        conn.query_row(
            "SELECT id, name, version, version_id, codename, build_id, pretty_name FROM os_version",
            [],
            |_row| Ok(()),
        )
        .unwrap();
    }
}
