//! `systemd_units` table — on-disk inventory of systemd unit files.
//!
//! Slice-5 scope is intentionally narrow: enumerate every unit
//! file under the standard search paths and surface the static
//! metadata operators usually want — name, type, description,
//! `ExecStart`, file path. Runtime state (active/inactive,
//! enabled/disabled) needs D-Bus or `systemctl`; that's queued
//! for a Slice-8 follow-up where the agent already speaks D-Bus
//! for other purposes.
//!
//! Search paths, in standard systemd precedence order:
//! - `/etc/systemd/system` (operator-edited overrides)
//! - `/run/systemd/system` (transient)
//! - `/usr/lib/systemd/system` (vendor)
//! - `/lib/systemd/system` (vendor, on distros without the
//!   /usr-merge symlink)
//!
//! We yield one row per unique unit *name* — if the same unit
//! exists in multiple paths, only the first (highest-precedence)
//! win is kept. That mirrors how systemd itself resolves overrides.
//!
//! Drop-in directories (`<unit>.d/*.conf`) are not merged in this
//! slice; an operator wanting the merged view can issue
//! `systemctl cat <unit>` out-of-band. Rare enough to defer.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "systemd_units";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS systemd_units (
        name        TEXT,
        type        TEXT,
        description TEXT,
        exec_start  TEXT,
        path        TEXT
    );
";

const SEARCH_PATHS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

#[derive(Debug)]
pub struct SystemdUnitsTable;

impl BoweryTable for SystemdUnitsTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let rows = collect();
        let mut stmt = conn.prepare(
            "INSERT INTO systemd_units (name, type, description, exec_start, path)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.name,
                r.unit_type,
                r.description,
                r.exec_start,
                r.path
            ])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct UnitRow {
    name: String,
    unit_type: Option<String>,
    description: Option<String>,
    exec_start: Option<String>,
    path: String,
}

fn collect() -> Vec<UnitRow> {
    let mut by_name: HashMap<String, UnitRow> = HashMap::new();
    for dir in SEARCH_PATHS {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            // Skip .wants / .requires / .d directories — those are
            // dependency or drop-in subdirs, not units.
            if !is_unit_file(name) {
                continue;
            }
            // First-write-wins, so iteration order across SEARCH_PATHS
            // dictates precedence (higher-priority dirs come first).
            if by_name.contains_key(name) {
                continue;
            }
            let path = entry.path();
            if let Some(row) = parse_unit(name, &path) {
                by_name.insert(name.to_string(), row);
            }
        }
    }
    let mut out: Vec<UnitRow> = by_name.into_values().collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn is_unit_file(name: &str) -> bool {
    const EXTS: &[&str] = &[
        ".service",
        ".socket",
        ".target",
        ".timer",
        ".mount",
        ".automount",
        ".path",
        ".swap",
        ".slice",
        ".scope",
        ".device",
    ];
    EXTS.iter().any(|e| name.ends_with(e))
}

fn parse_unit(name: &str, path: &Path) -> Option<UnitRow> {
    let unit_type = name.rsplit('.').next().map(str::to_string);
    let path_str = path.to_str()?.to_string();
    let mut row = UnitRow {
        name: name.to_string(),
        unit_type,
        description: None,
        exec_start: None,
        path: path_str,
    };
    let Ok(contents) = fs::read_to_string(path) else {
        return Some(row);
    };
    let mut section: Option<&str> = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(stripped) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = match stripped {
                "Unit" => Some("Unit"),
                "Service" => Some("Service"),
                _ => Some("Other"),
            };
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match (section, key) {
            (Some("Unit"), "Description") if row.description.is_none() => {
                row.description = Some(value.to_string());
            }
            (Some("Service"), "ExecStart") if row.exec_start.is_none() => {
                row.exec_start = Some(value.to_string());
            }
            _ => {}
        }
    }
    Some(row)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn registers_table() {
        let conn = Connection::open_in_memory().unwrap();
        SystemdUnitsTable.register(&conn).unwrap();
        // We can't assert >= 1 — minimal containers have no
        // systemd. Schema must be queryable regardless.
        let _: i64 = conn
            .query_row("SELECT COUNT(*) FROM systemd_units", [], |row| row.get(0))
            .unwrap();
    }

    #[test]
    fn is_unit_file_recognises_common_extensions() {
        assert!(is_unit_file("cron.service"));
        assert!(is_unit_file("multi-user.target"));
        assert!(is_unit_file("logrotate.timer"));
        assert!(!is_unit_file("cron.service.d"));
        assert!(!is_unit_file("multi-user.target.wants"));
        assert!(!is_unit_file("README"));
    }

    #[test]
    fn parses_synthesized_unit() {
        // Use a tempfile so the parser sees a real on-disk file.
        let dir = tempdir();
        let path = dir.join("test.service");
        fs::write(
            &path,
            "[Unit]\nDescription=Test Service\n# comment\n[Service]\nExecStart=/usr/bin/true\n",
        )
        .unwrap();
        let row = parse_unit("test.service", &path).unwrap();
        assert_eq!(row.name, "test.service");
        assert_eq!(row.unit_type.as_deref(), Some("service"));
        assert_eq!(row.description.as_deref(), Some("Test Service"));
        assert_eq!(row.exec_start.as_deref(), Some("/usr/bin/true"));
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bowery-systemd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
}
