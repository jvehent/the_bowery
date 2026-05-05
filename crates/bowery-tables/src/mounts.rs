//! `mounts` table — parses `/proc/self/mountinfo`.
//!
//! `mountinfo` (kernel-documented at
//! [Documentation/filesystems/proc.rst](https://docs.kernel.org/filesystems/proc.html)
//! § 3.5) is the authoritative per-namespace mount table. Format
//! per line:
//!
//! ```text
//! mount_id parent_id major:minor root mount_point mount_opts \
//!   optional-fields - fs_type source super_opts
//! ```
//!
//! The optional-fields block is variable-length and terminated by
//! ` - ` (dash with surrounding spaces). We split on that
//! separator to recover the post-dash fields reliably.
//!
//! One row per mount entry. Pseudo / virtual filesystems are
//! included on purpose — operators triaging a host want to see
//! `tmpfs`, `proc`, `cgroup2`, etc. just as much as block devices.

use std::fs;

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "mounts";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS mounts (
        mount_id      INTEGER,
        parent_id     INTEGER,
        device        TEXT,
        fs_type       TEXT,
        mount_point   TEXT,
        mount_options TEXT
    );
";

#[derive(Debug)]
pub struct MountsTable;

impl BoweryTable for MountsTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let contents = fs::read_to_string("/proc/self/mountinfo").map_err(|e| TableError::Io {
            table: NAME,
            source: e,
        })?;
        let rows = parse_mountinfo(&contents);
        let mut stmt = conn.prepare(
            "INSERT INTO mounts (mount_id, parent_id, device, fs_type, mount_point, mount_options)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.mount_id,
                r.parent_id,
                r.device,
                r.fs_type,
                r.mount_point,
                r.mount_options,
            ])?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MountRow {
    mount_id: Option<i64>,
    parent_id: Option<i64>,
    device: Option<String>,
    fs_type: Option<String>,
    mount_point: Option<String>,
    mount_options: Option<String>,
}

fn parse_mountinfo(contents: &str) -> Vec<MountRow> {
    let mut out = Vec::new();
    for line in contents.lines() {
        if line.is_empty() {
            continue;
        }
        if let Some(row) = parse_line(line) {
            out.push(row);
        }
    }
    out
}

fn parse_line(line: &str) -> Option<MountRow> {
    // Split on " - " separator that delimits pre-dash and post-dash sections.
    let (pre, post) = line.split_once(" - ")?;
    let mut pre_fields = pre.split_whitespace();
    let mount_id: Option<i64> = pre_fields.next().and_then(|s| s.parse().ok());
    let parent_id: Option<i64> = pre_fields.next().and_then(|s| s.parse().ok());
    let _major_minor = pre_fields.next();
    let _root = pre_fields.next();
    let mount_point = pre_fields.next().map(unescape_mountpoint);
    let mount_options = pre_fields.next().map(str::to_string);
    // Remaining pre fields are optional shared/master/propagate-from
    // tags we don't surface.

    let mut post_fields = post.split_whitespace();
    let fs_type = post_fields.next().map(str::to_string);
    let device = post_fields.next().map(str::to_string);
    Some(MountRow {
        mount_id,
        parent_id,
        device,
        fs_type,
        mount_point,
        mount_options,
    })
}

/// `mountinfo` octal-escapes whitespace and a few other chars in
/// the mount path (e.g. a space becomes `\040`). Decode the common
/// cases so operator queries can match on plain paths.
fn unescape_mountpoint(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // Try to consume 3 octal digits.
            let d1 = chars.peek().copied();
            if let Some(d1c) = d1
                && d1c.is_ascii_digit()
            {
                chars.next();
                let d2 = chars.next();
                let d3 = chars.next();
                if let (Some(d2c), Some(d3c)) = (d2, d3) {
                    let triplet = format!("{d1c}{d2c}{d3c}");
                    if let Ok(byte) = u8::from_str_radix(&triplet, 8) {
                        out.push(byte as char);
                        continue;
                    }
                }
                // Malformed escape — emit raw.
                out.push('\\');
                out.push(d1c);
                if let Some(d2c) = d2 {
                    out.push(d2c);
                }
                if let Some(d3c) = d3 {
                    out.push(d3c);
                }
            } else {
                out.push('\\');
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_mountinfo() {
        let raw = "\
22 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
28 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
75 80 0:29 / /usr/lib/modules rw,nosuid - overlay none rw,lowerdir=/modules
";
        let rows = parse_mountinfo(raw);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].mount_id, Some(22));
        assert_eq!(rows[0].fs_type.as_deref(), Some("sysfs"));
        assert_eq!(rows[0].mount_point.as_deref(), Some("/sys"));
        assert_eq!(rows[1].fs_type.as_deref(), Some("ext4"));
        assert_eq!(rows[1].device.as_deref(), Some("/dev/sda1"));
        assert_eq!(rows[2].mount_point.as_deref(), Some("/usr/lib/modules"));
    }

    #[test]
    fn unescapes_octal_in_mountpoint() {
        let raw = "1 1 0:1 / /mnt/with\\040space rw - tmpfs none rw";
        let rows = parse_mountinfo(raw);
        assert_eq!(rows[0].mount_point.as_deref(), Some("/mnt/with space"));
    }

    #[test]
    fn registers_real_mounts() {
        let conn = Connection::open_in_memory().unwrap();
        MountsTable.register(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM mounts", [], |row| row.get(0))
            .unwrap();
        assert!(count >= 1, "host must have at least one mount");
        // Root or /proc must be present on any Linux host.
        let common: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM mounts WHERE mount_point IN ('/', '/proc')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(common >= 1, "expected '/' or '/proc' mount");
    }
}
