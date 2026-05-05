//! `crontab` table — system cron entries from `/etc/crontab` and
//! `/etc/cron.d/*`.
//!
//! Only system crontabs are surfaced — they have a `user` field
//! between the schedule and the command, which user crontabs
//! (`/var/spool/cron/crontabs/<user>`) lack. Including user
//! crontabs would either misalign the schema or require root to
//! read, both worse than the operator running a separate query
//! once user-context cron becomes load-bearing.
//!
//! Format per line:
//!
//! ```text
//! MIN  HOUR  DOM  MON  DOW  USER  COMMAND...
//! ```
//!
//! Lines starting with `#` are comments. Blank lines and
//! environment assignments (`KEY=VALUE`) are skipped — they're
//! cron-runtime config, not jobs. The `@reboot` / `@daily` /
//! `@hourly` / etc. shortcuts surface as a single-token
//! schedule in the `minute` column with the rest set to NULL,
//! so operators can `WHERE minute LIKE '@%'` to find them.

use std::fs;
use std::path::Path;

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "crontab";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS crontab (
        minute        TEXT,
        hour          TEXT,
        day_of_month  TEXT,
        month         TEXT,
        day_of_week   TEXT,
        user          TEXT,
        command       TEXT,
        path          TEXT
    );
";

#[derive(Debug)]
pub struct CrontabTable;

impl BoweryTable for CrontabTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let mut rows = Vec::new();
        if let Ok(contents) = fs::read_to_string("/etc/crontab") {
            rows.extend(parse_system_crontab(&contents, "/etc/crontab"));
        }
        if let Ok(entries) = fs::read_dir("/etc/cron.d") {
            for entry in entries.flatten() {
                let path = entry.path();
                if !looks_like_crontab(&path) {
                    continue;
                }
                if let Ok(contents) = fs::read_to_string(&path) {
                    let path_str = path.to_str().unwrap_or("/etc/cron.d");
                    rows.extend(parse_system_crontab(&contents, path_str));
                }
            }
        }
        let mut stmt = conn.prepare(
            "INSERT INTO crontab (minute, hour, day_of_month, month, day_of_week,
                                  user, command, path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.minute,
                r.hour,
                r.day_of_month,
                r.month,
                r.day_of_week,
                r.user,
                r.command,
                r.path,
            ])?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CronRow {
    minute: Option<String>,
    hour: Option<String>,
    day_of_month: Option<String>,
    month: Option<String>,
    day_of_week: Option<String>,
    user: Option<String>,
    command: Option<String>,
    path: String,
}

/// Conservative filename filter for `/etc/cron.d`. Debian/Ubuntu's
/// `run-parts` rejects names containing dots or unusual chars; we
/// don't enforce that strictly (operators may keep `.bak` files
/// they don't want surfaced), but we do skip dotfiles outright.
fn looks_like_crontab(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    !name.starts_with('.') && path.is_file()
}

fn parse_system_crontab(contents: &str, path: &str) -> Vec<CronRow> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Environment assignments: KEY=VALUE with no whitespace
        // before the '='. Skip them.
        if is_env_assignment(trimmed) {
            continue;
        }
        if let Some(row) = parse_crontab_line(trimmed, path) {
            out.push(row);
        }
    }
    out
}

fn is_env_assignment(line: &str) -> bool {
    let Some(eq_idx) = line.find('=') else {
        return false;
    };
    let key = &line[..eq_idx];
    !key.is_empty() && !key.contains(char::is_whitespace)
}

fn parse_crontab_line(line: &str, path: &str) -> Option<CronRow> {
    if let Some(rest) = line.strip_prefix('@') {
        // shortcut form: @daily, @reboot, etc.
        let (token, command) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let (user, command) = split_user_command(command)?;
        return Some(CronRow {
            minute: Some(format!("@{token}")),
            hour: None,
            day_of_month: None,
            month: None,
            day_of_week: None,
            user: Some(user),
            command: Some(command),
            path: path.to_string(),
        });
    }
    let mut iter = line.splitn(7, char::is_whitespace);
    let minute = iter.next()?;
    let hour = iter.next()?;
    let dom = iter.next()?;
    let mon = iter.next()?;
    let dow = iter.next()?;
    let user = iter.next()?;
    let command = iter.next().unwrap_or("").trim();
    if command.is_empty() {
        return None;
    }
    Some(CronRow {
        minute: Some(minute.to_string()),
        hour: Some(hour.to_string()),
        day_of_month: Some(dom.to_string()),
        month: Some(mon.to_string()),
        day_of_week: Some(dow.to_string()),
        user: Some(user.to_string()),
        command: Some(command.to_string()),
        path: path.to_string(),
    })
}

fn split_user_command(rest: &str) -> Option<(String, String)> {
    let rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }
    let (user, command) = rest.split_once(char::is_whitespace)?;
    Some((user.to_string(), command.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_system_crontab() {
        let raw = "\
# header comment
SHELL=/bin/sh
PATH=/usr/sbin:/usr/bin

30 3 * * 0 root /usr/lib/foo/bar -A -r
*/5 * * * * nobody true
@daily root /usr/local/bin/nightly
";
        let rows = parse_system_crontab(raw, "/etc/crontab");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].minute.as_deref(), Some("30"));
        assert_eq!(rows[0].hour.as_deref(), Some("3"));
        assert_eq!(rows[0].day_of_week.as_deref(), Some("0"));
        assert_eq!(rows[0].user.as_deref(), Some("root"));
        assert!(
            rows[0]
                .command
                .as_deref()
                .unwrap()
                .contains("/usr/lib/foo/bar")
        );
        assert_eq!(rows[1].user.as_deref(), Some("nobody"));
        assert_eq!(rows[2].minute.as_deref(), Some("@daily"));
        assert_eq!(rows[2].hour, None);
        assert_eq!(rows[2].user.as_deref(), Some("root"));
        assert_eq!(rows[2].command.as_deref(), Some("/usr/local/bin/nightly"));
    }

    #[test]
    fn registers_table() {
        let conn = Connection::open_in_memory().unwrap();
        CrontabTable.register(&conn).unwrap();
        // CI containers may have empty/no crontab — schema must
        // be queryable regardless.
        let _: i64 = conn
            .query_row("SELECT COUNT(*) FROM crontab", [], |row| row.get(0))
            .unwrap();
    }

    #[test]
    fn ignores_environment_lines() {
        assert!(is_env_assignment("PATH=/usr/bin"));
        assert!(is_env_assignment("MAILTO=root"));
        assert!(!is_env_assignment("0 1 * * * root /bin/true"));
        assert!(!is_env_assignment("# 0 1 * * * /bin/true"));
    }
}
