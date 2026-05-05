//! Phase-9 SQL engine.
//!
//! [`Sql::query`] runs a single operator-supplied SQL statement
//! against a freshly-built in-memory `SQLite` database populated by
//! `bowery-tables` at registration time. Returns one row at a time
//! as [`Row`] (slice 1 collects them in-memory; streaming arrives
//! in slice 6 with the wire format).
//!
//! [`Sql::query`]: Sql::query
//! [`Row`]: Row
//!
//! ## Lifetime model
//!
//! Each `query()` call gets its own `Connection`, registers every
//! table from the default set, runs the user's SQL, returns the
//! rows, and drops the connection. No connection caching, no
//! shared state — slow-changing tables (`os_version`, `users`)
//! re-read their source per query, but that's microseconds
//! compared to the tokio scheduling overhead and not worth a cache
//! that complicates the cancellation story.
//!
//! ## Timeout
//!
//! The whole `query()` runs inside `tokio::task::spawn_blocking`,
//! wrapped in `tokio::time::timeout`. If the user's SQL stalls
//! (e.g., an infinite recursive CTE), the wall-clock deadline
//! fires and the future is dropped — but the `spawn_blocking` task
//! continues to completion in the blocking pool. `SQLite`'s
//! progress-handler-based cooperative cancellation lands in slice
//! 6 alongside the streaming wire format.

#![warn(unreachable_pub)]

use std::time::Duration;

use rusqlite::Connection;
use rusqlite::types::Value;
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum SqlError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("table registration: {0}")]
    Tables(#[from] bowery_tables::TableError),

    #[error("query timed out after {0:?}")]
    Timeout(Duration),

    #[error("query returned more than {limit} rows; refused")]
    RowCapExceeded { limit: usize },

    #[error("query worker panicked")]
    Cancelled,
}

/// Cap on rows a single query may return. Defends against an
/// operator query that joins every table against itself producing
/// pathological output. 1 M is well above any reasonable single
/// agent's table sizes (~tens of thousands of /proc rows worst
/// case).
pub const DEFAULT_ROW_CAP: usize = 1_000_000;

/// One row in the result set. Column order matches the order
/// `SQLite` returned (i.e. the SELECT's projection order).
#[derive(Debug, Clone)]
pub struct Row {
    pub columns: Vec<(String, Value)>,
}

/// SQL engine handle. Cheap to construct; the actual connection
/// lives only inside `query()`. Hold one per agent or per call —
/// it makes no difference.
#[derive(Debug, Clone, Default)]
pub struct Sql {
    row_cap: usize,
}

impl Sql {
    pub fn new() -> Self {
        Self {
            row_cap: DEFAULT_ROW_CAP,
        }
    }

    #[must_use]
    pub fn with_row_cap(mut self, cap: usize) -> Self {
        self.row_cap = cap.max(1);
        self
    }

    /// Run `sql` against the registered table set, capped at
    /// `timeout` wall-clock and `self.row_cap` rows.
    pub async fn query(&self, sql: &str, timeout: Duration) -> Result<Vec<Row>, SqlError> {
        let row_cap = self.row_cap;
        let sql = sql.to_string();
        let join = tokio::task::spawn_blocking(move || run_blocking(&sql, row_cap));
        match tokio::time::timeout(timeout, join).await {
            Ok(Ok(result)) => result,
            Ok(Err(_join_err)) => Err(SqlError::Cancelled),
            Err(_) => Err(SqlError::Timeout(timeout)),
        }
    }
}

/// Synchronous query runner — opens a connection, registers every
/// table, prepares + steps the user's SQL, collects rows.
fn run_blocking(sql: &str, row_cap: usize) -> Result<Vec<Row>, SqlError> {
    let conn = Connection::open_in_memory()?;
    bowery_tables::register_all(&conn)?;
    debug!(
        sql_preview = sql.chars().take(80).collect::<String>(),
        "running SQL"
    );

    let mut stmt = conn.prepare(sql)?;
    let column_names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(str::to_string)
        .collect();
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        if out.len() >= row_cap {
            return Err(SqlError::RowCapExceeded { limit: row_cap });
        }
        let mut cells = Vec::with_capacity(column_names.len());
        for (idx, name) in column_names.iter().enumerate() {
            let v = row.get_ref(idx)?;
            cells.push((name.clone(), value_from_ref(v)));
        }
        out.push(Row { columns: cells });
    }
    Ok(out)
}

fn value_from_ref(v: rusqlite::types::ValueRef<'_>) -> Value {
    match v {
        rusqlite::types::ValueRef::Null => Value::Null,
        rusqlite::types::ValueRef::Integer(i) => Value::Integer(i),
        rusqlite::types::ValueRef::Real(f) => Value::Real(f),
        rusqlite::types::ValueRef::Text(b) => {
            // `SQLite` TEXT is loosely UTF-8; the rusqlite ValueRef API
            // returns &[u8] so we lossy-decode for transport. Rare in
            // practice — every table here writes legitimate UTF-8.
            Value::Text(String::from_utf8_lossy(b).into_owned())
        }
        rusqlite::types::ValueRef::Blob(b) => Value::Blob(b.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn select_one_returns_one_row() {
        let sql = Sql::new();
        let rows = sql
            .query("SELECT 1 AS one", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].columns[0].0, "one");
        assert!(matches!(rows[0].columns[0].1, Value::Integer(1)));
    }

    #[tokio::test]
    async fn os_version_table_is_queryable() {
        let sql = Sql::new();
        let rows = sql
            .query(
                "SELECT id, name, pretty_name FROM os_version",
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "os_version must produce exactly one row");
        // Every column reachable; values may be NULL on hosts without
        // a populated /etc/os-release.
        assert_eq!(rows[0].columns.len(), 3);
    }

    #[tokio::test]
    async fn system_info_table_is_queryable() {
        let sql = Sql::new();
        let rows = sql
            .query(
                "SELECT hostname, kernel_version, cpu_logical_cores FROM system_info",
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        // hostname + kernel are reliable on any Linux test host.
        match &rows[0].columns[0].1 {
            Value::Text(s) => assert!(!s.is_empty(), "hostname must resolve"),
            other => panic!("hostname must be Text, got {other:?}"),
        }
        match &rows[0].columns[1].1 {
            Value::Text(s) => assert!(!s.is_empty(), "kernel_version must resolve"),
            other => panic!("kernel_version must be Text, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn slice_2_tables_are_queryable() {
        // Smoke test: every Phase-9 slice-2 table accepts a basic
        // projection. We don't assert on row counts beyond what's
        // load-bearing (loopback for `interfaces`, self-pid for
        // `processes`, root mount for `mounts`) — the per-table
        // tests cover correctness; this just confirms registration
        // wired them onto the shared connection.
        let sql = Sql::new();
        for table in ["processes", "mounts", "kernel_modules", "interfaces"] {
            let q = format!("SELECT COUNT(*) AS n FROM {table}");
            let rows = sql.query(&q, Duration::from_secs(2)).await.unwrap();
            assert_eq!(rows.len(), 1, "{table}: COUNT(*) must return one row");
        }
        // Cross-table sanity: every process must reference a real
        // mount-relevant fs (loose join — not a referential check,
        // just confirms two slice-2 tables coexist on the same conn).
        let rows = sql
            .query(
                "SELECT processes.pid FROM processes, interfaces WHERE interfaces.name = 'lo' LIMIT 1",
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn slice_3_network_tables_are_queryable() {
        // Smoke test: every slice-3 network table accepts a basic
        // projection. Sandbox/CI hosts may have empty /proc/net so
        // we don't assert on row counts.
        let sql = Sql::new();
        for table in ["listening_ports", "process_open_sockets"] {
            let q = format!("SELECT COUNT(*) AS n FROM {table}");
            let rows = sql.query(&q, Duration::from_secs(2)).await.unwrap();
            assert_eq!(rows.len(), 1, "{table}: COUNT(*) must return one row");
        }
        // Inode-based JOIN matches the documented usage pattern.
        let rows = sql
            .query(
                "SELECT process_open_sockets.pid, listening_ports.port
                 FROM process_open_sockets
                 JOIN listening_ports USING (inode)
                 LIMIT 5",
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        // The query must execute even if 0 rows match.
        assert!(rows.len() <= 5);
    }

    #[tokio::test]
    async fn slice_4_identity_tables_are_queryable() {
        let sql = Sql::new();
        for table in ["users", "logged_in_users", "last"] {
            let q = format!("SELECT COUNT(*) AS n FROM {table}");
            let rows = sql.query(&q, Duration::from_secs(2)).await.unwrap();
            assert_eq!(rows.len(), 1, "{table}: COUNT(*) must return one row");
        }
        // root must be queryable on any Linux host.
        let rows = sql
            .query(
                "SELECT username, uid FROM users WHERE uid = 0",
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(!rows.is_empty(), "root must appear in users");
    }

    #[tokio::test]
    async fn slice_5_service_tables_are_queryable() {
        let sql = Sql::new();
        for table in ["systemd_units", "crontab"] {
            let q = format!("SELECT COUNT(*) AS n FROM {table}");
            let rows = sql.query(&q, Duration::from_secs(2)).await.unwrap();
            assert_eq!(rows.len(), 1, "{table}: COUNT(*) must return one row");
        }
    }

    #[tokio::test]
    async fn join_across_tables_works() {
        // Cross-product across two single-row tables — sanity that
        // we have a working SQL engine, not just two separate
        // SELECT * paths.
        let sql = Sql::new();
        let rows = sql
            .query(
                "SELECT os_version.id, system_info.hostname FROM os_version, system_info",
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn syntax_error_is_reported_cleanly() {
        let sql = Sql::new();
        let err = sql
            .query("SELECT * FROM does_not_exist", Duration::from_secs(2))
            .await
            .expect_err("missing table");
        assert!(matches!(err, SqlError::Sqlite(_)));
    }

    #[tokio::test]
    async fn row_cap_is_enforced() {
        let sql = Sql::new().with_row_cap(2);
        // recursive CTE producing 1000 rows
        let err = sql
            .query(
                "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 1000)
                 SELECT x FROM c",
                Duration::from_secs(2),
            )
            .await
            .expect_err("must hit row cap");
        assert!(matches!(err, SqlError::RowCapExceeded { limit: 2 }));
    }
}
