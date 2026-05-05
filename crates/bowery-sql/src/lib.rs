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

use std::sync::Arc;
use std::time::Duration;

use bowery_tables::BoweryTable;
use rusqlite::Connection;
pub use rusqlite::types::Value;
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
/// it makes no difference. `extra_tables` are registered on every
/// connection alongside the default Phase-9 set; this is how
/// agent-state-aware tables (`bowery_peers`, `bowery_alerts`,
/// etc.) get plumbed in without bowery-tables having to depend
/// on the agent crate.
#[derive(Clone, Default)]
pub struct Sql {
    row_cap: usize,
    extra_tables: Vec<Arc<dyn BoweryTable>>,
    /// Phase-9 final-4 + final-5: when non-empty, default tables
    /// matching one of these names are skipped during
    /// registration. Lets the agent substitute a privileged
    /// instance (e.g. `ProcessesTable::new(expose_cmdline=true)`)
    /// for the default instance without the second registration
    /// inserting duplicate rows.
    overridden_defaults: Vec<&'static str>,
    /// SECURITY-AUDIT-PHASE9 F-13: maximum concurrent queries.
    /// Each query opens a fresh in-memory `SQLite` + walks all
    /// tables; concurrent operators scale that linearly. The
    /// semaphore holds back queries past the cap until earlier
    /// ones drain. `None` = unbounded (today's behaviour).
    concurrency_cap: Option<Arc<tokio::sync::Semaphore>>,
}

impl std::fmt::Debug for Sql {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sql")
            .field("row_cap", &self.row_cap)
            .field("extra_table_count", &self.extra_tables.len())
            .field("overridden_defaults", &self.overridden_defaults)
            .field("concurrency_cap", &self.concurrency_cap.is_some())
            .finish()
    }
}

impl Sql {
    pub fn new() -> Self {
        Self {
            row_cap: DEFAULT_ROW_CAP,
            extra_tables: Vec::new(),
            overridden_defaults: Vec::new(),
            concurrency_cap: None,
        }
    }

    #[must_use]
    pub fn with_row_cap(mut self, cap: usize) -> Self {
        self.row_cap = cap.max(1);
        self
    }

    /// Register an additional table on every query connection.
    /// Use this for tables whose data source needs agent-specific
    /// state (`bowery-baseline` handle, `KnownNeighbors`, the
    /// alert inbox, etc.) that `bowery-tables` doesn't depend on.
    /// Order is preserved across calls but irrelevant — each table
    /// owns its own schema.
    #[must_use]
    pub fn with_extra_table(mut self, table: Arc<dyn BoweryTable>) -> Self {
        self.extra_tables.push(table);
        self
    }

    /// Skip a default `bowery-tables` entry by name. Use together
    /// with `with_extra_table(custom_instance)` to substitute a
    /// configured table (e.g. the agent's `ProcessesTable` with
    /// `expose_cmdline = true`) for the default-default-config
    /// version.
    #[must_use]
    pub fn override_default_table(mut self, name: &'static str) -> Self {
        self.overridden_defaults.push(name);
        self
    }

    /// Cap the number of concurrent `query()` invocations.
    /// SECURITY-AUDIT-PHASE9 F-13: each query opens a fresh
    /// in-memory `SQLite` and registers every table; without a cap
    /// concurrent operators scale memory + CPU linearly. Default
    /// `None` (unbounded); pass `Some(N)` to enforce.
    #[must_use]
    pub fn with_concurrency_cap(mut self, cap: usize) -> Self {
        if cap > 0 {
            self.concurrency_cap = Some(Arc::new(tokio::sync::Semaphore::new(cap)));
        }
        self
    }

    /// Run `sql` against the registered table set, capped at
    /// `timeout` wall-clock and `self.row_cap` rows.
    pub async fn query(&self, sql: &str, timeout: Duration) -> Result<Vec<Row>, SqlError> {
        let row_cap = self.row_cap;
        let sql = sql.to_string();
        let extras = self.extra_tables.clone();
        let overrides = self.overridden_defaults.clone();
        // Phase-9 final-5 / F-13: hold a semaphore permit across
        // the whole query (including the spawn_blocking +
        // timeout). Cap doesn't apply when concurrency_cap is
        // None — preserves today's unbounded default for
        // standalone Sql users.
        let _permit = if let Some(sem) = self.concurrency_cap.as_ref() {
            Some(
                Arc::clone(sem)
                    .acquire_owned()
                    .await
                    .map_err(|_| SqlError::Cancelled)?,
            )
        } else {
            None
        };
        // Phase-9 final-6 / F-14: cooperative cancellation. When
        // the wall-clock timeout fires, we set
        // `cancel_flag.store(true)`; the `progress_handler`
        // installed inside `run_blocking` polls it every 1024
        // VDBE ops and returns `true` (interrupt) on cancel.
        // Without this, SQLite would happily walk a recursive CTE
        // for hours after our future was dropped, holding a
        // blocking-pool slot until completion.
        let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_for_blocking = cancel_flag.clone();
        let join = tokio::task::spawn_blocking(move || {
            run_blocking(&sql, row_cap, &extras, &overrides, &cancel_for_blocking)
        });
        let outcome = tokio::time::timeout(timeout, join).await;
        // Always raise the flag — even on success, where it's a
        // no-op. On timeout, this is what kicks the running
        // query out of its inner loop.
        cancel_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        match outcome {
            Ok(Ok(result)) => result,
            Ok(Err(_join_err)) => Err(SqlError::Cancelled),
            Err(_) => Err(SqlError::Timeout(timeout)),
        }
    }
}

/// Synchronous query runner — opens a connection, registers every
/// table (default set + caller-supplied extras), installs a
/// SELECT-only `set_authorizer` gate, then prepares + steps the
/// user's SQL and collects rows.
///
/// The authorizer is **disabled during registration** so each
/// `BoweryTable::register` impl is free to `CREATE TABLE` and
/// `INSERT` its rows. After registration we install a hook that
/// allows reads (`Read` / `Select` / `Recursive` / `Function`)
/// and a small whitelist of harmless `Pragma`s, but denies every
/// destructive or escape-prone op (`Attach`, `Detach`, `Pragma
/// writable_schema`, `Insert`/`Update`/`Delete`, `Create*`,
/// `Drop*`, `AlterTable`, `Transaction`, `Savepoint`, …). This
/// closes the SECURITY-AUDIT-PHASE9 F-15 escape — operators can no
/// longer `ATTACH DATABASE 'file:///etc/passwd' AS x` or use
/// `PRAGMA writable_schema = ON` to force-write the in-memory db.
fn run_blocking(
    sql: &str,
    row_cap: usize,
    extras: &[Arc<dyn BoweryTable>],
    overrides: &[&'static str],
    cancel_flag: &Arc<std::sync::atomic::AtomicBool>,
) -> Result<Vec<Row>, SqlError> {
    let conn = Connection::open_in_memory()?;
    // Skip default tables whose names appear in `overrides` —
    // the caller will register a replacement via `extras`.
    for table in bowery_tables::default_tables() {
        if overrides.contains(&table.name()) {
            continue;
        }
        table.register(&conn)?;
    }
    for extra in extras {
        extra.register(&conn)?;
    }
    install_select_only_authorizer(&conn);
    // Phase-9 final-6 / F-14: cooperative cancellation. The
    // closure returns `true` to interrupt; SQLite calls it every
    // ~1024 VDBE ops, so even a pathological CTE notices the
    // cancel within a few ms.
    let cancel_for_handler = cancel_flag.clone();
    conn.progress_handler(
        1024,
        Some(move || cancel_for_handler.load(std::sync::atomic::Ordering::Relaxed)),
    );
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

/// Install a SELECT-only authorizer hook on `conn`. Allows row
/// reads + a small whitelist of read-only pragmas; denies every
/// other op so an operator-supplied `ATTACH`, `PRAGMA
/// writable_schema = ON`, `DROP`, `INSERT`, etc. cannot escape
/// the in-memory connection or modify Bowery state.
fn install_select_only_authorizer(conn: &Connection) {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Pragmas that are read-only / inspection-only and don't
    /// expose a writable side effect. Anything else is denied.
    const SAFE_PRAGMAS: &[&str] = &[
        "table_info",
        "index_list",
        "index_info",
        "database_list",
        "foreign_key_list",
        "compile_options",
        "encoding",
    ];

    conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
        // Operator queries: SELECT, recursive CTE, and read-row
        // operations against any registered table. Function calls
        // are allowed too (e.g. `length(x)`, aggregates) — SQLite
        // treats `length`/`coalesce`/`count` as Function actions.
        AuthAction::Select
        | AuthAction::Read { .. }
        | AuthAction::Function { .. }
        | AuthAction::Recursive => Authorization::Allow,

        // Whitelisted read-only pragmas only.
        AuthAction::Pragma {
            pragma_name,
            pragma_value,
        } => {
            if pragma_value.is_some() {
                // any `PRAGMA x = y` is a write — deny.
                Authorization::Deny
            } else if SAFE_PRAGMAS.contains(&pragma_name) {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }

        // Everything else: ATTACH / DETACH / DROP / CREATE / ALTER /
        // INSERT / UPDATE / DELETE / TRANSACTION / SAVEPOINT /
        // TRIGGER / VIEW / INDEX / VTABLE / unknown — denied.
        _ => Authorization::Deny,
    }));
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
    async fn authorizer_blocks_attach_database() {
        // SECURITY-AUDIT-PHASE9 F-15: an operator-supplied
        // `ATTACH DATABASE` statement is denied by the SELECT-only
        // authorizer, even though SQLite would otherwise accept it.
        let sql = Sql::new();
        let err = sql
            .query(
                "ATTACH DATABASE 'file:///tmp/bowery-attack.db' AS x",
                Duration::from_secs(2),
            )
            .await
            .expect_err("attach must be denied");
        assert!(
            matches!(err, SqlError::Sqlite(_)),
            "expected sqlite-level denial, got {err:?}"
        );
    }

    #[tokio::test]
    async fn authorizer_blocks_writable_schema_pragma() {
        // SECURITY-AUDIT-PHASE9 F-15: `PRAGMA writable_schema = ON`
        // is a write to a pragma, which the authorizer denies.
        let sql = Sql::new();
        let err = sql
            .query("PRAGMA writable_schema = ON", Duration::from_secs(2))
            .await
            .expect_err("write-pragma must be denied");
        assert!(matches!(err, SqlError::Sqlite(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn authorizer_blocks_drop_table() {
        // Operator SQL trying to drop one of our registered tables
        // is denied. (Even if it weren't, the in-memory connection
        // is fresh per query — but rejecting up-front gives the
        // operator a structured error instead of a half-executed
        // statement.)
        let sql = Sql::new();
        let err = sql
            .query("DROP TABLE processes", Duration::from_secs(2))
            .await
            .expect_err("drop must be denied");
        assert!(matches!(err, SqlError::Sqlite(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn authorizer_allows_read_only_pragma() {
        // PRAGMA database_list and friends are read-only and should
        // pass — useful for operators introspecting the registered
        // table set.
        let sql = Sql::new();
        let rows = sql
            .query("PRAGMA database_list", Duration::from_secs(2))
            .await
            .expect("read-only pragma must pass");
        assert!(!rows.is_empty(), "database_list should return ≥1 row");
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
