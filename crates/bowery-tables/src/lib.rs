//! Per-table implementations of the Phase-9 SQL surface.
//!
//! Each table implements [`BoweryTable`] and registers itself onto a
//! `rusqlite::Connection` via `register(&conn)`. Slice-1 strategy:
//! `register` creates a temp table and bulk-inserts every row at
//! query time. That trades memory for code simplicity — fine for the
//! small tables (`os_version`, `system_info`) and even adequate for
//! `users` / `kernel_modules` / `mounts` (a few hundred rows).
//!
//! Slice 2 introduces the `procfs` walking tables (`processes`,
//! `process_open_sockets`) which need filter pushdown to avoid
//! materialising every pid into RAM. Those tables will swap to
//! `rusqlite::vtab` modules; the [`BoweryTable`] trait stays the
//! same — the implementation just chooses materialised vs lazy.

#![warn(unreachable_pub)]

pub mod crontab;
pub mod interfaces;
pub mod kernel_modules;
pub mod last;
pub mod listening_ports;
pub mod logged_in_users;
pub mod mounts;
pub mod os_version;
pub mod process_open_sockets;
pub mod processes;
pub mod system_info;
pub mod systemd_units;
pub mod users;
mod utmp;

use rusqlite::Connection;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TableError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("table {table}: data-source io error: {source}")]
    Io {
        table: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("table {table}: malformed source ({reason})")]
    Malformed { table: &'static str, reason: String },
}

/// A queryable table. Each table is registered with a fresh
/// `Connection` per query; `register` is responsible for creating
/// the schema and populating it from whatever data source the
/// table observes (procfs, /etc/os-release, netlink, ...).
///
/// `name` matches the SQL identifier the operator will use in
/// `SELECT … FROM <name>`. Stable.
pub trait BoweryTable: Send + Sync {
    /// SQL identifier for this table.
    fn name(&self) -> &'static str;

    /// Create the schema and populate the rows.
    fn register(&self, conn: &Connection) -> Result<(), TableError>;
}

/// Register every Phase-9 table on `conn`. The set of tables grows
/// across slices; callers can also build their own mix via the
/// per-table `register` functions if they need a subset.
pub fn register_all(conn: &Connection) -> Result<(), TableError> {
    for table in default_tables() {
        table.register(conn)?;
    }
    Ok(())
}

/// The Phase-9 table list. Returns `Vec<Box<dyn BoweryTable>>` so
/// new tables drop in by adding one line here.
pub fn default_tables() -> Vec<Box<dyn BoweryTable>> {
    vec![
        Box::new(os_version::OsVersionTable),
        Box::new(system_info::SystemInfoTable),
        Box::new(processes::ProcessesTable::default()),
        Box::new(mounts::MountsTable),
        Box::new(kernel_modules::KernelModulesTable),
        Box::new(interfaces::InterfacesTable),
        Box::new(listening_ports::ListeningPortsTable),
        Box::new(process_open_sockets::ProcessOpenSocketsTable),
        Box::new(users::UsersTable),
        Box::new(logged_in_users::LoggedInUsersTable),
        Box::new(last::LastTable),
        Box::new(systemd_units::SystemdUnitsTable),
        Box::new(crontab::CrontabTable),
    ]
}
