//! `system_info` table — host CPU / RAM / kernel summary.
//!
//! Always one row. Columns aim at the questions a SOC operator
//! actually asks: "what kind of host is this, and what's it
//! running?" — `cpu_brand`, `cpu_logical_cores`,
//! `physical_memory_bytes`, `kernel_version`, plus DMI identity
//! when available.
//!
//! DMI fields are best-effort. Containers / VMs frequently expose
//! synthetic or empty DMI; we surface NULL there rather than
//! pretending the field exists.

use std::fs;

use rusqlite::{Connection, params};

use crate::{BoweryTable, TableError};

const NAME: &str = "system_info";
const SCHEMA: &str = r"
    CREATE TABLE IF NOT EXISTS system_info (
        hostname              TEXT,
        uuid                  TEXT,
        cpu_brand             TEXT,
        cpu_count             INTEGER,
        cpu_logical_cores     INTEGER,
        hardware_model        TEXT,
        hardware_vendor       TEXT,
        board_model           TEXT,
        physical_memory_bytes INTEGER,
        kernel_version        TEXT
    );
";

#[derive(Debug)]
pub struct SystemInfoTable;

impl BoweryTable for SystemInfoTable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(&self, conn: &Connection) -> Result<(), TableError> {
        conn.execute_batch(SCHEMA)?;
        let row = collect();
        conn.execute(
            "INSERT INTO system_info (hostname, uuid, cpu_brand, cpu_count, cpu_logical_cores,
                                       hardware_model, hardware_vendor, board_model,
                                       physical_memory_bytes, kernel_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                row.hostname,
                row.uuid,
                row.cpu_brand,
                row.cpu_count,
                row.cpu_logical_cores,
                row.hardware_model,
                row.hardware_vendor,
                row.board_model,
                row.physical_memory_bytes,
                row.kernel_version,
            ],
        )?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct SysInfo {
    hostname: Option<String>,
    uuid: Option<String>,
    cpu_brand: Option<String>,
    cpu_count: Option<i64>,
    cpu_logical_cores: Option<i64>,
    hardware_model: Option<String>,
    hardware_vendor: Option<String>,
    board_model: Option<String>,
    physical_memory_bytes: Option<i64>,
    kernel_version: Option<String>,
}

fn collect() -> SysInfo {
    let mut out = SysInfo {
        hostname: read_trimmed("/proc/sys/kernel/hostname"),
        kernel_version: read_trimmed("/proc/sys/kernel/osrelease"),
        uuid: read_trimmed("/sys/class/dmi/id/product_uuid"),
        hardware_model: read_trimmed("/sys/class/dmi/id/product_name"),
        hardware_vendor: read_trimmed("/sys/class/dmi/id/sys_vendor"),
        board_model: read_trimmed("/sys/class/dmi/id/board_name"),
        ..Default::default()
    };
    if let Ok(contents) = fs::read_to_string("/proc/cpuinfo") {
        let (brand, physical, logical) = parse_cpuinfo(&contents);
        out.cpu_brand = brand;
        out.cpu_count = physical;
        out.cpu_logical_cores = logical;
    }
    if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
        out.physical_memory_bytes = parse_meminfo_total_bytes(&contents);
    }
    out
}

fn read_trimmed(path: &str) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(s) => {
            let s = s.trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        }
        Err(_) => None,
    }
}

/// Parse the slim `/proc/cpuinfo` shape we care about. Returns
/// `(model_name, physical_cpu_count, logical_core_count)`.
///
/// Linux's cpuinfo is per-logical-cpu. Each block has lines like
/// `processor  : 0`, `physical id : 0`, `cpu cores : 4`,
/// `model name : Intel(R) Xeon(R) ...`. We:
/// - count `processor:` lines for logical cores
/// - take the first `model name:` value as the brand
/// - track unique `physical id` values for socket count
fn parse_cpuinfo(contents: &str) -> (Option<String>, Option<i64>, Option<i64>) {
    use std::collections::HashSet;
    let mut brand: Option<String> = None;
    let mut logical_cores: i64 = 0;
    let mut physical_ids = HashSet::new();
    let mut seen_processor_in_block = false;
    for line in contents.lines() {
        if line.is_empty() {
            seen_processor_in_block = false;
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "processor" if !seen_processor_in_block => {
                logical_cores += 1;
                seen_processor_in_block = true;
            }
            "model name" if brand.is_none() => brand = Some(value.to_string()),
            "physical id" => {
                physical_ids.insert(value.to_string());
            }
            _ => {}
        }
    }
    let logical = if logical_cores > 0 {
        Some(logical_cores)
    } else {
        None
    };
    let physical = if physical_ids.is_empty() {
        // No "physical id" line at all (single-socket systems / VMs)
        // — assume 1 if we did see at least one logical CPU.
        logical.map(|_| 1)
    } else {
        i64::try_from(physical_ids.len()).ok()
    };
    (brand, physical, logical)
}

/// `MemTotal:       16384068 kB` → bytes.
fn parse_meminfo_total_bytes(contents: &str) -> Option<i64> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let rest = rest.trim();
            // shape: "<digits> kB"
            let kib_str = rest.split_whitespace().next()?;
            let kib: i64 = kib_str.parse().ok()?;
            return Some(kib * 1024);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpuinfo_basic() {
        let raw = "\
processor       : 0
model name      : Intel(R) Test CPU @ 1.00GHz
physical id     : 0
cpu cores       : 2

processor       : 1
model name      : Intel(R) Test CPU @ 1.00GHz
physical id     : 0
cpu cores       : 2

processor       : 2
model name      : Intel(R) Test CPU @ 1.00GHz
physical id     : 1
cpu cores       : 2

";
        let (brand, phys, logical) = parse_cpuinfo(raw);
        assert!(brand.unwrap().contains("Intel"));
        assert_eq!(phys, Some(2)); // two unique physical ids
        assert_eq!(logical, Some(3));
    }

    #[test]
    fn parse_meminfo_basic() {
        let raw = "MemTotal:       16384068 kB\nMemFree: 1234 kB\n";
        assert_eq!(parse_meminfo_total_bytes(raw), Some(16_384_068 * 1024));
    }

    #[test]
    fn registers_one_row() {
        let conn = Connection::open_in_memory().unwrap();
        SystemInfoTable.register(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM system_info", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        // Hostname / kernel_version are reliably present on any Linux
        // test host. DMI fields may be NULL inside containers; don't
        // assert on those.
        let (hostname, kernel): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT hostname, kernel_version FROM system_info",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(hostname.is_some(), "hostname should resolve");
        assert!(kernel.is_some(), "kernel_version should resolve");
    }
}
