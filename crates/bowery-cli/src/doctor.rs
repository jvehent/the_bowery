//! `bowery doctor` — host-readiness checks for running a Bowery agent.
//!
//! All checks are reads of `/proc` and `/sys`; nothing here mutates state or
//! requires elevated privileges. Each check produces a [`Check`] with a
//! status, human-readable detail, and (when applicable) a remediation hint.
//!
//! See [DESIGN.md](../../DESIGN.md) §4.1 for why each requirement matters.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Status {
    /// Requirement met.
    Pass,
    /// Requirement met but worth noting (e.g. degraded but functional).
    Warn,
    /// Requirement not met — agent will not work.
    Fail,
    /// Could not be determined here; rely on adjacent checks.
    Unknown,
}

impl Status {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Unknown => " N/A",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Check {
    pub(crate) name: &'static str,
    pub(crate) status: Status,
    pub(crate) detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fix: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Report {
    pub(crate) checks: Vec<Check>,
    pub(crate) verdict: Verdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Verdict {
    /// All checks pass (warnings allowed).
    Ready,
    /// One or more checks fail; the agent will not start (or will misbehave).
    NotReady,
}

/// Run every check and produce a verdict.
pub(crate) fn run() -> Report {
    let checks = vec![
        check_kernel_version(),
        check_btf(),
        check_active_lsms(),
        check_bpffs(),
        check_lsm_cmdline(),
        check_kernel_config(),
        check_sql_smoke(),
    ];
    let any_fail = checks.iter().any(|c| c.status == Status::Fail);
    let verdict = if any_fail {
        Verdict::NotReady
    } else {
        Verdict::Ready
    };
    Report { checks, verdict }
}

/// Phase-9 slice 8: confirm the native SQL surface is wirable —
/// build an in-memory `bowery-sql` engine, run `SELECT 1`, and
/// fail the check if either step errors. Catches build-time
/// breakage (missing rusqlite features, schema regressions in
/// `bowery-tables`, etc.) without requiring a running agent.
fn check_sql_smoke() -> Check {
    use std::time::Duration;

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return Check {
                name: "Phase-9 SQL surface",
                status: Status::Fail,
                detail: format!("tokio runtime build failed: {e}"),
                fix: None,
            };
        }
    };
    let outcome = runtime.block_on(async {
        let sql = bowery_sql::Sql::new();
        sql.query("SELECT 1 AS one", Duration::from_secs(2)).await
    });
    match outcome {
        Ok(rows) => {
            let label = match rows.first().and_then(|r| r.columns.first()) {
                Some((_, bowery_sql::Value::Integer(1))) => "ok",
                _ => "ran but unexpected shape",
            };
            Check {
                name: "Phase-9 SQL surface",
                status: Status::Pass,
                detail: format!("SELECT 1 → {label}"),
                fix: None,
            }
        }
        Err(e) => Check {
            name: "Phase-9 SQL surface",
            status: Status::Fail,
            detail: format!("SELECT 1 failed: {e}"),
            fix: Some("rebuild with `cargo build` and re-run `bowery doctor`".into()),
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

fn check_kernel_version() -> Check {
    let raw = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let (major, minor) = parse_kernel_version(&raw);
    let status = if major > 5 || (major == 5 && minor >= 13) {
        Status::Pass
    } else if major == 5 && minor >= 7 {
        Status::Warn
    } else if major == 0 {
        Status::Unknown
    } else {
        Status::Fail
    };
    let fix = match status {
        Status::Warn => Some(
            "kernel ≥ 5.13 recommended for full LSM hook coverage; ≥ 5.7 is the minimum".into(),
        ),
        Status::Fail => Some(
            "KRSI requires Linux ≥ 5.7 (5.13+ recommended); upgrade or replace the kernel".into(),
        ),
        _ => None,
    };
    Check {
        name: "kernel version",
        status,
        detail: if raw.is_empty() {
            "/proc/sys/kernel/osrelease unreadable".into()
        } else {
            raw
        },
        fix,
    }
}

pub(crate) fn parse_kernel_version(s: &str) -> (u32, u32) {
    let mut parts = s.split(['.', '-']);
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}

fn check_btf() -> Check {
    let path = Path::new("/sys/kernel/btf/vmlinux");
    match fs::metadata(path) {
        Ok(meta) => Check {
            name: "BTF",
            status: Status::Pass,
            detail: format!("{} ({} bytes)", path.display(), meta.len()),
            fix: None,
        },
        Err(_) => Check {
            name: "BTF",
            status: Status::Fail,
            detail: format!("{} missing", path.display()),
            fix: Some(
                "rebuild kernel with CONFIG_DEBUG_INFO_BTF=y \
                 (CO-RE eBPF programs require BTF)"
                    .into(),
            ),
        },
    }
}

fn check_active_lsms() -> Check {
    let path = "/sys/kernel/security/lsm";
    let raw = match fs::read_to_string(path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            return Check {
                name: "BPF-LSM active",
                status: Status::Fail,
                detail: format!("{path} unreadable"),
                fix: Some(
                    "kernel may lack CONFIG_SECURITY=y / CONFIG_SECURITYFS=y, \
                     or securityfs is not mounted"
                        .into(),
                ),
            };
        }
    };
    if raw.split(',').any(|x| x.trim() == "bpf") {
        Check {
            name: "BPF-LSM active",
            status: Status::Pass,
            detail: raw,
            fix: None,
        }
    } else {
        Check {
            name: "BPF-LSM active",
            status: Status::Fail,
            detail: format!("`bpf` not in active LSMs ({raw})"),
            fix: Some(
                "add `lsm=...,bpf` to GRUB_CMDLINE_LINUX in /etc/default/grub, \
                 then `update-grub` (Debian/Ubuntu) or \
                 `grub2-mkconfig -o /boot/grub2/grub.cfg` (RHEL), then reboot"
                    .into(),
            ),
        }
    }
}

fn check_bpffs() -> Check {
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let bpf_line = mounts
        .lines()
        .find(|l| l.split_whitespace().nth(2) == Some("bpf"));
    match bpf_line {
        Some(line) => {
            let mountpoint = line.split_whitespace().nth(1).unwrap_or("?");
            Check {
                name: "bpffs",
                status: Status::Pass,
                detail: format!("mounted at {mountpoint}"),
                fix: None,
            }
        }
        None => Check {
            name: "bpffs",
            status: Status::Warn,
            detail: "no `bpf` filesystem mounted".into(),
            fix: Some(
                "sudo mount -t bpf bpf /sys/fs/bpf  \
                 (or add `bpf  /sys/fs/bpf  bpf  defaults  0 0` to /etc/fstab)"
                    .into(),
            ),
        },
    }
}

fn check_lsm_cmdline() -> Check {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let lsm_arg = cmdline
        .split_whitespace()
        .find(|tok| tok.starts_with("lsm="));
    match lsm_arg {
        Some(arg) => {
            let value = arg.trim_start_matches("lsm=");
            if value.split(',').any(|x| x == "bpf") {
                Check {
                    name: "boot lsm= flag",
                    status: Status::Pass,
                    detail: arg.to_string(),
                    fix: None,
                }
            } else {
                Check {
                    name: "boot lsm= flag",
                    status: Status::Fail,
                    detail: format!("{arg} (missing `bpf`)"),
                    fix: Some("append `,bpf` to the lsm= cmdline parameter and reboot".into()),
                }
            }
        }
        None => Check {
            name: "boot lsm= flag",
            status: Status::Warn,
            detail: "no explicit lsm= on the cmdline (using kernel default)".into(),
            fix: Some(
                "if `BPF-LSM active` above passes, the distro default already includes bpf; \
                 otherwise set lsm=...,bpf explicitly"
                    .into(),
            ),
        },
    }
}

fn check_kernel_config() -> Check {
    let raw = read_kernel_config();
    let Some(raw) = raw else {
        return Check {
            name: "kernel config",
            status: Status::Unknown,
            detail: "/proc/config.gz unreadable and /boot/config-$(uname -r) absent".into(),
            fix: Some(
                "kernel built without CONFIG_IKCONFIG_PROC=y; \
                 trust the runtime probes above for the verdict"
                    .into(),
            ),
        };
    };

    let required = [
        "CONFIG_BPF_SYSCALL",
        "CONFIG_BPF_JIT",
        "CONFIG_BPF_LSM",
        "CONFIG_DEBUG_INFO_BTF",
    ];
    let mut missing: Vec<&str> = Vec::new();
    for key in required {
        let needle = format!("{key}=y");
        if !raw.lines().any(|l| l.trim() == needle) {
            missing.push(key);
        }
    }
    if missing.is_empty() {
        Check {
            name: "kernel config",
            status: Status::Pass,
            detail: format!(
                "{}/{} required options enabled",
                required.len(),
                required.len()
            ),
            fix: None,
        }
    } else {
        Check {
            name: "kernel config",
            status: Status::Fail,
            detail: format!("missing or =m: {}", missing.join(", ")),
            fix: Some(
                "rebuild kernel with the listed options =y, \
                 or switch to a distro kernel that has them"
                    .into(),
            ),
        }
    }
}

fn read_kernel_config() -> Option<String> {
    if let Ok(out) = Command::new("zcat").arg("/proc/config.gz").output()
        && out.status.success()
        && let Ok(s) = String::from_utf8(out.stdout)
    {
        return Some(s);
    }
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())?;
    fs::read_to_string(format!("/boot/config-{release}")).ok()
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

pub(crate) fn print_human(report: &Report) {
    println!("== Bowery host readiness ==\n");
    let name_width = report
        .checks
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(0);
    for check in &report.checks {
        println!(
            "  {} {:<width$}  {}",
            check.status.label(),
            check.name,
            check.detail,
            width = name_width
        );
        if let Some(fix) = &check.fix {
            // Visual indent: line up under the detail column.
            println!("       fix: {fix}");
        }
    }
    println!();
    let fails = report
        .checks
        .iter()
        .filter(|c| c.status == Status::Fail)
        .count();
    let warns = report
        .checks
        .iter()
        .filter(|c| c.status == Status::Warn)
        .count();
    let unknowns = report
        .checks
        .iter()
        .filter(|c| c.status == Status::Unknown)
        .count();
    match report.verdict {
        Verdict::Ready => {
            let mut suffix = String::new();
            if warns > 0 {
                let _ = write!(suffix, "; {warns} warning(s)");
            }
            if unknowns > 0 {
                let _ = write!(suffix, "; {unknowns} undetermined");
            }
            println!("Result: ready{suffix}");
        }
        Verdict::NotReady => {
            println!("Result: NOT ready ({fails} failure(s), {warns} warning(s))");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modern_release() {
        assert_eq!(parse_kernel_version("6.6.0-generic"), (6, 6));
        assert_eq!(parse_kernel_version("5.13.0-1029-aws"), (5, 13));
        assert_eq!(
            parse_kernel_version("6.6.87.2-microsoft-standard-WSL2"),
            (6, 6)
        );
    }

    #[test]
    fn parse_handles_missing_minor() {
        assert_eq!(parse_kernel_version("6"), (6, 0));
        assert_eq!(parse_kernel_version(""), (0, 0));
    }

    #[test]
    fn run_does_not_panic_in_any_environment() {
        // Whatever host this runs on, the doctor must complete and produce
        // a structured report — never panic.
        let report = run();
        assert!(!report.checks.is_empty(), "checks must run");
        assert!(report.checks.iter().all(|c| !c.name.is_empty()));
    }
}
