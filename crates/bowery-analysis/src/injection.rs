//! Process injection: one process taking control of another.
//!
//! `T1055`, and the gap that most undermines the rest of this agent.
//! Injected code inherits the identity of the process it lands in, so a
//! packaged, unmodified binary is still packaged and unmodified after
//! something else is running inside it. Provenance, lineage, the
//! sanctioned-reader exemptions — all of them vouch for the host
//! process and none of them can see the passenger.
//!
//! # Why a debugger list, and why it is anchored on provenance
//!
//! `ptrace` is how debuggers work, and a host that never runs one is
//! not a host anyone develops on. The exemption is the same shape used
//! for credential readers and for privilege helpers: the tool must be at
//! a path this rule names **and** be a binary a package vouches for.
//! Neither half is sufficient. A copy of `gdb` in `/tmp` is not a
//! debugger for this purpose, and neither is a trojanised one at the
//! right path.
//!
//! # What it cannot see
//!
//! **A debugger being used as the weapon** — see below. Beyond that, the
//! three doors into another process's memory are all watched now:
//! `ptrace`, `process_vm_writev` (reported through the same event with a
//! sentinel request, because it is the same finding), and writing
//! `/proc/<pid>/mem`, which the file probe already sees as a
//! write-intent open and `defense_evasion.proc_mem_write` scores.
//!
//! **A debugger being used as the weapon.** An attacker who runs the
//! distribution's own `gdb` to attach to a process is exempted by the
//! rule, exactly as an attacker who runs the distribution's own `sudo`
//! is exempted by the privilege-transition rule. The exemption is what
//! makes the detection usable and it is also its boundary.

/// The rule id an injection attempt is reported under.
pub const RULE_ID: &str = "defense_evasion.ptrace_inject";

#[must_use]
pub const fn rule_ids() -> &'static [&'static str] {
    &[RULE_ID]
}

/// Absolute exe paths whose job is to control other processes.
///
/// Paths, not names, and honoured only for a packaged binary — see the
/// module docs. Both `/usr/bin` and `/bin` spellings appear because a
/// non-merged-usr host resolves to the latter.
const DEBUGGERS: &[&str] = &[
    "/usr/bin/gdb",
    "/usr/bin/gdbserver",
    "/usr/bin/lldb",
    "/usr/bin/lldb-server",
    "/usr/bin/strace",
    "/usr/bin/ltrace",
    "/usr/bin/gcore",
    "/usr/bin/perf",
    "/usr/bin/criu",
    "/usr/bin/rr",
    "/usr/bin/valgrind",
    "/usr/bin/dotnet-dump",
    "/usr/bin/java",
    "/bin/gdb",
    "/bin/strace",
    // systemd-coredump inspects a crashing process legitimately.
    "/usr/lib/systemd/systemd-coredump",
    "/lib/systemd/systemd-coredump",
    "/usr/bin/apport",
    "/usr/share/apport/apport",
];

/// What the request was, for the operator.
#[must_use]
pub fn request_name(request: u32) -> &'static str {
    match request {
        4 => "POKETEXT (write to its code)",
        5 => "POKEDATA (write to its data)",
        13 => "SETREGS (redirect its execution)",
        16 => "ATTACH",
        // Not a ptrace request: the sentinel the probe uses for
        // process_vm_writev, which reaches the same place without
        // ptrace at all.
        0xFFFF_FFFF => "process_vm_writev (wrote its memory directly)",
        0x4206 => "SEIZE",
        _ => "control request",
    }
}

/// Is this a debugger the distribution ships, doing its job?
///
/// Both conditions are required. `exe` is `None` when the caller could
/// not resolve it, which earns no exemption: the same fail-closed
/// default as the credential readers, because an exemption must be
/// demonstrated rather than assumed.
#[must_use]
pub fn is_sanctioned_debugger(
    exe: Option<&str>,
    provenance: crate::provenance::Provenance,
) -> bool {
    let Some(exe) = exe else {
        return false;
    };
    provenance == crate::provenance::Provenance::PackagedIntact && DEBUGGERS.contains(&exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::Provenance;

    #[test]
    fn the_distributions_debugger_is_not_a_finding() {
        assert!(is_sanctioned_debugger(
            Some("/usr/bin/gdb"),
            Provenance::PackagedIntact
        ));
    }

    /// The half that makes the path list safe.
    #[test]
    fn a_debugger_no_package_owns_is_not_sanctioned() {
        for p in [
            Provenance::Unpackaged,
            Provenance::PackagedModified,
            Provenance::Unknown,
        ] {
            assert!(!is_sanctioned_debugger(Some("/usr/bin/gdb"), p));
        }
    }

    #[test]
    fn a_copy_of_gdb_elsewhere_is_not_a_debugger() {
        assert!(!is_sanctioned_debugger(
            Some("/tmp/gdb"),
            Provenance::PackagedIntact
        ));
    }

    /// Fails closed, like every other exemption here.
    #[test]
    fn an_unresolvable_exe_earns_no_exemption() {
        assert!(!is_sanctioned_debugger(None, Provenance::PackagedIntact));
    }

    #[test]
    fn every_request_reads_as_something() {
        for r in [4u32, 5, 13, 16, 0x4206, 999] {
            assert!(!request_name(r).is_empty());
        }
        assert!(request_name(16).contains("ATTACH"));
    }

    #[test]
    fn sanctioned_paths_are_absolute() {
        for d in DEBUGGERS {
            assert!(d.starts_with('/'), "{d} must be an absolute path");
        }
    }
}
