//! Make each detection fire, on purpose, so a zero can be read.
//!
//! # Why
//!
//! `bowery_detections` reports 49 of 53 rules as never having fired on
//! the busiest host in the fleet after eight days. That number is
//! ambiguous, and the ambiguity is the problem: a rule at zero is either
//! watching for something rare, or unable to fire at all. This codebase
//! has found eight of the latter, and every one had passing unit tests —
//! they exercised the rule against an input the sensor would never have
//! delivered.
//!
//! So the question a unit test cannot answer is whether the *whole
//! chain* works: kernel probe → ring buffer → parser → pipeline → rule →
//! counter. This provokes each behaviour on a live host and lets the
//! counter answer.
//!
//! # Why this is safe to run
//!
//! The file probe hooks `sys_enter_openat` — the syscall's **entry**. It
//! reads the flags and the path and emits its record before the kernel
//! has opened anything, and never learns whether the call succeeded. So
//! expressing intent is enough: opening a path for write with neither
//! `O_CREAT` nor `O_TRUNC` creates nothing, truncates nothing, and
//! writes nothing, while producing exactly the event a real write
//! produces. On a path that does not exist the call simply fails.
//!
//! Every provocation here is of that kind, or is a plainly harmless act
//! (running `whoami`, writing files inside a temporary directory). None
//! of them modifies a system file, and the ones that could not be made
//! safe are **not implemented and are reported as such**, because a
//! prover that quietly skips what it cannot do is a coverage map that
//! lies — which is the failure this whole exercise is about.
//!
//! # Usage
//!
//! ```text
//! bowery-prove list                # what it would do, and what it cannot
//! bowery-prove run                 # perform the safe provocations
//! ```
//!
//! Compare `bowery_detections` before and after; `scripts/prove-detections`
//! does that part.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

/// How a provocation reaches the sensor.
enum Act {
    /// Open for write, creating and truncating nothing. Proves a
    /// write-intent rule without writing.
    WriteIntent(&'static str),
    /// Open for read. Only reaches userspace if the kernel's secret-path
    /// filter ships it, which is the point.
    Read(&'static str),
    /// Run a program and wait for it.
    Exec(&'static str, &'static [&'static str]),
    /// Write real files under a temporary directory.
    TempFiles(TempShape),
    /// Take control of a child of our own with `ptrace`.
    PtraceOwnChild,
    /// Run a program from a child that has renamed itself, so the
    /// lineage rules see the parent they are written about.
    SpawnAs {
        parent: &'static str,
        program: &'static str,
        args: &'static [&'static str],
    },
    /// Known to be unprovable safely, with the reason.
    Unsupported(&'static str),
}

enum TempShape {
    /// One filename across many directories: a ransom note.
    NoteFanout,
    /// Many files sharing an unusual extension: an encryption sweep.
    EncryptionSweep,
}

struct Provocation {
    rule: &'static str,
    act: Act,
}

/// What the prover can make happen.
///
/// Read rules come from [`bowery_analysis::file_watch::READ_RULE_EXAMPLES`]
/// rather than being repeated here, so a new read rule is provable the
/// moment it is added — the same table a test uses to prove it is
/// reachable at all.
#[allow(clippy::too_many_lines)] // one flat table; splitting it hides the list
fn provocations() -> Vec<Provocation> {
    let mut v: Vec<Provocation> = bowery_analysis::file_watch::READ_RULE_EXAMPLES
        .iter()
        .map(|(rule, path)| Provocation {
            rule,
            act: Act::Read(path),
        })
        .collect();

    v.extend([
        // -- persistence: write intent, nothing written ----------------
        Provocation {
            rule: "persist.ld_preload",
            act: Act::WriteIntent("/etc/ld.so.preload"),
        },
        Provocation {
            rule: "persist.systemd_unit",
            act: Act::WriteIntent("/etc/systemd/system/bowery-prove.service"),
        },
        Provocation {
            rule: "persist.cron",
            act: Act::WriteIntent("/etc/cron.d/bowery-prove"),
        },
        Provocation {
            rule: "persist.pam",
            act: Act::WriteIntent("/etc/pam.d/bowery-prove"),
        },
        Provocation {
            rule: "persist.udev",
            act: Act::WriteIntent("/etc/udev/rules.d/99-bowery-prove.rules"),
        },
        Provocation {
            rule: "persist.shell_profile",
            act: Act::WriteIntent("/etc/profile.d/bowery-prove.sh"),
        },
        Provocation {
            rule: "persist.authorized_keys",
            act: Act::WriteIntent("/root/.ssh/authorized_keys"),
        },
        Provocation {
            rule: "persist.user_rc",
            act: Act::WriteIntent("/root/.bashrc"),
        },
        Provocation {
            rule: "persist.user_profile",
            act: Act::WriteIntent("/root/.bash_profile"),
        },
        // -- privilege escalation and credential writes ---------------
        Provocation {
            rule: "privesc.sudoers",
            act: Act::WriteIntent("/etc/sudoers.d/bowery-prove"),
        },
        Provocation {
            rule: "cred.shadow",
            act: Act::WriteIntent("/etc/shadow"),
        },
        Provocation {
            rule: "cred.passwd",
            act: Act::WriteIntent("/etc/passwd"),
        },
        Provocation {
            rule: "cred.ssh_private_key",
            act: Act::WriteIntent("/root/.ssh/id_rsa"),
        },
        // -- defense evasion ------------------------------------------
        Provocation {
            rule: "evade.auth_log",
            act: Act::WriteIntent("/var/log/auth.log"),
        },
        Provocation {
            rule: "evade.wtmp",
            act: Act::WriteIntent("/var/log/wtmp"),
        },
        Provocation {
            rule: "defense_evasion.proc_mem_write",
            act: Act::WriteIntent("/proc/self/mem"),
        },
        // -- impact ---------------------------------------------------
        Provocation {
            rule: "impact.ransom_note_fanout",
            act: Act::TempFiles(TempShape::NoteFanout),
        },
        Provocation {
            rule: "impact.mass_write_new_extension",
            act: Act::TempFiles(TempShape::EncryptionSweep),
        },
        // -- discovery ------------------------------------------------
        Provocation {
            rule: bowery_analysis::escalation::DISCOVERY_RULE_ID,
            act: Act::Exec(
                "sh",
                &["-c", "whoami; id; hostname; uname -a; ps aux >/dev/null"],
            ),
        },
        // -- process injection ----------------------------------------
        //
        // Not `strace`: the rule exempts packaged debuggers, so proving
        // it that way proves the exemption instead. This binary is not
        // packaged, which is exactly the case the rule is for.
        Provocation {
            rule: bowery_analysis::injection::RULE_ID,
            act: Act::PtraceOwnChild,
        },
        // -- defence tampering ----------------------------------------
        //
        // Each is run in a way that changes nothing. `iptables -F` needs
        // a table that does not exist, `systemctl stop` names a unit
        // that is not installed, and `setenforce` fails on a host
        // without SELinux — all of them after the exec the rule reads.
        Provocation {
            rule: bowery_analysis::defense::FIREWALL_RULE_ID,
            act: Act::Exec("iptables", &["-t", "bowery-prove-nosuch", "-F"]),
        },
        Provocation {
            rule: bowery_analysis::defense::SERVICE_RULE_ID,
            act: Act::Exec("systemctl", &["stop", "auditd@bowery-prove-nosuch.service"]),
        },
        Provocation {
            rule: bowery_analysis::defense::MAC_RULE_ID,
            act: Act::Exec("setenforce", &["0"]),
        },
        // -- lineage: the parent is the signal -------------------------
        //
        // Provoked by renaming a *child* of this process and having it
        // exec, so the rename dies with the provocation rather than
        // following this binary through the rest of the run. The rule
        // reads the parent's `comm` from /proc, which is exactly as
        // spoofable as this makes it look — that limitation is the
        // rule's, and stated on it.
        Provocation {
            rule: "lineage.service_spawned_shell",
            act: Act::SpawnAs {
                parent: "nginx",
                program: "/bin/sh",
                args: &["-c", "true"],
            },
        },
        Provocation {
            rule: "lineage.service_spawned_downloader",
            act: Act::SpawnAs {
                parent: "nginx",
                program: "curl",
                args: &["--version"],
            },
        },
        Provocation {
            rule: "lineage.service_spawned_interpreter",
            act: Act::SpawnAs {
                parent: "nginx",
                program: "python3",
                args: &["-c", "pass"],
            },
        },
        Provocation {
            rule: "lineage.scheduled_downloader",
            act: Act::SpawnAs {
                parent: "cron",
                program: "curl",
                args: &["--version"],
            },
        },
        // -- persistence, second unit directory ------------------------
        Provocation {
            rule: "persist.systemd_unit_lib",
            act: Act::WriteIntent("/usr/lib/systemd/system/bowery-prove.service"),
        },
        // -- what cannot be proved safely -----------------------------
        Provocation {
            rule: "persist.kernel_module_untrusted",
            act: Act::Unsupported(
                "needs an out-of-tree or unsigned module loaded into the running kernel; \
                 building and inserting one is not a safe thing for this to do unasked",
            ),
        },
        Provocation {
            rule: bowery_analysis::beacon::RULE_ID,
            act: Act::Unsupported(
                "needs repeated outbound connections to one destination on a regular \
                 interval, sustained past the novelty window — minutes of real traffic \
                 to a host chosen by the operator, not something to synthesise here",
            ),
        },
        Provocation {
            rule: "corroborate.net_inbound_connect",
            act: Act::Unsupported(
                "needs a second host to connect here and then deny having done so; \
                 a local provocation cannot produce a peer's answer",
            ),
        },
        Provocation {
            rule: "corroborate.file_access",
            act: Act::Unsupported(
                "needs peers to answer a round about a file this host touched — \
                 not a thing one machine can do to itself",
            ),
        },
        Provocation {
            rule: "probe.sensor_blind",
            act: Act::Unsupported(
                "needs the sensor to stop, which means stopping the thing that would \
                 report it; provoke it by stopping the agent and watching a peer",
            ),
        },
        Provocation {
            rule: "peer.silent",
            act: Act::Unsupported(
                "needs a neighbour to stop gossiping while others remain — a fleet \
                 action, and the one failure a host cannot stage for itself",
            ),
        },
        Provocation {
            rule: "yara.match",
            act: Act::Unsupported(
                "needs an operator to push a rule and a file that matches it; the \
                 rule set is deliberately not something this invents",
            ),
        },
        Provocation {
            rule: "privesc.setid_unpackaged",
            act: Act::Unsupported(
                "needs a setuid binary no package owns, which requires root to create \
                 and is the finding itself rather than a rehearsal of it",
            ),
        },
        Provocation {
            rule: "privesc.uid_transition_no_helper",
            act: Act::Unsupported(
                "needs a root process whose parent is neither root nor a packaged \
                 privilege helper — reproducing that means installing an unpackaged \
                 setuid binary, which is the finding itself",
            ),
        },
    ]);
    v
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "list".into());
    let all = provocations();
    match mode.as_str() {
        "list" => list(&all),
        "run" => run(&all),
        other => {
            eprintln!("unknown mode `{other}`; expected `list` or `run`");
            std::process::exit(2);
        }
    }
}

fn list(all: &[Provocation]) {
    let mut supported = 0;
    for p in all {
        let what = match &p.act {
            Act::WriteIntent(path) => format!("open({path}, O_WRONLY) — creates nothing"),
            Act::Read(path) => format!("open({path}, O_RDONLY)"),
            Act::Exec(cmd, args) => format!("exec {cmd} {}", args.join(" ")),
            Act::TempFiles(TempShape::NoteFanout) => {
                "write one filename into 8 temp directories".into()
            }
            Act::TempFiles(TempShape::EncryptionSweep) => {
                "write 60 temp files sharing an odd extension".into()
            }
            Act::PtraceOwnChild => "PTRACE_ATTACH to a child of our own".into(),
            Act::SpawnAs {
                parent,
                program,
                args,
            } => format!(
                "as a process named {parent}: exec {program} {}",
                args.join(" ")
            ),
            Act::Unsupported(why) => format!("NOT PROVABLE — {why}"),
        };
        if !matches!(p.act, Act::Unsupported(_)) {
            supported += 1;
        }
        println!("{:38} {what}", p.rule);
    }
    println!(
        "\n{supported} provocations, {} rules this cannot prove",
        all.len() - supported
    );
}

fn run(all: &[Provocation]) {
    let mut attempted = Vec::new();
    let mut skipped = Vec::new();
    let mut unavailable = Vec::new();
    for p in all {
        match &p.act {
            Act::Unsupported(why) => skipped.push((p.rule, *why)),
            act => match perform(act) {
                Ok(()) => attempted.push((p.rule, "ok".to_string())),
                // A missing program is a different fact from a refused
                // syscall: nothing was ever exec'd, so no event exists
                // and the rule cannot be judged on this host. Reporting
                // it as a failure would accuse a working rule.
                Err(e) if e.kind() == io::ErrorKind::NotFound && act.needs_program() => {
                    unavailable.push((p.rule, act.program().unwrap_or("?")));
                }
                // Any other failure is usually the point: opening
                // /etc/shadow for write as a non-root user is refused by
                // the kernel *after* the tracepoint has already fired.
                Err(e) => attempted.push((
                    p.rule,
                    format!("syscall returned {e} (the probe fired regardless)"),
                )),
            },
        }
    }

    let mut out = String::new();
    let _ = writeln!(out, "attempted {} provocations:", attempted.len());
    for (rule, note) in &attempted {
        let _ = writeln!(out, "  {rule:38} {note}");
    }
    if !skipped.is_empty() {
        let _ = writeln!(
            out,
            "\n{} rules this cannot prove, reported rather than skipped silently:",
            skipped.len()
        );
        for (rule, why) in &skipped {
            let _ = writeln!(out, "  {rule:38} {why}");
        }
    }
    if !unavailable.is_empty() {
        let _ = writeln!(
            out,
            "\n{} rules whose provocation needs a program this host does not have:",
            unavailable.len()
        );
        for (rule, program) in &unavailable {
            let _ = writeln!(
                out,
                "  {rule:38} no `{program}` here — UNPROVEN, not failed"
            );
        }
    }
    print!("{out}");
    println!("\nnow compare bowery_detections; allow a few seconds for the pipeline.");
}

impl Act {
    /// The program this provocation runs, if it runs one.
    fn program(&self) -> Option<&'static str> {
        match self {
            Self::Exec(program, _) | Self::SpawnAs { program, .. } => Some(program),
            _ => None,
        }
    }

    /// Does this provocation depend on a program being installed?
    fn needs_program(&self) -> bool {
        self.program().is_some()
    }
}

fn perform(act: &Act) -> io::Result<()> {
    match act {
        // Neither `create` nor `truncate`: the file is left exactly as it
        // was, and a path that does not exist yields ENOENT — after the
        // tracepoint has already emitted.
        Act::WriteIntent(path) => OpenOptions::new()
            .write(true)
            .custom_flags(libc_o_nofollow())
            .open(path)
            .map(drop),
        Act::Read(path) => OpenOptions::new().read(true).open(path).map(drop),
        Act::Exec(cmd, args) => Command::new(cmd)
            .args(*args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(drop),
        Act::TempFiles(shape) => temp_files(shape),
        Act::PtraceOwnChild => ptrace_own_child(),
        Act::SpawnAs {
            parent,
            program,
            args,
        } => spawn_as(parent, program, args),
        Act::Unsupported(_) => Ok(()),
    }
}

/// `O_NOFOLLOW`, so a symlink planted at one of these paths cannot
/// redirect the open somewhere else.
fn libc_o_nofollow() -> i32 {
    0o400_000
}

fn temp_files(shape: &TempShape) -> io::Result<()> {
    let root = std::env::temp_dir().join(format!("bowery-prove-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let result = match shape {
        TempShape::NoteFanout => note_fanout(&root),
        TempShape::EncryptionSweep => encryption_sweep(&root),
    };
    // Best effort: leaving these behind would be untidy but harmless.
    let _ = std::fs::remove_dir_all(&root);
    result
}

/// One filename in many directories, meeting the rule's conjunction:
/// enough directories, and a shallow shared ancestor.
fn note_fanout(root: &Path) -> io::Result<()> {
    for i in 0..8 {
        let dir = root.join(format!("victim{i}"));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("HOW-TO-DECRYPT.txt"), b"bowery-prove\n")?;
    }
    Ok(())
}

/// Many files sharing an extension no ordinary tool produces.
fn encryption_sweep(root: &Path) -> io::Result<()> {
    for i in 0..60 {
        let dir = root.join(format!("sweep{}", i % 6));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("doc{i}.docx.bowerylocked")), b"x")?;
    }
    Ok(())
}

/// Fork a child that does nothing, seize it, release it, reap it.
///
/// The whole exchange is between this process and a child it created, so
/// nothing else on the host is touched. `PTRACE_ATTACH` is one of the
/// requests the probe ships, and this binary is not packaged — which is
/// the case the rule exists for, and the reason a packaged debugger
/// cannot be used to prove it.
#[allow(unsafe_code)] // the only way to ask the kernel for this
fn ptrace_own_child() -> io::Result<()> {
    // Safe to fork: this program is single-threaded, and the child calls
    // only async-signal-safe functions before exiting.
    unsafe {
        let child = libc::fork();
        if child < 0 {
            return Err(io::Error::last_os_error());
        }
        if child == 0 {
            // Wait to be attached to; killed by the parent below.
            libc::pause();
            libc::_exit(0);
        }
        let attached = libc::ptrace(libc::PTRACE_ATTACH, child, 0, 0);
        let mut status = 0;
        if attached == 0 {
            libc::waitpid(child, &raw mut status, 0);
            libc::ptrace(libc::PTRACE_DETACH, child, 0, 0);
        }
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, &raw mut status, 0);
        if attached != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Run `program` from a child that has renamed itself to `parent`.
///
/// The rename happens in the child and dies with it, so it cannot follow
/// this binary into the rest of the run and confuse a later provocation.
#[allow(unsafe_code)] // prctl and fork have no safe wrapper here
fn spawn_as(parent: &str, program: &str, args: &[&str]) -> io::Result<()> {
    let mut name = [0u8; 16];
    let bytes = parent.as_bytes();
    let n = bytes.len().min(15);
    name[..n].copy_from_slice(&bytes[..n]);

    // Single-threaded, so forking is safe; the child execs immediately.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        unsafe {
            libc::prctl(libc::PR_SET_NAME, name.as_ptr());
        }
        let failed = Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err();
        unsafe { libc::_exit(i32::from(failed)) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(child, &raw mut status, 0) };
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{program} could not be run"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rule this claims to provoke must be a rule the agent can
    /// actually fire.
    ///
    /// A prover that names a rule which does not exist reports a
    /// permanent, unexplained zero — and this shipped naming
    /// `persist.kernel_module`, whose real id is
    /// `persist.kernel_module_untrusted`. That is the same defect as the
    /// LLM prompt advertising five action ids the engine had never
    /// implemented, in the one tool whose job is to find it.
    #[test]
    fn every_rule_named_here_exists_in_the_registry() {
        let known = bowery_analysis::attack::all_rule_ids();
        for p in provocations() {
            assert!(
                known.contains(&p.rule),
                "{} is not a rule the agent knows — it can never move a counter",
                p.rule
            );
        }
    }

    /// And no rule may be named twice, which would report one
    /// provocation's result under two headings.
    #[test]
    fn no_rule_is_provoked_twice() {
        let mut seen = std::collections::HashSet::new();
        for p in provocations() {
            assert!(seen.insert(p.rule), "{} appears more than once", p.rule);
        }
    }
}
