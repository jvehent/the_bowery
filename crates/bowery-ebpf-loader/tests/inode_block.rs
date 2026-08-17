//! Does blocking an inode actually stop the kernel executing that file?
//!
//! Everything else about inode blocking can be checked on any host — the
//! BTF offsets resolve, the maps exist, the action refuses protected
//! paths. None of it proves the one thing that matters, which is that
//! `bprm_check_security` returns `-EPERM` for the file we named and for
//! nothing else.
//!
//! That needs a kernel with `CONFIG_BPF_LSM=y`, `bpf` in the active LSM
//! list, BTF, and root. The test **skips** rather than fails when any of
//! those is missing: Raspberry Pi kernels ship neither BPF-LSM nor BTF,
//! CI containers have no `CAP_BPF`, and turning a legitimate
//! can't-run-here into a red build teaches people to ignore it.
//!
//! Run it where it can mean something:
//!
//! ```text
//! sudo -E BOWERY_BPF_OBJ_PATH=/path/to/bowery-ebpf \
//!     cargo test -p bowery-ebpf-loader --test inode_block -- --nocapture
//! ```

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::process::Command;

use bowery_ebpf_loader::BpfBlocker;

/// Why this host cannot run the test, or `None` when it can.
fn cannot_run() -> Option<String> {
    // Effective uid from /proc rather than libc::geteuid, to keep the
    // test free of unsafe: `Uid:` is real/effective/saved/fs.
    let euid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_string))
        })
        .unwrap_or_default();
    if euid != "0" {
        return Some(format!("not root (euid {euid})"));
    }
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return Some("no /sys/kernel/btf/vmlinux".into());
    }
    match std::fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(l) if l.split(',').any(|s| s.trim() == "bpf") => {}
        Ok(l) => return Some(format!("bpf not in active LSMs ({})", l.trim())),
        Err(e) => return Some(format!("cannot read active LSMs: {e}")),
    }
    None
}

fn object_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BOWERY_BPF_OBJ_PATH") {
        return Some(PathBuf::from(p));
    }
    for p in [
        "/usr/local/lib/bowery/bowery-ebpf",
        "/usr/lib/bowery/bowery-ebpf",
    ] {
        if std::path::Path::new(p).exists() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

/// A tiny executable script we own, so blocking it cannot hurt the host.
fn make_victim(dir: &std::path::Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, "#!/bin/sh\nexit 7\n").expect("write victim");
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&p, perms).unwrap();
    p
}

/// Run it and report whether the kernel let it start at all.
///
/// Distinguishes "denied" from "ran and failed": a blocked exec yields
/// `EACCES`/`EPERM` from the spawn itself, while an allowed one runs and
/// exits 7.
fn exec_allowed(path: &std::path::Path) -> bool {
    match Command::new(path).status() {
        Ok(st) => st.code() == Some(7),
        Err(_) => false,
    }
}

#[test]
fn blocking_an_inode_stops_that_file_executing_and_leaves_others_alone() {
    if let Some(why) = cannot_run() {
        eprintln!("SKIP: {why}");
        return;
    }
    let Some(obj) = object_path() else {
        eprintln!("SKIP: no BPF object found (set BOWERY_BPF_OBJ_PATH)");
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let victim = make_victim(dir.path(), "victim.sh");
    let bystander = make_victim(dir.path(), "bystander.sh");

    // Both run before anything is blocked. If this fails the test is
    // broken, not the blocker.
    assert!(exec_allowed(&victim), "victim must run before blocking");
    assert!(
        exec_allowed(&bystander),
        "bystander must run before blocking"
    );

    let mut blocker = BpfBlocker::load(&obj).expect("load blocker");
    assert!(
        blocker.inode_matching_armed(),
        "this kernel has BTF, so offsets must have resolved"
    );

    // The kernel's dev_t, not the one `stat` reports. These are two
    // packings of the same major/minor pair, and using the wrong one
    // fails silently: the map write succeeds and nothing ever matches.
    let md = std::fs::metadata(&victim).unwrap();
    let dev = bowery_response::action::kernel_dev_from_stat_dev(md.dev());
    blocker.block_inode(dev, md.ino()).expect("block");

    assert!(
        !exec_allowed(&victim),
        "the blocked file must not execute — this is the whole feature"
    );
    assert!(
        exec_allowed(&bystander),
        "an unrelated file must be unaffected; blocking one inode must not \
         become blocking everything"
    );

    // A rename keeps the inode, so the block must follow the file. This
    // is exactly what the comm key could not do.
    let renamed = dir.path().join("renamed.sh");
    std::fs::rename(&victim, &renamed).unwrap();
    assert!(
        !exec_allowed(&renamed),
        "renaming a blocked file must not escape the block"
    );

    // A copy is a different file and must run: the block is on identity,
    // not on content or name.
    let copy = dir.path().join("copy.sh");
    std::fs::copy(&renamed, &copy).unwrap();
    let mut perms = std::fs::metadata(&copy).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&copy, perms).unwrap();
    assert!(
        exec_allowed(&copy),
        "a copy has its own inode and must not inherit the block"
    );

    assert!(blocker.unblock_inode(dev, md.ino()).expect("unblock"));
    assert!(exec_allowed(&renamed), "unblocking must restore execution");
}

/// An object loaded without armed offsets must never deny anything.
///
/// This is the property that makes the design safe rather than merely
/// careful: the dangerous state is unreachable, not just avoided.
#[test]
fn an_unarmed_blocker_refuses_to_claim_it_blocked_anything() {
    if let Some(why) = cannot_run() {
        eprintln!("SKIP: {why}");
        return;
    }
    let Some(obj) = object_path() else {
        eprintln!("SKIP: no BPF object found");
        return;
    };
    let mut blocker = BpfBlocker::load(&obj).expect("load");
    if blocker.inode_matching_armed() {
        // Cannot force the unarmed path on a host whose BTF resolves;
        // the refusal is unit-tested via the engine instead.
        eprintln!("SKIP: this kernel arms successfully");
        return;
    }
    let err = blocker.block_inode(1, 2).unwrap_err();
    assert!(
        err.to_string().contains("not armed"),
        "an unarmed blocker must refuse rather than silently no-op: {err}"
    );
}
