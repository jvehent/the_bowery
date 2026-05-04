//! Phase-7 LSM blocker smoke test.
//!
//! Loads the BPF object, attaches the `bprm_check_security` LSM
//! program, inserts the comm given on the command line into
//! `BLOCKED_COMMS`, then sleeps so the operator can verify (in
//! another shell) that processes whose `comm` matches the entry now
//! get `EPERM` from any `execve`.
//!
//! Usage:
//!     sudo BOWERY_BPF_OBJ_PATH=/path/to/bowery-ebpf \
//!         cargo run --example `lsm_block` -p bowery-ebpf-loader -- bash
//!
//! Verify in another shell on the same host:
//!     bash -c 'ls'
//!     # bash: /usr/bin/ls: Operation not permitted (`EPERM`)
//!
//! Ctrl-C the example to release the block.

use std::time::Duration;

use bowery_ebpf_loader::{BpfBlocker, BpfEventSource};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    let comm = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: lsm_block <comm-to-block>"))?;

    let path = BpfEventSource::from_default_locations()?
        .obj_path()
        .to_path_buf();
    println!("loading {}", path.display());
    let mut blocker = BpfBlocker::load(&path)?;

    println!("blocking comm = {comm:?}");
    blocker.block_comm(&comm)?;
    println!("entries in BLOCKED_COMMS: {}", blocker.len()?);

    println!("LSM hook is now denying execve from any task whose comm matches.");
    println!("Test in another shell, then ctrl-c here to unblock.");
    let _ = tokio::signal::ctrl_c().await;

    println!("\nunblocking…");
    blocker.unblock_comm(&comm)?;
    println!("entries: {}", blocker.len()?);

    // Held alive briefly so the verifier doesn't tear down before the
    // print is flushed.
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}
