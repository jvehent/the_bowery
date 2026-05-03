//! Bowery's kernel-side eBPF programs.
//!
//! Phase 2 BPF starts with a single tracepoint (`sched/sched_process_exec`)
//! that emits a [`ExecEvent`] over a ring buffer. The user-space loader
//! (`bowery-ebpf-loader`) drains the ring buffer, enriches the event with
//! `/proc` data, and feeds it into the agent's pipeline as
//! `bowery_events::Event::ProcessExec`.
//!
//! Why a tracepoint and not an LSM-BPF program?
//! - tracepoints are stable across kernels (no CO-RE relocations needed
//!   for the basic fields we read here)
//! - they fire post-exec (the new task is alive, comm is set, /proc/<pid>/exe
//!   is resolvable) — perfect for our user-space enrichment
//! - they're observe-only, which is what Phase 2 wants. Blocking exec is
//!   a Phase 7 (response engine) concern; that's where LSM hooks come in.
//!
//! Subsequent commits add LSM hooks for blocking, plus tracepoints/kprobes
//! for file open, network connect, and process exit.

#![no_std]
#![no_main]
#![allow(static_mut_refs)] // aya-ebpf's #[map] macro generates these

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

/// Wire format for a process-exec event. **Must** match the layout
/// expected by the user-space loader. Keep this in sync with the
/// `ExecEvent` struct in `bowery-ebpf-loader/src/lib.rs`.
#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}

/// Ring buffer carrying ExecEvent records from kernel to user-space.
/// 256 KiB is enough for ~9k events at this struct size; the user-space
/// loader is expected to drain promptly.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exec(_ctx: &TracePointContext) -> Result<(), i64> {
    // Reserve space in the ring buffer up front. If the buffer is full,
    // we drop the event (acceptable signal loss under load — the
    // user-space drop counter will surface it).
    let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) else {
        return Err(-1);
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // SAFETY: we reserved exactly sizeof(ExecEvent) bytes; the pointer
    // is valid until we call submit/discard.
    unsafe {
        let event = entry.as_mut_ptr();
        (*event).pid = (pid_tgid >> 32) as u32;
        (*event).uid = uid_gid as u32;
        (*event).comm = comm;
    }
    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The verifier rejects panicking BPF programs; this should never
    // execute. Loop forever to satisfy the `!` return type.
    loop {}
}
