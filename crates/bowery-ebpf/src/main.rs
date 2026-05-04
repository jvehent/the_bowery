//! Bowery's kernel-side eBPF programs.
//!
//! Phase 2 BPF surface (after expansion):
//! - `sched/sched_process_exec` → [`ExecEvent`] over `EVENTS` ringbuf
//! - `sched/sched_process_exit` → [`ExitEvent`] over `EXIT_EVENTS` ringbuf
//! - `sock/inet_sock_set_state` → [`ConnectEvent`] over `CONNECT_EVENTS`
//!   ringbuf, filtered to outgoing TCP connect attempts
//!   (`oldstate=TCP_CLOSE` → `newstate=TCP_SYN_SENT`)
//!
//! The user-space loader (`bowery-ebpf-loader`) drains all three ring
//! buffers concurrently, enriches the records with `/proc` data, and
//! emits typed [`bowery_events::Event`] records into the agent pipeline.
//!
//! Why a tracepoint and not an LSM-BPF program for connect events?
//! - tracepoints are stable across kernels (no CO-RE needed for the
//!   fields we read here)
//! - `inet_sock_set_state` exposes daddr / dport / family directly in
//!   args — no struct-sock walking required
//! - it fires on both TCP v4 and v6 in process context, so
//!   `bpf_get_current_pid_tgid` is the connecting task
//! - observe-only matches Phase 2's mandate; blocking belongs to the
//!   response engine (Phase 7), which is where LSM hooks come in

#![no_std]
#![no_main]
#![allow(static_mut_refs)] // aya-ebpf's #[map] macro generates these

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

// ---------------------------------------------------------------------------
// Wire formats (must match the user-space loader byte-for-byte).
// ---------------------------------------------------------------------------

/// Process-exec record. Layout: 4 + 4 + 16 = 24 bytes, no padding.
#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}

/// Process-exit record. Layout: 4 + 16 = 20 bytes, no padding.
/// We don't carry `exit_code` here — the `sched_process_exit` tracepoint
/// args expose only `comm`, `pid`, `prio`. Reading `task->exit_code`
/// would require CO-RE, which we'd rather avoid for now.
#[repr(C)]
pub struct ExitEvent {
    pub pid: u32,
    pub comm: [u8; 16],
}

/// Outgoing-TCP-connect record. Layout: 4 + 2 + 2 + 4 + 16 + 16 = 44
/// bytes. `dport` is in network byte order; `daddr_v4` is the raw 4
/// bytes from the tracepoint (also network order). `family` is `AF_INET`
/// (2) or `AF_INET6` (10) — userspace decides which `daddr_*` field to
/// trust based on it.
#[repr(C)]
pub struct ConnectEvent {
    pub pid: u32,
    pub family: u16,
    pub dport: u16,
    pub daddr_v4: [u8; 4],
    pub daddr_v6: [u8; 16],
    pub comm: [u8; 16],
}

// ---------------------------------------------------------------------------
// Ring buffers.
// ---------------------------------------------------------------------------

/// Exec events: 256 KiB ≈ 10k records — comfortable for normal hosts.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Exit events: same bus pressure as exec, smaller record, so 64 KiB
/// suffices.
#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// TCP connect events: bursty in some workloads (browsers, CI runners),
/// so match the exec ring at 256 KiB.
#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ---------------------------------------------------------------------------
// Programs.
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exec(_ctx: &TracePointContext) -> Result<(), i64> {
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

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exit(_ctx: &TracePointContext) -> Result<(), i64> {
    // Only emit thread-group leaders to avoid one record per dying
    // thread — userspace cares about process death, not thread death.
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    if pid != tid {
        return Ok(());
    }

    let Some(mut entry) = EXIT_EVENTS.reserve::<ExitEvent>(0) else {
        return Err(-1);
    };
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // SAFETY: reservation guarantees a valid sizeof(ExitEvent) buffer.
    unsafe {
        let event = entry.as_mut_ptr();
        (*event).pid = pid;
        (*event).comm = comm;
    }
    entry.submit(0);
    Ok(())
}

// `inet_sock_set_state` tracepoint format (stable since 4.16):
//   offset 16: int oldstate
//   offset 20: int newstate
//   offset 24: u16 sport
//   offset 26: u16 dport (net order)
//   offset 28: u16 family (AF_INET=2, AF_INET6=10)
//   offset 30: u16 protocol (IPPROTO_TCP=6)
//   offset 32: u8 saddr[4]
//   offset 36: u8 daddr[4]
//   offset 40: u8 saddr_v6[16]
//   offset 56: u8 daddr_v6[16]
// We filter for outgoing TCP connect: protocol=6, oldstate=CLOSE(7),
// newstate=SYN_SENT(2).
const TCP_SYN_SENT: i32 = 2;
const TCP_CLOSE: i32 = 7;
const IPPROTO_TCP: u16 = 6;

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_connect(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offsets are taken from the kernel's stable
    // tracepoint format (sock:inet_sock_set_state, kernel ≥4.16).
    // Out-of-bounds reads return Err, not UB.
    let oldstate: i32 = unsafe { ctx.read_at(16)? };
    let newstate: i32 = unsafe { ctx.read_at(20)? };
    if oldstate != TCP_CLOSE || newstate != TCP_SYN_SENT {
        return Ok(());
    }
    // SAFETY: same justification as above.
    let protocol: u16 = unsafe { ctx.read_at(30)? };
    if protocol != IPPROTO_TCP {
        return Ok(());
    }
    // SAFETY: same justification as above.
    let family: u16 = unsafe { ctx.read_at(28)? };
    let dport: u16 = unsafe { ctx.read_at(26)? };
    let daddr_v4: [u8; 4] = unsafe { ctx.read_at(36)? };
    let daddr_v6: [u8; 16] = unsafe { ctx.read_at(56)? };

    let Some(mut entry) = CONNECT_EVENTS.reserve::<ConnectEvent>(0) else {
        return Err(-1);
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // SAFETY: reservation guarantees a valid sizeof(ConnectEvent) buffer.
    unsafe {
        let event = entry.as_mut_ptr();
        (*event).pid = (pid_tgid >> 32) as u32;
        (*event).family = family;
        (*event).dport = dport;
        (*event).daddr_v4 = daddr_v4;
        (*event).daddr_v6 = daddr_v6;
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
