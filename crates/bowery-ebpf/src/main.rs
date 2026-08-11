//! Bowery's kernel-side eBPF programs.
//!
//! Phase 2 BPF surface (after expansion):
//! - `sched/sched_process_exec` → [`ExecEvent`] over `EVENTS` ringbuf
//! - `sched/sched_process_exit` → [`ExitEvent`] over `EXIT_EVENTS` ringbuf
//! - `sock/inet_sock_set_state` → [`ConnectEvent`] over `CONNECT_EVENTS`
//!   ringbuf, capturing TCP connection setup in BOTH directions:
//!   outbound (`TCP_CLOSE` → `TCP_SYN_SENT`) and inbound
//!   (`TCP_SYN_RECV` → `TCP_ESTABLISHED`). The inbound half is what
//!   lets two hosts correlate the two ends of the same hop.
//!
//! Phase 7 surface (this expansion):
//! - `lsm/bprm_check_security` → consults `BLOCKED_COMMS` (hash map of
//!   16-byte `comm` keys); returns `-EPERM` when the *calling task*'s
//!   comm is in the map. Userspace populates / depopulates the map
//!   via the loader's `BpfBlocker`. This is the simplest dimension
//!   the LSM hook can match on without CO-RE struct walking; richer
//!   keys (sha256 of binary, inode) come in follow-up commits.
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
//! - observe-only matches Phase 2's mandate; LSM hooks below now
//!   provide the blocking surface for Phase 7

#![no_std]
#![no_main]
#![allow(static_mut_refs)] // aya-ebpf's #[map] macro generates these

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{lsm, map, tracepoint},
    maps::{LruHashMap, RingBuf},
    programs::{LsmContext, TracePointContext},
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
    /// Connecting task for `DIRECTION_OUT`. **Zero for
    /// `DIRECTION_IN`**: the SYN_RECV -> ESTABLISHED transition runs in
    /// softirq context, where `bpf_get_current_pid_tgid` returns
    /// whatever task happened to be interrupted — recording it would be
    /// a lie, and a convincing one.
    pub pid: u32,
    pub family: u16,
    /// Remote peer's port, network byte order. The *destination* for an
    /// outbound connection; the client's ephemeral port for an inbound
    /// one.
    pub dport: u16,
    /// Our own port, network byte order. The ephemeral source port
    /// outbound; the listening port inbound (which is the interesting
    /// one — it says what service was reached).
    pub sport: u16,
    /// [`DIRECTION_OUT`] or [`DIRECTION_IN`].
    pub direction: u8,
    pub _pad: u8,
    /// Remote peer's address — the destination outbound, the *source*
    /// inbound.
    pub daddr_v4: [u8; 4],
    pub daddr_v6: [u8; 16],
    /// Connecting task's comm. Zero for `DIRECTION_IN`, same reason as
    /// `pid`.
    pub comm: [u8; 16],
}

/// This host initiated the connection (`TCP_CLOSE` -> `TCP_SYN_SENT`).
pub const DIRECTION_OUT: u8 = 0;
/// This host accepted the connection (`TCP_SYN_RECV` -> `TCP_ESTABLISHED`).
///
/// The other half of a lateral-movement hop: whoever connected to us
/// recorded the outbound side on *their* host, with the process
/// attribution we can never see from here.
pub const DIRECTION_IN: u8 = 1;

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

/// Phase-7 LSM blocklist keyed by 16-byte `comm` (Linux kernel's
/// `task->comm`). Userspace inserts an entry to forbid the matching
/// process from execing anything new — `block_exec` returns `-EPERM`
/// from the `bprm_check_security` LSM hook.
///
/// `LruHashMap` (BPF_MAP_TYPE_LRU_HASH) automatically evicts the
/// least-recently-used entry once full, so a steady drip of new
/// `BlockExec` actions can never wedge the map. Capacity 4096 is
/// well above realistic concurrent-block-list-size on a single host
/// (Phase-8 audit recommended this; the previous 256 was a hard cap
/// with no eviction).
#[map]
static BLOCKED_COMMS: LruHashMap<[u8; 16], u8> = LruHashMap::with_max_entries(4096, 0);

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
const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_SENT: i32 = 2;
const TCP_SYN_RECV: i32 = 3;
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
    // Two transitions, one per direction:
    //   CLOSE    -> SYN_SENT     we dialled out
    //   SYN_RECV -> ESTABLISHED  we accepted a connection
    // Everything else (teardown, retransmit) is noise here.
    let direction = if oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT {
        DIRECTION_OUT
    } else if oldstate == TCP_SYN_RECV && newstate == TCP_ESTABLISHED {
        DIRECTION_IN
    } else {
        return Ok(());
    };
    // SAFETY: same justification as above.
    let protocol: u16 = unsafe { ctx.read_at(30)? };
    if protocol != IPPROTO_TCP {
        return Ok(());
    }
    // SAFETY: same justification as above.
    let family: u16 = unsafe { ctx.read_at(28)? };
    let sport: u16 = unsafe { ctx.read_at(24)? };
    let dport: u16 = unsafe { ctx.read_at(26)? };
    let daddr_v4: [u8; 4] = unsafe { ctx.read_at(36)? };
    let daddr_v6: [u8; 16] = unsafe { ctx.read_at(56)? };

    let Some(mut entry) = CONNECT_EVENTS.reserve::<ConnectEvent>(0) else {
        return Err(-1);
    };
    // Only meaningful when we are the ones dialling; see `ConnectEvent::pid`.
    let (pid, comm) = if direction == DIRECTION_OUT {
        (
            (bpf_get_current_pid_tgid() >> 32) as u32,
            bpf_get_current_comm().unwrap_or([0u8; 16]),
        )
    } else {
        (0u32, [0u8; 16])
    };

    // SAFETY: reservation guarantees a valid sizeof(ConnectEvent) buffer.
    unsafe {
        let event = entry.as_mut_ptr();
        (*event).pid = pid;
        (*event).family = family;
        (*event).dport = dport;
        (*event).sport = sport;
        (*event).direction = direction;
        (*event)._pad = 0;
        (*event).daddr_v4 = daddr_v4;
        (*event).daddr_v6 = daddr_v6;
        (*event).comm = comm;
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// LSM hook — Phase 7 enforcement.
// ---------------------------------------------------------------------------

/// Block exec when the calling task's `comm` is in `BLOCKED_COMMS`.
///
/// The kernel's `bprm_check_security` LSM hook fires *during* the
/// `execve` syscall, before the new program image is committed.
/// `bpf_get_current_comm()` here returns the **calling task's**
/// comm — i.e. the parent that's trying to exec. This gives us the
/// "block this compromised shell from spawning more processes"
/// semantics. Matching on the *new* binary requires walking
/// `bprm->file->f_inode->i_ino` (struct chain → CO-RE territory), and
/// lands in a follow-up commit.
///
/// The hook returns `0` to allow and a negative errno to deny. The
/// verifier requires the return type to be `i32`.
///
/// Trailing-whitespace normalisation: writing to `/proc/<pid>/comm`
/// via `echo` includes the trailing `\n` from the shell, so the
/// kernel stores e.g. `b"bash\n\0\0..."`. We don't want that to
/// silently mismatch a userspace blocklist entry inserted as
/// `b"bash\0\0\0..."`. Zero out trailing whitespace bytes before the
/// map lookup so both `echo "x" > /proc/<pid>/comm` and
/// `printf "x" > /proc/<pid>/comm` produce the same key.
#[lsm(hook = "bprm_check_security")]
pub fn block_exec(_ctx: LsmContext) -> i32 {
    let mut comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    normalise_comm(&mut comm);
    // SAFETY: `BLOCKED_COMMS.get` reads through aya-ebpf's lookup
    // helper; kernel side enforces no aliasing for us. Returning a
    // borrowed pointer that we immediately discriminate on is safe.
    let blocked = unsafe { BLOCKED_COMMS.get(&comm) }.is_some();
    if blocked { -1 } else { 0 }
}

/// Zero trailing ASCII whitespace bytes (`\n`, `\r`, `\t`, space).
/// Stops at the first non-whitespace byte from the right; interior
/// whitespace is preserved (the kernel itself prevents `\0` interior
/// bytes via the `__set_task_comm` strncpy semantics, so anything
/// past the first `\0` is already irrelevant). Bounded `for` loop
/// keeps the BPF verifier happy without unrolled branches.
#[inline(always)]
fn normalise_comm(comm: &mut [u8; 16]) {
    // Iterate right-to-left over a fixed-size array; the verifier
    // can prove termination because the loop bound is a compile-time
    // constant.
    let mut i = comm.len();
    while i > 0 {
        i -= 1;
        match comm[i] {
            b'\n' | b'\r' | b'\t' | b' ' | 0 => comm[i] = 0,
            _ => break,
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The verifier rejects panicking BPF programs; this should never
    // execute. Loop forever to satisfy the `!` return type.
    loop {}
}
