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
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map, tracepoint},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
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
    /// **Our own** address on this socket.
    ///
    /// Needed to ask a peer "did you connect to me?" without naming the
    /// wrong address: a host with several addresses that guessed would
    /// get back "no record" for a connection the peer legitimately made
    /// elsewhere, and alert that a healthy agent is lying. That is the
    /// worst false positive this system can emit, so the address is
    /// measured rather than assumed.
    pub saddr_v4: [u8; 4],
    pub daddr_v6: [u8; 16],
    pub saddr_v6: [u8; 16],
    /// Connecting task's comm. Zero for `DIRECTION_IN`, same reason as
    /// `pid`.
    pub comm: [u8; 16],
}

/// The open asked for write intent.
pub const ACCESS_WRITE: u8 = 0;
/// A read of a path whose *name* suggests it holds a secret. The kernel
/// filter is deliberately permissive — userspace has the full path and
/// decides what actually matters.
pub const ACCESS_SENSITIVE_READ: u8 = 1;

/// Longest path captured for a file event.
///
/// Paths can reach `PATH_MAX` (4096), but a 4 KiB record per open would
/// dominate the ring and force drops on exactly the busy hosts that
/// matter most. 256 bytes covers every persistence and credential path
/// we watch for with room to spare; anything longer is truncated and
/// says so, because a silently shortened path is a path that quietly
/// stops matching a rule.
pub const FILE_PATH_LEN: usize = 256;

/// A file opened with write intent. Layout: 4 + 4 + 1 + 1 + 2 + 16 + 256.
#[repr(C)]
pub struct FileEvent {
    pub pid: u32,
    /// Raw `openat` flags, as the kernel received them.
    pub flags: u32,
    /// 1 when the path did not fit in `path` and was cut short.
    pub truncated: u8,
    /// [`ACCESS_WRITE`] or [`ACCESS_SENSITIVE_READ`].
    pub access: u8,
    pub _pad1: u16,
    pub comm: [u8; 16],
    /// NUL-terminated where it fits. May be a *relative* path: `openat`
    /// takes a dirfd, and resolving one in the kernel probe is not
    /// possible. Userspace matches only absolute paths and counts the
    /// rest, so the blind spot is measured rather than assumed away.
    pub path: [u8; FILE_PATH_LEN],
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

// ---------------------------------------------------------------------------
// Loss accounting.
// ---------------------------------------------------------------------------

/// Per-ring count of events the kernel could not hand to userspace.
///
/// `RingBuf::reserve` returns `None` when the ring is full, and the
/// probe then has no choice but to drop the event. Nothing about that
/// is visible from userspace: a saturated sensor and a quiet host
/// produce byte-identical output, which is the worst failure mode an
/// EDR has. Counting here is the only place the information exists.
///
/// `PerCpuArray`, not `Array`: each CPU increments only its own slot,
/// so the counter needs no atomics and cannot lose increments to a
/// race. Userspace sums across CPUs.
///
/// Indices are [`DROP_EXEC`], [`DROP_EXIT`], [`DROP_CONNECT`].
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DROP_SLOTS, 0);

pub const DROP_EXEC: u32 = 0;
pub const DROP_EXIT: u32 = 1;
pub const DROP_CONNECT: u32 = 2;
pub const DROP_FILE: u32 = 3;
/// Sized with headroom so a new probe doesn't require userspace to
/// tolerate a resized map mid-upgrade.
pub const DROP_SLOTS: u32 = 8;

/// Record one dropped event. Best-effort by construction: if the
/// counter itself is unavailable there is nothing useful to do, and a
/// probe must never fail because its telemetry did.
#[inline(always)]
fn count_drop(slot: u32) {
    if let Some(ptr) = DROPS.get_ptr_mut(slot) {
        // SAFETY: per-CPU slot, so this CPU is the only writer; the
        // pointer is valid for the lifetime of the map.
        unsafe { *ptr = (*ptr).saturating_add(1) };
    }
}

/// Write-intent file opens. Same 256 KiB as the exec ring: writes are
/// far rarer than reads, but a build or a package upgrade produces
/// bursts.
#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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

/// Kernel struct field offsets, resolved by userspace from the running
/// kernel's BTF and written here before the blocker is armed.
///
/// aya has no eBPF-side CO-RE — its loader can apply
/// `BPF_CORE_FIELD_BYTE_OFFSET` relocations but nothing in `aya-ebpf`
/// emits them for a Rust field access — so the offsets have to arrive
/// out of band. See `bowery-ebpf-loader`'s `btf` module for why
/// hardcoding them was never an option: this hook denies execs, so a
/// wrong offset reads an arbitrary kernel address and blocks arbitrary
/// binaries as root.
///
/// Slot 0 is the **arming word** and the rest are offsets. The layout is
/// duplicated in the loader and the two must not drift.
#[map]
static EXEC_OFFSETS: Array<u32> = Array::with_max_entries(OFF_COUNT, 0);

const OFF_COUNT: u32 = 6;
/// Slot 0. Anything else — including the zero an unpopulated map holds —
/// means "not armed", and [`block_exec`] allows every exec.
///
/// This is the property that makes the whole design safe: an object
/// loaded without userspace resolving offsets cannot deny anything, so
/// the dangerous state is unreachable by accident rather than merely
/// avoided by convention.
const OFF_ARMED_MAGIC: u32 = 0xB0_9E_00_01;
const OFF_ARMED: u32 = 0;
const OFF_BINPRM_FILE: u32 = 1;
const OFF_FILE_INODE: u32 = 2;
const OFF_INODE_INO: u32 = 3;
const OFF_INODE_SB: u32 = 4;
const OFF_SB_DEV: u32 = 5;

/// Kernel module loads, which are how an attacker stops any of this
/// working.
///
/// A module runs in kernel context and can hide processes, files and
/// sockets from every other probe here — including the ones that would
/// have reported it. Catching the *load* is the only chance: after it,
/// the module decides what the agent is allowed to see.
#[repr(C)]
pub struct ModuleLoadEvent {
    pub pid: u32,
    /// Kernel taint bitmask at load time. Bit 12 (`TAINT_OOT_MODULE`)
    /// and bit 13 (`TAINT_UNSIGNED_MODULE`) are the ones that matter.
    pub taints: u32,
    pub comm: [u8; 16],
    pub name: [u8; 64],
}

#[map]
static MODULE_EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024, 0);

/// One process taking control of another.
#[repr(C)]
pub struct PtraceEvent {
    pub pid: u32,
    pub target_pid: u32,
    pub request: u32,
    pub _pad: u32,
    pub comm: [u8; 16],
}

#[map]
static PTRACE_EVENTS: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

/// Blocklist keyed by the identity of the *file being executed*:
/// `[dev, ino]`.
///
/// This is what `BLOCKED_COMMS` should always have been. `comm` is 16
/// bytes any process sets with `prctl`, so a comm blocklist is both
/// bypassable (rename yourself) and weaponisable (name yourself `sshd`
/// and the agent locks the real one out). A (dev, ino) pair names the
/// file itself: a copy gets a new inode and a rename keeps the old one,
/// which is the correct behaviour in both cases.
#[map]
static BLOCKED_INODES: LruHashMap<[u64; 2], u8> = LruHashMap::with_max_entries(4096, 0);

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
        count_drop(DROP_EXEC);
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
        count_drop(DROP_EXIT);
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
    let saddr_v4: [u8; 4] = unsafe { ctx.read_at(32)? };
    let daddr_v6: [u8; 16] = unsafe { ctx.read_at(56)? };
    let saddr_v6: [u8; 16] = unsafe { ctx.read_at(40)? };

    let Some(mut entry) = CONNECT_EVENTS.reserve::<ConnectEvent>(0) else {
        count_drop(DROP_CONNECT);
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
        (*event).saddr_v4 = saddr_v4;
        (*event).daddr_v6 = daddr_v6;
        (*event).saddr_v6 = saddr_v6;
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
// ---------------------------------------------------------------------------
// File opens (write intent).
// ---------------------------------------------------------------------------

// `sys_enter_openat` argument layout.
//
// These offsets are STRUCTURAL, not per-architecture guesswork. Every
// syscall-enter tracepoint shares `struct syscall_trace_enter`:
// `trace_entry` (8 bytes), then `int nr` (4 + 4 padding), then
// `unsigned long args[]`. So argument N sits at 16 + 8*N on any 64-bit
// architecture, whatever the syscall's own prototype says the types are.
//
// Userspace still verifies them against the kernel's own published
// format file before attaching, and refuses to attach on a mismatch.
// This project has already shipped one bug from assumed tracepoint
// offsets (byte-swapped ports that every test agreed on), and the
// failure mode here is worse: a wrong offset yields a garbage pointer
// and silently empty paths.
/// `module:module_load` layout. Unlike a syscall tracepoint, whose args
/// are a uniform array, this one has named fields: `taints` (u32) then
/// `name` as a `__data_loc`. Verified against the kernel's own format
/// file at load time — see `verify_module_load_layout`.
/// `sys_enter_ptrace` args, at the structural offsets every 64-bit
/// syscall tracepoint uses: `trace_entry`(8) + `nr`(4+4 pad) + args[].
const PTRACE_ARG_REQUEST: usize = 16; // args[0]
const PTRACE_ARG_PID: usize = 24; // args[1]

/// The requests that write or seize another process, from
/// `uapi/linux/ptrace.h`. Reading (`PEEK*`) and the self-attach a
/// debuggee performs (`TRACEME`) are deliberately absent: this is about
/// taking control of a process, not observing one.
const PTRACE_POKETEXT: u64 = 4;
const PTRACE_POKEDATA: u64 = 5;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SETREGS: u64 = 13;
const PTRACE_SEIZE: u64 = 0x4206;

/// Not a `ptrace` request. `process_vm_writev` reaches the same place by
/// another door, and reporting it as its own event type would mean a
/// second ring, a second parser and a second rule for one finding —
/// "something wrote another process's memory". This sentinel rides the
/// same record; userspace names it.
const REQUEST_VM_WRITEV: u64 = 0xFFFF_FFFF;

/// `sys_enter_process_vm_writev` args: pid is args[0].
const VM_WRITEV_ARG_PID: usize = 16;

const MODLOAD_TAINTS: usize = 8;
const MODLOAD_NAME_DATALOC: usize = 12;

const OPENAT_ARG_FILENAME: usize = 24; // args[1]
const OPENAT_ARG_FLAGS: usize = 32; // args[2]

// Access modes and creation flags. Values from asm-generic/fcntl.h,
// shared by x86_64 and aarch64.
const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;

/// Scratch for the path, because 256 bytes will not fit on the 512-byte
/// BPF stack alongside everything else. Per-CPU, so there is no sharing
/// and no lock.
#[repr(C)]
pub struct PathScratch {
    pub buf: [u8; FILE_PATH_LEN],
}

#[map]
static PATH_SCRATCH: PerCpuArray<PathScratch> = PerCpuArray::with_max_entries(1, 0);

/// Does the path end with `pat`?
///
/// **Suffix matching, with no scan for the last slash.** Finding the
/// basename by scanning meant a 256-iteration loop over a map-backed
/// buffer, and the verifier explores that one state per iteration: the
/// program was rejected after eight seconds of analysis. Anchoring each
/// pattern at the end of the string needs one computed offset per
/// pattern and no loop over the path at all.
///
/// Patterns therefore begin with `/`, which makes them match a whole
/// final path component — `/shadow` matches `/etc/shadow` but not
/// `/var/lib/myshadow`.
#[inline(always)]
fn ends_with(buf: &[u8; FILE_PATH_LEN], len: usize, pat: &[u8]) -> bool {
    if len < pat.len() || len > FILE_PATH_LEN {
        return false;
    }
    let start = len - pat.len();
    let mut i = 0;
    while i < pat.len() {
        if buf[(start + i) & (FILE_PATH_LEN - 1)] != pat[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Is this the name of a file that holds a secret?
///
/// Deliberately permissive: userspace sees the whole path and decides
/// what warrants an alert, so a false positive here costs one ring slot
/// rather than an operator's attention.
#[inline(always)]
fn is_secret_path(buf: &[u8; FILE_PATH_LEN], len: usize) -> bool {
    // Unix account and password databases.
    ends_with(buf, len, b"/shadow")
        || ends_with(buf, len, b"/gshadow")
        || ends_with(buf, len, b"/opasswd")
        || ends_with(buf, len, b"/sudoers")
        // SSH private keys and host keys.
        || ends_with(buf, len, b"/id_rsa")
        || ends_with(buf, len, b"/id_dsa")
        || ends_with(buf, len, b"/id_ecdsa")
        || ends_with(buf, len, b"/id_ed25519")
        || ends_with(buf, len, b"_key")
        || ends_with(buf, len, b"/authorized_keys")
        // Cloud and cluster credentials.
        || ends_with(buf, len, b"/credentials")
        || ends_with(buf, len, b"/kubeconfig")
        // Application and service credentials.
        || ends_with(buf, len, b"/.netrc")
        || ends_with(buf, len, b"/.pgpass")
        || ends_with(buf, len, b"/.my.cnf")
        || ends_with(buf, len, b"/.git-credentials")
        || ends_with(buf, len, b"/.htpasswd")
        || ends_with(buf, len, b"/.dockercfg")
        || ends_with(buf, len, b"/secring.gpg")
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_openat(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_openat(ctx: &TracePointContext) -> Result<(), i64> {
    let flags: u64 = unsafe { ctx.read_at(OPENAT_ARG_FLAGS)? };
    let filename_ptr: u64 = unsafe { ctx.read_at(OPENAT_ARG_FILENAME)? };
    if filename_ptr == 0 {
        return Ok(());
    }

    // Write intent is what persistence, tampering and ransomware have in
    // common, and it is cheap to test.
    let accmode = flags & O_ACCMODE;
    let writes = accmode == O_WRONLY || accmode == O_RDWR;
    let creates = flags & (O_CREAT | O_TRUNC | O_APPEND) != 0;
    let write_intent = writes || creates;

    let Some(scratch) = PATH_SCRATCH.get_ptr_mut(0) else {
        return Ok(());
    };
    // SAFETY: per-CPU slot, so this CPU is its only writer.
    let buf = unsafe { &mut (*scratch).buf };

    // The filename is in *user* memory and may be paged out or racing a
    // rename; a failed read means we emit nothing rather than a wrong
    // path. `_str_bytes` stops at the NUL, so a typical 30-byte path
    // costs 30 bytes and not 256 — which is what makes reading on every
    // openat affordable.
    let Ok(read) = (unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, buf) })
    else {
        return Ok(());
    };
    let len = read.len();

    let access = if write_intent {
        ACCESS_WRITE
    } else {
        // Reads outnumber writes by orders of magnitude, so only the
        // ones whose name suggests a secret are shipped. Everything else
        // is dropped here, in the kernel, where it costs nothing.
        if !is_secret_path(buf, len) {
            return Ok(());
        }
        ACCESS_SENSITIVE_READ
    };

    let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) else {
        count_drop(DROP_FILE);
        return Err(-1);
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // SAFETY: we reserved exactly sizeof(FileEvent); the pointer is
    // valid until submit/discard.
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).pid = (pid_tgid >> 32) as u32;
        (*event).flags = flags as u32;
        (*event).access = access;
        (*event)._pad1 = 0;
        (*event).comm = comm;
        (*event).truncated = u8::from(len >= FILE_PATH_LEN - 1);
        (*event).path = *buf;
    }
    entry.submit(0);
    Ok(())
}

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
/// Report `ptrace` requests that write to or seize another process.
///
/// Injected code inherits the identity of the process it lands in, which
/// is what makes this worth a probe: a packaged, unmodified binary is
/// still packaged and unmodified after something else is running inside
/// it, so every provenance and lineage check in this agent is blind to
/// it.
///
/// Filtered in the kernel to the control-taking requests. Reads
/// (`PEEK*`) and `TRACEME` are far more common and are not injection —
/// shipping them would bury the signal in a debugger's own traffic.
#[tracepoint]
pub fn ptrace_enter(ctx: TracePointContext) -> u32 {
    match try_ptrace(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ptrace(ctx: &TracePointContext) -> Result<(), i64> {
    let request: u64 = unsafe { ctx.read_at(PTRACE_ARG_REQUEST)? };
    if request != PTRACE_ATTACH
        && request != PTRACE_SEIZE
        && request != PTRACE_POKETEXT
        && request != PTRACE_POKEDATA
        && request != PTRACE_SETREGS
    {
        return Ok(());
    }
    let target: u64 = unsafe { ctx.read_at(PTRACE_ARG_PID)? };

    let Some(mut entry) = PTRACE_EVENTS.reserve::<PtraceEvent>(0) else {
        count_drop(DROP_EXEC);
        return Err(-1);
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).pid = (pid_tgid >> 32) as u32;
        (*event).target_pid = target as u32;
        (*event).request = request as u32;
        (*event)._pad = 0;
        (*event).comm = comm;
    }
    entry.submit(0);
    Ok(())
}

/// Report `process_vm_writev`, which writes another process's memory
/// without `ptrace` at all.
///
/// Almost nothing legitimate does this. It exists for debuggers and
/// checkpoint/restore, both of which are exempted in userspace by the
/// same packaged-binary test the `ptrace` path uses.
#[tracepoint]
pub fn vm_writev_enter(ctx: TracePointContext) -> u32 {
    match try_vm_writev(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_vm_writev(ctx: &TracePointContext) -> Result<(), i64> {
    let target: u64 = unsafe { ctx.read_at(VM_WRITEV_ARG_PID)? };
    let Some(mut entry) = PTRACE_EVENTS.reserve::<PtraceEvent>(0) else {
        count_drop(DROP_EXEC);
        return Err(-1);
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).pid = (pid_tgid >> 32) as u32;
        (*event).target_pid = target as u32;
        (*event).request = REQUEST_VM_WRITEV as u32;
        (*event)._pad = 0;
        (*event).comm = comm;
    }
    entry.submit(0);
    Ok(())
}

/// Report every module load, with the taint flags the kernel assigned.
///
/// Deliberately reports *all* of them rather than filtering in-kernel on
/// taint. A stock host loads modules constantly at boot and on hotplug,
/// so the interesting question — is this one unsigned, out-of-tree, or
/// arriving long after boot — is a userspace judgement, and filtering
/// here would throw away the context needed to make it.
#[tracepoint]
pub fn module_load(ctx: TracePointContext) -> u32 {
    match try_module_load(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_module_load(ctx: &TracePointContext) -> Result<(), i64> {
    let taints: u32 = unsafe { ctx.read_at(MODLOAD_TAINTS)? };
    // `__data_loc` packs the payload's length in the high 16 bits and
    // its offset from the record start in the low 16.
    let dataloc: u32 = unsafe { ctx.read_at(MODLOAD_NAME_DATALOC)? };
    let name_off = (dataloc & 0xffff) as usize;

    let Some(mut entry) = MODULE_EVENTS.reserve::<ModuleLoadEvent>(0) else {
        count_drop(DROP_EXEC);
        return Err(-1);
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).pid = (pid_tgid >> 32) as u32;
        (*event).taints = taints;
        (*event).comm = comm;
        (*event).name = [0u8; 64];
        // Bounded copy from the record's variable-length area. The
        // verifier needs a compile-time bound, and a module name is far
        // shorter than 64 bytes (MODULE_NAME_LEN is 56).
        let mut i = 0usize;
        while i < 56 {
            let Ok(b) = ctx.read_at::<u8>(name_off + i) else {
                break;
            };
            if b == 0 {
                break;
            }
            (*event).name[i & 63] = b;
            i += 1;
        }
    }
    entry.submit(0);
    Ok(())
}

#[lsm(hook = "bprm_check_security")]
pub fn block_exec(ctx: LsmContext) -> i32 {
    // Identity of the binary being exec'd, when userspace has armed us
    // with resolved offsets. Checked first because it is the one that
    // cannot be spoofed.
    if let Some(key) = exec_inode(&ctx) {
        // SAFETY: aya-ebpf's lookup helper; the kernel enforces no
        // aliasing. The borrowed pointer is discriminated immediately.
        if unsafe { BLOCKED_INODES.get(&key) }.is_some() {
            return -1;
        }
    }

    let mut comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    normalise_comm(&mut comm);
    // SAFETY: as above.
    let blocked = unsafe { BLOCKED_COMMS.get(&comm) }.is_some();
    if blocked { -1 } else { 0 }
}

/// `[dev, ino]` of the file this exec is about, or `None`.
///
/// # Every failure path returns `None`, which means *allow*
///
/// This runs inside a hook whose return value denies execution, so the
/// bias has to be absolute: not armed, an offset missing, any
/// `bpf_probe_read_kernel` failing, a null pointer anywhere in the
/// chain — all of them yield `None` and the exec proceeds. The worst
/// outcome of a bug here is a missed block. Denying on a failed read
/// would make a transient kernel-memory read failure into an
/// unbootable host.
#[inline(always)]
fn exec_inode(ctx: &LsmContext) -> Option<[u64; 2]> {
    if *EXEC_OFFSETS.get(OFF_ARMED)? != OFF_ARMED_MAGIC {
        return None;
    }
    let off_binprm_file = *EXEC_OFFSETS.get(OFF_BINPRM_FILE)? as usize;
    let off_file_inode = *EXEC_OFFSETS.get(OFF_FILE_INODE)? as usize;
    let off_inode_ino = *EXEC_OFFSETS.get(OFF_INODE_INO)? as usize;
    let off_inode_sb = *EXEC_OFFSETS.get(OFF_INODE_SB)? as usize;
    let off_sb_dev = *EXEC_OFFSETS.get(OFF_SB_DEV)? as usize;

    // Argument 0 of bprm_check_security is `struct linux_binprm *`.
    // SAFETY: the LSM hook's own argument, as the kernel passed it.
    let bprm: *const u8 = unsafe { ctx.arg(0) };
    if bprm.is_null() {
        return None;
    }

    // SAFETY: every read goes through bpf_probe_read_kernel, which is
    // fault-tolerant by design — it returns an error rather than
    // faulting, and `?` turns each error into "allow".
    let file = unsafe { read_ptr(bprm.add(off_binprm_file))? };
    let inode = unsafe { read_ptr(file.add(off_file_inode))? };
    let ino: u64 = unsafe { bpf_probe_read_kernel(inode.add(off_inode_ino).cast()).ok()? };
    let sb = unsafe { read_ptr(inode.add(off_inode_sb))? };
    let dev: u32 = unsafe { bpf_probe_read_kernel(sb.add(off_sb_dev).cast()).ok()? };

    Some([u64::from(dev), ino])
}

/// Read a kernel pointer, rejecting null.
///
/// # Safety
/// `at` must be an address the kernel may legitimately hold a pointer
/// at; `bpf_probe_read_kernel` tolerates it not being readable.
#[inline(always)]
unsafe fn read_ptr(at: *const u8) -> Option<*const u8> {
    let p: u64 = unsafe { bpf_probe_read_kernel(at.cast()).ok()? };
    if p == 0 {
        return None;
    }
    Some(p as *const u8)
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
