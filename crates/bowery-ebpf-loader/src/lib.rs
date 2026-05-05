// This crate parses kernel-produced byte records and sets test env
// vars; both are unavoidable here. The workspace-wide `unsafe_code =
// "forbid"` is good policy; we override per-crate with a deliberate
// `allow` and document each unsafe block.
#![allow(unsafe_code)]

//! User-space loader for The Bowery's eBPF programs.
//!
//! Phase 2 BPF surface (after expansion):
//! - `sched/sched_process_exec` → [`bowery_events::Event::ProcessExec`]
//! - `sched/sched_process_exit` → [`bowery_events::Event::ProcessExit`]
//! - `sock/inet_sock_set_state` → [`bowery_events::Event::NetworkConnect`]
//!   (filtered to outgoing TCP connect attempts)
//!
//! Phase 7 surface ([`BpfBlocker`]):
//! - `lsm/bprm_check_security` → returns `-EPERM` when the calling
//!   task's `comm` is in `BLOCKED_COMMS`. Userspace populates the map
//!   via [`BpfBlocker::block_comm`] / [`BpfBlocker::unblock_comm`].
//!
//! Each tracepoint owns its own ring buffer; we spawn one async drain
//! per ring, all feeding the same [`bowery_events::Event`] mpsc channel.
//!
//! Locating the BPF object:
//! 1. `/usr/local/lib/bowery/bowery-ebpf`
//! 2. `/usr/lib/bowery/bowery-ebpf`
//! 3. `BOWERY_BPF_OBJ_PATH` env var, **only** when `BOWERY_BPF_DEV_MODE`
//!    is also set (dev-mode escape hatch for `xtest run-agent`).
//!
//! Each candidate is integrity-checked: must exist as a regular file,
//! be root-owned, and not be group/world-writable. Symlinks are
//! refused outright — a symlink's target can be swapped at any
//! moment, so a root-owned target through a user-writable symlink
//! is the same as a user-controlled file.
//!
//! If none are found, [`BpfEventSource::from_default_locations`] returns
//! a `NotFound` error and the agent falls back to
//! `bowery_events::source::NoopEventSource`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;

use aya::Ebpf;
use aya::maps::ring_buf::RingBuf;
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, BtfError};
use bowery_events::source::{DEFAULT_CHANNEL_CAPACITY, EventSource};
use bowery_events::{Event, NetFamily, NetworkConnect, ProcessExec, ProcessExit, enrich};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Wire formats — must match crates/bowery-ebpf/src/main.rs.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct RawExecEvent {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawExitEvent {
    pid: u32,
    comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawConnectEvent {
    pid: u32,
    family: u16,
    /// Network byte order — converted in user space.
    dport: u16,
    daddr_v4: [u8; 4],
    daddr_v6: [u8; 16],
    comm: [u8; 16],
}

const RAW_EXEC_SIZE: usize = std::mem::size_of::<RawExecEvent>();
const RAW_EXIT_SIZE: usize = std::mem::size_of::<RawExitEvent>();
const RAW_CONNECT_SIZE: usize = std::mem::size_of::<RawConnectEvent>();

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("BPF object not found in any of the default locations")]
    NotFound,
    #[error("BPF object path does not exist: {0}")]
    BadPath(PathBuf),
    #[error(
        "BPF object at {path} fails integrity checks: {reason}. \
         The agent runs as root with CAP_BPF + CAP_SYS_ADMIN; loading \
         a BPF object the kernel's lower-privileged users could have \
         tampered with is full kernel-memory access."
    )]
    InsecureObject { path: PathBuf, reason: String },
    #[error("aya: {0}")]
    Aya(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("btf: {0}")]
    Btf(#[from] BtfError),
}

/// Event source backed by The Bowery's three Phase-2 tracepoints.
#[derive(Debug)]
pub struct BpfEventSource {
    obj_path: PathBuf,
}

impl BpfEventSource {
    /// Use the BPF object at `path`. Validates integrity (Phase-8 H8):
    ///
    /// - Path must exist and resolve to a regular file (no symlinks).
    /// - Owned by root (uid 0) — anything else means a non-root user
    ///   could substitute the object and gain kernel-memory access via
    ///   the agent's `CAP_BPF`.
    /// - Mode must not be group/world-writable (`& 0o022 == 0`).
    ///
    /// Returns `InsecureObject` if any check fails — fail-closed by
    /// design. An honest packaging mistake produces a clear error;
    /// silently falling back to a tampered file would be worse.
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, LoaderError> {
        let path = path.into();
        validate_bpf_object(&path)?;
        Ok(Self { obj_path: path })
    }

    /// Try the env var (only when the agent's `BOWERY_BPF_DEV_MODE`
    /// also says yes — env-var override is dev-only), then standard
    /// install paths.
    ///
    /// The previous behavior (cwd-relative dev fallback) is gone: any
    /// path that survived the integrity check (root-owned, not
    /// world-writable, not a symlink) is fine, but searching cwd is
    /// a privilege-escalation footgun if the agent is ever cd'd into
    /// a non-root-owned directory.
    pub fn from_default_locations() -> Result<Self, LoaderError> {
        if std::env::var_os("BOWERY_BPF_DEV_MODE").is_some()
            && let Ok(p) = std::env::var("BOWERY_BPF_OBJ_PATH")
        {
            tracing::warn!(
                path = %p,
                "BOWERY_BPF_DEV_MODE is set; trusting BOWERY_BPF_OBJ_PATH override"
            );
            return Self::from_path(p);
        }
        for candidate in [
            "/usr/local/lib/bowery/bowery-ebpf",
            "/usr/lib/bowery/bowery-ebpf",
        ] {
            if Path::new(candidate).exists() {
                return Self::from_path(candidate);
            }
        }
        Err(LoaderError::NotFound)
    }

    pub fn obj_path(&self) -> &Path {
        &self.obj_path
    }
}

/// Phase-8 H8: validate that the BPF object's filesystem metadata is
/// consistent with "only root-equivalent users could have written this."
fn validate_bpf_object(path: &Path) -> Result<(), LoaderError> {
    use std::os::unix::fs::MetadataExt;

    if !path.exists() {
        return Err(LoaderError::BadPath(path.to_path_buf()));
    }
    // `symlink_metadata` (NOT `metadata`) — we want to detect symlinks
    // rather than follow them. A symlink whose target is root-owned
    // doesn't help: the *symlink* itself is the entity an attacker
    // controls, and they can swap its target at any moment.
    let md = std::fs::symlink_metadata(path).map_err(|e| LoaderError::InsecureObject {
        path: path.to_path_buf(),
        reason: format!("stat: {e}"),
    })?;
    if md.file_type().is_symlink() {
        return Err(LoaderError::InsecureObject {
            path: path.to_path_buf(),
            reason: "BPF object path is a symlink; refuse to load".into(),
        });
    }
    if !md.is_file() {
        return Err(LoaderError::InsecureObject {
            path: path.to_path_buf(),
            reason: format!("not a regular file (mode {:o})", md.mode()),
        });
    }
    if md.uid() != 0 {
        return Err(LoaderError::InsecureObject {
            path: path.to_path_buf(),
            reason: format!("owner uid is {}, expected 0 (root)", md.uid()),
        });
    }
    let mode = md.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(LoaderError::InsecureObject {
            path: path.to_path_buf(),
            reason: format!("mode {mode:o} is group/world-writable; require 0o644 or stricter"),
        });
    }
    Ok(())
}

impl EventSource for BpfEventSource {
    fn start(self: Box<Self>) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        let obj_path = self.obj_path;

        tokio::spawn(async move {
            if let Err(e) = run(&obj_path, tx).await {
                error!(error = %e, path = %obj_path.display(), "BPF source exited");
            }
        });

        rx
    }
}

async fn run(obj_path: &Path, tx: mpsc::Sender<Event>) -> Result<(), LoaderError> {
    info!(path = %obj_path.display(), "loading BPF object");
    // aya can panic on malformed BTF in some 0.13 paths. catch_unwind
    // turns that into a clean error rather than tearing down the
    // whole agent — important because the integrity check above is
    // a static metadata check and can't catch every malformed-bytes
    // case.
    let load = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Ebpf::load_file(obj_path)));
    let mut ebpf = match load {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => return Err(LoaderError::Aya(e.to_string())),
        Err(payload) => {
            let msg = panic_payload_to_string(&payload);
            return Err(LoaderError::Aya(format!(
                "panic while loading BPF object: {msg}"
            )));
        }
    };

    // Best-effort: hook up aya-log if the BPF program emits log records.
    // No log map => silently skip.
    let _ = aya_log::EbpfLogger::init(&mut ebpf);

    attach_tp(
        &mut ebpf,
        "sched_process_exec",
        "sched",
        "sched_process_exec",
    )?;
    attach_tp(
        &mut ebpf,
        "sched_process_exit",
        "sched",
        "sched_process_exit",
    )?;
    attach_tp(
        &mut ebpf,
        "inet_sock_set_state",
        "sock",
        "inet_sock_set_state",
    )?;

    let exec_ring = take_ring(&mut ebpf, "EVENTS")?;
    let exit_ring = take_ring(&mut ebpf, "EXIT_EVENTS")?;
    let connect_ring = take_ring(&mut ebpf, "CONNECT_EVENTS")?;

    // The three drains share the same Event channel. If any one of them
    // errors out we propagate; a closed receiver is a normal shutdown
    // signal (handled inside the drain loop, returns Ok).
    tokio::try_join!(
        drain_ring(exec_ring, tx.clone(), parse_exec, "exec"),
        drain_ring(exit_ring, tx.clone(), parse_exit, "exit"),
        drain_ring(connect_ring, tx, parse_connect, "connect"),
    )?;

    Ok(())
}

fn attach_tp(
    ebpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<(), LoaderError> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| LoaderError::Aya(format!("program '{program_name}' not found")))?
        .try_into()
        .map_err(|e: aya::programs::ProgramError| LoaderError::Aya(e.to_string()))?;
    program
        .load()
        .map_err(|e| LoaderError::Aya(e.to_string()))?;
    program
        .attach(category, name)
        .map_err(|e| LoaderError::Aya(e.to_string()))?;
    info!(category, name, "attached tracepoint");
    Ok(())
}

fn take_ring(ebpf: &mut Ebpf, name: &str) -> Result<RingBuf<MapData>, LoaderError> {
    let map = ebpf
        .take_map(name)
        .ok_or_else(|| LoaderError::Aya(format!("map '{name}' not found")))?;
    RingBuf::try_from(map).map_err(|e| LoaderError::Aya(e.to_string()))
}

/// Drain a single ring buffer, calling `parse` on each record. Records
/// with the wrong byte length, or that `parse` declines to translate
/// (e.g. unknown address family), are dropped with a debug log.
async fn drain_ring<F>(
    mut ring: RingBuf<MapData>,
    tx: mpsc::Sender<Event>,
    parse: F,
    name: &'static str,
) -> Result<(), LoaderError>
where
    F: Fn(&[u8]) -> Option<Event>,
{
    let async_fd = AsyncFd::new(ring.as_raw_fd())?;
    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                error!(ring = name, error = %e, "ringbuf poll failed");
                return Err(LoaderError::Io(e));
            }
        };

        // Drain everything the kernel has produced since the last wake.
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            let parsed = parse(bytes);
            drop(item); // release the ring slot before any user-space work
            if let Some(event) = parsed
                && tx.send(event).await.is_err()
            {
                debug!(ring = name, "consumer dropped channel; exiting drain");
                return Ok(());
            }
        }

        guard.clear_ready();
    }
}

// ---------------------------------------------------------------------------
// Parsers — one per ring buffer.
// ---------------------------------------------------------------------------

fn parse_exec(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < RAW_EXEC_SIZE {
        warn!(got = bytes.len(), want = RAW_EXEC_SIZE, "short exec record");
        return None;
    }
    // SAFETY: ringbuf records are aligned to 8 bytes and we've
    // size-checked above. RawExecEvent is repr(C) and contains only POD
    // scalars + byte arrays, so the read is safe.
    let raw: RawExecEvent = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawExecEvent>()) };

    let comm = comm_to_string(&raw.comm);
    let exe_path = enrich::pid_exe_path(raw.pid);
    let args = enrich::pid_cmdline(raw.pid).unwrap_or_default();
    Some(Event::ProcessExec(ProcessExec {
        pid: raw.pid,
        // sched_process_exec doesn't carry ppid; let the pipeline fill
        // it from /proc if it cares (Phase 3 doesn't).
        ppid: 0,
        uid: raw.uid,
        comm,
        exe_path,
        args,
        ts: std::time::SystemTime::now(),
    }))
}

fn parse_exit(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < RAW_EXIT_SIZE {
        warn!(got = bytes.len(), want = RAW_EXIT_SIZE, "short exit record");
        return None;
    }
    // SAFETY: same justification as parse_exec.
    let raw: RawExitEvent = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawExitEvent>()) };

    Some(Event::ProcessExit(ProcessExit {
        pid: raw.pid,
        // The tracepoint args don't include the exit code; reading it
        // would require CO-RE on task->exit_code. 0 is the sentinel for
        // "unknown" — userspace consumers should treat exit_code as
        // optional in Phase 2.
        exit_code: 0,
        ts: std::time::SystemTime::now(),
    }))
}

fn parse_connect(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < RAW_CONNECT_SIZE {
        warn!(
            got = bytes.len(),
            want = RAW_CONNECT_SIZE,
            "short connect record"
        );
        return None;
    }
    // SAFETY: same justification as parse_exec.
    let raw: RawConnectEvent =
        unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawConnectEvent>()) };

    let (family, daddr) = match raw.family {
        AF_INET => (NetFamily::V4, IpAddr::V4(Ipv4Addr::from(raw.daddr_v4))),
        AF_INET6 => (NetFamily::V6, IpAddr::V6(Ipv6Addr::from(raw.daddr_v6))),
        other => {
            debug!(family = other, "unknown sock family in connect record");
            return None;
        }
    };

    Some(Event::NetworkConnect(NetworkConnect {
        pid: raw.pid,
        family,
        daddr,
        dport: u16::from_be(raw.dport),
        ts: std::time::SystemTime::now(),
    }))
}

/// Render a panic payload (whatever was passed to `panic!()`) as a
/// best-effort string. Handles the two common payload types
/// (`&str`, `String`); falls back to a generic marker for anything else.
fn panic_payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Phase 7: BPF-LSM blocker.
// ---------------------------------------------------------------------------

/// Holds a loaded BPF object, an attached `lsm/bprm_check_security`
/// program (as [`block_exec`](https://github.com/jvehent/the_bowery/blob/main/crates/bowery-ebpf/src/main.rs)),
/// and a handle to the kernel-side `BLOCKED_COMMS` hash map.
///
/// On drop the LSM program is detached: the agent shutting down stops
/// enforcing. Persisting blocks across agent restarts means pinning
/// the program to bpffs, which we do not yet do (Phase 8 hardening).
///
/// # Why a separate Ebpf instance?
///
/// `BpfEventSource` already loads the same ELF and attaches its
/// tracepoints. Loading the ELF twice keeps the lifecycles
/// independent: the event source can crash and restart without
/// affecting blocks, and vice versa. The duplicated kernel state is a
/// few KiB — not worth the refactor cost in slice 3a.
pub struct BpfBlocker {
    // The Ebpf instance owns the program + maps; dropping it drops the
    // attach link and removes the kernel-side state.
    ebpf: Ebpf,
}

impl std::fmt::Debug for BpfBlocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BpfBlocker").finish_non_exhaustive()
    }
}

impl BpfBlocker {
    /// Load the BPF object at `obj_path`, attach the LSM program, and
    /// return a handle that can update the blocklist map.
    ///
    /// Requires:
    /// - kernel compiled with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`
    /// - `bpf` listed in the active LSM cmdline (`/sys/kernel/security/lsm`)
    /// - the calling process to have `CAP_BPF` + `CAP_SYS_ADMIN`
    ///   (typically: running as root or under the shipped systemd unit)
    pub fn load(obj_path: &Path) -> Result<Self, LoaderError> {
        info!(path = %obj_path.display(), "loading BPF object for LSM blocker");
        let mut ebpf = Ebpf::load_file(obj_path).map_err(|e| LoaderError::Aya(e.to_string()))?;

        // BTF is required by the kernel verifier for LSM programs even
        // when our hook doesn't use any CO-RE relocations directly:
        // the verifier checks that the program signature matches the
        // hook signature it's attaching to.
        let btf = Btf::from_sys_fs().map_err(LoaderError::Btf)?;

        let program: &mut Lsm = ebpf
            .program_mut("block_exec")
            .ok_or_else(|| LoaderError::Aya("program 'block_exec' not found".into()))?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| LoaderError::Aya(e.to_string()))?;
        program
            .load("bprm_check_security", &btf)
            .map_err(|e| LoaderError::Aya(e.to_string()))?;
        program
            .attach()
            .map_err(|e| LoaderError::Aya(e.to_string()))?;
        info!("attached lsm/bprm_check_security");

        Ok(Self { ebpf })
    }

    /// Add `comm` to the blocklist. Truncates / null-pads to 16 bytes
    /// to match the kernel `task->comm` layout. Idempotent: re-adding
    /// the same comm is a no-op.
    pub fn block_comm(&mut self, comm: &str) -> Result<(), LoaderError> {
        let key = comm_key(comm);
        let mut map = self.blocked_comms_mut()?;
        map.insert(key, 1u8, 0)
            .map_err(|e| LoaderError::Aya(format!("BLOCKED_COMMS insert: {e}")))?;
        debug!(comm, "added to BLOCKED_COMMS");
        Ok(())
    }

    /// Remove `comm` from the blocklist. Returns `Ok(false)` if the
    /// comm wasn't present.
    pub fn unblock_comm(&mut self, comm: &str) -> Result<bool, LoaderError> {
        let key = comm_key(comm);
        let mut map = self.blocked_comms_mut()?;
        match map.remove(&key) {
            Ok(()) => {
                debug!(comm, "removed from BLOCKED_COMMS");
                Ok(true)
            }
            Err(aya::maps::MapError::KeyNotFound) => Ok(false),
            Err(e) => Err(LoaderError::Aya(format!("BLOCKED_COMMS remove: {e}"))),
        }
    }

    /// Number of comm entries currently in the blocklist.
    pub fn len(&self) -> Result<usize, LoaderError> {
        let map = self.blocked_comms()?;
        let mut n = 0usize;
        for k in map.keys() {
            let _ = k.map_err(|e| LoaderError::Aya(format!("BLOCKED_COMMS scan: {e}")))?;
            n += 1;
        }
        Ok(n)
    }

    pub fn is_empty(&self) -> Result<bool, LoaderError> {
        Ok(self.len()? == 0)
    }

    fn blocked_comms(&self) -> Result<AyaHashMap<&MapData, [u8; 16], u8>, LoaderError> {
        let map = self
            .ebpf
            .map("BLOCKED_COMMS")
            .ok_or_else(|| LoaderError::Aya("BLOCKED_COMMS map not found".into()))?;
        AyaHashMap::try_from(map).map_err(|e| LoaderError::Aya(e.to_string()))
    }

    fn blocked_comms_mut(&mut self) -> Result<AyaHashMap<&mut MapData, [u8; 16], u8>, LoaderError> {
        let map = self
            .ebpf
            .map_mut("BLOCKED_COMMS")
            .ok_or_else(|| LoaderError::Aya("BLOCKED_COMMS map not found".into()))?;
        AyaHashMap::try_from(map).map_err(|e| LoaderError::Aya(e.to_string()))
    }
}

/// Convert a string to a 16-byte `task->comm` key. Truncates to 15
/// bytes (leaves a trailing null) so the result is always
/// nul-terminated, matching the kernel's invariant for `comm`.
fn comm_key(comm: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let bytes = comm.as_bytes();
    let n = bytes.len().min(15);
    key[..n].copy_from_slice(&bytes[..n]);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comm_strips_trailing_nuls() {
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(b"bash");
        assert_eq!(comm_to_string(&buf), "bash");
    }

    #[test]
    fn comm_handles_full_buffer() {
        let buf = *b"abcdefghijklmnop";
        assert_eq!(comm_to_string(&buf), "abcdefghijklmnop");
    }

    #[test]
    fn comm_handles_invalid_utf8_lossily() {
        let mut buf = [0u8; 16];
        buf[..3].copy_from_slice(&[0xff, 0xfe, b'a']);
        // Non-empty, doesn't panic.
        let s = comm_to_string(&buf);
        assert!(!s.is_empty());
    }

    #[test]
    fn from_default_locations_returns_notfound_when_absent() {
        // Make sure we don't accidentally pick up an in-tree build.
        // Set the env var to a known-absent path.
        // SAFETY: tests are single-threaded by default for `cargo test`
        // unless the user opts into parallel; this is best-effort.
        unsafe {
            std::env::set_var("BOWERY_BPF_OBJ_PATH", "/nonexistent/bowery-ebpf");
        }
        let result = BpfEventSource::from_default_locations();
        unsafe {
            std::env::remove_var("BOWERY_BPF_OBJ_PATH");
        }
        // Either NotFound (preferred) or BadPath if the env var is honored
        // and the path validated. Both are acceptable signals that we
        // didn't find a real object.
        assert!(matches!(
            result,
            Err(LoaderError::NotFound | LoaderError::BadPath(_))
        ));
    }

    /// Reinterpret a `repr(C)` event as its raw byte slice for round-trip
    /// testing. Matches the layout the kernel writes into the ringbuf.
    fn as_bytes<T: Copy>(value: &T) -> &[u8] {
        // SAFETY: T is Copy and repr(C) by contract of all callers; we
        // expose exactly size_of::<T> bytes pinned to value's lifetime.
        unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), size_of::<T>())
        }
    }

    #[test]
    fn parse_exit_reads_pid() {
        let event_raw = RawExitEvent {
            pid: 4242,
            comm: *b"victim\0\0\0\0\0\0\0\0\0\0",
        };
        let event = parse_exit(as_bytes(&event_raw)).expect("parses");
        match event {
            Event::ProcessExit(e) => {
                assert_eq!(e.pid, 4242);
                assert_eq!(e.exit_code, 0);
            }
            other => panic!("expected ProcessExit, got {other:?}"),
        }
    }

    #[test]
    fn parse_connect_v4_decodes_ipv4_and_dport() {
        let event_raw = RawConnectEvent {
            pid: 1234,
            family: AF_INET,
            // 443 in network byte order
            dport: 443u16.to_be(),
            daddr_v4: [192, 168, 1, 50],
            daddr_v6: [0; 16],
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
        };
        let event = parse_connect(as_bytes(&event_raw)).expect("parses");
        match event {
            Event::NetworkConnect(c) => {
                assert_eq!(c.pid, 1234);
                assert_eq!(c.family, NetFamily::V4);
                assert_eq!(c.dport, 443);
                assert_eq!(c.daddr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
            }
            other => panic!("expected NetworkConnect, got {other:?}"),
        }
    }

    #[test]
    fn parse_connect_v6_decodes_ipv6() {
        let mut v6 = [0u8; 16];
        v6[0..2].copy_from_slice(&[0x20, 0x01]); // 2001::1
        v6[15] = 1;
        let event_raw = RawConnectEvent {
            pid: 99,
            family: AF_INET6,
            dport: 80u16.to_be(),
            daddr_v4: [0; 4],
            daddr_v6: v6,
            comm: *b"firefox\0\0\0\0\0\0\0\0\0",
        };
        let event = parse_connect(as_bytes(&event_raw)).expect("parses");
        match event {
            Event::NetworkConnect(c) => {
                assert_eq!(c.family, NetFamily::V6);
                assert_eq!(c.dport, 80);
                let expected = Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1);
                assert_eq!(c.daddr, IpAddr::V6(expected));
            }
            other => panic!("expected NetworkConnect, got {other:?}"),
        }
    }

    #[test]
    fn parse_connect_drops_unknown_family() {
        let event_raw = RawConnectEvent {
            pid: 1,
            family: 17, // AF_NETLINK — not something we care about
            dport: 0,
            daddr_v4: [0; 4],
            daddr_v6: [0; 16],
            comm: [0; 16],
        };
        assert!(parse_connect(as_bytes(&event_raw)).is_none());
    }

    #[test]
    fn parse_exec_short_record_returns_none() {
        let bytes = [0u8; 4];
        assert!(parse_exec(&bytes).is_none());
    }

    #[test]
    fn comm_key_pads_short_strings_with_nuls() {
        let key = comm_key("bash");
        assert_eq!(&key[..4], b"bash");
        assert!(key[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn comm_key_truncates_long_strings_and_keeps_trailing_nul() {
        let key = comm_key("a-very-long-comm-name-that-exceeds-fifteen");
        // Last byte must be 0 (kernel invariant).
        assert_eq!(key[15], 0);
        assert_eq!(&key[..15], b"a-very-long-com");
    }
}
