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
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aya::Ebpf;
use aya::maps::PerCpuArray;
use aya::maps::ring_buf::RingBuf;
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, BtfError};
use bowery_events::source::{
    DEFAULT_CHANNEL_CAPACITY, EventSource, PROBE_CONNECT, PROBE_EXEC, PROBE_EXIT, PROBE_FILE,
    PROBE_MODULE, PROBE_NAMES, ProbeHealth,
};
use bowery_events::{
    Event, FileOpen, NetDirection, NetFamily, NetworkConnect, ProcessExec, ProcessExit, enrich,
};
pub mod btf;

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

/// Mirrors `bowery_ebpf::FILE_PATH_LEN`.
const FILE_PATH_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawFileEvent {
    pid: u32,
    flags: u32,
    truncated: u8,
    /// Mirrors `bowery_ebpf::ACCESS_*`.
    access: u8,
    _pad1: u16,
    comm: [u8; 16],
    path: [u8; FILE_PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawConnectEvent {
    pid: u32,
    family: u16,
    /// Host byte order: the tracepoint applies `ntohs()` itself.
    dport: u16,
    /// Host byte order, same as `dport`.
    sport: u16,
    /// Mirrors `bowery_ebpf::DIRECTION_OUT` / `DIRECTION_IN`.
    direction: u8,
    _pad: u8,
    daddr_v4: [u8; 4],
    saddr_v4: [u8; 4],
    daddr_v6: [u8; 16],
    saddr_v6: [u8; 16],
    comm: [u8; 16],
}

const DIRECTION_IN: u8 = 1;

const RAW_EXEC_SIZE: usize = std::mem::size_of::<RawExecEvent>();
const RAW_EXIT_SIZE: usize = std::mem::size_of::<RawExitEvent>();
const RAW_CONNECT_SIZE: usize = std::mem::size_of::<RawConnectEvent>();
const RAW_FILE_SIZE: usize = core::mem::size_of::<RawFileEvent>();

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
    /// Shared with the drain tasks and with whoever asks via
    /// [`EventSource::health`]. Created before `start` so a caller can
    /// hold it across the `Box<Self>` consumption.
    health: Arc<ProbeHealth>,
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
        Ok(Self {
            obj_path: path,
            health: Arc::new(ProbeHealth::new()),
        })
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

    /// Live probe health. Clone it before `start` consumes the source.
    #[must_use]
    pub fn health(&self) -> Arc<ProbeHealth> {
        self.health.clone()
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
        let health = self.health;

        tokio::spawn(async move {
            let result = run(&obj_path, tx, health.clone()).await;
            // A source that exits is exactly as blind as one that never
            // started, and until now it said so only in a log line that
            // nobody reads at 03:00. Record it where the watchdog and
            // the SQL surface can see it.
            let reason = match result {
                Ok(()) => "BPF source exited without error".to_string(),
                Err(e) => e.to_string(),
            };
            error!(reason = %reason, path = %obj_path.display(), "BPF source exited");
            health.mark_stopped(reason);
        });

        rx
    }

    fn health(&self) -> Option<Arc<ProbeHealth>> {
        Some(self.health.clone())
    }
}

#[allow(clippy::too_many_lines)] // one linear bring-up sequence
async fn run(
    obj_path: &Path,
    tx: mpsc::Sender<Event>,
    health: Arc<ProbeHealth>,
) -> Result<(), LoaderError> {
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
    health.mark_attached(PROBE_EXEC);
    attach_tp(
        &mut ebpf,
        "sched_process_exit",
        "sched",
        "sched_process_exit",
    )?;
    health.mark_attached(PROBE_EXIT);
    attach_tp(
        &mut ebpf,
        "inet_sock_set_state",
        "sock",
        "inet_sock_set_state",
    )?;
    health.mark_attached(PROBE_CONNECT);

    // Attached only if its assumed layout checks out.
    let file_probe = match verify_openat_layout() {
        Ok(()) => attach_tp(
            &mut ebpf,
            "sys_enter_openat",
            "syscalls",
            "sys_enter_openat",
        )
        .inspect(|()| health.mark_attached(PROBE_FILE))
        .map_err(|e| warn!(error = %e, "file probe unavailable"))
        .is_ok(),
        Err(reason) => {
            error!(
                reason = %reason,
                "refusing to attach the file probe: the kernel's tracepoint layout \
                 does not match what the BPF program reads"
            );
            false
        }
    };

    // Same shape as the file probe: attached only if its layout checks
    // out, and absent entirely on an object built before it existed.
    let module_probe = match verify_module_load_layout() {
        Ok(()) => attach_tp(&mut ebpf, "module_load", "module", "module_load")
            .inspect(|()| health.mark_attached(PROBE_MODULE))
            .map_err(|e| warn!(error = %e, "module probe unavailable"))
            .is_ok(),
        Err(reason) => {
            error!(
                reason = %reason,
                "refusing to attach the module probe: the kernel's tracepoint layout \
                 does not match what the BPF program reads"
            );
            false
        }
    };

    let exec_ring = take_ring(&mut ebpf, "EVENTS")?;
    let exit_ring = take_ring(&mut ebpf, "EXIT_EVENTS")?;
    let connect_ring = take_ring(&mut ebpf, "CONNECT_EVENTS")?;
    // Absent on an object built before the file probe existed, which
    // must still load: an agent has to survive its own rollout.
    let file_ring = if file_probe {
        take_ring(&mut ebpf, "FILE_EVENTS")
            .map_err(|e| warn!(error = %e, "FILE_EVENTS ring unavailable"))
            .ok()
    } else {
        None
    };

    let module_ring = if module_probe {
        take_ring(&mut ebpf, "MODULE_EVENTS")
            .map_err(|e| warn!(error = %e, "MODULE_EVENTS ring unavailable"))
            .ok()
    } else {
        None
    };

    // Optional by design: an object built before the counter existed
    // simply has no DROPS map, and an agent must keep working against
    // it. Absent means "cannot tell", which the snapshot reports as
    // unknown rather than as zero.
    let drops_map: Option<PerCpuArray<MapData, u64>> = if let Some(map) = ebpf.take_map("DROPS") {
        PerCpuArray::try_from(map).map_or_else(
            |e| {
                warn!(error = %e, "DROPS map present but unusable; drop counts unavailable");
                None
            },
            |m| {
                // Symmetric with the warning below: an operator needs to
                // know which of the two states they are in without
                // reading the SQL view.
                info!("ring-buffer loss accounting active");
                Some(m)
            },
        )
    } else {
        warn!(
            "BPF object has no DROPS map — ring-buffer loss cannot be measured. \
             Rebuild the object (scripts/build-ebpf) to enable it."
        );
        None
    };

    // The three drains share the same Event channel. If any one of them
    // errors out we propagate; a closed receiver is a normal shutdown
    // signal (handled inside the drain loop, returns Ok).
    tokio::try_join!(
        drain_ring(
            exec_ring,
            tx.clone(),
            parse_exec,
            PROBE_EXEC,
            health.clone()
        ),
        drain_ring(
            exit_ring,
            tx.clone(),
            parse_exit,
            PROBE_EXIT,
            health.clone()
        ),
        drain_ring(
            connect_ring,
            tx.clone(),
            parse_connect,
            PROBE_CONNECT,
            health.clone()
        ),
        drain_optional_ring(
            file_ring,
            tx.clone(),
            parse_file,
            PROBE_FILE,
            health.clone()
        ),
        drain_optional_ring(module_ring, tx, parse_module, PROBE_MODULE, health.clone()),
        poll_drops(drops_map, health),
    )?;

    Ok(())
}

/// Drain a ring that may not exist on this object or kernel.
async fn drain_optional_ring<F>(
    ring: Option<RingBuf<MapData>>,
    tx: mpsc::Sender<Event>,
    parse: F,
    probe: usize,
    health: Arc<ProbeHealth>,
) -> Result<(), LoaderError>
where
    F: Fn(&[u8]) -> Option<Event>,
{
    if let Some(ring) = ring {
        return drain_ring(ring, tx, parse, probe, health).await;
    }
    // Never resolves: returning would end the try_join! and take the
    // working probes down with the missing one.
    std::future::pending::<()>().await;
    unreachable!()
}

/// How often the kernel's drop counters are copied into [`ProbeHealth`].
///
/// Polled rather than event-driven because drops happen precisely when
/// the ring is full — the moment userspace is least likely to be woken
/// promptly — and because a host that has gone quiet still needs its
/// last known loss reported.
const DROP_POLL_INTERVAL: Duration = Duration::from_secs(10);

async fn poll_drops(
    map: Option<PerCpuArray<MapData, u64>>,
    health: Arc<ProbeHealth>,
) -> Result<(), LoaderError> {
    let Some(map) = map else {
        // Never resolves: the other branches of try_join! run forever,
        // and returning Ok here would end the join and take the sensor
        // down with it.
        std::future::pending::<()>().await;
        unreachable!()
    };
    let slots = [PROBE_EXEC, PROBE_EXIT, PROBE_CONNECT];
    loop {
        for (i, probe) in slots.iter().enumerate() {
            let Ok(idx) = u32::try_from(i) else { continue };
            if let Ok(per_cpu) = map.get(&idx, 0) {
                let total: u64 = per_cpu.iter().copied().fold(0u64, u64::saturating_add);
                health.set_kernel_drops(*probe, total);
            }
        }
        tokio::time::sleep(DROP_POLL_INTERVAL).await;
    }
}

/// What the eBPF program assumes about `sys_enter_openat`'s layout.
///
/// Structural rather than architectural, but assumed tracepoint offsets
/// have already produced one shipped bug here, and this failure is
/// quiet: a wrong offset gives a garbage pointer and a silently empty
/// path, which looks exactly like a host that opens no files.
const OPENAT_EXPECTED: [(&str, usize); 2] = [("filename", 24), ("flags", 32)];

/// `module:module_load` field offsets the BPF program assumes.
///
/// Unlike a syscall tracepoint, whose arguments are a uniform array,
/// this one has named fields. Same discipline as openat: a proven
/// mismatch means the probe is not attached, because a wrong offset here
/// would report module names read from arbitrary bytes.
const MODLOAD_EXPECTED: [(&str, usize); 2] = [("taints", 8), ("name", 12)];

/// Check the assumed offsets against the kernel's published format.
///
/// `Err` only on a *proven* mismatch, which fails closed: the probe is
/// not attached and the sensor reports itself incomplete rather than
/// recording wrong paths. An unreadable format file is an inability to
/// check, not a mismatch, so it warns and proceeds.
fn verify_openat_layout() -> Result<(), String> {
    let candidates = [
        "/sys/kernel/tracing/events/syscalls/sys_enter_openat/format",
        "/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format",
    ];
    let Some(text) = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
    else {
        warn!(
            "could not read the sys_enter_openat format file; proceeding with \
             assumed argument offsets"
        );
        return Ok(());
    };
    for (field, expected) in OPENAT_EXPECTED {
        let Some(actual) = parse_field_offset(&text, field) else {
            warn!(field, "field absent from tracepoint format; cannot verify");
            continue;
        };
        if actual != expected {
            return Err(format!(
                "sys_enter_openat.{field} is at offset {actual}, but the BPF program reads {expected}"
            ));
        }
    }
    info!("sys_enter_openat layout verified against the kernel");
    Ok(())
}

/// Same check as [`verify_openat_layout`], for `module:module_load`.
fn verify_module_load_layout() -> Result<(), String> {
    let candidates = [
        "/sys/kernel/tracing/events/module/module_load/format",
        "/sys/kernel/debug/tracing/events/module/module_load/format",
    ];
    let Some(text) = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
    else {
        warn!(
            "could not read the module_load format file; proceeding with assumed \
             field offsets"
        );
        return Ok(());
    };
    for (field, expected) in MODLOAD_EXPECTED {
        let Some(actual) = parse_field_offset(&text, field) else {
            warn!(field, "field absent from tracepoint format; cannot verify");
            continue;
        };
        if actual != expected {
            return Err(format!(
                "module_load.{field} is at offset {actual}, but the BPF program reads {expected}"
            ));
        }
    }
    info!("module_load layout verified against the kernel");
    Ok(())
}

/// Pull `offset:N` for a named field out of a tracepoint format file.
fn parse_field_offset(format: &str, field: &str) -> Option<usize> {
    format.lines().find_map(|line| {
        let line = line.trim();
        if !line.starts_with("field:") {
            return None;
        }
        let (decl, rest) = line.split_once(';')?;
        let name = decl.rsplit([' ', '*']).find(|t| !t.is_empty())?;
        if name != field {
            return None;
        }
        let off = rest.split("offset:").nth(1)?;
        off.split(';').next()?.trim().parse().ok()
    })
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

/// Wall-clock now in ms, for `last_event` staleness reporting.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
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
    probe: usize,
    health: Arc<ProbeHealth>,
) -> Result<(), LoaderError>
where
    F: Fn(&[u8]) -> Option<Event>,
{
    let name = PROBE_NAMES.get(probe).copied().unwrap_or("?");
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
            match parsed {
                Some(event) => {
                    health.record_event(probe, now_unix_ms());
                    if tx.send(event).await.is_err() {
                        debug!(ring = name, "consumer dropped channel; exiting drain");
                        return Ok(());
                    }
                }
                // A record the kernel produced and userspace could not
                // use: version skew, or an address family we don't
                // model. Counted apart from a kernel drop because the
                // remedy is different.
                None => health.record_parse_failure(probe),
            }
        }

        guard.clear_ready();
    }
}

// ---------------------------------------------------------------------------
// Parsers — one per ring buffer.
// ---------------------------------------------------------------------------

/// Mirrors `ModuleLoadEvent` in the BPF program byte for byte.
#[repr(C)]
struct RawModuleEvent {
    pid: u32,
    taints: u32,
    comm: [u8; 16],
    name: [u8; 64],
}
const RAW_MODULE_SIZE: usize = std::mem::size_of::<RawModuleEvent>();

fn parse_module(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < RAW_MODULE_SIZE {
        warn!(
            got = bytes.len(),
            want = RAW_MODULE_SIZE,
            "short module record"
        );
        return None;
    }
    // SAFETY: size-checked above; RawModuleEvent is repr(C) POD.
    let raw: RawModuleEvent =
        unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawModuleEvent>()) };
    let name = cstr_to_string(&raw.name);
    if name.is_empty() {
        // A module with no readable name tells us nothing actionable and
        // would render as an empty alert subject.
        return None;
    }
    Some(Event::ModuleLoad(bowery_events::ModuleLoad {
        pid: raw.pid,
        comm: comm_to_string(&raw.comm),
        name,
        taints: raw.taints,
        ts: std::time::SystemTime::now(),
    }))
}

fn parse_file(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < RAW_FILE_SIZE {
        warn!(got = bytes.len(), want = RAW_FILE_SIZE, "short file record");
        return None;
    }
    // SAFETY: size-checked above; RawFileEvent is repr(C) POD.
    let raw: RawFileEvent = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawFileEvent>()) };

    let path = cstr_to_string(&raw.path);
    if path.is_empty() {
        return None;
    }
    Some(Event::FileOpen(FileOpen {
        pid: raw.pid,
        comm: comm_to_string(&raw.comm),
        path: PathBuf::from(path),
        flags: raw.flags,
        truncated: raw.truncated != 0,
        // 1 == ACCESS_SENSITIVE_READ in the BPF program.
        sensitive_read: raw.access == 1,
        ts: std::time::SystemTime::now(),
    }))
}

/// Decode a NUL-terminated buffer that may fill its whole extent.
fn cstr_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

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
    // Read the parent now, while the process almost certainly still
    // exists. Lineage rules ("nginx spawned a shell") are the whole
    // reason, and a few microseconds later the answer may be gone.
    let ppid = enrich::pid_ppid(raw.pid).unwrap_or(0);
    let parent_comm = if ppid == 0 {
        String::new()
    } else {
        enrich::pid_comm(ppid).unwrap_or_default()
    };
    Some(Event::ProcessExec(ProcessExec {
        pid: raw.pid,
        ppid,
        parent_comm,
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
        // This is not a malformed packet, it is version skew: the eBPF
        // object on disk was built from different source than this
        // binary. Every connect event is being discarded, which looks
        // exactly like a host that makes no network connections — so it
        // is an error, not a warning, and it names the fix.
        error!(
            got = bytes.len(),
            want = RAW_CONNECT_SIZE,
            "connect record size mismatch — the loaded eBPF object is out of \
             sync with this agent; rebuild it (scripts/build-ebpf) and \
             reinstall it alongside the binary. ALL connect events are being \
             dropped until then"
        );
        return None;
    }
    // SAFETY: same justification as parse_exec.
    let raw: RawConnectEvent =
        unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawConnectEvent>()) };

    let (family, daddr, laddr) = match raw.family {
        AF_INET => (
            NetFamily::V4,
            IpAddr::V4(Ipv4Addr::from(raw.daddr_v4)),
            IpAddr::V4(Ipv4Addr::from(raw.saddr_v4)),
        ),
        AF_INET6 => (
            NetFamily::V6,
            IpAddr::V6(Ipv6Addr::from(raw.daddr_v6)),
            IpAddr::V6(Ipv6Addr::from(raw.saddr_v6)),
        ),
        other => {
            debug!(family = other, "unknown sock family in connect record");
            return None;
        }
    };

    let direction = if raw.direction == DIRECTION_IN {
        NetDirection::Inbound
    } else {
        NetDirection::Outbound
    };

    Some(Event::NetworkConnect(NetworkConnect {
        pid: raw.pid,
        comm: comm_to_string(&raw.comm),
        family,
        daddr,
        local_addr: laddr,
        // NOT `from_be`. The kernel's inet_sock_set_state tracepoint
        // already applies ntohs() to both ports before they reach us
        // (include/trace/events/sock.h), so byte-swapping again yields
        // garbage. Confirmed against live traffic: 443 was being
        // recorded as 47873 (0x01BB read back as 0xBB01) and 80 as
        // 20480. The addresses are different — those really are raw
        // network-order bytes, which is why Ipv4Addr::from is correct.
        dport: raw.dport,
        local_port: raw.sport,
        direction,
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
    /// Whether `EXEC_OFFSETS` holds offsets resolved from this kernel's
    /// BTF. False means the hook cannot match on the executed file and
    /// an inode block must be refused rather than silently downgraded.
    inode_armed: bool,
}

/// `EXEC_OFFSETS` slot layout. Duplicated in `bowery-ebpf`'s
/// `main.rs`; the two must not drift.
const OFF_ARMED: u32 = 0;
const OFF_BINPRM_FILE: u32 = 1;
const OFF_FILE_INODE: u32 = 2;
const OFF_INODE_INO: u32 = 3;
const OFF_INODE_SB: u32 = 4;
const OFF_SB_DEV: u32 = 5;
/// Written to slot 0 only after every offset is in place.
const OFF_ARMED_MAGIC: u32 = 0xB09E_0001;

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

        let mut blocker = Self {
            ebpf,
            inode_armed: false,
        };
        // Arm inode matching if — and only if — every offset resolves
        // against the kernel actually running. A failure here is not
        // fatal: the comm blocklist still works, and the hook is written
        // so that an unarmed offsets map means "never block by inode".
        // See `btf` for why a guess would be unacceptable.
        match blocker.arm_inode_matching() {
            Ok(off) => {
                blocker.inode_armed = true;
                info!(?off, "inode matching armed from kernel BTF");
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "inode matching NOT armed; block_exec_by_inode will be refused. \
                     comm-keyed blocking is unaffected but remains spoofable"
                );
            }
        }
        Ok(blocker)
    }

    /// Resolve the offsets from the running kernel's BTF and write them
    /// into `EXEC_OFFSETS`, arming word last.
    ///
    /// The ordering is the safety property: the offsets are in place
    /// before the magic that tells the hook to trust them, so a partial
    /// write can only ever leave the hook disarmed.
    fn arm_inode_matching(&mut self) -> Result<crate::btf::ExecInodeOffsets, LoaderError> {
        let kbtf = crate::btf::Btf::from_running_kernel()
            .map_err(|e| LoaderError::Aya(format!("kernel BTF: {e}")))?;
        let off = crate::btf::ExecInodeOffsets::resolve(&kbtf)
            .map_err(|e| LoaderError::Aya(format!("resolving exec-inode offsets: {e}")))?;

        let map = self
            .ebpf
            .map_mut("EXEC_OFFSETS")
            .ok_or_else(|| LoaderError::Aya("EXEC_OFFSETS map not found".into()))?;
        let mut arr: AyaArray<&mut MapData, u32> =
            AyaArray::try_from(map).map_err(|e| LoaderError::Aya(e.to_string()))?;
        for (idx, val) in [
            (OFF_BINPRM_FILE, off.binprm_file),
            (OFF_FILE_INODE, off.file_inode),
            (OFF_INODE_INO, off.inode_ino),
            (OFF_INODE_SB, off.inode_sb),
            (OFF_SB_DEV, off.sb_dev),
        ] {
            arr.set(idx, val, 0)
                .map_err(|e| LoaderError::Aya(format!("EXEC_OFFSETS[{idx}]: {e}")))?;
        }
        // Last, deliberately.
        arr.set(OFF_ARMED, OFF_ARMED_MAGIC, 0)
            .map_err(|e| LoaderError::Aya(format!("EXEC_OFFSETS arming word: {e}")))?;
        Ok(off)
    }

    /// Can this host block by the identity of the executed file?
    ///
    /// `false` on a kernel whose BTF is absent or whose layout could not
    /// be resolved. Callers must refuse an inode block rather than
    /// silently falling back to `comm`, which would substitute a
    /// spoofable check for an unspoofable one without saying so.
    #[must_use]
    pub fn inode_matching_armed(&self) -> bool {
        self.inode_armed
    }

    /// Block execution of the file at `(dev, ino)`.
    ///
    /// `dev` must be the **kernel's** `dev_t` — what it stores in
    /// `super_block.s_dev` — not the one `stat` reports to userspace.
    /// They are different packings of the same major/minor pair, and
    /// passing the wrong one fails silently: the insert succeeds, the
    /// hook runs, and the comparison never matches. Convert with
    /// `bowery_response::action::kernel_dev_from_stat_dev`.
    ///
    /// # Errors
    /// When inode matching was never armed, or the map write fails.
    pub fn block_inode(&mut self, dev: u64, ino: u64) -> Result<(), LoaderError> {
        if !self.inode_armed {
            return Err(LoaderError::Aya(
                "inode matching is not armed on this kernel; refusing to pretend a \
                 block was installed"
                    .into(),
            ));
        }
        let mut map = self.blocked_inodes_mut()?;
        map.insert([dev, ino], 1u8, 0)
            .map_err(|e| LoaderError::Aya(format!("BLOCKED_INODES insert: {e}")))?;
        debug!(dev, ino, "added to BLOCKED_INODES");
        Ok(())
    }

    /// Remove `(dev, ino)`. `Ok(false)` when it wasn't present.
    pub fn unblock_inode(&mut self, dev: u64, ino: u64) -> Result<bool, LoaderError> {
        let mut map = self.blocked_inodes_mut()?;
        match map.remove(&[dev, ino]) {
            Ok(()) => Ok(true),
            Err(aya::maps::MapError::KeyNotFound) => Ok(false),
            Err(e) => Err(LoaderError::Aya(format!("BLOCKED_INODES remove: {e}"))),
        }
    }

    fn blocked_inodes_mut(
        &mut self,
    ) -> Result<AyaHashMap<&mut MapData, [u64; 2], u8>, LoaderError> {
        let map = self
            .ebpf
            .map_mut("BLOCKED_INODES")
            .ok_or_else(|| LoaderError::Aya("BLOCKED_INODES map not found".into()))?;
        AyaHashMap::try_from(map).map_err(|e| LoaderError::Aya(e.to_string()))
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
            sport: 54321,
            direction: 0,
            _pad: 0,
            family: AF_INET,
            // 443 in network byte order
            dport: 443,
            daddr_v4: [192, 168, 1, 50],
            saddr_v4: [10, 0, 0, 1],
            daddr_v6: [0; 16],
            saddr_v6: [0; 16],
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
            sport: 54321,
            direction: 0,
            _pad: 0,
            family: AF_INET6,
            dport: 80,
            daddr_v4: [0; 4],
            saddr_v4: [10, 0, 0, 1],
            daddr_v6: v6,
            saddr_v6: [0; 16],
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
            sport: 54321,
            direction: 0,
            _pad: 0,
            family: 17, // AF_NETLINK — not something we care about
            dport: 0,
            daddr_v4: [0; 4],
            saddr_v4: [10, 0, 0, 1],
            daddr_v6: [0; 16],
            saddr_v6: [0; 16],
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

#[cfg(test)]
mod inbound_tests {
    use super::*;

    fn as_bytes<T>(v: &T) -> &[u8] {
        // SAFETY: same justification as the sibling parse tests.
        unsafe { std::slice::from_raw_parts(std::ptr::from_ref(v).cast::<u8>(), size_of::<T>()) }
    }

    /// The accept-side record. `daddr`/`dport` describe the *client*,
    /// and `local_port` is the service it reached — the field that says
    /// what was actually touched.
    #[test]
    fn parse_connect_decodes_an_inbound_record() {
        let raw = RawConnectEvent {
            pid: 0,
            family: AF_INET,
            dport: 54321, // client's ephemeral port
            sport: 22,    // our listening port
            direction: DIRECTION_IN,
            _pad: 0,
            daddr_v4: [10, 0, 0, 42],
            saddr_v4: [10, 0, 0, 1],
            daddr_v6: [0; 16],
            saddr_v6: [0; 16],
            comm: [0; 16],
        };
        match parse_connect(as_bytes(&raw)).expect("parses") {
            Event::NetworkConnect(c) => {
                assert_eq!(c.direction, NetDirection::Inbound);
                assert_eq!(c.daddr.to_string(), "10.0.0.42", "remote is the client");
                assert_eq!(c.dport, 54321);
                assert_eq!(c.local_port, 22, "local side is the service reached");
                assert_eq!(
                    c.pid, 0,
                    "the accept-side transition runs in softirq context; a pid here \
                     would be whatever task was interrupted"
                );
            }
            other => panic!("expected NetworkConnect, got {other:?}"),
        }
    }

    /// Ports arrive in host order because the tracepoint applies
    /// `ntohs()` itself. Swapping them again turned 443 into 47873 in
    /// production for the whole life of this code path — caught only by
    /// reading real recorded traffic, since every synthetic test built
    /// its fixture with the same wrong convention it was asserting.
    #[test]
    fn ports_are_taken_in_host_order_not_byte_swapped() {
        let raw = RawConnectEvent {
            pid: 42,
            family: AF_INET,
            dport: 443,
            sport: 51000,
            direction: 0,
            _pad: 0,
            daddr_v4: [93, 184, 216, 34],
            saddr_v4: [10, 0, 0, 1],
            daddr_v6: [0; 16],
            saddr_v6: [0; 16],
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
        };
        match parse_connect(as_bytes(&raw)).expect("parses") {
            Event::NetworkConnect(c) => {
                assert_eq!(c.dport, 443, "443 must not become 47873");
                assert_eq!(
                    c.comm, "curl",
                    "the source host is the only place a connection's process                      is knowable; dropping comm throws that away"
                );
                assert_eq!(c.local_port, 51000);
                // The ADDRESS really is raw network-order bytes, which is
                // why it is built from the array rather than swapped.
                assert_eq!(c.daddr.to_string(), "93.184.216.34");
            }
            other => panic!("expected NetworkConnect, got {other:?}"),
        }
    }

    /// Layout is shared with the kernel-side struct by hand, so a size
    /// change on either side must fail loudly here rather than silently
    /// misparse every field after the drift.
    #[test]
    fn raw_connect_layout_is_pinned() {
        assert_eq!(
            RAW_CONNECT_SIZE, 68,
            "ConnectEvent layout changed; update crates/bowery-ebpf/src/main.rs to match"
        );
    }
}
