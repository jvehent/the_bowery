// This crate parses kernel-produced byte records and sets test env
// vars; both are unavoidable here. The workspace-wide `unsafe_code =
// "forbid"` is good policy; we override per-crate with a deliberate
// `allow` and document each unsafe block.
#![allow(unsafe_code)]

//! User-space loader for The Bowery's eBPF programs.
//!
//! Phase 2 BPF surface: load the compiled `bowery-ebpf` ELF, attach the
//! `sched_process_exec` tracepoint, drain its ring buffer asynchronously,
//! and emit each [`bowery_events::ProcessExec`] event into an
//! [`bowery_events::source::EventSource`]-compatible channel.
//!
//! Locating the BPF object:
//! 1. `BOWERY_BPF_OBJ_PATH` env var, if set
//! 2. `/usr/local/lib/bowery/bowery-ebpf`
//! 3. `/usr/lib/bowery/bowery-ebpf`
//! 4. `target/bpfel-unknown-none/release/bowery-ebpf` relative to the
//!    workspace root (handy for in-tree development)
//!
//! If none are found, [`BpfEventSource::from_default_locations`] returns
//! a `NotFound` error and the agent falls back to
//! `bowery_events::source::NoopEventSource`.

use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;

use aya::Ebpf;
use aya::maps::ring_buf::RingBuf;
use aya::programs::TracePoint;
use bowery_events::source::{DEFAULT_CHANNEL_CAPACITY, EventSource};
use bowery_events::{Event, ProcessExec, enrich};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Wire format of the ring buffer record. **Must** match
/// `crates/bowery-ebpf/src/main.rs::ExecEvent`.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawExecEvent {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
}

const RAW_EVENT_SIZE: usize = std::mem::size_of::<RawExecEvent>();

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("BPF object not found in any of the default locations")]
    NotFound,
    #[error("BPF object path does not exist: {0}")]
    BadPath(PathBuf),
    #[error("aya: {0}")]
    Aya(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Event source backed by the kernel's `sched_process_exec` tracepoint.
#[derive(Debug)]
pub struct BpfEventSource {
    obj_path: PathBuf,
}

impl BpfEventSource {
    /// Use the BPF object at `path`. Returns `BadPath` if it doesn't exist.
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, LoaderError> {
        let path = path.into();
        if !path.exists() {
            return Err(LoaderError::BadPath(path));
        }
        Ok(Self { obj_path: path })
    }

    /// Try the env var, then standard install paths, then the in-tree
    /// development build directory.
    pub fn from_default_locations() -> Result<Self, LoaderError> {
        if let Ok(p) = std::env::var("BOWERY_BPF_OBJ_PATH") {
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
        // In-tree dev build (when running from the workspace root):
        let here = std::env::current_dir().unwrap_or_default();
        let dev = here.join("crates/bowery-ebpf/target/bpfel-unknown-none/release/bowery-ebpf");
        if dev.exists() {
            return Self::from_path(dev);
        }
        Err(LoaderError::NotFound)
    }

    pub fn obj_path(&self) -> &Path {
        &self.obj_path
    }
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
    let mut ebpf = Ebpf::load_file(obj_path).map_err(|e| LoaderError::Aya(e.to_string()))?;

    // Best-effort: hook up aya-log if the BPF program emits log records.
    // No log map => silently skip.
    let _ = aya_log::EbpfLogger::init(&mut ebpf);

    let program: &mut TracePoint = ebpf
        .program_mut("sched_process_exec")
        .ok_or_else(|| LoaderError::Aya("program 'sched_process_exec' not found".into()))?
        .try_into()
        .map_err(|e: aya::programs::ProgramError| LoaderError::Aya(e.to_string()))?;
    program
        .load()
        .map_err(|e| LoaderError::Aya(e.to_string()))?;
    program
        .attach("sched", "sched_process_exec")
        .map_err(|e| LoaderError::Aya(e.to_string()))?;
    info!("attached tracepoint sched/sched_process_exec");

    let map = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| LoaderError::Aya("EVENTS map not found".into()))?;
    let mut ring = RingBuf::try_from(map).map_err(|e| LoaderError::Aya(e.to_string()))?;

    let async_fd = AsyncFd::new(ring.as_raw_fd())?;

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                error!(error = %e, "ringbuf poll failed");
                return Err(LoaderError::Io(e));
            }
        };

        // Drain everything the kernel has produced since the last wake.
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < RAW_EVENT_SIZE {
                warn!(
                    got = bytes.len(),
                    want = RAW_EVENT_SIZE,
                    "short ringbuf record"
                );
                continue;
            }
            // SAFETY: ringbuf records are aligned to 8 bytes and we've
            // size-checked above. RawExecEvent is repr(C) and contains
            // only POD scalars + a byte array, so the read is safe.
            let raw: RawExecEvent =
                unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawExecEvent>()) };
            drop(item); // release ring buffer slot before doing user-space work

            let event = enrich_into_event(&raw);
            if tx.send(event).await.is_err() {
                debug!("agent dropped the event channel; shutting BPF source");
                return Ok(());
            }
        }

        guard.clear_ready();
    }
}

fn enrich_into_event(raw: &RawExecEvent) -> Event {
    let comm = comm_to_string(&raw.comm);
    let exe_path = enrich::pid_exe_path(raw.pid);
    let args = enrich::pid_cmdline(raw.pid).unwrap_or_default();
    Event::ProcessExec(ProcessExec {
        pid: raw.pid,
        // The tracepoint doesn't carry ppid; let the user-space pipeline
        // fill it in if it cares (Phase 3 doesn't yet). 0 is the sentinel
        // for "unknown".
        ppid: 0,
        uid: raw.uid,
        comm,
        exe_path,
        args,
        ts: std::time::SystemTime::now(),
    })
}

fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
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
}
