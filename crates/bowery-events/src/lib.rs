//! Typed event schema for The Bowery.
//!
//! Phase 2 (userspace) defines the event types our pipeline will eventually
//! consume from eBPF. The [`source::EventSource`] trait abstracts over the
//! producer so the pipeline (enrich → baseline → scoring → response) can
//! be exercised with [`source::MockEventSource`] today and a kernel-driven
//! source later.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::SystemTime;

pub mod enrich;
pub mod source;

/// Top-level event observed on the host. Phase 2 only emits
/// [`Event::ProcessExec`] end-to-end through the agent pipeline; the other
/// variants are scaffolded for parity with what the BPF programs will
/// produce in a later phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    ProcessExec(ProcessExec),
    ProcessExit(ProcessExit),
    FileOpen(FileOpen),
    NetworkConnect(NetworkConnect),
    /// A watched file changed (userspace inotify — see the agent's file
    /// monitor). Distinct from `FileOpen` (a would-be eBPF hook): this is
    /// the operator-configured file-integrity signal, and carries no pid
    /// (inotify doesn't attribute the change to a process).
    FileChange(FileChange),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessExec {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    /// Linux `task->comm` (16 bytes max).
    pub comm: String,
    /// Resolved exe path. `None` when the kernel-side enrichment couldn't
    /// follow `/proc/<pid>/exe` (e.g. very short-lived process).
    pub exe_path: Option<PathBuf>,
    pub args: Vec<String>,
    pub ts: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessExit {
    pub pid: u32,
    pub exit_code: i32,
    pub ts: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOpen {
    pub pid: u32,
    pub path: PathBuf,
    pub flags: u32,
    pub ts: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnect {
    pub pid: u32,
    pub family: NetFamily,
    pub daddr: IpAddr,
    pub dport: u16,
    pub ts: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetFamily {
    V4,
    V6,
}

/// A change observed on a watched file (userspace inotify).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub path: PathBuf,
    pub op: FileOp,
    pub ts: SystemTime,
}

/// Class of change to a watched file. Serde-(de)serializable so operator
/// config (`[monitor] file_rules.ops`) can select which classes alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileOp {
    /// Content written and the writer closed the fd (`IN_CLOSE_WRITE`).
    Modify,
    /// Metadata changed — mode, owner, timestamps (`IN_ATTRIB`).
    Attrib,
    /// The file was removed (`IN_DELETE` / `IN_DELETE_SELF`).
    Delete,
    /// The file was replaced/renamed over or moved (`IN_MOVED_TO` / `IN_MOVE_SELF`).
    Move,
    /// The file was created (`IN_CREATE`).
    Create,
}

impl Event {
    /// PID of the process the event is attributed to. `0` for `FileChange`,
    /// which inotify does not attribute to a process.
    pub fn pid(&self) -> u32 {
        match self {
            Event::ProcessExec(e) => e.pid,
            Event::ProcessExit(e) => e.pid,
            Event::FileOpen(e) => e.pid,
            Event::NetworkConnect(e) => e.pid,
            Event::FileChange(_) => 0,
        }
    }

    pub fn timestamp(&self) -> SystemTime {
        match self {
            Event::ProcessExec(e) => e.ts,
            Event::ProcessExit(e) => e.ts,
            Event::FileOpen(e) => e.ts,
            Event::NetworkConnect(e) => e.ts,
            Event::FileChange(e) => e.ts,
        }
    }
}
