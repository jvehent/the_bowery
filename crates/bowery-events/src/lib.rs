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
    /// Opening task's `comm`. A path without the process that touched it
    /// is half a finding.
    pub comm: String,
    /// May be **relative**: `openat` resolves against a dirfd, which a
    /// kernel probe cannot follow. Rules match absolute paths only, and
    /// the relative ones are counted so the blind spot is measured.
    pub path: PathBuf,
    /// Raw `openat` flags.
    pub flags: u32,
    /// The path was longer than the probe's buffer and was cut short.
    /// Carried rather than hidden: a silently shortened path is one that
    /// quietly stops matching a rule.
    pub truncated: bool,
    pub ts: SystemTime,
}

/// A TCP connection setup observed on this host.
///
/// `daddr`/`dport` always describe the **remote** end: the destination
/// we dialled for [`NetDirection::Outbound`], and the client that dialled
/// *us* for [`NetDirection::Inbound`]. `local_port` is our side — the
/// ephemeral source port outbound, and the listening port inbound, which
/// is the one that says which service was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnect {
    /// Connecting process. **Always 0 for inbound**: the kernel's
    /// accept-side state transition runs in softirq context, where the
    /// current task is whatever was interrupted. The process that owns
    /// an inbound connection is knowable only on the host that made it —
    /// which is precisely why the two hosts have to compare notes.
    pub pid: u32,
    /// Connecting task's `comm`. Empty for inbound, same reason as
    /// `pid`.
    ///
    /// Carried because the *source* host is the only place a
    /// connection's process is knowable, and a pid alone is a poor
    /// answer minutes later: pids are reused, and the process is
    /// usually gone by the time anyone asks.
    pub comm: String,
    pub family: NetFamily,
    /// Remote peer address.
    pub daddr: IpAddr,
    /// **Our own** address on this socket. Measured, not assumed:
    /// asking a peer "did you connect to me?" has to name the address
    /// they actually reached, or a multi-homed host gets back "no
    /// record" for a legitimate connection and alerts that a healthy
    /// agent is lying.
    pub local_addr: IpAddr,
    /// Remote peer port.
    pub dport: u16,
    /// Our own port. **Zero for outbound**: at the
    /// `TCP_CLOSE -> TCP_SYN_SENT` transition the kernel has not yet
    /// assigned a source port. Correlation therefore matches on
    /// (remote address, remote port, time), not on a full 4-tuple.
    pub local_port: u16,
    pub direction: NetDirection,
    pub ts: SystemTime,
}

/// Which side initiated a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDirection {
    /// This host dialled out.
    Outbound,
    /// This host accepted. The other half of this connection was
    /// recorded as `Outbound` on some other machine — with the process
    /// attribution this side can never see.
    Inbound,
}

impl NetDirection {
    /// Stable operator-facing label, used in the `bowery_events`
    /// `direction` column.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Outbound => "out",
            Self::Inbound => "in",
        }
    }
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
