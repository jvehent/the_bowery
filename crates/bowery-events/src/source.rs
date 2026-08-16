//! Pluggable event source.
//!
//! An [`EventSource`] starts itself and returns a [`mpsc::Receiver`] that
//! produces [`Event`]s until the source decides to stop (channel close).
//! Implementations:
//!
//! - [`MockEventSource`]: deterministic event replay for tests.
//! - [`NoopEventSource`]: never produces; used as the production
//!   placeholder until the BPF source lands.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::Event;

/// Channel capacity used by the bundled sources. The agent's pipeline
/// applies its own backpressure; sources that produce faster than the
/// pipeline can drain will block at `send().await`.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// A producer of [`Event`]s.
///
/// Implementations take `Box<Self>` so the agent can hold the source
/// behind a `Box<dyn EventSource>` without a lifetime parameter.
pub trait EventSource: Send + 'static {
    fn start(self: Box<Self>) -> mpsc::Receiver<Event>;

    /// Live health of this source's probes, when it has any.
    ///
    /// `None` means the source cannot report health — which for
    /// [`NoopEventSource`] is itself the answer, since it observes
    /// nothing. Callers must treat `None` as "not watching" rather than
    /// as "no news".
    fn health(&self) -> Option<std::sync::Arc<ProbeHealth>> {
        None
    }
}

// ---------------------------------------------------------------------------
// MockEventSource
// ---------------------------------------------------------------------------

/// Replays a fixed sequence of events into the pipeline. Optionally pauses
/// between events so tests can observe intermediate state.
#[derive(Debug)]
pub struct MockEventSource {
    events: Vec<Event>,
    delay_between: Duration,
}

impl MockEventSource {
    pub fn new(events: Vec<Event>) -> Self {
        Self {
            events,
            delay_between: Duration::ZERO,
        }
    }

    #[must_use]
    pub fn with_delay(mut self, d: Duration) -> Self {
        self.delay_between = d;
        self
    }
}

impl EventSource for MockEventSource {
    fn health(&self) -> Option<std::sync::Arc<ProbeHealth>> {
        // A mock is a source that works, so it reports as one. Without
        // this every test fixture would look blind to the watchdog and
        // its first alert would be about the sensor rather than about
        // whatever the test is exercising.
        let health = ProbeHealth::new();
        for probe in 0..PROBE_COUNT {
            health.mark_attached(probe);
        }
        Some(std::sync::Arc::new(health))
    }

    fn start(self: Box<Self>) -> mpsc::Receiver<Event> {
        let MockEventSource {
            events,
            delay_between,
        } = *self;
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            for e in events {
                if !delay_between.is_zero() {
                    tokio::time::sleep(delay_between).await;
                }
                if tx.send(e).await.is_err() {
                    break;
                }
            }
        });
        rx
    }
}

// ---------------------------------------------------------------------------
// NoopEventSource
// ---------------------------------------------------------------------------

/// An event source that produces nothing and never closes its channel.
///
/// Phase 2 production placeholder until the BPF source is integrated.
/// The agent's pipeline task will pend on `recv()` indefinitely; shutdown
/// of the agent cancels the task via the shared shutdown channel.
#[derive(Debug, Default)]
pub struct NoopEventSource;

impl EventSource for NoopEventSource {
    fn start(self: Box<Self>) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            // Hold the sender alive so recv() pends forever rather than
            // returning None and causing the pipeline to exit early.
            let _tx = tx;
            std::future::pending::<()>().await;
        });
        rx
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::ProcessExec;

    fn exec(pid: u32) -> Event {
        Event::ProcessExec(ProcessExec {
            pid,
            ppid: 1,
            uid: 0,
            comm: "test".into(),
            exe_path: None,
            args: vec![],
            ts: SystemTime::UNIX_EPOCH,
        })
    }

    #[tokio::test]
    async fn mock_source_replays_in_order() {
        let source = MockEventSource::new(vec![exec(1), exec(2), exec(3)]);
        let mut rx = Box::new(source).start();
        for expected_pid in [1, 2, 3] {
            let event = rx.recv().await.expect("event");
            assert_eq!(event.pid(), expected_pid);
        }
        assert!(
            rx.recv().await.is_none(),
            "channel should close after replay"
        );
    }

    #[tokio::test]
    async fn noop_source_pends_indefinitely() {
        let source: Box<dyn EventSource> = Box::new(NoopEventSource);
        let mut rx = source.start();
        // recv should not resolve within a small budget. We don't want to
        // wait long in tests; 50ms is enough to demonstrate non-closure.
        let result = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(result.is_err(), "noop source must not close");
    }
}

// ---------------------------------------------------------------------------
// Sensor health
// ---------------------------------------------------------------------------

/// Probe slots, in the order [`ProbeHealth`] reports them.
pub const PROBE_EXEC: usize = 0;
pub const PROBE_EXIT: usize = 1;
pub const PROBE_CONNECT: usize = 2;
pub const PROBE_FILE: usize = 3;
pub const PROBE_COUNT: usize = 4;

/// Operator-facing probe names. These appear in a SQL view, so they are
/// spelled out rather than derived from Rust identifiers.
pub const PROBE_NAMES: [&str; PROBE_COUNT] = ["exec", "exit", "connect", "file"];

/// Live health of the kernel sensor.
///
/// This exists because of a failure that ran undetected on a real fleet
/// for days: two agents came up with no BPF object, fell back to
/// [`NoopEventSource`], logged one line at startup, and then observed
/// nothing at all — while continuing to gossip, answer SQL, and vote in
/// whisper quorums as though they were watching. Nothing downstream can
/// distinguish "nothing happened" from "we stopped looking", so the
/// sensor has to say which.
///
/// Counters are atomics rather than a lock because they are touched on
/// the per-event path.
#[derive(Debug, Default)]
pub struct ProbeHealth {
    attached: [AtomicBool; PROBE_COUNT],
    emitted: [AtomicU64; PROBE_COUNT],
    /// Records userspace decoded but could not translate — a short
    /// record, or an address family we don't model. Distinct from a
    /// kernel drop: this one means version skew or a parsing bug, not
    /// saturation.
    parse_failed: [AtomicU64; PROBE_COUNT],
    /// Events the kernel dropped because the ring was full. Only
    /// meaningful when [`Self::kernel_drops_available`] is true.
    kernel_drops: [AtomicU64; PROBE_COUNT],
    kernel_drops_available: AtomicBool,
    last_event_unix_ms: [AtomicU64; PROBE_COUNT],
    /// Why the source stopped, if it did. A source that exits is as
    /// blind as one that never started.
    stopped: Mutex<Option<String>>,
}

impl ProbeHealth {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_attached(&self, probe: usize) {
        if probe < PROBE_COUNT {
            self.attached[probe].store(true, Ordering::Relaxed);
        }
    }

    pub fn record_event(&self, probe: usize, now_unix_ms: u64) {
        if probe < PROBE_COUNT {
            self.emitted[probe].fetch_add(1, Ordering::Relaxed);
            self.last_event_unix_ms[probe].store(now_unix_ms, Ordering::Relaxed);
        }
    }

    pub fn record_parse_failure(&self, probe: usize) {
        if probe < PROBE_COUNT {
            self.parse_failed[probe].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Publish the kernel's own drop counter for a probe.
    pub fn set_kernel_drops(&self, probe: usize, drops: u64) {
        if probe < PROBE_COUNT {
            self.kernel_drops[probe].store(drops, Ordering::Relaxed);
            self.kernel_drops_available.store(true, Ordering::Relaxed);
        }
    }

    /// Whether the loaded BPF object exposes the drop counter at all.
    ///
    /// False on an object built before the counter existed. Reported as
    /// unknown rather than zero, because "no drops" and "cannot tell"
    /// are the same distinction this whole type is about.
    #[must_use]
    pub fn kernel_drops_available(&self) -> bool {
        self.kernel_drops_available.load(Ordering::Relaxed)
    }

    pub fn mark_stopped(&self, reason: impl Into<String>) {
        *self.stopped.lock().expect("probe health mutex poisoned") = Some(reason.into());
    }

    #[must_use]
    pub fn stopped_reason(&self) -> Option<String> {
        self.stopped
            .lock()
            .expect("probe health mutex poisoned")
            .clone()
    }

    /// Is the sensor doing its job right now?
    ///
    /// False when no probe ever attached, or when the source has
    /// stopped. This is the single question the rest of the agent asks.
    #[must_use]
    pub fn is_watching(&self) -> bool {
        self.stopped_reason().is_none() && self.attached.iter().any(|a| a.load(Ordering::Relaxed))
    }

    #[must_use]
    pub fn total_kernel_drops(&self) -> u64 {
        self.kernel_drops
            .iter()
            .map(|d| d.load(Ordering::Relaxed))
            .sum()
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<ProbeSnapshot> {
        (0..PROBE_COUNT)
            .map(|i| ProbeSnapshot {
                name: PROBE_NAMES[i],
                attached: self.attached[i].load(Ordering::Relaxed),
                emitted: self.emitted[i].load(Ordering::Relaxed),
                parse_failed: self.parse_failed[i].load(Ordering::Relaxed),
                kernel_drops: self
                    .kernel_drops_available()
                    .then(|| self.kernel_drops[i].load(Ordering::Relaxed)),
                last_event_unix_ms: match self.last_event_unix_ms[i].load(Ordering::Relaxed) {
                    0 => None,
                    v => Some(v),
                },
            })
            .collect()
    }
}

/// One probe's health, as an operator sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSnapshot {
    pub name: &'static str,
    pub attached: bool,
    pub emitted: u64,
    pub parse_failed: u64,
    /// `None` when the loaded object predates the drop counter.
    pub kernel_drops: Option<u64>,
    pub last_event_unix_ms: Option<u64>,
}
