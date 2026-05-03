//! Pluggable event source.
//!
//! An [`EventSource`] starts itself and returns a [`mpsc::Receiver`] that
//! produces [`Event`]s until the source decides to stop (channel close).
//! Implementations:
//!
//! - [`MockEventSource`]: deterministic event replay for tests.
//! - [`NoopEventSource`]: never produces; used as the production
//!   placeholder until the BPF source lands.

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
