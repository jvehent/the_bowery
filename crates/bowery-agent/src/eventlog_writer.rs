//! Bridges the event pipeline to the on-disk [`EventLog`].
//!
//! Three properties drive the shape of this module:
//!
//! 1. **The pipeline must never block on disk.** Detection latency is the
//!    product; an fsync stall must not become a detection stall. So the
//!    handle is a bounded channel written with `try_send`.
//! 2. **A full queue drops, and says so.** Dropping is the right choice
//!    under overload — a stalled sensor is worse than a gap — but a
//!    *silent* gap is the classic EDR failure, where the console looks
//!    calm precisely because recording stopped. Every drop is counted and
//!    surfaced through `bowery_eventlog_status`.
//! 3. **Writes are batched.** At exec-storm rates the transaction commit
//!    dominates, so the writer drains everything available and commits
//!    once.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bowery_eventlog::{EventLog, Retention};
use bowery_events::Event;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Largest number of events pulled into one transaction. Bounds the
/// memory a single batch can pin and keeps one burst from starving the
/// shutdown check.
const MAX_BATCH: usize = 512;

/// Handle held by the event pipeline. Cloning is cheap.
#[derive(Debug, Clone)]
pub(crate) struct EventLogHandle {
    tx: mpsc::Sender<Event>,
    dropped: Arc<AtomicU64>,
}

impl EventLogHandle {
    /// Record `event`, or count a drop if the writer is behind.
    ///
    /// Deliberately infallible and non-async: it is called from the hot
    /// path for every event on the host, and must not add a `.await`
    /// point or an error branch there.
    pub(crate) fn record(&self, event: Event) {
        if self.tx.try_send(event).is_err() {
            // Counted, not logged: at the rate this fires under overload
            // the logging would itself become the bottleneck. The count
            // is what `bowery_eventlog_status` reports.
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The shared counter, for the `bowery_eventlog_status` view.
    ///
    /// Handing out the `Arc` rather than a snapshot matters: the SQL
    /// table is registered once at startup but re-read on every query,
    /// so it has to observe the live value, not the value at wiring
    /// time.
    pub(crate) fn dropped_counter(&self) -> Arc<AtomicU64> {
        self.dropped.clone()
    }
}

/// Spawn the disk writer and the maintenance timer.
///
/// Returns the handle for the pipeline plus both task handles so
/// shutdown can join them.
pub(crate) fn spawn(
    log: Arc<EventLog>,
    queue_capacity: usize,
    retention: Retention,
    maintenance_interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) -> (EventLogHandle, JoinHandle<()>, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<Event>(queue_capacity.max(1));
    let dropped = Arc::new(AtomicU64::new(0));
    let handle = EventLogHandle {
        tx,
        dropped: dropped.clone(),
    };

    let writer_log = log.clone();
    let writer = tokio::spawn(async move {
        let mut batch: Vec<Event> = Vec::with_capacity(MAX_BATCH);
        loop {
            // `recv_many` blocks until at least one event is available,
            // then takes everything queued up to the cap — so a quiet
            // host commits one row at a time and a busy one amortises
            // the transaction across hundreds, with no timer to tune.
            let n = rx.recv_many(&mut batch, MAX_BATCH).await;
            if n == 0 {
                break; // all senders dropped
            }
            let to_write = std::mem::take(&mut batch);
            let log = writer_log.clone();
            // `spawn_blocking`: SQLite is synchronous and this is the
            // one place we knowingly touch the disk.
            let written = tokio::task::spawn_blocking(move || log.append_batch(&to_write)).await;
            match written {
                Ok(Ok(n)) => debug!(events = n, "event log batch committed"),
                Ok(Err(e)) => warn!(error = %e, "event log write failed; events lost"),
                Err(e) => warn!(error = %e, "event log writer task panicked"),
            }
            batch.clear();
        }
        debug!("event log writer stopped");
    });

    let maintenance = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(maintenance_interval);
        // The first tick fires immediately; skip it so startup doesn't
        // prune before anything has been recorded.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let log = log.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        let removed = log.prune(retention)?;
                        // Checkpoint after pruning so the deleted pages
                        // actually leave the WAL. Not needed for
                        // visibility — readers already see
                        // un-checkpointed rows.
                        log.checkpoint()?;
                        Ok::<u64, bowery_eventlog::Error>(removed)
                    })
                    .await;
                    match result {
                        Ok(Ok(0)) => {}
                        Ok(Ok(removed)) => info!(removed, "event log retention reclaimed rows"),
                        Ok(Err(e)) => warn!(error = %e, "event log maintenance failed"),
                        Err(e) => warn!(error = %e, "event log maintenance task panicked"),
                    }
                }
                _ = shutdown_rx.changed() => break,
            }
        }
        debug!("event log maintenance stopped");
    });

    (handle, writer, maintenance)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::SystemTime;

    use bowery_events::ProcessExec;

    use super::*;

    fn exec(pid: u32) -> Event {
        Event::ProcessExec(ProcessExec {
            pid,
            ppid: 1,
            uid: 0,
            comm: "t".into(),
            exe_path: Some(PathBuf::from("/bin/t")),
            args: vec![],
            ts: SystemTime::now(),
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_reach_the_log() {
        let log = Arc::new(EventLog::open_in_memory().unwrap());
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (handle, writer, maintenance) = spawn(
            log.clone(),
            64,
            Retention::default(),
            Duration::from_hours(1),
            shutdown_rx,
        );

        for pid in 0..10 {
            handle.record(exec(pid));
        }
        drop(handle); // closes the channel so the writer drains and exits
        writer.await.unwrap();
        maintenance.abort();

        assert_eq!(log.stats().unwrap().rows, 10);
    }

    /// Overload must cost events, not latency — and the loss must be
    /// countable, because a silent gap is indistinguishable from a quiet
    /// host.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_queue_drops_and_counts_instead_of_blocking() {
        let log = Arc::new(EventLog::open_in_memory().unwrap());
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        // Capacity 1, and we never let the writer run: every send past
        // the buffered one must be shed.
        let (handle, writer, maintenance) = spawn(
            log,
            1,
            Retention::default(),
            Duration::from_hours(1),
            shutdown_rx,
        );

        for pid in 0..500 {
            handle.record(exec(pid));
        }
        assert!(
            handle.dropped_counter().load(Ordering::Relaxed) > 0,
            "a saturated queue must report drops, not silently swallow them"
        );

        writer.abort();
        maintenance.abort();
    }
}
