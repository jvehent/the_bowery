//! Per-agent operator inbox.
//!
//! Phase 6a stores Alert messages in a bounded in-memory ring keyed by
//! arrival timestamp. A roaming operator dials any agent and sends a
//! signed `Subscribe { since_unix_ms }`; the agent returns every alert
//! still in the ring with `ts >= since_unix_ms`, plus a cursor to use
//! on the next subscribe.
//!
//! Properties:
//! - **Bounded memory**: `capacity` caps the number of stored alerts;
//!   inserts at capacity evict the oldest (FIFO).
//! - **TTL retention**: alerts older than `retention` are evicted on
//!   each `read_since` (lazy sweep — keeps appends cheap).
//! - **Monotonic cursors**: callers pass back `cursor_unix_ms` from a
//!   previous response and we filter `ts >= cursor`. We never decrease
//!   the cursor for them; they're free to rewind it themselves if a
//!   client crashes mid-batch.
//! - **No per-operator partitioning yet**. The DESIGN's full vision is
//!   "one inbox per operator fingerprint"; for v1 we keep a single
//!   shared ring and let access control happen at the Subscribe-verify
//!   step (sender must be a configured operator).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bowery_proto::Alert;

/// Default ring capacity — matches the DESIGN doc's per-operator size
/// cap (10k messages). Each `Alert` is small (~few hundred bytes), so
/// 10k upper-bounds inbox memory at single-digit MiB.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// Default retention window. DESIGN locks 72 h.
pub const DEFAULT_RETENTION: Duration = Duration::from_hours(72);

/// Bounded ring of [`Alert`]s with TTL retention.
#[derive(Debug)]
pub struct AlertInbox {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    items: VecDeque<Alert>,
    capacity: usize,
    retention: Duration,
}

impl AlertInbox {
    pub fn new(capacity: usize, retention: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                items: VecDeque::with_capacity(capacity.min(1024)),
                capacity: capacity.max(1),
                retention,
            }),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_RETENTION)
    }

    /// Append an alert. Evicts the oldest entry if the ring is at
    /// capacity. Returns the now-current ring length.
    pub fn append(&self, alert: Alert) -> usize {
        let mut g = self.inner.lock().expect("inbox poisoned");
        if g.items.len() >= g.capacity {
            g.items.pop_front();
        }
        g.items.push_back(alert);
        g.items.len()
    }

    /// Return all alerts whose `ts_unix_ms` is `>= since_unix_ms`,
    /// sweeping expired entries first. `max_items == 0` means "no
    /// cap; return everything." The returned cursor is suitable for
    /// the next call: it equals the largest returned `ts_unix_ms + 1`,
    /// or `since_unix_ms` if nothing matched.
    pub fn read_since(&self, since_unix_ms: u64, max_items: usize) -> (Vec<Alert>, u64) {
        let now_ms = current_unix_ms();
        let mut g = self.inner.lock().expect("inbox poisoned");
        let retention_ms = u64::try_from(g.retention.as_millis()).unwrap_or(u64::MAX);
        let cutoff = now_ms.saturating_sub(retention_ms);

        // Lazy sweep: drop everything older than `cutoff`. Items are
        // appended in monotonic-ish ts order, so we can pop from the
        // front until the head is fresh. Out-of-order arrivals (clock
        // skew on append) end up dropped slightly early — acceptable.
        while let Some(front) = g.items.front()
            && front.ts_unix_ms < cutoff
        {
            g.items.pop_front();
        }

        let cap = if max_items == 0 {
            usize::MAX
        } else {
            max_items
        };
        let mut out = Vec::new();
        let mut max_ts = since_unix_ms;
        for alert in &g.items {
            if alert.ts_unix_ms < since_unix_ms {
                continue;
            }
            if alert.ts_unix_ms > max_ts {
                max_ts = alert.ts_unix_ms;
            }
            out.push(alert.clone());
            if out.len() >= cap {
                break;
            }
        }
        let cursor = if out.is_empty() {
            since_unix_ms
        } else {
            max_ts.saturating_add(1)
        };
        (out, cursor)
    }

    /// Number of alerts currently buffered. Test-only.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("inbox poisoned").items.len()
    }

    /// Whether the inbox is empty. Test-only.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Wall-clock millis since Unix epoch. Saturates to `0` if the system
/// clock is somehow before the epoch (paranoia; shouldn't happen).
pub fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert_at(ts_ms: u64, episode: &str) -> Alert {
        Alert {
            originator_fp: vec![0u8; 32],
            episode_id: episode.into(),
            exe_sha256_hex: String::new(),
            exe_path: String::new(),
            suspicion: 0.5,
            rationale: String::new(),
            suggested_actions: vec![],
            ts_unix_ms: ts_ms,
            backend: "test".into(),
        }
    }

    /// Build a wall-clock-relative alert. We use `now`-anchored
    /// timestamps so the retention sweep doesn't eat our fixtures.
    fn fresh_alert_at(offset_ms: u64, episode: &str) -> Alert {
        alert_at(current_unix_ms().saturating_add(offset_ms), episode)
    }

    #[test]
    fn append_then_read_returns_in_order() {
        let inbox = AlertInbox::with_defaults();
        inbox.append(fresh_alert_at(0, "a"));
        inbox.append(fresh_alert_at(100, "b"));
        inbox.append(fresh_alert_at(200, "c"));

        let (items, cursor) = inbox.read_since(0, 0);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].episode_id, "a");
        assert_eq!(items[2].episode_id, "c");
        assert!(cursor > items[2].ts_unix_ms);
    }

    #[test]
    fn read_since_filters_below_cursor() {
        let inbox = AlertInbox::with_defaults();
        let a = fresh_alert_at(0, "a");
        let b = fresh_alert_at(100, "b");
        let c = fresh_alert_at(200, "c");
        let cutoff = b.ts_unix_ms;
        inbox.append(a);
        inbox.append(b);
        inbox.append(c);

        let (items, cursor) = inbox.read_since(cutoff, 0);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].episode_id, "b");
        assert!(cursor > items[1].ts_unix_ms);
    }

    #[test]
    fn empty_read_returns_unchanged_cursor() {
        let inbox = AlertInbox::with_defaults();
        let (items, cursor) = inbox.read_since(123, 0);
        assert!(items.is_empty());
        assert_eq!(cursor, 123);
    }

    #[test]
    fn max_items_caps_returned_batch() {
        let inbox = AlertInbox::with_defaults();
        for i in 0..50u64 {
            inbox.append(fresh_alert_at(i, &i.to_string()));
        }
        let (items, _) = inbox.read_since(0, 10);
        assert_eq!(items.len(), 10);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let inbox = AlertInbox::new(3, DEFAULT_RETENTION);
        inbox.append(fresh_alert_at(0, "a"));
        inbox.append(fresh_alert_at(10, "b"));
        inbox.append(fresh_alert_at(20, "c"));
        inbox.append(fresh_alert_at(30, "d"));
        let (items, _) = inbox.read_since(0, 0);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].episode_id, "b");
        assert_eq!(items[2].episode_id, "d");
    }

    #[test]
    fn retention_evicts_old_entries_lazily() {
        let inbox = AlertInbox::new(100, Duration::from_millis(50));
        // Old alert (already expired): ts is well in the past.
        inbox.append(alert_at(1, "ancient"));
        // Fresh alert at "now-ish": current_unix_ms is gigantic; use it.
        let now = current_unix_ms();
        inbox.append(alert_at(now, "fresh"));
        assert_eq!(inbox.len(), 2);
        let (items, _) = inbox.read_since(0, 0);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].episode_id, "fresh");
    }
}
