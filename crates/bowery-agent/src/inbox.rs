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
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bowery_proto::Alert;
use tracing::debug;

/// Default ring capacity — matches the DESIGN doc's per-operator size
/// cap (10k messages). Each `Alert` is small (~few hundred bytes), so
/// 10k upper-bounds inbox memory at single-digit MiB.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// Default retention window. DESIGN locks 72 h.
pub const DEFAULT_RETENTION: Duration = Duration::from_hours(72);

/// What became of an alert handed to the inbox.
///
/// `#[must_use]` on purpose. Most callers emit an `AlertEmitted` event
/// after appending, and a suppressed alert must not produce one — an
/// operator watching the event stream would otherwise see a finding the
/// inbox does not hold. Making the outcome impossible to ignore is what
/// keeps those two views agreeing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a suppressed alert must not be announced as if it had been raised"]
pub enum Appended {
    /// In the ring, possibly with a damped score.
    Stored,
    /// An operator-signed silence took it below the alert threshold.
    /// It is counted against that silence in `bowery_silences`, and
    /// against its rule in `bowery_detections`.
    Suppressed { silence_id: String },
}

impl Appended {
    /// Did this alert reach the inbox?
    #[must_use]
    pub fn stored(&self) -> bool {
        matches!(self, Self::Stored)
    }
}

/// Bounded ring of [`Alert`]s with TTL retention.
#[derive(Debug)]
pub struct AlertInbox {
    inner: Mutex<Inner>,
    /// Operator judgements about which findings are benign. `None` means
    /// nothing is ever suppressed, which is what a test agent and a
    /// freshly installed one both want.
    silences: Option<Arc<crate::silence_store::SilenceStore>>,
    /// The score an alert must still reach after damping to be kept.
    /// Held here because this is where damping happens; it mirrors
    /// `[alerts] threshold`.
    alert_threshold: f32,
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
            silences: None,
            alert_threshold: 0.0,
        }
    }

    /// Honour operator-signed silences, damping or withholding alerts
    /// that match one.
    ///
    /// Off unless called: an agent that was never told about silences
    /// suppresses nothing, which is the right default for the one
    /// feature here that can create absence.
    #[must_use]
    pub fn with_silences(
        mut self,
        silences: Arc<crate::silence_store::SilenceStore>,
        alert_threshold: f32,
    ) -> Self {
        self.silences = Some(silences);
        self.alert_threshold = alert_threshold;
        self
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_RETENTION)
    }

    /// Append an alert, unless an operator has judged it benign.
    ///
    /// The single choke point every alert path goes through, which is
    /// why silencing is applied here rather than at the twenty-five
    /// construction sites: a detection added next year cannot forget to
    /// honour a silence, and cannot accidentally honour one twice.
    ///
    /// Evicts the oldest entry if the ring is at capacity.
    ///
    /// **The detection counter is not touched here.** Callers record the
    /// fire before appending, so `bowery_detections` reports what fired
    /// whether or not an operator chose to hear about it. Suppression
    /// hides an alert; it must never rewrite history.
    pub fn append(&self, alert: Alert) -> Appended {
        debug_assert!(
            !alert.rule_id.is_empty(),
            "alert {} carries no rule_id — it cannot be counted against a detection, \
             found by rule in bowery_alerts, or pointed at by an operator saying it is \
             benign. Built-in detections are checked harder in `AlertBuilder::new`.",
            alert.episode_id,
        );
        let alert = match self.apply_silences(alert) {
            Ok(alert) => alert,
            Err(silence_id) => return Appended::Suppressed { silence_id },
        };
        let mut g = self.inner.lock().expect("inbox poisoned");
        if g.items.len() >= g.capacity {
            g.items.pop_front();
        }
        g.items.push_back(alert);
        Appended::Stored
    }

    /// Damp an alert, or refuse it outright.
    ///
    /// `Err(silence_id)` means the damped score fell below the alert
    /// threshold. A damped alert that still clears the bar is kept, and
    /// says in its own rationale that it was damped and by what — an
    /// alert that arrives at 0.4 because a silence took it down from
    /// 0.95 is a different fact from one that was always 0.4.
    fn apply_silences(&self, mut alert: Alert) -> Result<Alert, String> {
        use bowery_analysis::silence::{AlertSubject, SilenceDecision, damped_note};
        let Some(store) = self.silences.as_ref() else {
            return Ok(alert);
        };
        let host_fp_hex = hex_lower(&alert.originator_fp);
        let subject = AlertSubject {
            rule_id: &alert.rule_id,
            exe_sha256_hex: &alert.exe_sha256_hex,
            exe_path: &alert.exe_path,
            host_fp_hex: &host_fp_hex,
        };
        match store.decide(&subject, alert.suspicion, current_unix_ms()) {
            SilenceDecision::Unaffected => Ok(alert),
            SilenceDecision::Damped {
                silence_id,
                reason,
                from,
                to,
            } => {
                if to < self.alert_threshold {
                    debug!(
                        silence = %silence_id,
                        episode = %alert.episode_id,
                        rule = %alert.rule_id,
                        from,
                        to,
                        "alert suppressed by an operator silence"
                    );
                    return Err(silence_id);
                }
                alert
                    .rationale
                    .push_str(&damped_note(&silence_id, &reason, from, to));
                alert.suspicion = to;
                Ok(alert)
            }
        }
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

/// Lowercase hex, for comparing a fingerprint against a silence's host
/// scope.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- silencing ------------------------------------------------------

    mod silencing {
        use super::*;
        use bowery_crypto::Identity;
        use bowery_proto::AlertSilence;
        use std::sync::Arc;

        const CLUSTER: &str = "prod";

        fn store_with(
            weight_permille: u32,
            spec_path: &str,
        ) -> Arc<crate::silence_store::SilenceStore> {
            let op = Identity::generate();
            let store = crate::silence_store::SilenceStore::in_memory(CLUSTER);
            let mut s = AlertSilence {
                id: "sil-test".into(),
                cluster_id: CLUSTER.into(),
                rule_id: "cred.read_netrc".into(),
                exe_sha256_hex: "8353a512".into(),
                exe_path: spec_path.into(),
                host_fp: Vec::new(),
                weight_permille,
                reason: "git reads its own netrc".into(),
                issued_unix_ms: 1,
                expires_unix_ms: u64::MAX,
                operator_fp: op.fingerprint().as_bytes().to_vec(),
                sig: Vec::new(),
            };
            let input = s.to_signing_input().expect("signable");
            s.sig = op.sign(&input).to_bytes().to_vec();
            let resolve = move |fp: &bowery_crypto::Fingerprint| {
                (*fp == op.fingerprint()).then(|| op.verifying_key())
            };
            store
                .accept(&s, &resolve, current_unix_ms())
                .expect("accepted");
            Arc::new(store)
        }

        fn netrc_alert(suspicion: f32) -> Alert {
            Alert {
                originator_fp: vec![0xaa; 32],
                episode_id: "file-cred.read_netrc-1".into(),
                rule_id: "cred.read_netrc".into(),
                exe_sha256_hex: "8353a512".into(),
                exe_path: "/home/j/.netrc".into(),
                suspicion,
                rationale: "credential-access read".into(),
                suggested_actions: Vec::new(),
                ts_unix_ms: current_unix_ms(),
                backend: "test".into(),
                confirmation: None,
                context: Vec::new(),
            }
        }

        #[test]
        fn a_silenced_alert_never_reaches_the_inbox() {
            let inbox = AlertInbox::new(16, DEFAULT_RETENTION)
                .with_silences(store_with(0, "/home/j/.netrc"), 0.5);
            assert!(matches!(
                inbox.append(netrc_alert(0.9)),
                Appended::Suppressed { .. }
            ));
            assert!(inbox.read_since(0, 100).0.is_empty());
        }

        /// A damped alert that still clears the bar is kept, and says so
        /// — arriving at 0.4 because a silence took it down from 0.9 is
        /// a different fact from having always been 0.4.
        #[test]
        fn a_damped_alert_that_still_clears_the_bar_says_it_was_damped() {
            let inbox = AlertInbox::new(16, DEFAULT_RETENTION)
                .with_silences(store_with(500, "/home/j/.netrc"), 0.2);
            assert_eq!(inbox.append(netrc_alert(0.9)), Appended::Stored);
            let (alerts, _) = inbox.read_since(0, 100);
            assert_eq!(alerts.len(), 1);
            assert!(
                (alerts[0].suspicion - 0.45).abs() < 1e-6,
                "{}",
                alerts[0].suspicion
            );
            assert!(
                alerts[0].rationale.contains("reduced to"),
                "{}",
                alerts[0].rationale
            );
            assert!(
                alerts[0].rationale.contains("sil-test"),
                "{}",
                alerts[0].rationale
            );
        }

        /// The silence names a path; a finding elsewhere is untouched.
        #[test]
        fn an_alert_the_silence_does_not_cover_is_unaffected() {
            let inbox = AlertInbox::new(16, DEFAULT_RETENTION)
                .with_silences(store_with(0, "/home/other/.netrc"), 0.5);
            assert_eq!(inbox.append(netrc_alert(0.9)), Appended::Stored);
            assert!((inbox.read_since(0, 100).0[0].suspicion - 0.9).abs() < f32::EPSILON);
        }

        /// An agent nobody has configured suppresses nothing.
        #[test]
        fn an_inbox_without_a_silence_store_suppresses_nothing() {
            let inbox = AlertInbox::new(16, DEFAULT_RETENTION);
            assert_eq!(inbox.append(netrc_alert(0.9)), Appended::Stored);
        }

        /// Suppression hides an alert; it must never make the fleet look
        /// quiet. The silence's own counter is what says otherwise.
        #[test]
        fn a_suppressed_alert_is_counted_against_its_silence() {
            let store = store_with(0, "/home/j/.netrc");
            let inbox = AlertInbox::new(16, DEFAULT_RETENTION).with_silences(store.clone(), 0.5);
            for _ in 0..4 {
                let _ = inbox.append(netrc_alert(0.9));
            }
            let rows = store.rows();
            assert_eq!(
                rows[0].matched, 4,
                "a muted fleet must not look like a quiet one"
            );
            assert!(rows[0].last_matched_unix_ms.is_some());
        }
    }

    fn alert_at(ts_ms: u64, episode: &str) -> Alert {
        Alert {
            originator_fp: vec![0u8; 32],
            rule_id: "cred.read_netrc".into(),
            episode_id: episode.into(),
            exe_sha256_hex: String::new(),
            exe_path: String::new(),
            suspicion: 0.5,
            rationale: String::new(),
            suggested_actions: vec![],
            ts_unix_ms: ts_ms,
            backend: "test".into(),
            confirmation: None,
            context: Vec::new(),
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
        let _ = inbox.append(fresh_alert_at(0, "a"));
        let _ = inbox.append(fresh_alert_at(100, "b"));
        let _ = inbox.append(fresh_alert_at(200, "c"));

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
        let _ = inbox.append(a);
        let _ = inbox.append(b);
        let _ = inbox.append(c);

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
            let _ = inbox.append(fresh_alert_at(i, &i.to_string()));
        }
        let (items, _) = inbox.read_since(0, 10);
        assert_eq!(items.len(), 10);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let inbox = AlertInbox::new(3, DEFAULT_RETENTION);
        let _ = inbox.append(fresh_alert_at(0, "a"));
        let _ = inbox.append(fresh_alert_at(10, "b"));
        let _ = inbox.append(fresh_alert_at(20, "c"));
        let _ = inbox.append(fresh_alert_at(30, "d"));
        let (items, _) = inbox.read_since(0, 0);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].episode_id, "b");
        assert_eq!(items[2].episode_id, "d");
    }

    #[test]
    fn retention_evicts_old_entries_lazily() {
        let inbox = AlertInbox::new(100, Duration::from_millis(50));
        // Old alert (already expired): ts is well in the past.
        let _ = inbox.append(alert_at(1, "ancient"));
        // Fresh alert at "now-ish": current_unix_ms is gigantic; use it.
        let now = current_unix_ms();
        let _ = inbox.append(alert_at(now, "fresh"));
        assert_eq!(inbox.len(), 2);
        let (items, _) = inbox.read_since(0, 0);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].episode_id, "fresh");
    }
}
