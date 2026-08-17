//! Command-and-control beaconing: a process calling home on a timer.
//!
//! `T1071.001` is one of two techniques still at `none` on the coverage
//! map. Connection events have been recorded since Phase 2 and nothing
//! has ever scored them.
//!
//! # Why periodicity alone is not the detection
//!
//! Regular outbound connections are what healthy infrastructure looks
//! like. NTP polls. Package managers check for updates. Monitoring
//! agents push metrics. Certificate clients renew. A rule that fires on
//! "connects at a regular interval" fires on all of them, on every host,
//! forever — the same trap as scoring ransomware by write *rate*, which
//! would have fired on every build and unpack.
//!
//! So periodicity is a *precondition*, and the finding needs a
//! conjunction:
//!
//! 1. **Regular.** Low variation between intervals — a timer, not a
//!    human and not a retry storm.
//! 2. **Sustained.** Enough intervals that regularity means something;
//!    three connections can look periodic by chance.
//! 3. **New to this host.** The destination is not one this host has
//!    been talking to all along. This is the condition that excludes
//!    NTP and the package mirror without naming them — a signature list
//!    of "known good" endpoints would be both endless and an evasion
//!    target.
//!
//! Condition 3 is checked by the caller against the destination
//! baseline, because this module deliberately holds no state beyond the
//! timestamps it is given.
//!
//! # What it cannot see
//!
//! **Jittered beacons.** Every serious implant randomises its interval,
//! and a wide enough jitter is indistinguishable from ordinary traffic
//! by this measure. The map says so rather than claiming the technique
//! is covered.
//!
//! **Anything over an existing connection.** The sensor reports
//! connection *setup*; a beacon multiplexed onto one long-lived TLS
//! session produces one event and never appears here.
//!
//! **Low-and-slow.** A daily beacon needs days of history and will
//! usually fall outside the event log's retention before it is visible.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A destination this host contacts on a timer.
#[derive(Debug, Clone, PartialEq)]
pub struct Beacon {
    pub dst_addr: String,
    pub dst_port: u16,
    /// Connections observed in the window.
    pub samples: usize,
    /// Mean gap between them.
    pub interval: Duration,
    /// Standard deviation over the mean. Zero is a perfect metronome.
    pub jitter: f32,
}

/// How regular a series of intervals has to be.
///
/// 0.15 admits a timer with ordinary scheduling noise and rejects
/// anything that merely happens to repeat. Deliberately strict: a missed
/// beacon costs one detection, while a loose threshold costs the
/// operator's attention on every cron job in the estate.
pub const DEFAULT_MAX_JITTER: f32 = 0.15;

/// Intervals needed before regularity means anything.
///
/// Six connections give five intervals. Fewer than that and a coincidence
/// looks like a metronome.
pub const DEFAULT_MIN_SAMPLES: usize = 6;

/// Ignore anything faster than this: sub-second repetition is a retry
/// loop or a connection pool, not a beacon.
pub const MIN_INTERVAL: Duration = Duration::from_secs(10);

/// ...and anything slower, because the event log will not hold enough
/// history for the measurement to mean anything.
pub const MAX_INTERVAL: Duration = Duration::from_hours(6);

/// Judge a series of connection times to one destination.
///
/// `times` must be sorted ascending. `None` when the series is too
/// short, too fast, too slow, or too irregular to be a timer.
#[must_use]
pub fn assess(
    dst_addr: &str,
    dst_port: u16,
    times: &[Instant],
    min_samples: usize,
    max_jitter: f32,
) -> Option<Beacon> {
    if times.len() < min_samples.max(3) {
        return None;
    }
    let gaps: Vec<f64> = times
        .windows(2)
        .map(|w| w[1].duration_since(w[0]).as_secs_f64())
        .collect();
    // `gaps` is bounded by the tracker's 256-sample cap, so the count
    // is nowhere near f64's mantissa.
    #[allow(clippy::cast_precision_loss)]
    let n = gaps.len() as f64;
    let mean = gaps.iter().sum::<f64>() / n;
    if mean < MIN_INTERVAL.as_secs_f64() || mean > MAX_INTERVAL.as_secs_f64() {
        return None;
    }
    // Coefficient of variation. Scale-free, so a 30-second beacon and a
    // 30-minute one are held to the same standard of regularity.
    let variance = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / n;
    #[allow(clippy::cast_possible_truncation)]
    let jitter = (variance.sqrt() / mean) as f32;
    if jitter > max_jitter {
        return None;
    }
    Some(Beacon {
        dst_addr: dst_addr.to_string(),
        dst_port,
        samples: times.len(),
        interval: Duration::from_secs_f64(mean),
        jitter,
    })
}

/// The rule id a beacon is reported under.
pub const RULE_ID: &str = "c2.beacon_new_destination";

/// Every rule id this module can produce.
#[must_use]
pub const fn rule_ids() -> &'static [&'static str] {
    &[RULE_ID]
}

/// Tracks outbound connection times per destination.
#[derive(Debug)]
pub struct BeaconTracker {
    inner: Mutex<HashMap<(String, u16), Vec<Instant>>>,
    /// How far back timestamps are kept.
    window: Duration,
    min_samples: usize,
    max_jitter: f32,
    max_tracked: usize,
    /// Destinations already reported, so a beacon is one finding rather
    /// than one per connection forever after.
    reported: Mutex<HashMap<(String, u16), Instant>>,
    remind_after: Duration,
}

impl BeaconTracker {
    #[must_use]
    pub fn new(window: Duration, min_samples: usize, max_jitter: f32) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window,
            min_samples,
            max_jitter,
            // A host talks to a bounded set of endpoints; this caps a
            // scan or a connection storm rather than a real workload.
            max_tracked: 4096,
            reported: Mutex::new(HashMap::new()),
            remind_after: Duration::from_hours(6),
        }
    }

    /// Record an outbound connection, and report a beacon if this
    /// completes one.
    ///
    /// Reports **once** per destination per remind window. A beacon that
    /// keeps beaconing is one finding, not one per callback — the point
    /// is to say "this is happening", and repeating it is the noise this
    /// project keeps having to remove.
    pub fn observe(&self, dst_addr: &str, dst_port: u16, now: Instant) -> Option<Beacon> {
        let key = (dst_addr.to_string(), dst_port);
        {
            let mut seen = self.reported.lock().ok()?;
            if let Some(at) = seen.get(&key) {
                if now.duration_since(*at) < self.remind_after {
                    return None;
                }
                seen.remove(&key);
            }
        }
        let mut guard = self.inner.lock().ok()?;
        if guard.len() >= self.max_tracked && !guard.contains_key(&key) {
            guard.clear();
        }
        let times = guard.entry(key.clone()).or_default();
        times.retain(|t| now.duration_since(*t) < self.window);
        times.push(now);
        // Bound a chatty destination: only the most recent matter, and
        // an unbounded vec is a memory leak with extra steps.
        if times.len() > 256 {
            let excess = times.len() - 256;
            times.drain(..excess);
        }
        let beacon = assess(dst_addr, dst_port, times, self.min_samples, self.max_jitter)?;
        if let Ok(mut seen) = self.reported.lock() {
            seen.insert(key, now);
        }
        Some(beacon)
    }

    /// Forget a destination — used when it turns out to be established
    /// infrastructure and the caller decided not to report it.
    pub fn forget(&self, dst_addr: &str, dst_port: u16) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(&(dst_addr.to_string(), dst_port));
        }
    }
}

/// Operator-facing text for a beacon.
#[must_use]
pub fn rationale(b: &Beacon, first_seen_hours: Option<u64>) -> String {
    let age = match first_seen_hours {
        Some(h) if h < 48 => format!(
            "This host first contacted it {h}h ago, so it is not something this machine \
             has been talking to all along"
        ),
        Some(h) => format!("This host first contacted it {h}h ago"),
        None => "This host has no earlier record of contacting it".to_string(),
    };
    format!(
        "possible C2 beaconing: {} connections to {}:{} at a mean interval of {}s with {:.0}% \
         variation — a timer rather than a person or a retry loop. {age}. Regular outbound \
         traffic is also what NTP, package mirrors and monitoring agents look like, which is \
         why novelty rather than periodicity is what makes this worth reading. Note the sensor \
         sees connection setup only: a beacon multiplexed onto one long-lived session, or one \
         jittered widely enough, would not appear here",
        b.samples,
        b.dst_addr,
        b.dst_port,
        b.interval.as_secs(),
        b.jitter * 100.0
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(start: Instant, gaps_secs: &[u64]) -> Vec<Instant> {
        let mut t = start;
        let mut out = vec![t];
        for g in gaps_secs {
            t += Duration::from_secs(*g);
            out.push(t);
        }
        out
    }

    #[test]
    fn a_metronome_is_a_beacon() {
        let t = series(Instant::now(), &[60; 8]);
        let b = assess("10.0.0.9", 443, &t, DEFAULT_MIN_SAMPLES, DEFAULT_MAX_JITTER)
            .expect("perfectly regular");
        assert_eq!(b.samples, 9);
        assert_eq!(b.interval.as_secs(), 60);
        assert!(b.jitter < 0.01);
    }

    /// Ordinary scheduling noise must not disqualify a timer.
    #[test]
    fn a_timer_with_a_little_slop_still_counts() {
        let t = series(Instant::now(), &[60, 62, 59, 61, 60, 58, 61]);
        assert!(assess("10.0.0.9", 443, &t, DEFAULT_MIN_SAMPLES, DEFAULT_MAX_JITTER).is_some());
    }

    /// The condition that keeps this from firing on everything: human
    /// and event-driven traffic is irregular.
    #[test]
    fn irregular_traffic_is_not_a_beacon() {
        let t = series(Instant::now(), &[15, 400, 32, 900, 20, 1200, 45]);
        assert!(assess("10.0.0.9", 443, &t, DEFAULT_MIN_SAMPLES, DEFAULT_MAX_JITTER).is_none());
    }

    /// Three connections can look periodic by coincidence.
    #[test]
    fn too_few_samples_prove_nothing() {
        let t = series(Instant::now(), &[60, 60]);
        assert!(assess("10.0.0.9", 443, &t, DEFAULT_MIN_SAMPLES, DEFAULT_MAX_JITTER).is_none());
    }

    /// A connection pool or a retry loop, not a beacon.
    #[test]
    fn sub_second_repetition_is_not_a_beacon() {
        let start = Instant::now();
        let t: Vec<Instant> = (0..10)
            .map(|i| start + Duration::from_millis(i * 200))
            .collect();
        assert!(assess("10.0.0.9", 443, &t, DEFAULT_MIN_SAMPLES, DEFAULT_MAX_JITTER).is_none());
    }

    #[test]
    fn an_interval_too_long_to_measure_is_rejected() {
        let t = series(Instant::now(), &[7 * 3600; 8]);
        assert!(assess("10.0.0.9", 443, &t, DEFAULT_MIN_SAMPLES, DEFAULT_MAX_JITTER).is_none());
    }

    #[test]
    fn the_tracker_reports_once_not_once_per_callback() {
        let tr = BeaconTracker::new(
            Duration::from_hours(2),
            DEFAULT_MIN_SAMPLES,
            DEFAULT_MAX_JITTER,
        );
        let start = Instant::now();
        let mut hits = 0;
        for i in 0..20 {
            if tr
                .observe("10.0.0.9", 443, start + Duration::from_secs(i * 60))
                .is_some()
            {
                hits += 1;
            }
        }
        assert_eq!(hits, 1, "a beacon that keeps beaconing is one finding");
    }

    #[test]
    fn different_destinations_are_tracked_separately() {
        let tr = BeaconTracker::new(
            Duration::from_hours(2),
            DEFAULT_MIN_SAMPLES,
            DEFAULT_MAX_JITTER,
        );
        let start = Instant::now();
        // Interleaved, so pooling them would destroy the regularity of
        // both and neither would ever be found.
        let mut found = 0;
        for i in 0..12 {
            let t = start + Duration::from_secs(i * 60);
            if tr.observe("10.0.0.9", 443, t).is_some() {
                found += 1;
            }
            if tr
                .observe("10.0.0.10", 8080, t + Duration::from_secs(5))
                .is_some()
            {
                found += 1;
            }
        }
        assert_eq!(
            found, 2,
            "each destination must be judged on its own series"
        );
    }

    #[test]
    fn the_rationale_says_what_it_cannot_see() {
        let t = series(Instant::now(), &[60; 8]);
        let b = assess("10.0.0.9", 443, &t, DEFAULT_MIN_SAMPLES, DEFAULT_MAX_JITTER).unwrap();
        let r = rationale(&b, Some(3));
        assert!(r.contains("3h ago"));
        assert!(
            r.contains("multiplexed"),
            "the blind spot must be stated: {r}"
        );
        assert!(
            r.contains("NTP"),
            "the false-positive shape must be named: {r}"
        );
    }

    #[test]
    fn tracking_is_bounded() {
        let tr = BeaconTracker::new(
            Duration::from_hours(2),
            DEFAULT_MIN_SAMPLES,
            DEFAULT_MAX_JITTER,
        );
        let now = Instant::now();
        for i in 0..10_000 {
            tr.observe(&format!("10.0.{}.{}", i / 256, i % 256), 443, now);
        }
        assert!(tr.inner.lock().unwrap().len() <= 4096);
    }
}
