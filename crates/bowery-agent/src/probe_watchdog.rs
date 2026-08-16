//! Says out loud when this agent has stopped watching.
//!
//! The failure this exists for ran on a live fleet for days. Two agents
//! came up with no BPF object, fell back to the no-op source, logged one
//! line at startup, and then observed nothing — while continuing to
//! gossip, answer SQL, and vote in whisper quorums as though they were
//! healthy. It was noticed by accident, from a row count that looked
//! wrong.
//!
//! Every other detection in this agent is worthless on a blind sensor,
//! so blindness has to reach an operator through the same path as any
//! other finding: an alert in the inbox, which the console badges, the
//! SQL surface exposes, and `bowery notify` emails.
//!
//! # What counts as blind
//!
//! - **No health-reporting source at all.** The no-op fallback. This is
//!   the case that actually happened.
//! - **The source stopped.** A drain task that exits leaves an agent
//!   just as blind as one that never started, and previously said so
//!   only in a log line.
//! - **The kernel is dropping events.** The ring filled and the probe
//!   discarded records. Not blindness, but a measured hole in the
//!   history, and until the counter existed it was invisible.
//!
//! # What deliberately does not count
//!
//! **A quiet host.** "No events recently" is indistinguishable from a
//! genuinely idle machine, and an EDR that cries wolf every time a Pi
//! goes idle overnight teaches its operator to ignore it. Staleness is
//! reported in `bowery_probe_status` for a human to judge; it does not
//! raise an alert on its own.

use std::sync::Arc;
use std::time::Duration;

use bowery_crypto::Fingerprint;
use bowery_events::source::ProbeHealth;
use bowery_proto::Alert;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::agent::AgentEvent;
use crate::inbox::{AlertInbox, current_unix_ms};

/// How often health is examined.
pub const CHECK_INTERVAL: Duration = Duration::from_mins(1);

/// How long a known-bad state waits before re-alerting.
///
/// An agent that is blind stays blind until someone acts, so a single
/// alert can be missed and never repeated. Re-stating it hourly keeps
/// it in front of an operator without becoming the noise it is warning
/// about.
pub const REMIND_AFTER: Duration = Duration::from_hours(1);

/// Suspicion stamped on a sensor alert.
///
/// High on purpose. A blind agent is not a detection — it is the
/// absence of every detection, which is worse than any single one.
const SENSOR_SUSPICION: f32 = 0.95;

/// What the watchdog concluded on one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Watching, and no new loss since the last check.
    Healthy,
    /// Not observing at all.
    Blind { reason: String },
    /// Watching, but the kernel discarded events since the last check.
    Dropping { total: u64, since_last: u64 },
}

impl Verdict {
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Stable key for "is this the same problem as last time?", so a
    /// persistent fault re-alerts on the reminder schedule rather than
    /// every pass.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Blind { .. } => "blind",
            Self::Dropping { .. } => "dropping",
        }
    }
}

/// Decide the state of the sensor.
///
/// Pure, so the policy is testable without a kernel: `health` is `None`
/// when the agent has no health-reporting source, and `previous_drops`
/// is the total from the last pass.
#[must_use]
pub fn assess(health: Option<&ProbeHealth>, previous_drops: u64) -> Verdict {
    let Some(health) = health else {
        return Verdict::Blind {
            reason: "no kernel event source: the BPF object is missing or failed to load, \
                     so this agent observes no execs, exits, or connections"
                .to_string(),
        };
    };
    if let Some(reason) = health.stopped_reason() {
        return Verdict::Blind {
            reason: format!("kernel event source stopped: {reason}"),
        };
    }
    if !health.is_watching() {
        return Verdict::Blind {
            reason: "no kernel probe is attached".to_string(),
        };
    }
    let total = health.total_kernel_drops();
    if total > previous_drops {
        return Verdict::Dropping {
            total,
            since_last: total - previous_drops,
        };
    }
    Verdict::Healthy
}

/// Operator-facing text for a verdict.
#[must_use]
pub fn rationale(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Healthy => "kernel sensor healthy".to_string(),
        Verdict::Blind { reason } => format!(
            "SENSOR BLIND — {reason}. Every detection on this host is \
             inactive while this persists; its whisper answers should not \
             be trusted as evidence of absence."
        ),
        Verdict::Dropping { total, since_last } => format!(
            "SENSOR DROPPING EVENTS — the kernel discarded {since_last} event(s) \
             since the last check ({total} total) because a ring buffer was full. \
             History on this host has gaps; consider raising the ring sizes in \
             the BPF object if this recurs."
        ),
    }
}

/// Watch `health` and raise alerts when the sensor is not doing its job.
pub fn spawn(
    health: Option<Arc<ProbeHealth>>,
    inbox: Arc<AlertInbox>,
    originator_fp: Fingerprint,
    backend_label: String,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut previous_drops = 0u64;
        let mut last_alert: Option<(&'static str, tokio::time::Instant)> = None;

        // One immediate pass: a missing BPF object is knowable at
        // startup, and waiting a minute to say so is a minute of
        // believing the host is covered.
        let mut ticker = tokio::time::interval(CHECK_INTERVAL);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown_rx.changed() => break,
            }

            let verdict = assess(health.as_deref(), previous_drops);
            if let Verdict::Dropping { total, .. } = &verdict {
                previous_drops = *total;
            }
            if verdict.is_healthy() {
                if last_alert.is_some() {
                    info!("kernel sensor recovered");
                    last_alert = None;
                }
                continue;
            }

            // Re-alert on a state change, or once the reminder is due.
            let now = tokio::time::Instant::now();
            let due = match last_alert {
                Some((kind, at)) => {
                    kind != verdict.kind() || now.duration_since(at) >= REMIND_AFTER
                }
                None => true,
            };
            if !due {
                continue;
            }
            last_alert = Some((verdict.kind(), now));

            let text = rationale(&verdict);
            if matches!(verdict, Verdict::Blind { .. }) {
                error!(reason = %text, "sensor alert");
            } else {
                warn!(reason = %text, "sensor alert");
            }

            let episode_id = format!("sensor-{}-{}", verdict.kind(), current_unix_ms());
            inbox.append(Alert {
                originator_fp: originator_fp.as_bytes().to_vec(),
                episode_id: episode_id.clone(),
                exe_sha256_hex: String::new(),
                exe_path: String::new(),
                suspicion: SENSOR_SUSPICION,
                rationale: text,
                suggested_actions: Vec::new(),
                ts_unix_ms: current_unix_ms(),
                backend: backend_label.clone(),
                // No confirmation block: this is a fact about *this*
                // host, not a claim peers can corroborate. Asking the
                // neighbourhood whether we are blind would be absurd.
                confirmation: None,
            });
            let _ = events_tx.send(AgentEvent::AlertEmitted {
                episode_id,
                suspicion: SENSOR_SUSPICION,
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_events::source::{PROBE_EXEC, ProbeHealth};

    #[test]
    fn no_source_at_all_is_blind() {
        // The case that actually happened: no BPF object, silent
        // fallback to the no-op source, days of observing nothing.
        let v = assess(None, 0);
        assert!(matches!(v, Verdict::Blind { .. }));
        assert!(rationale(&v).contains("SENSOR BLIND"));
        assert!(
            rationale(&v).contains("should not be trusted as evidence of absence"),
            "the alert must say why a blind peer's whisper vote is worthless"
        );
    }

    #[test]
    fn an_attached_source_with_no_drops_is_healthy() {
        let h = ProbeHealth::new();
        h.mark_attached(PROBE_EXEC);
        assert_eq!(assess(Some(&h), 0), Verdict::Healthy);
    }

    #[test]
    fn a_source_that_stopped_is_blind() {
        // Attached once, then the drain task exited. Previously this was
        // a log line and nothing else.
        let h = ProbeHealth::new();
        h.mark_attached(PROBE_EXEC);
        h.mark_stopped("ringbuf poll failed");
        match assess(Some(&h), 0) {
            Verdict::Blind { reason } => assert!(reason.contains("ringbuf poll failed")),
            other => panic!("expected blind, got {other:?}"),
        }
    }

    #[test]
    fn attached_but_never_marked_is_blind() {
        let h = ProbeHealth::new();
        assert!(matches!(assess(Some(&h), 0), Verdict::Blind { .. }));
    }

    #[test]
    fn new_kernel_drops_are_reported_once_per_increase() {
        let h = ProbeHealth::new();
        h.mark_attached(PROBE_EXEC);
        h.set_kernel_drops(PROBE_EXEC, 40);

        // First observation: 40 new.
        match assess(Some(&h), 0) {
            Verdict::Dropping { total, since_last } => {
                assert_eq!(total, 40);
                assert_eq!(since_last, 40);
            }
            other => panic!("expected dropping, got {other:?}"),
        }
        // Same total on the next pass is not a new problem — otherwise
        // one saturated moment alerts forever.
        assert_eq!(assess(Some(&h), 40), Verdict::Healthy);

        h.set_kernel_drops(PROBE_EXEC, 55);
        match assess(Some(&h), 40) {
            Verdict::Dropping { since_last, .. } => assert_eq!(since_last, 15),
            other => panic!("expected dropping, got {other:?}"),
        }
    }

    #[test]
    fn blindness_outranks_drops() {
        // A stopped source may also have a stale drop count. Report the
        // condition that makes every other signal meaningless.
        let h = ProbeHealth::new();
        h.mark_attached(PROBE_EXEC);
        h.set_kernel_drops(PROBE_EXEC, 99);
        h.mark_stopped("exited");
        assert!(matches!(assess(Some(&h), 0), Verdict::Blind { .. }));
    }

    #[test]
    fn an_idle_host_is_not_an_alert() {
        // No events ever recorded, but attached and running. A Pi idle
        // overnight must not page anyone; staleness is reported in SQL
        // for a human to judge.
        let h = ProbeHealth::new();
        h.mark_attached(PROBE_EXEC);
        assert_eq!(h.snapshot()[PROBE_EXEC].emitted, 0);
        assert_eq!(assess(Some(&h), 0), Verdict::Healthy);
    }

    #[test]
    fn drop_counts_are_unknown_not_zero_on_an_old_object() {
        // An object built before the counter map has no DROPS. Reporting
        // zero would claim a clean bill of health nobody measured.
        let h = ProbeHealth::new();
        h.mark_attached(PROBE_EXEC);
        assert!(!h.kernel_drops_available());
        assert_eq!(h.snapshot()[PROBE_EXEC].kernel_drops, None);

        h.set_kernel_drops(PROBE_EXEC, 0);
        assert!(h.kernel_drops_available());
        assert_eq!(h.snapshot()[PROBE_EXEC].kernel_drops, Some(0));
    }
}
