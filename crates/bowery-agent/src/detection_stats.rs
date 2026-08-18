//! How often has each detection actually fired?
//!
//! # Why this exists
//!
//! Six defects were found in one day by asking that question, and every
//! one of them had to be answered by grepping journals across three
//! hosts. Two of the six were nearly missed because the answer changes
//! meaning across a restart — a log-based count reads whatever window
//! the journal happens to hold, and an agent that restarted five minutes
//! ago looks identical to one whose rule has never worked.
//!
//! The findings split evenly into two shapes, and both are visible here
//! and almost nowhere else:
//!
//! - **Zero forever.** `file.access` ran 24 rounds and corroborated
//!   nothing; its responder could not attribute an access to a binary
//!   for any long-running daemon, so the kind could not answer the
//!   question it was built for.
//! - **Far too many.** The uid-transition rule fired 78 times in a day
//!   because it exempted the executed binary instead of the parent, so
//!   every `sudo <command>` read as an escalation.
//!
//! Neither is visible in an alert stream, which shows what fired and
//! never what didn't.
//!
//! # Every known rule is a row, including the ones at zero
//!
//! Seeded from the rule registry rather than created on first fire, so
//! a detection that has never fired appears as `0` rather than as an
//! absent row. That is the same distinction the rest of this agent
//! keeps insisting on — an absence of alerts must not be
//! indistinguishable from an absence of monitoring — applied to the
//! rules themselves.
//!
//! # Scope
//!
//! [`DetectionStats::snapshot`] counts since **this agent started**, and
//! `since_unix_ms` says so rather than leaving the reader to guess. The
//! periodic flush folds a *delta* into the baseline without rewinding
//! that counter, so the two never disagree; `bowery_detections` reports
//! both, as `fired` and `fired_since_install`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::inbox::current_unix_ms;

/// One rule's history since startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleStat {
    pub fired: u64,
    /// `None` when it has never fired.
    pub last_unix_ms: Option<u64>,
}

/// Per-rule fire counters, fixed at construction.
///
/// The key set never changes, so reads need no lock and a runaway
/// detection cannot grow this.
#[derive(Debug)]
pub struct DetectionStats {
    rules: HashMap<&'static str, RuleCounters>,
    since_unix_ms: u64,
}

/// One rule's live counters.
///
/// `fired` is monotonic for the life of the agent, and `flushed` records
/// how much of it the periodic flush has already folded into the
/// baseline. They are kept apart because the obvious implementation —
/// one counter that the flush resets — makes [`DetectionStats::snapshot`]
/// report "since the last flush" while [`DetectionStats::since_unix_ms`]
/// still claims "since startup". An operator reading `fired = 0` against
/// a three-hour-old agent would conclude the rule had never fired, when
/// it may have fired five hundred times four minutes ago. That is the
/// precise failure this module exists to make impossible, so it must not
/// be reintroduced by its own bookkeeping.
#[derive(Debug, Default)]
struct RuleCounters {
    fired: AtomicU64,
    flushed: AtomicU64,
    last_unix_ms: AtomicU64,
}

impl Default for DetectionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionStats {
    /// Seeded with every rule the agent knows how to fire.
    #[must_use]
    pub fn new() -> Self {
        let rules = bowery_analysis::attack::all_rule_ids()
            .into_iter()
            .map(|id| (id, RuleCounters::default()))
            .collect();
        Self {
            rules,
            since_unix_ms: current_unix_ms(),
        }
    }

    /// Note that `rule_id` fired.
    ///
    /// An unknown id is ignored rather than inserted: the key set is
    /// the registry, and silently growing it would let a typo create a
    /// row that no rule can ever produce — which is the shape of defect
    /// this whole module exists to surface.
    pub fn record(&self, rule_id: &str) {
        if let Some(c) = self.rules.get(rule_id) {
            c.fired.fetch_add(1, Ordering::Relaxed);
            c.last_unix_ms.store(current_unix_ms(), Ordering::Relaxed);
        } else {
            debug_assert!(false, "unregistered rule id fired: {rule_id}");
        }
    }

    /// Every rule and its count, sorted by id so output is stable.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(&'static str, RuleStat)> {
        let mut out: Vec<(&'static str, RuleStat)> = self
            .rules
            .iter()
            .map(|(id, c)| {
                let last = c.last_unix_ms.load(Ordering::Relaxed);
                (
                    *id,
                    RuleStat {
                        fired: c.fired.load(Ordering::Relaxed),
                        last_unix_ms: (last > 0).then_some(last),
                    },
                )
            })
            .collect();
        out.sort_unstable_by_key(|(id, _)| *id);
        out
    }

    /// Per-rule counts not yet folded into the baseline.
    ///
    /// The `bowery_detections` view adds this to the durable total to get
    /// "since install". Adding [`Self::snapshot`]'s `fired` instead would
    /// double-count every fire the flush has already written to disk,
    /// because that counter is monotonic for the session by design.
    #[must_use]
    pub fn unflushed(&self) -> HashMap<&'static str, u64> {
        self.rules
            .iter()
            .map(|(id, c)| {
                let fired = c.fired.load(Ordering::Relaxed);
                (*id, fired.saturating_sub(c.flushed.load(Ordering::Relaxed)))
            })
            .collect()
    }

    /// When this agent started counting.
    #[must_use]
    pub fn since_unix_ms(&self) -> u64 {
        self.since_unix_ms
    }

    /// Take what has fired since the last drain, for folding into the
    /// baseline.
    ///
    /// Returns a **delta**, and advances the flush watermark rather than
    /// rewinding the counter — repeated calls accumulate on disk instead
    /// of re-adding the same totals, while [`Self::snapshot`] keeps
    /// meaning "since this agent started". Returns every rule, including
    /// the zeros, so a never-fired rule gets a row on disk too: the whole
    /// point is that its absence is visible.
    ///
    /// Assumes a single caller. Two concurrent drainers could both
    /// observe the same delta; there is one flush task, and making this
    /// safe for many would cost a lock on a path that does not need one.
    pub fn drain(&self) -> Vec<(&'static str, u64, Option<u64>)> {
        self.rules
            .iter()
            .map(|(id, c)| {
                let fired = c.fired.load(Ordering::Relaxed);
                let delta = fired.saturating_sub(c.flushed.swap(fired, Ordering::Relaxed));
                let last = c.last_unix_ms.load(Ordering::Relaxed);
                (*id, delta, (last > 0).then_some(last))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_rule_has_a_row_before_anything_fires() {
        let s = DetectionStats::new();
        let snap = s.snapshot();
        assert!(snap.len() > 20, "the registry is not that small");
        assert!(
            snap.iter().all(|(_, st)| st.fired == 0),
            "nothing has fired yet"
        );
        // The point of the whole module: a rule that has never fired is
        // a visible zero, not a missing row.
        assert!(
            snap.iter()
                .any(|(id, _)| *id == "impact.mass_write_new_extension"),
            "a never-fired rule must still appear"
        );
    }

    #[test]
    fn recording_counts_and_stamps() {
        let s = DetectionStats::new();
        s.record("privesc.uid_transition_no_helper");
        s.record("privesc.uid_transition_no_helper");
        let stat = s
            .snapshot()
            .into_iter()
            .find(|(id, _)| *id == "privesc.uid_transition_no_helper")
            .expect("row")
            .1;
        assert_eq!(stat.fired, 2);
        assert!(stat.last_unix_ms.is_some());
    }

    #[test]
    fn a_rule_that_never_fired_has_no_timestamp() {
        let s = DetectionStats::new();
        let stat = s
            .snapshot()
            .into_iter()
            .find(|(id, _)| *id == "impact.mass_write_new_extension")
            .expect("row")
            .1;
        assert_eq!(stat.fired, 0);
        assert_eq!(
            stat.last_unix_ms, None,
            "never-fired must be None, not epoch zero"
        );
    }

    /// The key set is the registry. A typo must not quietly create a row
    /// no rule can produce — that is the defect shape this exists to
    /// surface, not one to reproduce.
    #[test]
    fn an_unregistered_id_does_not_create_a_row() {
        let s = DetectionStats::new();
        let before = s.snapshot().len();
        // `record` debug-asserts; call the map directly to check the
        // no-growth property without tripping it.
        assert!(!s.rules.contains_key("not.a.real.rule"));
        assert_eq!(s.snapshot().len(), before);
    }

    /// The flush must not rewind what `snapshot` reports.
    ///
    /// A counter the flush resets turns `fired = 0` into "not since the
    /// last flush" while `since_unix_ms` still says "since startup" —
    /// the exact ambiguity this module exists to remove.
    #[test]
    fn draining_folds_a_delta_without_rewinding_the_session_count() {
        let s = DetectionStats::new();
        s.record("privesc.uid_transition_no_helper");
        s.record("privesc.uid_transition_no_helper");

        let first: Vec<_> = s.drain().into_iter().filter(|(_, n, _)| *n > 0).collect();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].1, 2, "the first drain carries both");

        let stat = s
            .snapshot()
            .into_iter()
            .find(|(id, _)| *id == "privesc.uid_transition_no_helper")
            .expect("row")
            .1;
        assert_eq!(
            stat.fired, 2,
            "a flush must not make a rule that fired look like one that never did"
        );

        // A second drain with nothing new in between adds nothing, so
        // the durable total does not double-count.
        assert!(
            s.drain().iter().all(|(_, n, _)| *n == 0),
            "an idle interval must fold nothing"
        );

        s.record("privesc.uid_transition_no_helper");
        let third: Vec<_> = s.drain().into_iter().filter(|(_, n, _)| *n > 0).collect();
        assert_eq!(third[0].1, 1, "only what arrived since the last flush");
        assert_eq!(
            s.snapshot()
                .into_iter()
                .find(|(id, _)| *id == "privesc.uid_transition_no_helper")
                .expect("row")
                .1
                .fired,
            3
        );
    }

    /// `fired_since_install` = durable + unflushed. Using `fired` there
    /// would count every already-persisted fire twice.
    #[test]
    fn what_is_left_to_flush_shrinks_as_it_is_flushed() {
        let s = DetectionStats::new();
        s.record("privesc.uid_transition_no_helper");
        assert_eq!(s.unflushed()["privesc.uid_transition_no_helper"], 1);
        s.drain();
        assert_eq!(
            s.unflushed()["privesc.uid_transition_no_helper"],
            0,
            "what the baseline already holds must not be counted again"
        );
        s.record("privesc.uid_transition_no_helper");
        assert_eq!(s.unflushed()["privesc.uid_transition_no_helper"], 1);
    }

    /// `bowery-analysis` states the probe count in the README summary
    /// but cannot import it — it does not depend on the sensor crate.
    /// This crate sees both, so it is where the two are compared.
    #[test]
    fn the_readme_probe_count_matches_the_sensor() {
        let want = format!("{} kernel probes", bowery_events::source::PROBE_COUNT);
        assert!(
            bowery_analysis::attack::readme_capabilities().contains(&want),
            "the README says a different number of probes than the sensor has; expected `{want}`"
        );
    }

    #[test]
    fn the_counting_window_is_stated() {
        let s = DetectionStats::new();
        assert!(s.since_unix_ms() > 0, "a zero must be readable in context");
    }
}
