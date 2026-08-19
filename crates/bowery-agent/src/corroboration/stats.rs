//! Why the corroboration engine produced nothing.
//!
//! `bowery_detections` reports how often each rule fired, and for these
//! kinds the answer is usually zero. Zero is ambiguous in exactly the
//! way this codebase keeps finding costly: it can mean nothing
//! suspicious happened, or that every claim raised was thrown away
//! before anyone was asked.
//!
//! Measured on the reference fleet over six hours: 87 claims raised for
//! `net.inbound_connect`, 87 dropped because the connecting host was a
//! workstation nobody in the mesh can answer for, and a detection table
//! reading `0`. The engine was working perfectly and had nothing it
//! could ask. There was no way to tell that apart from a quiet network.
//!
//! Same role `bowery_probe_status` plays for the sensors: it is what
//! distinguishes quiet from blind.

use std::collections::HashMap;
use std::sync::Mutex;

/// Per-kind counters for one agent's corroboration engine.
#[derive(Debug, Default)]
pub struct CorroborationStats {
    inner: Mutex<HashMap<&'static str, Counters>>,
}

/// What happened to the claims of one kind.
///
/// Every field is a *terminal* outcome for a claim except `rounds`, so
/// `raised` should equal `no_audience + deduped + shed + rounds` once
/// in-flight work settles. A drift between them is itself a finding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Claims the detector offered.
    pub raised: u64,
    /// No pinned peer could speak to it, so nobody was asked. On a host
    /// whose inbound connections come from outside the mesh this is
    /// nearly all of them, and it is not a fault.
    pub no_audience: u64,
    /// Collapsed as a repeat inside the dedup window.
    pub deduped: u64,
    /// Dropped for backpressure — the engine was already saturated.
    pub shed: u64,
    /// Rounds actually dispatched to at least one peer.
    pub rounds: u64,
    /// Answers received across those rounds.
    pub corroborated: u64,
    pub denied: u64,
    pub refused: u64,
    pub no_reply: u64,
}

impl CorroborationStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn bump(&self, kind: &'static str, f: impl FnOnce(&mut Counters)) {
        if let Ok(mut g) = self.inner.lock() {
            f(g.entry(kind).or_default());
        }
    }

    pub fn raised(&self, kind: &'static str) {
        self.bump(kind, |c| c.raised += 1);
    }

    pub fn no_audience(&self, kind: &'static str) {
        self.bump(kind, |c| c.no_audience += 1);
    }

    pub fn deduped(&self, kind: &'static str) {
        self.bump(kind, |c| c.deduped += 1);
    }

    pub fn shed(&self, kind: &'static str) {
        self.bump(kind, |c| c.shed += 1);
    }

    /// A round ran; record it and what came back.
    pub fn round(
        &self,
        kind: &'static str,
        corroborated: u64,
        denied: u64,
        refused: u64,
        no_reply: u64,
    ) {
        self.bump(kind, |c| {
            c.rounds += 1;
            c.corroborated += corroborated;
            c.denied += denied;
            c.refused += refused;
            c.no_reply += no_reply;
        });
    }

    /// Snapshot, sorted by kind so the view is stable between queries.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(&'static str, Counters)> {
        let Ok(g) = self.inner.lock() else {
            return Vec::new();
        };
        let mut out: Vec<_> = g.iter().map(|(k, v)| (*k, *v)).collect();
        out.sort_unstable_by_key(|(k, _)| *k);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape observed on the fleet: every claim raised, every one
    /// dropped for want of anyone to ask, and a detection count of zero
    /// that says none of it.
    #[test]
    fn a_kind_that_never_finds_an_audience_is_visible_as_such() {
        let s = CorroborationStats::new();
        for _ in 0..87 {
            s.raised("net.inbound_connect");
            s.no_audience("net.inbound_connect");
        }
        let snap = s.snapshot();
        assert_eq!(snap.len(), 1);
        let (kind, c) = snap[0];
        assert_eq!(kind, "net.inbound_connect");
        assert_eq!(c.raised, 87);
        assert_eq!(c.no_audience, 87);
        assert_eq!(c.rounds, 0, "nothing was ever asked");
        assert_eq!(
            c.raised,
            c.no_audience + c.deduped + c.shed + c.rounds,
            "every claim must have exactly one terminal outcome"
        );
    }

    /// A working kind and a starved one must be distinguishable, which
    /// is the entire point.
    #[test]
    fn rounds_and_answers_are_counted_apart_from_drops() {
        let s = CorroborationStats::new();
        s.raised("file.access");
        s.round("file.access", 2, 1, 0, 1);
        s.raised("net.inbound_connect");
        s.no_audience("net.inbound_connect");

        let snap = s.snapshot();
        assert_eq!(snap[0].0, "file.access", "sorted by kind");
        assert_eq!(snap[0].1.rounds, 1);
        assert_eq!(snap[0].1.corroborated, 2);
        assert_eq!(snap[0].1.denied, 1);
        assert_eq!(snap[0].1.no_reply, 1);
        assert_eq!(snap[0].1.no_audience, 0);

        assert_eq!(snap[1].1.rounds, 0);
        assert_eq!(snap[1].1.no_audience, 1);
    }

    #[test]
    fn an_engine_that_has_done_nothing_reports_nothing() {
        assert!(CorroborationStats::new().snapshot().is_empty());
    }
}
