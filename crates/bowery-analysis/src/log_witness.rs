//! Peers remembering how much history a host had.
//!
//! Root on a host can delete that host's event log, and nothing local
//! survives to say it existed. Local integrity checks cannot help: a
//! verifier only ever sees what remains, so a log truncated from 376,000
//! rows to nothing is indistinguishable from an agent installed a minute
//! ago. That is the whole appeal of clearing it.
//!
//! It is not indistinguishable to a *neighbour* who wrote the number
//! down. An attacker can delete a host's records; they cannot reach into
//! the memory of every machine that already heard how many there were.
//!
//! # The invariant
//!
//! `highest_seq` counts every event the log has ever accepted, and it is
//! read from SQLite's `sqlite_sequence` rather than from `MAX(seq)` over
//! the rows. That distinction is what makes the invariant hold: `DELETE`
//! does not reset `sqlite_sequence`, so retention pruning every row in
//! the log still leaves the height where it was. The number survives a
//! restart too, because it lives in the file.
//!
//! It falls only when the database itself is replaced — which is what
//! deleting the log and letting the agent recreate it does.
//!
//! So a report of a *lower* `highest_seq` than a peer already witnessed
//! means the log lost history it had. There is no benign path to it
//! inside the agent.
//!
//! # What it deliberately does not claim
//!
//! A rollback is not proof of an attacker. Reinstalling an agent,
//! wiping `/var/lib/bowery`, or restoring a host from an older image all
//! produce exactly this, and the alert says so — it reports that the log
//! went backwards and by how much, not that someone did it on purpose.
//! Being unable to tell those apart is honest; staying silent because
//! one of them is innocent would not be.
//!
//! And it sees nothing at all until a peer has witnessed a host at least
//! once. A log cleared before any neighbour ever heard from it leaves no
//! trace here either — the same shape as every other detection that
//! needs a baseline, and worth stating rather than discovering.

use std::collections::HashMap;

/// One host's claim about how much history it holds.
///
/// Signed by the reporting agent before it reaches the gossip layer;
/// this type is the verified payload, not the wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogReport {
    /// Highest sequence number the log has ever assigned.
    pub highest_seq: u64,
    /// When the reporting host stamped it.
    pub reported_unix_ms: u64,
}

/// A host's log losing history it previously had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackFinding {
    /// Hex fingerprint of the host whose log went backwards.
    pub host_fp_hex: String,
    /// What a peer last witnessed.
    pub witnessed_seq: u64,
    /// What it now reports.
    pub reported_seq: u64,
    /// How many events went missing.
    pub lost: u64,
}

pub const RULE_ID: &str = "evade.event_log_rollback";

/// Every rule id this module can produce.
#[must_use]
pub const fn rule_ids() -> &'static [&'static str] {
    &[RULE_ID]
}

/// Operator-facing text for a rollback.
#[must_use]
pub fn rationale(f: &RollbackFinding) -> String {
    format!(
        "host {} reports its event log at sequence {}, and this agent previously \
         witnessed it at {} — {} events of history are gone. That number only ever \
         rises: it survives a restart, and retention prunes old rows without reissuing \
         sequence numbers, so there is no path to a lower one inside the agent. \
         Clearing that log is how an intrusion removes its own record, and this host \
         cannot report it about itself once the record is gone. Reinstalling the agent, \
         wiping /var/lib/bowery, or restoring the host from an older image produce the \
         same evidence and are worth ruling out first",
        &f.host_fp_hex[..f.host_fp_hex.len().min(16)],
        f.reported_seq,
        f.witnessed_seq,
        f.lost,
    )
}

/// What this agent remembers about its neighbours' logs.
///
/// Bounded by the pinned peer set in practice — an entry is created only
/// for a peer whose signature verified — but capped anyway, because a
/// map that grows with anything an attacker influences is a map worth
/// capping.
#[derive(Debug)]
pub struct LogWitness {
    seen: HashMap<String, LogReport>,
    max_tracked: usize,
}

impl Default for LogWitness {
    fn default() -> Self {
        Self::new()
    }
}

impl LogWitness {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            max_tracked: 1024,
        }
    }

    /// Record a verified report, and say whether it lost history.
    ///
    /// Returns `Some` exactly once per rollback: the witness adopts the
    /// new, lower value afterwards, so a host that was genuinely
    /// reinstalled reports once and then counts up again rather than
    /// alerting on every subsequent gossip round.
    pub fn observe(&mut self, host_fp_hex: &str, report: LogReport) -> Option<RollbackFinding> {
        if self.seen.len() >= self.max_tracked && !self.seen.contains_key(host_fp_hex) {
            return None;
        }
        let Some(previous) = self.seen.get(host_fp_hex).copied() else {
            self.seen.insert(host_fp_hex.to_string(), report);
            return None;
        };

        // Gossip is eventually consistent and can redeliver an older
        // value after a newer one. A stale report is not a rollback, so
        // only a report *stamped later* than what we hold can be one.
        if report.reported_unix_ms < previous.reported_unix_ms {
            return None;
        }

        if report.highest_seq >= previous.highest_seq {
            self.seen.insert(host_fp_hex.to_string(), report);
            return None;
        }

        let finding = RollbackFinding {
            host_fp_hex: host_fp_hex.to_string(),
            witnessed_seq: previous.highest_seq,
            reported_seq: report.highest_seq,
            lost: previous.highest_seq - report.highest_seq,
        };
        // Adopt the new value so this reports once, not forever.
        self.seen.insert(host_fp_hex.to_string(), report);
        Some(finding)
    }

    /// How many peers this agent can currently speak for.
    #[must_use]
    pub fn witnessed_peers(&self) -> usize {
        self.seen.len()
    }

    /// What this agent last witnessed for a peer, if anything.
    #[must_use]
    pub fn witnessed(&self, host_fp_hex: &str) -> Option<LogReport> {
        self.seen.get(host_fp_hex).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(seq: u64, ts: u64) -> LogReport {
        LogReport {
            highest_seq: seq,
            reported_unix_ms: ts,
        }
    }

    /// The first sighting establishes the baseline and accuses nobody.
    #[test]
    fn a_peer_seen_for_the_first_time_is_not_a_finding() {
        let mut w = LogWitness::new();
        assert_eq!(w.observe("aa", report(100, 1_000)), None);
        assert_eq!(w.witnessed("aa"), Some(report(100, 1_000)));
    }

    #[test]
    fn a_log_that_keeps_growing_is_not_a_finding() {
        let mut w = LogWitness::new();
        w.observe("aa", report(100, 1_000));
        assert_eq!(w.observe("aa", report(101, 2_000)), None);
        assert_eq!(w.observe("aa", report(50_000, 3_000)), None);
    }

    /// The whole point: history a peer already counted, gone.
    #[test]
    fn a_log_that_went_backwards_is_a_finding() {
        let mut w = LogWitness::new();
        w.observe("aa", report(376_000, 1_000));
        let f = w
            .observe("aa", report(12, 2_000))
            .expect("a log cannot lose sequence numbers on its own");
        assert_eq!(f.witnessed_seq, 376_000);
        assert_eq!(f.reported_seq, 12);
        assert_eq!(f.lost, 375_988);
    }

    /// Reported once, not on every gossip round afterwards — otherwise a
    /// reinstalled agent alerts forever and gets muted.
    #[test]
    fn a_rollback_is_reported_once_and_then_counted_from() {
        let mut w = LogWitness::new();
        w.observe("aa", report(500, 1_000));
        assert!(w.observe("aa", report(3, 2_000)).is_some());
        assert_eq!(w.observe("aa", report(4, 3_000)), None);
        assert_eq!(w.observe("aa", report(5, 4_000)), None);
    }

    /// Gossip can redeliver an old value after a new one. That is not a
    /// host losing history, and treating it as one would make this fire
    /// on ordinary mesh behaviour.
    #[test]
    fn a_stale_report_arriving_late_is_not_a_rollback() {
        let mut w = LogWitness::new();
        w.observe("aa", report(100, 5_000));
        assert_eq!(w.observe("aa", report(90, 4_000)), None);
        // And the stale value must not have overwritten the newer one.
        assert_eq!(w.witnessed("aa").map(|r| r.highest_seq), Some(100));
    }

    /// An equal sequence number is a host that simply has not logged
    /// anything since — the common case on an idle Pi.
    #[test]
    fn an_unchanged_sequence_is_not_a_finding() {
        let mut w = LogWitness::new();
        w.observe("aa", report(100, 1_000));
        assert_eq!(w.observe("aa", report(100, 2_000)), None);
    }

    #[test]
    fn peers_are_tracked_separately() {
        let mut w = LogWitness::new();
        w.observe("aa", report(100, 1_000));
        w.observe("bb", report(5, 1_000));
        // `bb` is simply younger; it is not `aa` rolling back.
        assert_eq!(w.observe("bb", report(6, 2_000)), None);
        assert!(w.observe("aa", report(6, 2_000)).is_some());
        assert_eq!(w.witnessed_peers(), 2);
    }

    #[test]
    fn tracking_is_bounded() {
        let mut w = LogWitness::new();
        for i in 0..2_000 {
            w.observe(&format!("peer{i}"), report(1, 1_000));
        }
        assert!(w.witnessed_peers() <= 1_024);
    }

    #[test]
    fn the_rationale_states_the_numbers_and_the_innocent_explanations() {
        let f = RollbackFinding {
            host_fp_hex: "abcdef0123456789abcdef".into(),
            witnessed_seq: 376_000,
            reported_seq: 12,
            lost: 375_988,
        };
        let why = rationale(&f);
        assert!(why.contains("376000") && why.contains("12") && why.contains("375988"));
        assert!(
            why.contains("Reinstalling"),
            "an operator must be told what else produces this"
        );
    }
}
