//! Statistical baseline scoring.
//!
//! Phase 3 implements the simplest meaningful scorer: how rare is this
//! binary, given how many times we've seen it before? `score` is in
//! `[0, 1]`, where 1.0 means "never seen" and approaches 0.0 as the
//! observation count grows. The shape is `1 / (1 + seen_count / k)`,
//! with `k` controlling how quickly familiarity drains the score.
//!
//! Future phases add scorers for syscall-frequency deviation, network
//! peer rarity, parent-child edge novelty, etc. Each scorer combines into
//! a single "this episode's deviation" score consumed by the LLM gate.

use std::sync::Arc;

use bowery_baseline::Baseline;
use serde::Serialize;
use thiserror::Error;
use tracing::warn;

use crate::episode::Episode;

/// Familiarity half-life: at `seen_count = HALF_LIFE`, the score is 0.5.
/// Tunable later from config.
const DEFAULT_HALF_LIFE: f32 = 8.0;

#[derive(Debug, Error)]
pub enum Error {
    #[error("baseline error: {0}")]
    Baseline(#[from] bowery_baseline::Error),
}

/// The result of scoring one episode against the baseline.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BinaryScore {
    /// Raw deviation in `[0, 1]`. Higher = more anomalous.
    pub value: f32,
    /// `seen_count` from the baseline at the time of scoring. Useful for
    /// downstream context-builders that want to surface "first time" or
    /// "rare" framing to the LLM.
    pub baseline_seen_count: u64,
    /// One-line human-readable explanation.
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct BinaryScorer {
    baseline: Arc<Baseline>,
    half_life: f32,
}

impl BinaryScorer {
    pub fn new(baseline: Arc<Baseline>) -> Self {
        Self {
            baseline,
            half_life: DEFAULT_HALF_LIFE,
        }
    }

    #[must_use]
    pub fn with_half_life(mut self, k: f32) -> Self {
        self.half_life = k.max(0.5);
        self
    }

    /// Score an episode. The episode's exe is hashed by a previous stage
    /// (the agent's pipeline) and looked up in the baseline.
    ///
    /// `exe_sha` is the caller-computed SHA-256 of the episode root's
    /// executable. We don't recompute it here to avoid synchronous file
    /// I/O on the analyzer hot path.
    pub fn score(&self, _episode: &Episode, exe_sha: &[u8; 32]) -> Result<BinaryScore, Error> {
        let record = self.baseline.get_binary(exe_sha)?;
        match record {
            None => Ok(BinaryScore {
                value: 1.0,
                baseline_seen_count: 0,
                reason: "binary never seen on this host".into(),
            }),
            Some(rec) => {
                #[allow(clippy::cast_precision_loss)]
                let n = rec.seen_count as f32;
                let value = 1.0 / (1.0 + n / self.half_life);
                Ok(BinaryScore {
                    value,
                    baseline_seen_count: rec.seen_count,
                    reason: format!("binary seen {} times before", rec.seen_count),
                })
            }
        }
    }

    /// Like `score` but logs and yields a fallback value on baseline error.
    pub fn score_or_default(&self, episode: &Episode, exe_sha: &[u8; 32]) -> BinaryScore {
        match self.score(episode, exe_sha) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "baseline scorer failed; defaulting to neutral");
                BinaryScore {
                    value: 0.5,
                    baseline_seen_count: 0,
                    reason: format!("baseline lookup failed: {e}"),
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // exact comparisons against the deterministic 1.0 sentinel for unseen binaries
mod tests {
    use std::path::PathBuf;
    use std::time::SystemTime;

    use bowery_events::ProcessExec;

    use super::*;

    fn ep() -> Episode {
        Episode::from_exec(ProcessExec {
            pid: 1,
            ppid: 1,
            uid: 0,
            comm: "x".into(),
            exe_path: Some(PathBuf::from("/usr/bin/curl")),
            args: vec![],
            ts: SystemTime::UNIX_EPOCH,
        })
    }

    fn sha(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn unseen_binary_scores_one() {
        let baseline = Arc::new(Baseline::open_in_memory().unwrap());
        let scorer = BinaryScorer::new(baseline);
        let s = scorer.score(&ep(), &sha(1)).unwrap();
        assert_eq!(s.value, 1.0);
        assert_eq!(s.baseline_seen_count, 0);
    }

    #[test]
    fn score_decreases_monotonically_with_familiarity() {
        let baseline = Arc::new(Baseline::open_in_memory().unwrap());
        let scorer = BinaryScorer::new(baseline.clone()).with_half_life(8.0);
        let s_before = scorer.score(&ep(), &sha(2)).unwrap();
        baseline.upsert_binary(&sha(2)).unwrap();
        let s_one = scorer.score(&ep(), &sha(2)).unwrap();
        assert!(s_one.value < s_before.value);
        for _ in 0..10 {
            baseline.upsert_binary(&sha(2)).unwrap();
        }
        let s_many = scorer.score(&ep(), &sha(2)).unwrap();
        assert!(s_many.value < s_one.value);
        assert!(s_many.value > 0.0);
    }

    #[test]
    fn score_at_half_life_is_one_half() {
        let baseline = Arc::new(Baseline::open_in_memory().unwrap());
        let scorer = BinaryScorer::new(baseline.clone()).with_half_life(8.0);
        for _ in 0..8 {
            baseline.upsert_binary(&sha(3)).unwrap();
        }
        let s = scorer.score(&ep(), &sha(3)).unwrap();
        assert!((s.value - 0.5).abs() < 0.01);
    }
}
