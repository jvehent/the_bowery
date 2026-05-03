//! Episode analyzer: combines rule pre-filter and baseline scorer into a
//! single [`Verdict`].
//!
//! Phase 3 produces a Verdict that downstream phases (LLM analyzer,
//! response engine) consume. The shape — suspicion in `[0, 1]`, optional
//! rationale, suggested actions — mirrors what the LLM stage will emit
//! later, so the response engine can be developed against either.

use std::sync::Arc;

use serde::Serialize;

use crate::episode::Episode;
use crate::rule::{Rule, RuleHit, evaluate_all};
use crate::score::{BinaryScore, BinaryScorer};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub episode_id: String,
    /// Aggregated suspicion in `[0, 1]`. The Phase 3 aggregation rule is:
    /// `max(score.value, max_severity_weight(rule_hits))`.
    pub suspicion: f32,
    pub score: BinaryScore,
    pub rule_hits: Vec<RuleHit>,
}

/// Pre-filter analyzer: rules + scorer, no LLM. Runs synchronously per
/// episode; the agent calls it from `spawn_blocking` so it never blocks
/// the async runtime.
pub struct Analyzer {
    rules: Vec<Box<dyn Rule>>,
    scorer: BinaryScorer,
}

impl std::fmt::Debug for Analyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Analyzer")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl Analyzer {
    pub fn new(rules: Vec<Box<dyn Rule>>, scorer: BinaryScorer) -> Self {
        Self { rules, scorer }
    }

    pub fn with_default_rules(baseline: Arc<bowery_baseline::Baseline>) -> Self {
        Self {
            rules: crate::rule::default_rules(),
            scorer: BinaryScorer::new(baseline),
        }
    }

    pub fn analyze(&self, episode: &Episode, exe_sha: &[u8; 32]) -> Verdict {
        let rule_hits = evaluate_all(&self.rules, episode);
        let score = self.scorer.score_or_default(episode, exe_sha);
        let suspicion = score.value.max(rule_hits_weight(&rule_hits));
        Verdict {
            episode_id: episode.id.clone(),
            suspicion,
            score,
            rule_hits,
        }
    }
}

fn rule_hits_weight(hits: &[RuleHit]) -> f32 {
    use crate::rule::RuleSeverity;
    hits.iter()
        .map(|h| match h.severity {
            RuleSeverity::Info => 0.1,
            RuleSeverity::Low => 0.3,
            RuleSeverity::Medium => 0.6,
            RuleSeverity::High => 0.9,
        })
        .fold(0.0_f32, f32::max)
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // exact comparisons against deterministic 1.0 sentinel for unseen binaries
mod tests {
    use std::path::PathBuf;
    use std::time::SystemTime;

    use bowery_baseline::Baseline;
    use bowery_events::ProcessExec;

    use super::*;

    fn ep(args: Vec<&str>, exe: Option<&str>) -> Episode {
        Episode::from_exec(ProcessExec {
            pid: 42,
            ppid: 1,
            uid: 0,
            comm: "x".into(),
            exe_path: exe.map(PathBuf::from),
            args: args.into_iter().map(String::from).collect(),
            ts: SystemTime::UNIX_EPOCH,
        })
    }

    #[test]
    fn unseen_normal_binary_yields_high_suspicion_via_score() {
        let baseline = Arc::new(Baseline::open_in_memory().unwrap());
        let analyzer = Analyzer::with_default_rules(baseline);
        let v = analyzer.analyze(&ep(vec!["curl"], Some("/usr/bin/curl")), &[1; 32]);
        assert_eq!(v.suspicion, 1.0); // never seen
        assert!(v.rule_hits.is_empty());
    }

    #[test]
    fn familiar_normal_binary_yields_low_suspicion() {
        let baseline = Arc::new(Baseline::open_in_memory().unwrap());
        for _ in 0..100 {
            baseline.upsert_binary(&[2; 32]).unwrap();
        }
        let analyzer = Analyzer::with_default_rules(baseline);
        let v = analyzer.analyze(&ep(vec!["curl"], Some("/usr/bin/curl")), &[2; 32]);
        assert!(v.suspicion < 0.2, "suspicion {}", v.suspicion);
        assert!(v.rule_hits.is_empty());
    }

    #[test]
    fn rule_hit_lifts_familiar_binary_into_high_suspicion() {
        let baseline = Arc::new(Baseline::open_in_memory().unwrap());
        for _ in 0..100 {
            baseline.upsert_binary(&[3; 32]).unwrap();
        }
        let analyzer = Analyzer::with_default_rules(baseline);
        // Familiar sha but exec'd from /tmp + bash -i: rule hits dominate.
        let v = analyzer.analyze(&ep(vec!["bash", "-i"], Some("/tmp/payload")), &[3; 32]);
        assert!(v.suspicion >= 0.9, "suspicion {}", v.suspicion);
        assert_eq!(v.rule_hits.len(), 2);
    }
}
