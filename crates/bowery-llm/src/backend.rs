//! Backend trait + the bundled mock backend.
//!
//! Real backends (Candle, llama.cpp via `llama-cpp-2`) live behind
//! feature flags and ship in follow-up modules. The mock here is
//! deterministic and zero-cost so the agent's wiring is testable
//! without a model file.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::context::AnalysisContext;

/// Allowed action ids the LLM may suggest. The response engine
/// (Phase 7) will validate these against the active policy.
pub const SUGGESTED_ACTIONS: &[&str] = &[
    "alert",
    "throttle_network",
    "quarantine_file_writes",
    "kill_process",
    "block_file",
    "kill_connection",
];

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("model not loaded: {0}")]
    ModelNotLoaded(String),

    #[error("inference failed: {0}")]
    Inference(String),

    #[error("response was not valid JSON: {0}")]
    BadResponse(String),

    #[error("backend cancelled")]
    Cancelled,
}

/// Verdict emitted by the LLM analyzer.
///
/// Fields parallel the JSON schema the prompt asks the model to emit
/// (see [`crate::prompt`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmVerdict {
    /// Refined suspicion in `[0, 1]`. May be lower or higher than the
    /// pre-filter's `pre_verdict.suspicion`.
    pub suspicion: f32,
    /// One- or two-sentence explanation.
    pub rationale: String,
    /// Suggested action ids. Filtered to [`SUGGESTED_ACTIONS`] by the
    /// caller in case the model invented something.
    pub suggested_actions: Vec<String>,
    /// A short question the agent may broadcast to peer hosts via the
    /// whisper protocol (Phase 5). Empty string means "no whisper".
    pub whisper_query: String,
    /// Backend label — useful for logs and operator audits.
    pub backend: String,
}

#[async_trait]
pub trait LlmAnalyzer: Send + Sync {
    /// Analyse `ctx` and return an [`LlmVerdict`].
    async fn analyze(&self, ctx: &AnalysisContext) -> Result<LlmVerdict, LlmError>;

    /// Backend identifier embedded in [`LlmVerdict::backend`].
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// MockLlmAnalyzer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MockMode {
    /// Echoes the pre-filter suspicion and recommends `alert` for any
    /// non-trivial input. Default.
    #[default]
    Echo,
    /// Always returns `suspicion = 0.0` and no actions. Useful for
    /// negative tests.
    Quiet,
    /// Always errors. Useful for fault-injection tests.
    Failing,
}

#[derive(Debug, Clone, Default)]
pub struct MockLlmAnalyzer {
    mode: MockMode,
}

impl MockLlmAnalyzer {
    pub fn new(mode: MockMode) -> Self {
        Self { mode }
    }
}

#[async_trait]
impl LlmAnalyzer for MockLlmAnalyzer {
    async fn analyze(&self, ctx: &AnalysisContext) -> Result<LlmVerdict, LlmError> {
        match self.mode {
            MockMode::Echo => {
                let pre = ctx.pre_verdict.suspicion;
                let mut actions = Vec::new();
                if pre >= 0.5 {
                    actions.push("alert".to_string());
                }
                if pre >= 0.9 {
                    actions.push("throttle_network".to_string());
                }
                Ok(LlmVerdict {
                    suspicion: pre,
                    rationale: format!(
                        "mock backend echoing pre-filter (rule_hits={}, baseline_seen={})",
                        ctx.pre_verdict.rule_hits.len(),
                        ctx.pre_verdict.score.baseline_seen_count
                    ),
                    suggested_actions: actions,
                    whisper_query: if pre >= 0.5 {
                        format!(
                            "have you seen episodes like {} on hosts of role {}?",
                            ctx.pre_verdict.episode_id, ctx.local_role_summary
                        )
                    } else {
                        String::new()
                    },
                    backend: self.name().to_string(),
                })
            }
            MockMode::Quiet => Ok(LlmVerdict {
                suspicion: 0.0,
                rationale: "mock-quiet".into(),
                suggested_actions: Vec::new(),
                whisper_query: String::new(),
                backend: self.name().to_string(),
            }),
            MockMode::Failing => Err(LlmError::Inference("mock-failing".into())),
        }
    }

    fn name(&self) -> &str {
        match self.mode {
            MockMode::Echo => "mock/echo",
            MockMode::Quiet => "mock/quiet",
            MockMode::Failing => "mock/failing",
        }
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // mock backend returns deterministic exact values
mod tests {
    use super::*;
    use bowery_analysis::{BinaryScore, RuleHit, RuleSeverity, Verdict};

    fn ctx_with_suspicion(s: f32, hits: usize) -> AnalysisContext {
        let verdict = Verdict {
            episode_id: "ep-test".into(),
            suspicion: s,
            score: BinaryScore {
                value: s,
                baseline_seen_count: 0,
                reason: "test".into(),
            },
            rule_hits: (0..hits)
                .map(|i| RuleHit {
                    rule_id: "exec_from_writable_path",
                    severity: RuleSeverity::Medium,
                    reason: format!("test hit {i}"),
                })
                .collect(),
        };
        AnalysisContext::new(verdict)
    }

    #[tokio::test]
    async fn echo_mode_passes_pre_filter_suspicion_through() {
        let m = MockLlmAnalyzer::new(MockMode::Echo);
        let v = m.analyze(&ctx_with_suspicion(0.95, 1)).await.unwrap();
        assert!((v.suspicion - 0.95).abs() < 1e-6);
        assert!(v.suggested_actions.contains(&"alert".to_string()));
        assert!(
            v.suggested_actions
                .contains(&"throttle_network".to_string())
        );
        assert!(!v.whisper_query.is_empty());
    }

    #[tokio::test]
    async fn echo_mode_silent_for_low_suspicion() {
        let m = MockLlmAnalyzer::new(MockMode::Echo);
        let v = m.analyze(&ctx_with_suspicion(0.1, 0)).await.unwrap();
        assert!(v.suggested_actions.is_empty());
        assert!(v.whisper_query.is_empty());
    }

    #[tokio::test]
    async fn quiet_mode_zeroes_everything() {
        let m = MockLlmAnalyzer::new(MockMode::Quiet);
        let v = m.analyze(&ctx_with_suspicion(0.99, 5)).await.unwrap();
        assert_eq!(v.suspicion, 0.0);
        assert!(v.suggested_actions.is_empty());
    }

    #[tokio::test]
    async fn failing_mode_returns_error() {
        let m = MockLlmAnalyzer::new(MockMode::Failing);
        let err = m
            .analyze(&ctx_with_suspicion(0.5, 0))
            .await
            .expect_err("should error");
        assert!(matches!(err, LlmError::Inference(_)));
    }
}
