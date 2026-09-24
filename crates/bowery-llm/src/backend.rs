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

/// Prefix for the backend tag embedded in [`LlmVerdict::backend`].
///
/// The rest of the tag is the model actually loaded — see
/// [`backend_tag_for`]. It used to be the whole tag, a constant reading
/// `llama-cpp/qwen3-0.6b`, and otter1 spent an afternoon stamping that
/// on every alert while running `gemma-4-e2b-it-q4_k_m`. A label that
/// names the wrong model is worse than no label: it is the audit trail
/// for "which analyser judged this", and it was confidently wrong.
const BACKEND_PREFIX: &str = "llama-cpp";

/// The backend tag for a given model file.
///
/// Derived from the file stem rather than from GGUF metadata: the stem
/// is what the operator wrote in `[llm.llama_cpp] model_path`, so it is
/// the string they can match against their own config, and it needs no
/// model to be loaded to compute. A path with no usable stem yields
/// just the prefix, which claims nothing beyond the backend itself.
#[must_use]
pub fn backend_tag_for(model_path: &std::path::Path) -> String {
    match model_path.file_stem().and_then(|s| s.to_str()) {
        Some(stem) if !stem.is_empty() => format!("{BACKEND_PREFIX}/{stem}"),
        _ => BACKEND_PREFIX.to_string(),
    }
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
                // Real action ids, so the response path is actually
                // exercisable on a mock-backend fleet. These used to be
                // "alert" and "throttle_network", neither of which the
                // engine implements — so every suggestion was skipped as
                // an unknown id and the whole enforcement path, dry-run
                // included, was unreachable.
                //
                // Suggesting them is not the same as performing them:
                // `[response] mode` still defaults to off, and the policy
                // still defaults to deny-all.
                let mut actions = Vec::new();
                if pre >= 0.9 {
                    actions.push("kill_process".to_string());
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
        // Whatever the mock suggests must be an action the engine can
        // actually perform, or the response path is unreachable and
        // every suggestion is skipped as an unknown id — which is
        // exactly what a live fleet was doing, 22 times in three hours.
        for a in &v.suggested_actions {
            assert!(
                bowery_response::Action::known_ids().contains(&a.as_str()),
                "mock suggested `{a}`, which the engine cannot perform"
            );
        }
        assert!(
            v.suggested_actions.contains(&"kill_process".to_string()),
            "a 0.95 verdict should propose something: {:?}",
            v.suggested_actions
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

#[cfg(test)]
mod backend_tag_tests {
    use super::*;
    use std::path::Path;

    /// The tag names the model that is loaded, not a guess made at
    /// compile time.
    ///
    /// It used to be `const BACKEND_TAG = "llama-cpp/qwen3-0.6b"`.
    /// otter1 ran `gemma-4-e2b-it-q4_k_m` for an afternoon and stamped
    /// `qwen3-0.6b` on every alert it produced. The `backend` field is
    /// the audit trail for *which analyser judged this*, so a label
    /// that names the wrong model is worse than none: it is confidently
    /// wrong, and it is the field a mixed fleet would be segmented by.
    ///
    /// Lives here rather than beside the llama.cpp backend on purpose.
    /// That module is behind `feature = "llama-cpp"`, which CI does not
    /// build, so a test next to it would never run — which is how the
    /// constant survived in the first place.
    #[test]
    fn the_tag_names_the_model_actually_configured() {
        assert_eq!(
            backend_tag_for(Path::new(
                "/var/lib/bowery/models/gemma-4-e2b-it-q4_k_m.gguf"
            )),
            "llama-cpp/gemma-4-e2b-it-q4_k_m"
        );
        assert_eq!(
            backend_tag_for(Path::new("/var/lib/bowery/models/qwen3-0.6b-q4_k_m.gguf")),
            "llama-cpp/qwen3-0.6b-q4_k_m"
        );
        assert_ne!(
            backend_tag_for(Path::new("/models/gemma-4-e2b-it-q4_k_m.gguf")),
            "llama-cpp/qwen3-0.6b",
            "the bug this replaced"
        );
    }

    /// A path with nothing usable claims only the backend.
    #[test]
    fn an_unusable_path_claims_nothing_beyond_the_backend() {
        assert_eq!(backend_tag_for(Path::new("/")), "llama-cpp");
        assert_eq!(backend_tag_for(Path::new("")), "llama-cpp");
        assert_eq!(backend_tag_for(Path::new("..")), "llama-cpp");
    }
}
