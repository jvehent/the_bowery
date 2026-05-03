//! LLM analyzer for The Bowery.
//!
//! Phase 4 surface:
//! - [`LlmAnalyzer`] trait with async `analyze`.
//! - [`AnalysisContext`] / [`LlmVerdict`] — the structured I/O the trait
//!   exchanges with whichever backend is plugged in.
//! - [`prompt`]: deterministic prompt builder shaped for Qwen3 chat
//!   formatting (works with any chat-tuned model that follows the
//!   chatml-style `<|im_start|>` / `<|im_end|>` convention).
//! - [`MockLlmAnalyzer`]: deterministic, no-cost backend used in default
//!   builds and tests. Returns a verdict derived from the input — useful
//!   to exercise the rest of the pipeline without depending on a model
//!   file.
//! - [`InferenceQueue`]: bounded SLO-based scheduler. Drops oldest
//!   pending requests when the backlog grows past the configured
//!   capacity so the LLM never becomes a back-pressure bottleneck on the
//!   event pipeline.
//! - With the `llama-cpp` feature: a real Qwen3-0.6B-capable backend
//!   wrapping llama.cpp. The build dep is opt-in because llama.cpp adds
//!   ~30s to the build and a C++ toolchain requirement.
//!
//! See [DESIGN.md](../../DESIGN.md) §6 for why we gate the LLM behind
//! the rules + scorer instead of running it on every event.

pub mod backend;
pub mod context;
pub mod prompt;
pub mod queue;

pub use backend::{LlmAnalyzer, LlmError, LlmVerdict, MockLlmAnalyzer, MockMode};
pub use context::AnalysisContext;
pub use prompt::PromptStyle;
pub use queue::{InferenceOutcome, InferenceQueue, QueueConfig, ShedReason, Submitter};
