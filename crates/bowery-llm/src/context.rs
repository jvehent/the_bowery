//! Input context the LLM analyzer sees.
//!
//! Built by the agent's pipeline after the rule pre-filter and baseline
//! scorer have produced a [`bowery_analysis::Verdict`]. The LLM uses this
//! to write a rationale, suggested actions, and (in later phases) a
//! whisper question to send to peers.

use std::path::PathBuf;

use bowery_analysis::Verdict;

/// Bundled inputs handed to a [`crate::LlmAnalyzer`].
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// The Phase 3 verdict — rule hits + baseline score + aggregated
    /// suspicion. The LLM's job is to *explain* and *recommend*, not to
    /// re-derive these signals.
    pub pre_verdict: Verdict,
    /// Resolved exe path of the rooting process, if any. Useful framing.
    pub exe_path: Option<PathBuf>,
    /// Hex-encoded SHA-256 of the exe, if known.
    pub exe_sha256_hex: Option<String>,
    /// argv as observed.
    pub args: Vec<String>,
    /// Coarse role descriptor for the host the analysis runs on. Phase 3
    /// emits "host" as a placeholder; later phases derive this from the
    /// role vector.
    pub local_role_summary: String,
    /// Free-form additional context the agent wants to surface (e.g.
    /// recent peer answers when whisper Q&A lands).
    pub extra: Vec<(String, String)>,
}

impl AnalysisContext {
    pub fn new(pre_verdict: Verdict) -> Self {
        Self {
            pre_verdict,
            exe_path: None,
            exe_sha256_hex: None,
            args: Vec::new(),
            local_role_summary: "host".to_string(),
            extra: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_exe_path(mut self, p: PathBuf) -> Self {
        self.exe_path = Some(p);
        self
    }

    #[must_use]
    pub fn with_exe_sha256(mut self, sha: &[u8; 32]) -> Self {
        let mut s = String::with_capacity(64);
        for b in sha {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        self.exe_sha256_hex = Some(s);
        self
    }

    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    #[must_use]
    pub fn with_role_summary(mut self, summary: impl Into<String>) -> Self {
        self.local_role_summary = summary.into();
        self
    }
}
