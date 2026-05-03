//! Prompt construction.
//!
//! The default style is [`PromptStyle::Qwen3Chat`] — the chatml-style
//! `<|im_start|>` / `<|im_end|>` framing that Qwen3 (and many other
//! chat-tuned models) use. The prompt asks for **JSON-only** output so
//! the agent's parser doesn't have to wade through prose, and bounds the
//! suspicion field to `[0, 1]` so the model's choice composes cleanly
//! with the Phase 3 scorer.
//!
//! The renderer is deterministic — same context always produces the same
//! prompt — which makes test snapshots stable.

use crate::context::AnalysisContext;

const SYSTEM_INSTRUCTIONS: &str = r#"You are the analyst component of The Bowery, a host-based EDR.
You receive a structured incident summary and respond with a STRICT JSON object describing your assessment.

Respond with EXACTLY this JSON shape (no surrounding prose, no code fences):
{
  "suspicion": <float in [0, 1]>,
  "rationale": "<one or two sentences explaining the verdict>",
  "suggested_actions": ["<action_id>", ...],
  "whisper_query": "<short question to ask peer hosts, or empty string>"
}

Action ids you may use: "alert", "throttle_network", "quarantine_file_writes", "kill_process", "block_file", "kill_connection".
Be concise. Do not invent fields. Do not output anything other than the JSON object."#;

/// Prompt format selector. Phase 4 ships chatml; later phases may add
/// llama-3 or mistral variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PromptStyle {
    /// `<|im_start|>system\n...<|im_end|>` style. Works for Qwen3, Qwen2,
    /// many other instruct-tuned models.
    #[default]
    Qwen3Chat,
}

impl PromptStyle {
    /// Render `ctx` to a single prompt string.
    pub fn render(self, ctx: &AnalysisContext) -> String {
        match self {
            Self::Qwen3Chat => render_qwen3_chat(ctx),
        }
    }
}

fn render_qwen3_chat(ctx: &AnalysisContext) -> String {
    use std::fmt::Write as _;

    let mut prompt = String::with_capacity(2048);

    // System turn
    let _ = writeln!(
        prompt,
        "<|im_start|>system\n{SYSTEM_INSTRUCTIONS}<|im_end|>"
    );

    // User turn: the incident summary.
    let _ = writeln!(prompt, "<|im_start|>user");
    let _ = writeln!(prompt, "Host role: {}", ctx.local_role_summary);
    let _ = writeln!(prompt, "Episode id: {}", ctx.pre_verdict.episode_id);
    let _ = writeln!(
        prompt,
        "Pre-filter suspicion: {:.2}",
        ctx.pre_verdict.suspicion
    );
    let _ = writeln!(
        prompt,
        "Baseline: seen {} times before — {}",
        ctx.pre_verdict.score.baseline_seen_count, ctx.pre_verdict.score.reason
    );
    if ctx.pre_verdict.rule_hits.is_empty() {
        let _ = writeln!(prompt, "Rule hits: none");
    } else {
        let _ = writeln!(prompt, "Rule hits:");
        for hit in &ctx.pre_verdict.rule_hits {
            let _ = writeln!(
                prompt,
                "  - {} ({:?}): {}",
                hit.rule_id, hit.severity, hit.reason
            );
        }
    }
    if let Some(path) = &ctx.exe_path {
        let _ = writeln!(prompt, "Exe: {}", path.display());
    }
    if let Some(sha) = &ctx.exe_sha256_hex {
        let _ = writeln!(prompt, "Exe SHA-256: {sha}");
    }
    if !ctx.args.is_empty() {
        let _ = writeln!(prompt, "Args: {}", ctx.args.join(" "));
    }
    for (k, v) in &ctx.extra {
        let _ = writeln!(prompt, "{k}: {v}");
    }
    let _ = writeln!(prompt, "<|im_end|>");

    // Assistant turn primer — model continues from here.
    prompt.push_str("<|im_start|>assistant\n");
    prompt
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_analysis::{BinaryScore, RuleHit, RuleSeverity, Verdict};

    fn ctx() -> AnalysisContext {
        let verdict = Verdict {
            episode_id: "ep-1234-100".into(),
            suspicion: 0.92,
            score: BinaryScore {
                value: 1.0,
                baseline_seen_count: 0,
                reason: "binary never seen on this host".into(),
            },
            rule_hits: vec![RuleHit {
                rule_id: "exec_from_writable_path",
                severity: RuleSeverity::Medium,
                reason: "exec from world-writable path /tmp/ (/tmp/payload)".into(),
            }],
        };
        AnalysisContext::new(verdict)
            .with_role_summary("web-server")
            .with_args(vec!["payload".into(), "--exfil".into()])
    }

    #[test]
    fn qwen3_chat_includes_system_and_user_roles() {
        let p = PromptStyle::Qwen3Chat.render(&ctx());
        assert!(p.contains("<|im_start|>system"));
        assert!(p.contains("<|im_start|>user"));
        assert!(p.contains("<|im_start|>assistant"));
        // System block carries the JSON contract.
        assert!(p.contains("\"suspicion\""));
        assert!(p.contains("\"rationale\""));
    }

    #[test]
    fn qwen3_chat_surfaces_rule_hits_verbatim() {
        let p = PromptStyle::Qwen3Chat.render(&ctx());
        assert!(p.contains("exec_from_writable_path"));
        assert!(p.contains("/tmp/payload"));
    }

    #[test]
    fn qwen3_chat_surfaces_baseline_explanation() {
        let p = PromptStyle::Qwen3Chat.render(&ctx());
        assert!(p.contains("seen 0 times before"));
        assert!(p.contains("never seen on this host"));
    }

    #[test]
    fn qwen3_chat_is_deterministic() {
        let a = PromptStyle::Qwen3Chat.render(&ctx());
        let b = PromptStyle::Qwen3Chat.render(&ctx());
        assert_eq!(a, b);
    }
}
