//! Chat backend for the operator console — separate from the
//! agent-side [`crate::backend::LlmAnalyzer`] so the two surfaces
//! can evolve independently.
//!
//! Different from the analyzer:
//!
//! - **Multi-turn**: takes a list of [`ChatMessage`]s, returns the
//!   model's free-form reply.
//! - **No JSON contract**: the analyzer is wired to `parse_verdict`;
//!   the chat returns the raw text and lets the caller (the console
//!   `Chat` pane) decide how to interpret it.
//! - **Different prompt template family**: the agent is tuned for
//!   `Qwen3` `ChatML`; the operator chat targets Gemma's
//!   `<start_of_turn>` markers (per the Gemma 4 model card).
//!
//! The mock backend exists so the console builds without
//! `--features llm-llama-cpp`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::backend::LlmError;

/// Speaker role on a single chat turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::System,
            content: content.into(),
        }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::User,
            content: content.into(),
        }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: content.into(),
        }
    }
}

/// Backend-agnostic chat trait. Async because real backends
/// off-load to a worker thread.
#[async_trait]
pub trait Chat: Send + Sync {
    /// Run a multi-turn completion. The trailing assistant turn (if
    /// any) is the seed for what the model continues — typically you
    /// pass `[system, user, assistant, user, ...]` ending in a User
    /// turn and the model emits the next Assistant turn.
    async fn complete(&self, messages: &[ChatMessage]) -> Result<String, LlmError>;

    /// Backend identifier — e.g. `"llama-cpp/gemma-4-e2b-it"`.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Mock — always-on, no model file required.
// ---------------------------------------------------------------------------

/// A no-cost mock chat backend. Echoes the last user message and
/// pretends to be helpful. Useful for tests + when the operator
/// hasn't configured a real model.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockChat;

#[async_trait]
impl Chat for MockChat {
    async fn complete(&self, messages: &[ChatMessage]) -> Result<String, LlmError> {
        let last_user = messages
            .iter()
            .rev()
            .find(|m| m.role == ChatRole::User)
            .map_or("", |m| m.content.as_str());
        Ok(format!(
            "(mock chat — no model loaded) you said: {}\n\n\
             To get a real Gemma 4 chatbot, rebuild bowery-console with \
             `--features llm-llama-cpp` and re-launch. The binary will then \
             offer to download the GGUF on first run. See `docs/CONSOLE.md` \
             or press 8 (Help) for the full handbook.",
            last_user.lines().next().unwrap_or("")
        ))
    }

    fn name(&self) -> &'static str {
        "mock-chat"
    }
}

// ---------------------------------------------------------------------------
// Gemma 4 prompt template renderer (standalone — usable from any
// chat backend that wants Gemma chat formatting).
// ---------------------------------------------------------------------------

/// Render a list of chat messages into a Gemma 4 prompt. Per the
/// model card the template is:
///
/// ```text
/// <start_of_turn>user
/// {content}<end_of_turn>
/// <start_of_turn>model
/// {content}<end_of_turn>
/// ```
///
/// Gemma doesn't have a separate `system` role; we fold any
/// `System` messages into the first `User` turn the same way the
/// reference Transformers chat template does.
#[must_use]
pub fn render_gemma_prompt(messages: &[ChatMessage]) -> String {
    let mut out =
        String::with_capacity(messages.iter().map(|m| m.content.len() + 32).sum::<usize>() + 32);
    let mut pending_system: Option<String> = None;

    for msg in messages {
        match msg.role {
            ChatRole::System => match pending_system.as_mut() {
                Some(s) => {
                    s.push('\n');
                    s.push_str(&msg.content);
                }
                None => pending_system = Some(msg.content.clone()),
            },
            ChatRole::User => {
                out.push_str("<start_of_turn>user\n");
                if let Some(sys) = pending_system.take() {
                    out.push_str(&sys);
                    out.push_str("\n\n");
                }
                out.push_str(&msg.content);
                out.push_str("<end_of_turn>\n");
            }
            ChatRole::Assistant => {
                out.push_str("<start_of_turn>model\n");
                out.push_str(&msg.content);
                out.push_str("<end_of_turn>\n");
            }
        }
    }
    // Open a model turn for the model to continue from.
    out.push_str("<start_of_turn>model\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_basic_user_only() {
        let p = render_gemma_prompt(&[ChatMessage::user("hello")]);
        assert!(p.contains("<start_of_turn>user\nhello<end_of_turn>"));
        assert!(p.ends_with("<start_of_turn>model\n"));
    }

    #[test]
    fn render_system_folds_into_first_user() {
        let p = render_gemma_prompt(&[
            ChatMessage::system("you are bowery's helper"),
            ChatMessage::user("list ssh processes"),
        ]);
        assert!(p.contains("you are bowery's helper\n\nlist ssh processes"));
    }

    #[test]
    fn render_multi_turn() {
        let p = render_gemma_prompt(&[
            ChatMessage::user("hi"),
            ChatMessage::assistant("hello"),
            ChatMessage::user("bye"),
        ]);
        assert!(p.contains("<start_of_turn>user\nhi<end_of_turn>"));
        assert!(p.contains("<start_of_turn>model\nhello<end_of_turn>"));
        assert!(p.contains("<start_of_turn>user\nbye<end_of_turn>"));
        assert!(p.ends_with("<start_of_turn>model\n"));
    }

    #[tokio::test]
    async fn mock_chat_round_trips() {
        let chat = MockChat;
        let r = chat
            .complete(&[ChatMessage::user("hi there")])
            .await
            .unwrap();
        assert!(r.contains("hi there"));
    }
}
