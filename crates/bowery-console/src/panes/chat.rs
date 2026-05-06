//! Chat pane — natural-language interface to the SQL surface.
//!
//! The pane keeps a multi-turn conversation in memory, sends each
//! user turn through `bowery_llm::Chat`, and renders the model's
//! reply with simple SQL block detection. When the model emits a
//! ```sql … ``` block, the pane stores the most recent draft so
//! the operator can press `x` to execute it against the current
//! relay (Query pane gets the result).
//!
//! Backend selection:
//! - With `--features llm-llama-cpp` and a configured `[chat]`
//!   block on the console launch (see `--chat-model`), this pane
//!   loads Gemma 4 E2B-it via `LlamaCppChat`.
//! - Otherwise it falls back to the deterministic `MockChat` so the
//!   pane is reachable + testable without a model file.
//!
//! Privacy: prompts are kept on-host. We do NOT auto-feed
//! `bowery_alerts` / `bowery_audit` rows into the prompt — operators
//! paste what they want context on. This avoids quietly defeating
//! the embedded-LLM privacy posture.

use std::sync::Arc;

use bowery_llm::{Chat, ChatMessage};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tokio::sync::mpsc;

use crate::app::EngineEvent;
use crate::theme;

/// System prompt grounding the model in Bowery's SQL surface. Kept
/// terse — the smaller the prompt, the more headroom we have for
/// the conversation itself in the model's context window.
pub(crate) const SYSTEM_PROMPT: &str = include_str!("chat_system_prompt.txt");

#[derive(Debug, Clone)]
pub(crate) enum Turn {
    User(String),
    Assistant(String),
    Pending,
    Error(String),
}

pub(crate) struct ChatPane {
    pub(crate) turns: Vec<Turn>,
    /// Most recent fenced ```sql … ``` block extracted from the
    /// last assistant turn. `None` until the model proposes one.
    pub(crate) draft_sql: Option<String>,
    /// Box around the chat backend so we can swap mock ↔ real at
    /// startup based on whether `--features llm-llama-cpp` is on.
    pub(crate) backend: Arc<dyn Chat>,
    /// `true` while a turn is in flight; the pane rejects new
    /// submits until the previous reply lands.
    pub(crate) in_flight: bool,
}

impl std::fmt::Debug for ChatPane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatPane")
            .field("turns", &self.turns.len())
            .field("draft_sql", &self.draft_sql.is_some())
            .field("backend", &self.backend.name())
            .field("in_flight", &self.in_flight)
            .finish()
    }
}

impl ChatPane {
    pub(crate) fn new(backend: Arc<dyn Chat>) -> Self {
        Self {
            turns: Vec::new(),
            draft_sql: None,
            backend,
            in_flight: false,
        }
    }

    /// Push a user message; spawn the completion. Returns `Some`
    /// containing a status message to surface in the App's status
    /// bar (typically nothing on success, an error if rejected).
    pub(crate) fn submit(
        &mut self,
        line: &str,
        engine_tx: mpsc::Sender<EngineEvent>,
    ) -> Option<String> {
        if self.in_flight {
            return Some("chat busy — wait for the current reply".into());
        }
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        self.turns.push(Turn::User(line.to_string()));
        self.turns.push(Turn::Pending);
        self.in_flight = true;

        // Snapshot the conversation for the backend. We seed every
        // call with the system prompt — Gemma's template folds it
        // into the first user turn (see `bowery_llm::chat`).
        let mut messages = Vec::with_capacity(self.turns.len() + 1);
        messages.push(ChatMessage::system(SYSTEM_PROMPT));
        for turn in &self.turns {
            match turn {
                Turn::User(s) => messages.push(ChatMessage::user(s.clone())),
                Turn::Assistant(s) => messages.push(ChatMessage::assistant(s.clone())),
                Turn::Pending | Turn::Error(_) => {} // not part of the prompt
            }
        }

        let backend = self.backend.clone();
        tokio::spawn(async move {
            let outcome = backend.complete(&messages).await;
            let event = match outcome {
                Ok(reply) => EngineEvent::ChatReply(Ok(reply)),
                Err(e) => EngineEvent::ChatReply(Err(format!("{e}"))),
            };
            let _ = engine_tx.send(event).await;
        });
        None
    }

    pub(crate) fn on_reply(&mut self, result: Result<String, String>) {
        self.in_flight = false;
        // The trailing `Pending` placeholder gets replaced by the
        // real reply (or an error).
        let new_last = match result {
            Ok(reply) => {
                if let Some(sql) = extract_sql_block(&reply) {
                    self.draft_sql = Some(sql);
                }
                Turn::Assistant(reply)
            }
            Err(e) => Turn::Error(e),
        };
        if matches!(self.turns.last(), Some(Turn::Pending)) {
            *self.turns.last_mut().unwrap() = new_last;
        } else {
            self.turns.push(new_last);
        }
    }

    /// Take the current draft SQL (if any) for execution. Returns
    /// the SQL string and clears the draft so it isn't re-run.
    pub(crate) fn take_draft(&mut self) -> Option<String> {
        self.draft_sql.take()
    }

    pub(crate) fn render(&self, f: &mut Frame<'_>, area: Rect) {
        let title = if self.in_flight {
            format!("Chat ({} · thinking…)", self.backend.name())
        } else if self.draft_sql.is_some() {
            format!("Chat ({} · press x to run draft SQL)", self.backend.name())
        } else {
            format!("Chat ({})", self.backend.name())
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);

        let chunks = if self.draft_sql.is_some() {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(7)])
                .split(inner)
        } else {
            std::rc::Rc::from(vec![inner].into_boxed_slice())
        };

        f.render_widget(self.render_transcript(), chunks[0]);
        if self.draft_sql.is_some() && chunks.len() > 1 {
            f.render_widget(self.render_draft(), chunks[1]);
        }
    }

    fn render_transcript(&self) -> Paragraph<'static> {
        if self.turns.is_empty() {
            return Paragraph::new(
                "Ask the bot to find something on the network.\n\
                 Examples:\n  • \"list every sshd process and its parent pid\"\n  \
                 • \"which binaries did we observe in the last hour?\"\n  \
                 • \"what's in /etc/os-release?\"\n\n\
                 The model proposes SQL; press `x` to run it against the \
                 current relay (result lands in the Query pane).",
            )
            .style(theme::dim())
            .wrap(Wrap { trim: true });
        }

        let mut lines: Vec<Line<'static>> = Vec::with_capacity(self.turns.len() * 2);
        for turn in &self.turns {
            match turn {
                Turn::User(s) => {
                    lines.push(Line::from(Span::styled(
                        format!("> {s}"),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(""));
                }
                Turn::Assistant(s) => {
                    for raw in s.lines() {
                        lines.push(Line::from(raw.to_string()));
                    }
                    lines.push(Line::from(""));
                }
                Turn::Pending => {
                    lines.push(Line::from(Span::styled("  …", theme::dim())));
                    lines.push(Line::from(""));
                }
                Turn::Error(e) => {
                    lines.push(Line::from(Span::styled(
                        format!("error: {e}"),
                        theme::error(),
                    )));
                    lines.push(Line::from(""));
                }
            }
        }
        Paragraph::new(lines).wrap(Wrap { trim: false })
    }

    fn render_draft(&self) -> Paragraph<'static> {
        let sql = self
            .draft_sql
            .as_deref()
            .unwrap_or("(no draft)")
            .to_string();
        let body = vec![
            Line::from(Span::styled(
                "DRAFT SQL — press `x` to run against current relay",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(sql, Style::default().fg(Color::Green))),
        ];
        Paragraph::new(body).wrap(Wrap { trim: false })
    }
}

/// Find the first ```sql … ``` fenced block in a model reply.
/// Returns the SQL body (whitespace-trimmed) without the fence.
/// Falls back to the first ``` … ``` block of any fence type so we
/// catch models that omit the language tag.
pub(crate) fn extract_sql_block(text: &str) -> Option<String> {
    let mut chunks = text.split("```");
    // Skip the prefix before the first fence.
    let _ = chunks.next();
    while let Some(chunk) = chunks.next() {
        // chunk starts with the fence info string (e.g. "sql\n…")
        // and ends just before the closing ```.
        let body = chunk
            .strip_prefix("sql")
            .or_else(|| chunk.strip_prefix("SQL"));
        let body = if let Some(b) = body {
            b
        } else {
            // No language tag — accept the chunk as a generic
            // fenced block, but only when there's a closing fence
            // ahead so we don't grab text after the last ```.
            if chunks.clone().count() == 0 {
                return None;
            }
            chunk
        };
        let trimmed = body.trim_start_matches('\n').trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
        // Skip the next chunk — it's the text *between* fences,
        // not inside one.
        let _ = chunks.next();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sql_block_with_language_tag() {
        let r = extract_sql_block(
            "sure, run this:\n\n```sql\nSELECT pretty_name FROM os_version;\n```\n\nthat'll do it.",
        );
        assert_eq!(r.as_deref(), Some("SELECT pretty_name FROM os_version;"));
    }

    #[test]
    fn extract_sql_block_no_block() {
        assert!(extract_sql_block("no fenced sql here").is_none());
    }

    #[tokio::test]
    async fn pane_with_mock_backend_round_trips() {
        let pane = ChatPane::new(Arc::new(bowery_llm::MockChat));
        assert!(pane.turns.is_empty());
    }
}
