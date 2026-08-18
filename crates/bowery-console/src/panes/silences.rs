//! Silences pane — what this fleet has been told not to report.
//!
//! Reads `bowery_silences`, and exists for the same reason that view
//! does: silencing is the only feature here whose effect is absence, and
//! absence is what this project refuses to leave unexplained. Without
//! somewhere to see "this pattern has swallowed 40,000 alerts", a muted
//! fleet and a quiet one look identical.
//!
//! Ordered by `matched` descending, so the silence doing the most work
//! is the first thing an operator sees. A large count is either the
//! feature working or a pattern far wider than its author meant, and
//! only a human can tell — but only if the number is in front of them.
//!
//! Snapshotted on activation; `r` refreshes.

use std::time::Duration;

use bowery_cli::exec::{self, CollectSink};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};
use tokio::sync::mpsc;

use crate::app::{EngineEvent, Relay};
use crate::browse::Browser;
use crate::theme;

const SNAPSHOT_SQL: &str = "SELECT id, rule_id, weight, matched, expires_unix_ms, reason \
                            FROM bowery_silences ORDER BY matched DESC LIMIT 200";

#[derive(Debug, Default)]
pub(crate) struct SilencesPane {
    pub(crate) snapshot: Option<CollectSink>,
    /// Cursor + viewport over `snapshot.rows`.
    browser: Browser,
    pub(crate) loading: bool,
    pub(crate) error: Option<String>,
    pub(crate) loaded_once: bool,
}

impl SilencesPane {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn ensure_loaded(
        &mut self,
        relay: Relay,
        operator_key: std::path::PathBuf,
        engine_tx: mpsc::Sender<EngineEvent>,
    ) {
        if self.loaded_once || self.loading {
            return;
        }
        self.refresh(relay, operator_key, engine_tx);
    }

    pub(crate) fn refresh(
        &mut self,
        relay: Relay,
        operator_key: std::path::PathBuf,
        engine_tx: mpsc::Sender<EngineEvent>,
    ) {
        self.loading = true;
        self.error = None;
        let sql = SNAPSHOT_SQL.to_string();
        tokio::spawn(async move {
            let mut sink = CollectSink::default();
            let outcome = exec::sql(
                operator_key,
                relay.addr,
                relay.fp_hex.clone(),
                relay.pubkey_b64.clone(),
                Vec::new(),
                sql,
                Duration::from_secs(10),
                false,
                false, // console renders its own view: no stderr trace
                &mut sink,
            )
            .await;
            let event = match outcome {
                Ok(()) => EngineEvent::SilencesDone { result: Ok(sink) },
                Err(e) => EngineEvent::SilencesDone {
                    result: Err(format!("{e:#}")),
                },
            };
            let _ = engine_tx.send(event).await;
        });
    }

    /// Full-screen detail for the selected audit entry.
    pub(crate) fn render_detail(&mut self, f: &mut Frame<'_>, area: Rect) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        crate::panes::render_sink_detail(f, area, snapshot, &mut self.browser, "Silence", "");
    }

    pub(crate) fn browser_mut(&mut self) -> &mut Browser {
        &mut self.browser
    }

    pub(crate) fn has_rows(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|s| !s.rows.is_empty())
    }

    pub(crate) fn on_done(&mut self, result: Result<CollectSink, String>) {
        self.loading = false;
        self.loaded_once = true;
        match result {
            Ok(sink) => {
                self.snapshot = Some(sink);
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }

    pub(crate) fn render(&mut self, f: &mut Frame<'_>, area: Rect) {
        let title = match (&self.error, &self.snapshot) {
            (Some(_), _) => "Silences (error — press r to retry)".to_string(),
            (None, Some(s)) => format!("Silences ({} in force · r refreshes)", s.rows.len()),
            (None, None) => "Silences (loading…)".to_string(),
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);

        if let Some(e) = &self.error {
            f.render_widget(Paragraph::new(e.clone()).style(theme::error()), inner);
            return;
        }
        let Some(snapshot) = &self.snapshot else {
            f.render_widget(
                Paragraph::new("press 9 to load / r to refresh").style(theme::dim()),
                inner,
            );
            return;
        };
        if snapshot.rows.is_empty() {
            f.render_widget(
                Paragraph::new("nothing is being suppressed on this fleet").style(theme::dim()),
                inner,
            );
            return;
        }

        crate::panes::render_sink_table(
            f,
            inner,
            snapshot,
            &mut self.browser,
            "↑↓ move  ⏎ entry detail  r refresh",
        );
    }
}
