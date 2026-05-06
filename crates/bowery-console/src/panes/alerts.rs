//! Live alerts pane — long-polls the agent's operator inbox via
//! `bowery_cli::alerts::poll_once` on a 5-second cadence and
//! displays the newest entries on top.
//!
//! Sliding window: we keep the most recent `MAX_ALERTS` so a long
//! operator session doesn't grow unbounded.

use std::time::Duration;

use bowery_cli::alerts;
use bowery_proto::Alert;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::widgets::{Block, Borders, Cell, Row as TableRow, Table};
use tokio::sync::mpsc;

use crate::app::{EngineEvent, Relay};
use crate::theme;

const MAX_ALERTS: usize = 500;
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
pub(crate) struct AlertsPane {
    pub(crate) alerts: Vec<Alert>,
    pub(crate) cursor_unix_ms: u64,
    pub(crate) poller_started: bool,
    pub(crate) last_error: Option<String>,
}

impl AlertsPane {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn render(&self, f: &mut Frame<'_>, area: Rect) {
        let title = if let Some(e) = &self.last_error {
            format!("Alerts (poll error: {})", truncate(e, 40))
        } else {
            format!("Alerts ({} buffered)", self.alerts.len())
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);

        if self.alerts.is_empty() {
            let body = if self.poller_started {
                "waiting for alerts… (polling every 5s)"
            } else {
                "press 2 to switch to this pane and start the poller"
            };
            f.render_widget(
                ratatui::widgets::Paragraph::new(body).style(theme::dim()),
                inner,
            );
            return;
        }

        let header = TableRow::new([
            Cell::from("ts"),
            Cell::from("susp"),
            Cell::from("episode"),
            Cell::from("exe"),
        ])
        .style(theme::header_row());

        let rows: Vec<TableRow> = self
            .alerts
            .iter()
            .map(|a| {
                let ts = format!("{}", a.ts_unix_ms);
                let sus = format!("{:.2}", a.suspicion);
                let ep = a.episode_id.clone();
                let exe = if a.exe_path.is_empty() {
                    a.rationale.clone()
                } else {
                    a.exe_path.clone()
                };
                TableRow::new([
                    Cell::from(ts),
                    Cell::from(sus),
                    Cell::from(truncate(&ep, 16)),
                    Cell::from(truncate(&exe, 60)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(13),
            Constraint::Length(6),
            Constraint::Length(18),
            Constraint::Min(20),
        ];
        let table = Table::new(rows, widths).header(header);
        f.render_widget(table, inner);
    }

    /// Spawn the polling task on first activation. Subsequent calls
    /// no-op — the task drains until the channel closes.
    pub(crate) fn ensure_poller(
        &mut self,
        relay: Relay,
        operator_key: std::path::PathBuf,
        engine_tx: mpsc::Sender<EngineEvent>,
    ) {
        if self.poller_started {
            return;
        }
        self.poller_started = true;
        let mut cursor = self.cursor_unix_ms;
        tokio::spawn(async move {
            loop {
                let outcome = alerts::poll_once(
                    &operator_key,
                    relay.addr,
                    &relay.fp_hex,
                    &relay.pubkey_b64,
                    cursor,
                )
                .await;
                let event = match outcome {
                    Ok((items, next)) => {
                        cursor = next;
                        EngineEvent::AlertsBatch {
                            items,
                            cursor_unix_ms: next,
                        }
                    }
                    Err(e) => EngineEvent::AlertsError(format!("{e:#}")),
                };
                if engine_tx.send(event).await.is_err() {
                    break;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        });
    }

    pub(crate) fn on_batch(&mut self, items: Vec<Alert>, cursor_unix_ms: u64) {
        self.last_error = None;
        if cursor_unix_ms > self.cursor_unix_ms {
            self.cursor_unix_ms = cursor_unix_ms;
        }
        // Newest at the top; slide the window.
        for a in items.into_iter().rev() {
            self.alerts.insert(0, a);
        }
        if self.alerts.len() > MAX_ALERTS {
            self.alerts.truncate(MAX_ALERTS);
        }
    }

    pub(crate) fn on_error(&mut self, message: String) {
        self.last_error = Some(message);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut iter = s.chars();
        let head: String = iter.by_ref().take(max - 1).collect();
        format!("{head}…")
    }
}
