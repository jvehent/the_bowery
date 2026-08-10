//! Live alerts pane — long-polls the agent's operator inbox via
//! `bowery_cli::alerts::poll_once` on a 5-second cadence and
//! displays the newest entries on top.
//!
//! Sliding window: we keep the most recent `MAX_ALERTS` so a long
//! operator session doesn't grow unbounded.

use std::collections::HashMap;
use std::time::Duration;

use bowery_cli::alerts;
use bowery_proto::Alert;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::widgets::{Block, Borders, Cell, Row as TableRow, Table};
use time::OffsetDateTime;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use tokio::sync::mpsc;

use crate::app::{EngineEvent, Relay};
use crate::theme;

const MAX_ALERTS: usize = 500;
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// RFC3339 in UTC with millisecond precision. Spelled out rather than
/// using the `Rfc3339` well-known format so the rendered width is fixed
/// (24 chars) — `Rfc3339` emits a variable number of subsecond digits,
/// which would make the column jitter. Milliseconds are kept because
/// alerts arrive in bursts (a fan-out scan or a file-watch storm can put
/// several in the same second).
const TS_FORMAT: &[BorrowedFormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

#[derive(Debug, Default)]
pub(crate) struct AlertsPane {
    pub(crate) alerts: Vec<Alert>,
    pub(crate) cursor_unix_ms: u64,
    pub(crate) poller_started: bool,
    pub(crate) last_error: Option<String>,
    /// fingerprint-hex → operator-assigned name, from
    /// `~/.bowery/peers.toml`. Lets the pane show "web-1" instead of a
    /// 64-hex fingerprint for the agent that raised each alert.
    agent_names: HashMap<String, String>,
}

impl AlertsPane {
    pub(crate) fn new() -> Self {
        let mut pane = Self::default();
        pane.reload_agent_names();
        pane
    }

    /// (Re)load the fingerprint → name map from the operator's peer
    /// manifest. Cheap, and picks up `:peers add` without a restart.
    pub(crate) fn reload_agent_names(&mut self) {
        let Ok(path) = bowery_cli::peers::default_path() else {
            return;
        };
        let Ok(manifest) = bowery_cli::peers::Manifest::load(&path) else {
            return;
        };
        self.agent_names = manifest
            .peers
            .into_iter()
            .map(|p| (p.fp.to_ascii_lowercase(), p.name))
            .collect();
    }

    /// Human label for the agent that raised an alert: its
    /// operator-assigned name when the manifest knows the fingerprint,
    /// otherwise a short fingerprint so the row is still attributable.
    fn agent_label(&self, originator_fp: &[u8]) -> String {
        if originator_fp.is_empty() {
            return "-".to_string();
        }
        let hex = hex_lower(originator_fp);
        self.agent_names
            .get(&hex)
            .cloned()
            .unwrap_or_else(|| truncate(&hex, 12))
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
            Cell::from("time (UTC)"),
            Cell::from("agent"),
            Cell::from("susp"),
            Cell::from("episode"),
            Cell::from("exe"),
        ])
        .style(theme::header_row());

        let rows: Vec<TableRow> = self
            .alerts
            .iter()
            .map(|a| {
                let ts = format_ts_utc(a.ts_unix_ms);
                let agent = self.agent_label(&a.originator_fp);
                let sus = format!("{:.2}", a.suspicion);
                let ep = a.episode_id.clone();
                let exe = if a.exe_path.is_empty() {
                    a.rationale.clone()
                } else {
                    a.exe_path.clone()
                };
                TableRow::new([
                    Cell::from(ts),
                    Cell::from(truncate(&agent, 16)),
                    Cell::from(sus),
                    Cell::from(truncate(&ep, 16)),
                    Cell::from(truncate(&exe, 60)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(25),
            Constraint::Length(17),
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

/// Render a unix-millisecond timestamp as RFC3339 in UTC.
///
/// Falls back to the raw number if the value can't be represented as a
/// date (a corrupt or absurd timestamp shouldn't blank the column — the
/// operator should still see something is wrong).
fn format_ts_utc(ts_unix_ms: u64) -> String {
    let nanos = i128::from(ts_unix_ms) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|dt| dt.format(&TS_FORMAT).ok())
        .unwrap_or_else(|| ts_unix_ms.to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_timestamp_as_utc_rfc3339() {
        // Verified against an independent implementation:
        // 1786622341123 ms == 2026-08-13T11:59:01.123Z
        let ms = 1_786_622_341_123;
        let s = format_ts_utc(ms);
        assert!(s.ends_with('Z'), "must be UTC-suffixed, got {s}");
        assert_eq!(s.len(), 24, "fixed width keeps the column steady: {s}");
        assert_eq!(s, "2026-08-13T11:59:01.123Z", "got {s}");
        // Round-trips as a real RFC3339 instant.
        assert!(
            OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339).is_ok(),
            "not valid RFC3339: {s}"
        );
    }

    #[test]
    fn absurd_timestamp_falls_back_to_the_raw_value() {
        // Far past what a date can represent — must not panic or blank.
        let s = format_ts_utc(u64::MAX);
        assert_eq!(s, u64::MAX.to_string());
    }

    #[test]
    fn agent_label_prefers_the_manifest_name() {
        let mut pane = AlertsPane::default();
        pane.agent_names
            .insert("aa".repeat(32), "web-1".to_string());

        // Known fingerprint → operator-assigned name.
        assert_eq!(pane.agent_label(&[0xaa_u8; 32]), "web-1");
        // Unknown → short fingerprint, still attributable.
        let unknown = pane.agent_label(&[0xbb_u8; 32]);
        assert!(unknown.starts_with("bbbb"), "got {unknown}");
        assert!(unknown.chars().count() <= 12, "got {unknown}");
        // Missing originator → placeholder rather than an empty cell.
        assert_eq!(pane.agent_label(&[]), "-");
    }
}
