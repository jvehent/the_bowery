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
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row as TableRow, Table, TableState};
use time::OffsetDateTime;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use tokio::sync::mpsc;

use crate::app::{EngineEvent, Relay};
use crate::browse::Browser;
use crate::panes::{hex_lower, kv, split_hint};
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
    /// Cursor + viewport over `alerts`.
    browser: Browser,
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

    pub(crate) fn render(&mut self, f: &mut Frame<'_>, area: Rect) {
        let title = if let Some(e) = &self.last_error {
            format!("Alerts (poll error: {})", truncate(e, 40))
        } else {
            format!("Alerts ({} buffered)", self.alerts.len())
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);
        self.browser.set_len(self.alerts.len());

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
            Cell::from("conf"),
            Cell::from("susp"),
            Cell::from("episode"),
            Cell::from("exe"),
        ])
        .style(theme::header_row());

        // Header takes one line, the hint another; the rest is rows.
        let visible = self
            .browser
            .visible_range(inner.height.saturating_sub(2) as usize);
        let rows: Vec<TableRow> = self.alerts[visible]
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
                let row = TableRow::new([
                    Cell::from(ts),
                    Cell::from(truncate(&agent, 16)),
                    Cell::from(confirmation_badge(a.confirmation.as_ref())),
                    Cell::from(sus),
                    Cell::from(truncate(&ep, 16)),
                    Cell::from(truncate(&exe, 60)),
                ]);
                if a.confirmation.is_some_and(|c| c.confirmed) {
                    row.style(theme::confirmed_alert())
                } else {
                    row
                }
            })
            .collect();

        let widths = [
            Constraint::Length(25),
            Constraint::Length(17),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Length(18),
            Constraint::Min(20),
        ];
        // Reserve the last line for the key legend so the operator can
        // discover drill-down without reading the handbook.
        let (list_area, hint_area) = split_hint(inner);
        let table = Table::new(rows, widths)
            .header(header)
            .row_highlight_style(theme::selected_row())
            .highlight_symbol("▸ ");
        let mut state = TableState::default().with_selected(self.browser.selected_in_view());
        f.render_stateful_widget(table, list_area, &mut state);
        f.render_widget(
            Paragraph::new("↑↓ move  ⏎ detail  r refresh").style(theme::hint()),
            hint_area,
        );
    }

    /// Full-screen detail for the selected alert.
    ///
    /// The table can only show five truncated columns; every `Alert`
    /// field is already in memory, so this is pure rendering — no
    /// refetch, and it works even if the agent is now unreachable.
    pub(crate) fn render_detail(&mut self, f: &mut Frame<'_>, area: Rect) {
        // Sync the cursor bound here too: the overlay must not depend on
        // the list having been rendered first, and the poller can change
        // the list length while the overlay is open.
        self.browser.set_len(self.alerts.len());
        let Some(alert) = self.selected_alert() else {
            return;
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Alert detail — Esc back");
        let inner = block.inner(area);
        f.render_widget(block, area);

        let fp_hex = hex_lower(&alert.originator_fp);
        let agent = self.agent_label(&alert.originator_fp);
        let mut lines: Vec<Line<'static>> = vec![
            kv("time", format_ts_utc(alert.ts_unix_ms)),
            kv("agent", format!("{agent}  ({fp_hex})")),
            kv("suspicion", format!("{:.2}", alert.suspicion)),
            kv("episode", alert.episode_id.clone()),
            kv("backend", alert.backend.clone()),
            kv("exe path", alert.exe_path.clone()),
            kv("exe sha256", alert.exe_sha256_hex.clone()),
        ];
        if !alert.suggested_actions.is_empty() {
            lines.push(kv("suggested", alert.suggested_actions.join(", ")));
        }
        // Command line, ancestry, cwd, open handles. This is what turns
        // "a rare binary ran" into something judgeable without leaving
        // the console.
        if !alert.context.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("context", theme::detail_label())));
            for attr in &alert.context {
                lines.push(kv(&format!("  {}", attr.key), attr.value.clone()));
            }
        }
        if let Some(c) = alert.confirmation {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                if c.confirmed {
                    "neighbourhood: CONFIRMED"
                } else {
                    "neighbourhood: not confirmed"
                },
                if c.confirmed {
                    theme::confirmed_alert()
                } else {
                    theme::detail_label()
                },
            )));
            // Every bucket, not a summary. Peers with no record of the
            // observation are what confirms (it's anomalous here);
            // peers that have one argue it's ordinary. Refusals and
            // silence are shown separately and count toward neither —
            // collapsing them would make an unreachable neighbourhood
            // look like agreement.
            lines.push(kv(
                "  no record",
                format!("{} (quorum {})", c.peers_unseen, c.quorum),
            ));
            // "recorded", not "has record": `kv` pads the label to 12
            // columns, and a 12-char label leaves no gap before the
            // value ("has record1").
            lines.push(kv("  recorded", c.peers_seen.to_string()));
            if c.peers_refused > 0 {
                lines.push(kv("  declined", c.peers_refused.to_string()));
            }
            lines.push(kv("  no reply", c.peers_no_reply.to_string()));
            lines.push(kv("  asked", c.peers_asked.to_string()));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("rationale", theme::detail_label())));
        // Unwrapped and untruncated — the rationale is the analyst's
        // primary evidence and the table only ever showed it as a
        // fallback when exe_path happened to be empty.
        for chunk in alert.rationale.lines() {
            lines.push(Line::from(format!("  {chunk}")));
        }
        lines.push(Line::from(""));
        // Only advertise pivots that will actually fire: a file alert
        // has no sha256, a process alert may have no path, and a hint
        // for a key that does nothing is worse than no hint.
        let mut pivots = vec!["a audit for episode"];
        if !alert.exe_sha256_hex.is_empty() {
            pivots.push("b baseline for sha256");
        }
        if !alert.exe_path.is_empty() {
            pivots.push("p processes by path");
            pivots.push("f file on disk");
        }
        lines.push(Line::from(Span::styled(
            format!("pivots:  {}", pivots.join("   ")),
            theme::hint(),
        )));

        f.render_widget(
            Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }),
            inner,
        );
    }

    /// The alert under the cursor, if any.
    pub(crate) fn selected_alert(&self) -> Option<&Alert> {
        self.browser.selected().and_then(|i| self.alerts.get(i))
    }

    pub(crate) fn browser_mut(&mut self) -> &mut Browser {
        &mut self.browser
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
        // Dedup by episode_id: an episode can produce several alerts —
        // the initial one, an LLM-refined one, and a quorum-confirmed
        // one — and the later ones supersede rather than accompany the
        // first. Without this the same finding renders two or three
        // times, which is exactly the noise an operator doesn't need.
        //
        // Batches arrive oldest-first, so a later entry always supersedes
        // an earlier one for the same episode. Collapse within the batch
        // first: a single batch routinely carries both the original and
        // its superseding alert, and prepending them one at a time would
        // let the *older* one land on top.
        //
        // An empty episode_id is not an identity — those never dedup,
        // or every one of them would collapse into a single row.
        let mut batch: Vec<Alert> = Vec::with_capacity(items.len());
        for a in items {
            match batch
                .iter_mut()
                .find(|e| !a.episode_id.is_empty() && e.episode_id == a.episode_id)
            {
                Some(slot) => *slot = a,
                None => batch.push(a),
            }
        }
        // Newest at the top; slide the window.
        for a in batch.into_iter().rev() {
            if !a.episode_id.is_empty() {
                self.alerts.retain(|e| e.episode_id != a.episode_id);
            }
            self.alerts.insert(0, a);
        }
        if self.alerts.len() > MAX_ALERTS {
            self.alerts.truncate(MAX_ALERTS);
        }
        self.browser.set_len(self.alerts.len());
    }

    pub(crate) fn on_error(&mut self, message: String) {
        self.last_error = Some(message);
    }
}

/// Compact confirmation badge for the list column.
///
/// Blank when no whisper round ran, so the column reads as "nothing to
/// say" rather than implying a negative result.
fn confirmation_badge(c: Option<&bowery_proto::AlertConfirmation>) -> String {
    match c {
        None => String::new(),
        Some(c) if c.confirmed => format!("✓{}/{}", c.peers_unseen, c.peers_asked),
        Some(c) => format!(" {}/{}", c.peers_unseen, c.peers_asked),
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

#[cfg(test)]
mod render_tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn sample(n: usize) -> Vec<Alert> {
        (0..n)
            .map(|i| Alert {
                originator_fp: vec![0xaa; 32],
                episode_id: format!("ep-{i}"),
                exe_sha256_hex: "ab".repeat(32),
                exe_path: format!("/tmp/payload-{i}"),
                suspicion: 0.9,
                rationale: "exec from world-writable path /tmp/".into(),
                suggested_actions: vec!["kill_process".into()],
                ts_unix_ms: 1_786_622_341_123 + i as u64,
                backend: "llama-cpp/qwen3-0.6b".into(),
                confirmation: None,
                context: Vec::new(),
            })
            .collect()
    }

    fn confirmed(ep: &str, unseen: u32, asked: u32, confirmed: bool) -> Alert {
        Alert {
            episode_id: ep.into(),
            confirmation: Some(bowery_proto::AlertConfirmation {
                peers_asked: asked,
                peers_unseen: unseen,
                peers_seen: asked - unseen,
                peers_no_reply: 0,
                peers_refused: 0,
                quorum: 2,
                confirmed,
            }),
            ..sample(1).remove(0)
        }
    }

    fn draw(pane: &mut AlertsPane, detail: bool) -> String {
        let mut term = Terminal::new(TestBackend::new(100, 20)).unwrap();
        term.draw(|f| {
            if detail {
                pane.render_detail(f, f.area());
            } else {
                pane.render(f, f.area());
            }
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>()
    }

    #[test]
    fn list_renders_and_tracks_selection_beyond_the_viewport() {
        let mut pane = AlertsPane {
            alerts: sample(200),
            ..AlertsPane::default()
        };

        let first = draw(&mut pane, false);
        assert!(first.contains("ep-0"), "first page shows the top row");

        // Jump to the end: the viewport must follow, which is exactly
        // what was impossible before (only page one was reachable).
        pane.browser_mut().end();
        let last = draw(&mut pane, false);
        assert!(
            last.contains("ep-199"),
            "end of a 200-row list is reachable"
        );
        assert!(
            !last.contains("ep-0 "),
            "viewport scrolled off the first row"
        );
    }

    #[test]
    fn detail_shows_fields_the_table_cannot() {
        let mut pane = AlertsPane {
            alerts: sample(1),
            ..AlertsPane::default()
        };
        pane.browser_mut().home();

        let out = draw(&mut pane, true);
        // These three are absent from the table entirely.
        assert!(out.contains("llama-cpp"), "backend missing: {out}");
        assert!(out.contains("kill_process"), "suggested actions missing");
        assert!(out.contains(&"ab".repeat(8)), "exe sha256 missing");
        // Rationale is only a fallback in the table; here it's always shown.
        assert!(out.contains("world-writable"), "rationale missing");
    }

    #[test]
    fn superseding_alert_replaces_its_episode_instead_of_duplicating() {
        let mut pane = AlertsPane::default();
        // The original and its confirmation arrive in one drained batch,
        // oldest first — the case that made the naive prepend keep the
        // *older* row.
        pane.on_batch(vec![sample(1).remove(0), confirmed("ep-0", 4, 5, true)], 1);
        assert_eq!(pane.alerts.len(), 1, "one episode must be one row");
        assert!(
            pane.alerts[0].confirmation.is_some(),
            "the superseding alert must win, not the original"
        );

        // ... and again when they arrive in separate polls.
        let mut pane = AlertsPane::default();
        pane.on_batch(vec![sample(1).remove(0)], 1);
        pane.on_batch(vec![confirmed("ep-0", 4, 5, true)], 2);
        assert_eq!(pane.alerts.len(), 1);
        assert!(pane.alerts[0].confirmation.is_some());
    }

    #[test]
    fn empty_episode_ids_never_collapse_together() {
        let mut pane = AlertsPane::default();
        let mut a = sample(1).remove(0);
        let mut b = sample(1).remove(0);
        a.episode_id = String::new();
        b.episode_id = String::new();
        pane.on_batch(vec![a, b], 1);
        assert_eq!(
            pane.alerts.len(),
            2,
            "an empty episode_id is not an identity"
        );
    }

    #[test]
    fn confirmation_is_visible_in_both_list_and_detail() {
        let mut pane = AlertsPane {
            alerts: vec![confirmed("ep-0", 4, 5, true)],
            ..AlertsPane::default()
        };
        let list = draw(&mut pane, false);
        assert!(list.contains("✓4/5"), "confirmed badge missing: {list}");

        pane.browser_mut().home();
        let detail = draw(&mut pane, true);
        assert!(detail.contains("CONFIRMED"), "verdict missing: {detail}");
        // Both counts, with their gutter intact. `kv` pads labels into
        // 12 columns, so a 12-character label runs straight into its
        // value ("has record1") — asserting on the spacing is what
        // catches that.
        assert!(
            detail.contains("no record 4 (quorum 2)"),
            "denial count missing: {detail}"
        );
        assert!(
            detail.contains("recorded  1"),
            "corroboration count missing: {detail}"
        );

        // Not-confirmed must not wear a checkmark — the badge is the
        // whole signal an operator scans for.
        let mut pane = AlertsPane {
            alerts: vec![confirmed("ep-0", 1, 5, false)],
            ..AlertsPane::default()
        };
        let list = draw(&mut pane, false);
        assert!(!list.contains("✓"), "unconfirmed row wears a check: {list}");
    }

    #[test]
    fn detail_on_empty_list_is_a_noop() {
        let mut pane = AlertsPane::default();
        // Must not panic when nothing is selected.
        let _ = draw(&mut pane, true);
    }
}
