//! Alerts pane — the fleet's alert history, searchable.
//!
//! # Why this reads from an archive and not from the agents
//!
//! An agent's inbox is a bounded in-memory ring with a 72-hour TTL that
//! dies with the process, so "show me last week" was not a feature that
//! had been left out — the data did not exist to show. Worse, the pane
//! polled only the *currently connected* relay, so seeing another
//! host's alerts meant `:connect`-ing away from this one.
//!
//! The poller now drains **every agent in the peer manifest** and writes
//! what it gets to the operator-side archive
//! (`bowery_cli::archive`); the pane renders a query against that. The
//! consequences that matter:
//!
//! - History outlives the agent, so a host that restarts — or is
//!   restarted by whoever just rooted it — no longer takes the record of
//!   its own alerts with it.
//! - Every host is in one list, sorted by time, without reconnecting.
//! - What is on screen is a *filter*, so searching is the same
//!   mechanism as browsing rather than a separate mode.
//!
//! `bowery notify` writes to the same archive on its timer, so the
//! console shows alerts that arrived while it was closed.

use std::collections::HashMap;
use std::time::Duration;

use std::path::PathBuf;

use bowery_cli::alerts;
use bowery_cli::archive::{Archive, Filter};
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

/// Rows held in memory for rendering. The archive holds everything;
/// this only bounds what one screenful of scrollback can reach, and a
/// tighter filter is the way to see past it.
const MAX_ALERTS: usize = 2000;
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
    pub(crate) poller_started: bool,
    pub(crate) last_error: Option<String>,
    /// fingerprint-hex → operator-assigned name, from
    /// `~/.bowery/peers.toml`. Lets the pane show "web-1" instead of a
    /// 64-hex fingerprint for the agent that raised each alert.
    agent_names: HashMap<String, String>,
    /// Cursor + viewport over `alerts`.
    browser: Browser,
    /// Read handle on the archive. `None` when it could not be opened —
    /// the pane degrades to whatever the poller reports rather than
    /// showing nothing.
    archive: Option<Archive>,
    archive_path: Option<PathBuf>,
    /// The live query. Editing it is how an operator searches.
    filter: Filter,
    /// What the operator typed, kept for display.
    filter_text: String,
    /// Total archived rows, so the pane can say "12 of 4,318" instead
    /// of implying the filtered set is everything there is.
    total_rows: u64,
}

impl AlertsPane {
    pub(crate) fn new() -> Self {
        let mut pane = Self::default();
        pane.reload_agent_names();
        pane.filter.limit = MAX_ALERTS;
        pane.open_archive();
        pane.refresh_from_archive();
        pane
    }

    /// Build a pane over a supplied archive. Tests only — the real
    /// constructor opens `~/.bowery/alerts.db`, and a test that reached
    /// for the operator's own archive would both pollute it and depend
    /// on its contents.
    #[cfg(test)]
    pub(crate) fn with_archive(archive: Archive) -> Self {
        let mut pane = Self {
            archive: Some(archive),
            ..Self::default()
        };
        pane.filter.limit = MAX_ALERTS;
        pane.refresh_from_archive();
        pane
    }

    /// Open the archive read handle, remembering why if it fails.
    ///
    /// A missing archive is not an error state: on a fresh install
    /// nothing has polled yet. It becomes visible in the pane title as
    /// "0 archived" rather than as a failure, because the distinction
    /// between "nothing happened" and "nothing is recording" is one the
    /// operator has to be able to make.
    fn open_archive(&mut self) {
        let Ok(path) = bowery_cli::archive::default_path() else {
            return;
        };
        match Archive::open(&path) {
            Ok(a) => {
                self.archive = Some(a);
                self.archive_path = Some(path);
            }
            Err(e) => {
                self.last_error = Some(format!("archive: {e:#}"));
            }
        }
    }

    /// Re-run the current filter against the archive.
    ///
    /// Cheap enough to call on every poll tick: the archive is indexed
    /// on `ts_unix_ms` and the query is capped at `MAX_ALERTS`.
    pub(crate) fn refresh_from_archive(&mut self) {
        let Some(archive) = &self.archive else {
            return;
        };
        match archive.query(&self.filter) {
            Ok(rows) => {
                self.alerts = rows
                    .iter()
                    .map(bowery_cli::archive::Row::to_alert)
                    .collect();
                self.total_rows = archive.stats().map_or(0, |s| s.rows);
                self.browser.set_len(self.alerts.len());
            }
            Err(e) => self.last_error = Some(format!("archive query: {e:#}")),
        }
    }

    /// Apply a search string typed at the prompt.
    ///
    /// Bare words are a substring search across path, rationale, rule,
    /// episode and context. `key:value` terms narrow structurally, so
    /// the common questions — one host, one rule, only confirmed, only
    /// serious — do not require remembering a query language.
    ///
    /// Returns a line describing what is now in force, for the status
    /// bar: a filter that silently drops rows is how an operator comes
    /// to believe a quiet fleet.
    pub(crate) fn set_filter(&mut self, text: &str) -> String {
        self.filter_text = text.trim().to_string();
        let mut filter = Filter {
            limit: MAX_ALERTS,
            ..Filter::default()
        };
        let mut words: Vec<&str> = Vec::new();
        for token in self.filter_text.split_whitespace() {
            match token.split_once(':') {
                Some(("agent" | "host", v)) => filter.agent = Some(v.to_string()),
                Some(("rule", v)) => filter.rule_id = Some(v.to_string()),
                Some(("min", v)) => filter.min_suspicion = v.parse().ok(),
                Some(("since", v)) => {
                    filter.since_unix_ms = parse_since(v);
                }
                Some(("confirmed", v)) => filter.confirmed_only = matches!(v, "1" | "true" | "yes"),
                Some(("all", v)) => filter.all_versions = matches!(v, "1" | "true" | "yes"),
                _ => words.push(token),
            }
        }
        if !words.is_empty() {
            filter.text = Some(words.join(" "));
        }
        self.filter = filter;
        self.browser.home();
        self.refresh_from_archive();
        if self.filter_text.is_empty() {
            format!("filter cleared — {} alert(s)", self.alerts.len())
        } else {
            format!(
                "filter {:?} — {} of {} archived",
                self.filter_text,
                self.alerts.len(),
                self.total_rows
            )
        }
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
        } else if self.filter_text.is_empty() {
            format!("Alerts ({} archived)", self.total_rows)
        } else {
            // Always the pair, never the filtered count alone. "12
            // alerts" reads as the whole story; "12 of 4318" is the
            // only version that tells an operator a filter is hiding
            // things from them.
            format!(
                "Alerts ({} of {} — filter: {})",
                self.alerts.len(),
                self.total_rows,
                truncate(&self.filter_text, 40)
            )
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);
        self.browser.set_len(self.alerts.len());

        if self.alerts.is_empty() {
            f.render_widget(
                ratatui::widgets::Paragraph::new(self.empty_state())
                    .style(theme::dim())
                    .wrap(ratatui::widgets::Wrap { trim: false }),
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
            Paragraph::new(
                "↑↓ move  ⏎ detail  s silence  r refresh  \
                 type to search (agent: rule: min: since: confirmed:1 all:1, ':' clears)",
            )
            .style(theme::hint()),
            hint_area,
        );
    }

    /// What to say when there is nothing to list.
    ///
    /// Three different emptinesses, deliberately worded apart:
    /// over-filtered, archived-but-not-loaded, and genuinely nothing
    /// recorded. Collapsing them into "no alerts" is how an operator
    /// concludes a fleet is quiet when it is unmonitored — the failure
    /// this whole system exists to avoid.
    fn empty_state(&self) -> String {
        if !self.filter_text.is_empty() {
            return format!(
                "no alert matches {:?}.\n\n{} alert(s) are archived — submit an empty \
                 filter (just ':') to see them all.",
                self.filter_text, self.total_rows
            );
        }
        if self.total_rows > 0 {
            return format!(
                "{} archived, none loaded — press r to refresh.",
                self.total_rows
            );
        }
        if self.poller_started {
            return "no alerts archived yet.\n\nPolling every agent in ~/.bowery/peers.toml \
                    every 5s. An empty archive means nothing has been reported since this \
                    console or `bowery notify` last ran — not that nothing happened."
                .to_string();
        }
        "press 2 to switch to this pane and start the poller".to_string()
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
    ///
    /// Polls **every** agent in the peer manifest, not the connected
    /// relay. The relay is where operator *commands* go; alerts are
    /// something every agent has, and tying the alert view to the
    /// current connection meant an operator investigating one host was
    /// blind to the rest of the fleet for as long as they looked.
    pub(crate) fn ensure_poller(
        &mut self,
        _relay: Relay,
        operator_key: std::path::PathBuf,
        engine_tx: mpsc::Sender<EngineEvent>,
    ) {
        if self.poller_started {
            return;
        }
        self.poller_started = true;
        let archive_path = self.archive_path.clone();
        tokio::spawn(async move {
            // The poller owns its own archive handle. SQLite is in WAL
            // mode, so this writer and the pane's reader coexist; a
            // shared connection would have to be held across await
            // points instead.
            let mut archive = archive_path.as_ref().and_then(|p| Archive::open(p).ok());
            // Per-agent cursors, seeded from what is already archived so
            // a reopened console does not refetch a whole retention
            // window on every start.
            let mut cursors: HashMap<String, u64> = HashMap::new();

            loop {
                let peers = load_peers();
                let mut stored = 0usize;
                let mut errors: Vec<String> = Vec::new();

                for peer in &peers {
                    let Some(addr) = peer.addr.as_deref().and_then(|a| a.parse().ok()) else {
                        continue; // fan-out-only entry, nothing to dial
                    };
                    let fp_key = peer.fp.to_ascii_lowercase();
                    let since = match cursors.get(&fp_key) {
                        Some(c) => *c,
                        None => archive
                            .as_ref()
                            .and_then(|a| a.cursor_for(&fp_key).ok())
                            .unwrap_or(0),
                    };
                    match alerts::poll_once(&operator_key, addr, &peer.fp, &peer.pubkey_b64, since)
                        .await
                    {
                        Ok((items, next)) => {
                            cursors.insert(fp_key, next);
                            if let Some(a) = archive.as_mut() {
                                match a.record(&items, Some(&peer.name)) {
                                    Ok(n) => stored += n,
                                    Err(e) => errors.push(format!("{}: archive {e}", peer.name)),
                                }
                            }
                        }
                        // One unreachable host must not stop the rest.
                        // It is named, though: a silently skipped agent
                        // is indistinguishable from a quiet one.
                        Err(e) => errors.push(format!("{}: {e}", peer.name)),
                    }
                }

                let event = EngineEvent::AlertsArchived { stored, errors };
                if engine_tx.send(event).await.is_err() {
                    break;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        });
    }

    /// A poll cycle finished. Re-read the archive so anything new shows.
    pub(crate) fn on_archived(&mut self, stored: usize, errors: &[String]) {
        self.last_error = if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        };
        if stored > 0 || self.alerts.is_empty() {
            self.refresh_from_archive();
        } else {
            // Keep the total fresh even when this cycle stored nothing,
            // so `notify` writing in the background is visible here.
            if let Some(a) = &self.archive {
                self.total_rows = a.stats().map_or(self.total_rows, |s| s.rows);
            }
        }
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
                rule_id: "cred.read_netrc".into(),
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

    /// The pane renders the archive, so history predates the session:
    /// alerts that arrived while the console was closed (via `bowery
    /// notify`, or a previous run) must be on screen at startup. That
    /// was the whole complaint — the old pane started empty every time
    /// and could only ever show what it watched arrive.
    #[test]
    fn the_pane_opens_showing_history_it_did_not_witness() {
        let mut archive = Archive::open_in_memory().unwrap();
        archive
            .record(
                &[sample(1).remove(0), confirmed("ep-old", 4, 5, true)],
                Some("otter1"),
            )
            .unwrap();

        let mut pane = AlertsPane::with_archive(archive);
        assert_eq!(pane.alerts.len(), 2, "history must load without polling");
        let out = draw(&mut pane, false);
        assert!(out.contains("ep-old"), "archived alert not rendered: {out}");
    }

    /// A superseding alert replaces its episode rather than duplicating
    /// it — now enforced by the archive's `alerts_latest` view, so the
    /// pane inherits it. Asserted here too because the pane is where the
    /// duplication would be *seen*.
    #[test]
    fn superseding_alert_replaces_its_episode_instead_of_duplicating() {
        let mut archive = Archive::open_in_memory().unwrap();
        let mut original = sample(1).remove(0);
        original.episode_id = "ep-0".into();
        original.ts_unix_ms = 1000;
        let mut later = confirmed("ep-0", 4, 5, true);
        later.ts_unix_ms = 2000;
        archive.record(&[original, later], Some("otter1")).unwrap();

        let pane = AlertsPane::with_archive(archive);
        assert_eq!(pane.alerts.len(), 1, "one episode must be one row");
        assert!(
            pane.alerts[0].confirmation.is_some(),
            "the superseding alert must win, not the original"
        );
    }

    /// Alerts with no episode id are unrelated to one another, so
    /// collapsing on it would fold them all into one row.
    #[test]
    fn empty_episode_ids_never_collapse_together() {
        let mut archive = Archive::open_in_memory().unwrap();
        let mut a = sample(1).remove(0);
        let mut b = sample(1).remove(0);
        a.episode_id = String::new();
        a.ts_unix_ms = 1000;
        b.episode_id = String::new();
        b.ts_unix_ms = 2000;
        archive.record(&[a, b], Some("otter1")).unwrap();

        let pane = AlertsPane::with_archive(archive);
        assert_eq!(
            pane.alerts.len(),
            2,
            "an empty episode_id is not an identity"
        );
    }

    /// Searching is the same mechanism as browsing, so a filter must
    /// narrow the rendered set and be reversible.
    #[test]
    fn a_filter_narrows_the_list_and_clears_again() {
        let mut archive = Archive::open_in_memory().unwrap();
        let mut watchdog = sample(1).remove(0);
        watchdog.episode_id = "ep-watchdog".into();
        watchdog.exe_path = "/usr/bin/dd".into();
        watchdog.rationale = "write-intent open of /dev/watchdog0".into();
        watchdog.ts_unix_ms = 2000;
        let mut other = sample(1).remove(0);
        other.episode_id = "ep-other".into();
        other.ts_unix_ms = 1000;
        archive.record(&[watchdog, other], Some("otter1")).unwrap();

        let mut pane = AlertsPane::with_archive(archive);
        assert_eq!(pane.alerts.len(), 2);

        let msg = pane.set_filter("watchdog");
        assert_eq!(pane.alerts.len(), 1, "free text must narrow");
        assert_eq!(pane.alerts[0].episode_id, "ep-watchdog");
        // The status line has to name both numbers: a filtered count on
        // its own reads as the whole fleet being quiet.
        assert!(
            msg.contains("1 of 2"),
            "status must show both counts: {msg}"
        );

        assert!(
            !pane.set_filter("").is_empty(),
            "clearing must report what it did"
        );
        assert_eq!(pane.alerts.len(), 2, "clearing restores everything");
    }

    /// `key:value` terms exist so the routine questions don't require a
    /// query language. Structural terms must not also be matched as
    /// free text, or `rule:x` would find nothing.
    #[test]
    fn structural_filter_terms_are_parsed_not_searched() {
        let mut archive = Archive::open_in_memory().unwrap();
        let mut high = sample(1).remove(0);
        high.episode_id = "ep-high".into();
        high.rule_id = "cred.read_aws".into();
        high.suspicion = 0.95;
        high.ts_unix_ms = 2000;
        let mut low = sample(1).remove(0);
        low.episode_id = "ep-low".into();
        low.rule_id = "net.beacon".into();
        low.suspicion = 0.2;
        low.ts_unix_ms = 1000;
        archive.record(&[high, low], Some("otter1")).unwrap();

        let mut pane = AlertsPane::with_archive(archive);
        pane.set_filter("rule:cred.read_aws");
        assert_eq!(pane.alerts.len(), 1, "rule: must filter structurally");
        assert_eq!(pane.alerts[0].episode_id, "ep-high");

        pane.set_filter("min:0.5");
        assert_eq!(pane.alerts.len(), 1);
        assert_eq!(pane.alerts[0].episode_id, "ep-high");

        pane.set_filter("agent:otter1");
        assert_eq!(pane.alerts.len(), 2, "both are from this agent");

        pane.set_filter("agent:nosuchhost");
        assert!(pane.alerts.is_empty(), "an unknown agent matches nothing");
    }

    /// An empty list has three causes and they mean different things.
    /// Reporting "no alerts" for a filter that hid them is how an
    /// operator concludes a fleet is quiet.
    #[test]
    fn an_empty_list_says_which_emptiness_it_is() {
        let empty = AlertsPane::with_archive(Archive::open_in_memory().unwrap());
        let mut empty = empty;
        let out = draw(&mut empty, false);
        assert!(
            out.contains("no alerts archived yet") || out.contains("press 2"),
            "an empty archive must say so: {out}"
        );

        let mut archive = Archive::open_in_memory().unwrap();
        archive.record(&sample(1), Some("otter1")).unwrap();
        let mut pane = AlertsPane::with_archive(archive);
        pane.set_filter("nothingmatchesthis");
        let filtered = draw(&mut pane, false);
        assert!(
            filtered.contains("no alert matches"),
            "a filter hiding everything must say so, not report silence: {filtered}"
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

/// Peers from `~/.bowery/peers.toml`, re-read each cycle so `:peers add`
/// takes effect without restarting the console.
fn load_peers() -> Vec<bowery_cli::peers::Peer> {
    bowery_cli::peers::default_path()
        .ok()
        .and_then(|p| bowery_cli::peers::Manifest::load(&p).ok())
        .map(|m| m.peers)
        .unwrap_or_default()
}

/// `since:2h` / `since:7d` / `since:30m` → an absolute epoch bound.
fn parse_since(spec: &str) -> Option<u64> {
    let (value, unit) = spec.split_at(spec.len().checked_sub(1)?);
    let n: u64 = value.parse().ok()?;
    let secs = match unit {
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        "w" => n * 604_800,
        _ => return None,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis();
    u64::try_from(now).ok()?.checked_sub(secs * 1000)
}
