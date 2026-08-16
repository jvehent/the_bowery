//! Mesh map pane — visualizes the relay's view of the agent
//! network as a tree, with the current relay at the root and its
//! pinned peers as 1-hop children.
//!
//! Single-relay only. Runs a query against `bowery_mesh_peers` — the
//! *discovery* view, i.e. every peer the relay currently sees gossiping,
//! whether or not it has been pinned — and feeds the result to an ASCII
//! tree renderer. `bowery_peers` (the pinned set) is a strict subset,
//! surfaced here as the `pinned` flag, which makes the two most useful
//! failure modes visible at a glance: a peer that gossips but was never
//! pinned, and a peer that is pinned but has stopped gossiping. When Phase-10 multi-hop fan-out lands,
//! the same pane will switch to `--fanout --max-hops N` and stitch
//! responses from each agent into a multi-level graph keyed on
//! fingerprint. Until then, "Map" == "what does this one relay
//! know about its neighborhood".

use std::fmt::Write as _;
use std::time::Duration;

use bowery_cli::exec::{self, CollectSink};
use bowery_proto::SqlValueKind;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use tokio::sync::mpsc;

use crate::app::{EngineEvent, Relay};
use crate::browse::Browser;
use crate::theme;

/// Discovery view + the two adverts that decide whether a peer can take
/// part in a whisper round at all. A peer missing `has_role_vector`
/// silently never gets asked anything, which is invisible from the
/// pinned-set view alone.
const MAP_SQL: &str = "SELECT fingerprint_hex, whisper_addr, agent_version, pinned, \
                       has_role_vector, has_bloom_advert \
                       FROM bowery_mesh_peers ORDER BY fingerprint_hex";

#[derive(Debug, Default)]
pub(crate) struct MapPane {
    pub(crate) snapshot: Option<CollectSink>,
    pub(crate) loading: bool,
    pub(crate) error: Option<String>,
    pub(crate) loaded_once: bool,
    /// Last relay we mapped — used for the root label.
    pub(crate) snapshot_relay: Option<Relay>,
    /// Cursor over the peer rows (not the rendered tree lines — the root
    /// and trailer lines are not selectable).
    browser: Browser,
}

impl MapPane {
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
        self.snapshot_relay = Some(relay.clone());
        let sql = MAP_SQL.to_string();
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
                Ok(()) => EngineEvent::MapDone { result: Ok(sink) },
                Err(e) => EngineEvent::MapDone {
                    result: Err(format!("{e:#}")),
                },
            };
            let _ = engine_tx.send(event).await;
        });
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
            (Some(_), _) => "Map (error — press r to retry)".to_string(),
            (None, Some(s)) => format!("Map (1-hop · {} peers · r refreshes)", s.rows.len()),
            (None, None) if self.loading => "Map (loading…)".to_string(),
            _ => "Map".to_string(),
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
                Paragraph::new("press 3 to load / r to refresh").style(theme::dim()),
                inner,
            );
            return;
        };
        self.browser.set_len(snapshot.rows.len());
        let (tree_area, hint_area) = crate::panes::split_hint(inner);
        let lines = build_tree(
            snapshot,
            self.snapshot_relay.as_ref(),
            self.browser.selected(),
        );
        f.render_widget(Paragraph::new(lines), tree_area);
        f.render_widget(
            Paragraph::new("↑↓ move  ⏎ peer detail  r refresh").style(theme::hint()),
            hint_area,
        );
    }

    /// Full-screen detail for the selected mesh peer: every column of
    /// its `bowery_mesh_peers` row, including the full fingerprint the
    /// tree can only show truncated.
    pub(crate) fn render_detail(&mut self, f: &mut Frame<'_>, area: Rect) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        crate::panes::render_sink_detail(
            f,
            area,
            snapshot,
            &mut self.browser,
            "Mesh peer",
            "pivots:  n alerts it raised   m its mesh-peer row",
        );
    }

    pub(crate) fn browser_mut(&mut self) -> &mut Browser {
        &mut self.browser
    }

    pub(crate) fn has_rows(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|s| !s.rows.is_empty())
    }

    /// Fingerprint of the selected peer, for cross-pane pivots.
    pub(crate) fn selected_fingerprint(&self) -> Option<String> {
        let snapshot = self.snapshot.as_ref()?;
        let row = snapshot.rows.get(self.browser.selected()?)?;
        match row.values.first().and_then(|v| v.value.as_ref()) {
            Some(SqlValueKind::Text(s)) => Some(s.clone()),
            _ => None,
        }
    }
}

fn build_tree(
    snapshot: &CollectSink,
    relay: Option<&Relay>,
    selected: Option<usize>,
) -> Vec<Line<'static>> {
    let root = relay.map_or_else(
        || "◆ relay (unknown)".to_string(),
        |r| {
            let fp_short: String = r.fp_hex.chars().take(16).collect();
            format!("◆ relay  {fp_short}…  {}", r.addr)
        },
    );

    let mut lines: Vec<Line<'static>> = vec![Line::from(Span::styled(
        root,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))];

    if snapshot.rows.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no peers discovered on the mesh)".to_string(),
            theme::dim(),
        )));
        return lines;
    }

    let last_idx = snapshot.rows.len() - 1;
    for (i, row) in snapshot.rows.iter().enumerate() {
        let glyph = if i == last_idx {
            "└── "
        } else {
            "├── "
        };
        let fp = column_text(snapshot, row, "fingerprint_hex").unwrap_or_default();
        let fp_short: String = fp.chars().take(16).collect();
        let addr = column_text(snapshot, row, "whisper_addr").unwrap_or_default();
        let version = column_text(snapshot, row, "agent_version").unwrap_or_default();
        let pinned = column_text(snapshot, row, "pinned").is_some_and(|v| v == "1");

        // An unpinned peer can gossip all day and still never answer a
        // whisper — flag it in the tree rather than hiding it in detail.
        let (mark, mark_style) = if pinned {
            ("◆ ", Style::default().fg(Color::Green))
        } else {
            ("◇ ", Style::default().fg(Color::Yellow))
        };
        let mut trailer = format!("{fp_short}…");
        if !addr.is_empty() {
            let _ = write!(trailer, "  {addr}");
        }
        if !version.is_empty() {
            let _ = write!(trailer, "  v{version}");
        }
        if !pinned {
            trailer.push_str("  (unpinned)");
        }

        let line = Line::from(vec![
            Span::raw(glyph.to_string()),
            Span::styled(mark.to_string(), mark_style),
            Span::raw(trailer),
        ]);
        lines.push(if selected == Some(i) {
            line.style(theme::selected_row())
        } else {
            line
        });
    }

    let pinned_count = snapshot
        .rows
        .iter()
        .filter(|r| column_text(snapshot, r, "pinned").is_some_and(|v| v == "1"))
        .count();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            "{} peer(s) discovered, {} pinned  ·  ◆ pinned  ◇ unpinned",
            snapshot.rows.len(),
            pinned_count
        ),
        theme::dim(),
    )));

    lines
}

/// Look a value up by column name rather than position, so reordering
/// `MAP_SQL` can't silently shift every field by one.
fn column_text(
    sink: &CollectSink,
    row: &bowery_cli::exec::CollectedRow,
    column: &str,
) -> Option<String> {
    let idx = sink.columns.iter().position(|c| c == column)?;
    Some(crate::panes::query::render_value(row.values.get(idx)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panes::tests::text_row;

    fn snapshot() -> CollectSink {
        CollectSink {
            columns: [
                "fingerprint_hex",
                "whisper_addr",
                "agent_version",
                "pinned",
                "has_role_vector",
                "has_bloom_advert",
            ]
            .iter()
            .map(|c| (*c).to_string())
            .collect(),
            rows: vec![
                text_row(&[
                    "aa".repeat(32).as_str(),
                    "100.1.2.3:9902",
                    "0.0.1",
                    "1",
                    "1",
                    "1",
                ]),
                text_row(&[
                    "bb".repeat(32).as_str(),
                    "100.1.2.4:9902",
                    "0.0.1",
                    "0",
                    "0",
                    "0",
                ]),
            ],
        }
    }

    /// A peer that gossips but was never pinned answers nothing and is
    /// invisible in the pinned-set view — the tree has to call it out.
    #[test]
    fn tree_distinguishes_pinned_from_discovered() {
        let lines = build_tree(&snapshot(), None, Some(0));
        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect::<String>();
        assert!(
            text.contains("(unpinned)"),
            "unpinned peer unmarked: {text}"
        );
        assert!(text.contains("100.1.2.3:9902"), "addr missing: {text}");
        assert!(
            text.contains("2 peer(s) discovered, 1 pinned"),
            "summary wrong: {text}"
        );
    }

    /// Columns are looked up by name so reordering `MAP_SQL` can't shift
    /// every field by one.
    #[test]
    fn column_lookup_is_by_name_not_position() {
        let mut s = snapshot();
        s.columns.swap(0, 3); // fingerprint_hex <-> pinned
        for r in &mut s.rows {
            r.values.swap(0, 3);
        }
        let lines = build_tree(&s, None, None);
        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect::<String>();
        assert!(
            text.contains("aaaaaaaaaaaaaaaa"),
            "fingerprint must still be found after a column swap: {text}"
        );
    }

    #[test]
    fn empty_snapshot_renders_without_panicking() {
        let lines = build_tree(&CollectSink::default(), None, None);
        assert!(lines.len() >= 2, "root + empty notice");
    }
}
