//! Mesh map pane — visualizes the relay's view of the agent
//! network as a tree, with the current relay at the root and its
//! pinned peers as 1-hop children.
//!
//! C-5 v1: single-relay only. Runs `SELECT fingerprint_hex FROM
//! bowery_peers` against the current relay; the result feeds an
//! ASCII tree renderer. When Phase-10 multi-hop fan-out lands,
//! the same pane will switch to `--fanout --max-hops N` and stitch
//! responses from each agent into a multi-level graph keyed on
//! fingerprint. Until then, "Map" == "what does this one relay
//! know about its neighborhood".

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
use crate::theme;

const MAP_SQL: &str = "SELECT fingerprint_hex FROM bowery_peers ORDER BY fingerprint_hex";

#[derive(Debug, Default)]
pub(crate) struct MapPane {
    pub(crate) snapshot: Option<CollectSink>,
    pub(crate) loading: bool,
    pub(crate) error: Option<String>,
    pub(crate) loaded_once: bool,
    /// Last relay we mapped — used for the root label.
    pub(crate) snapshot_relay: Option<Relay>,
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

    pub(crate) fn render(&self, f: &mut Frame<'_>, area: Rect) {
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
        let lines = build_tree(snapshot, self.snapshot_relay.as_ref());
        let body = Paragraph::new(lines);
        f.render_widget(body, inner);
    }
}

fn build_tree(snapshot: &CollectSink, relay: Option<&Relay>) -> Vec<Line<'static>> {
    let root = relay.map_or_else(
        || "◆ relay (unknown)".to_string(),
        |r| {
            let fp_short: String = r.fp_hex.chars().take(16).collect();
            format!("◆ relay  {fp_short}…  {}", r.addr)
        },
    );

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(Span::styled(
        root,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));

    let peers: Vec<String> = snapshot
        .rows
        .iter()
        .filter_map(|r| match r.values.first().and_then(|v| v.value.as_ref()) {
            Some(SqlValueKind::Text(s)) => Some(s.clone()),
            _ => None,
        })
        .collect();

    if peers.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no pinned peers)".to_string(),
            theme::dim(),
        )));
        return lines;
    }

    let last_idx = peers.len() - 1;
    for (i, fp) in peers.iter().enumerate() {
        let glyph = if i == last_idx {
            "└── "
        } else {
            "├── "
        };
        let fp_short: String = fp.chars().take(16).collect();
        lines.push(Line::from(vec![
            Span::raw(glyph.to_string()),
            Span::styled("◆ ".to_string(), Style::default().fg(Color::Green)),
            Span::raw(format!("{fp_short}…")),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("{} agent(s) reachable at 1 hop", peers.len()),
        theme::dim(),
    )));
    lines.push(Line::from(Span::styled(
        "Phase 10 multi-hop will populate deeper levels.".to_string(),
        theme::dim(),
    )));

    lines
}
