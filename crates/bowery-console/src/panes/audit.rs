//! Audit pane — snapshots the relay's audit-chain via SQL. Uses
//! `bowery_audit` — the bonus table that exposes the agent's
//! Phase-7 enforcement audit log as queryable rows.
//!
//! On pane activation we run a snapshot once; the operator can press
//! `r` (in this pane) to refresh.

use std::time::Duration;

use bowery_cli::exec::{self, CollectSink};
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row as TableRow, Table};
use tokio::sync::mpsc;

use crate::app::{EngineEvent, Relay};
use crate::theme;

const SNAPSHOT_SQL: &str = "SELECT seq, action, outcome, recorded_at_unix \
                            FROM bowery_audit ORDER BY seq DESC LIMIT 200";

#[derive(Debug, Default)]
pub(crate) struct AuditPane {
    pub(crate) snapshot: Option<CollectSink>,
    pub(crate) loading: bool,
    pub(crate) error: Option<String>,
    pub(crate) loaded_once: bool,
}

impl AuditPane {
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
                &mut sink,
            )
            .await;
            let event = match outcome {
                Ok(()) => EngineEvent::AuditDone { result: Ok(sink) },
                Err(e) => EngineEvent::AuditDone {
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
            (Some(_), _) => "Audit (error — press r to retry)".to_string(),
            (None, Some(s)) => format!("Audit ({} entries · r refreshes)", s.rows.len()),
            (None, None) => "Audit (loading…)".to_string(),
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
                Paragraph::new("press 4 to load / r to refresh").style(theme::dim()),
                inner,
            );
            return;
        };
        if snapshot.rows.is_empty() {
            f.render_widget(
                Paragraph::new("audit log empty (no enforcement actions recorded)")
                    .style(theme::dim()),
                inner,
            );
            return;
        }

        let header = TableRow::new(
            snapshot
                .columns
                .iter()
                .map(|c| Cell::from(c.clone()))
                .collect::<Vec<_>>(),
        )
        .style(theme::header_row());

        let rows: Vec<TableRow> = snapshot
            .rows
            .iter()
            .map(|r| {
                let cells = r
                    .values
                    .iter()
                    .map(|v| Cell::from(crate::panes::query::render_value(v)))
                    .collect::<Vec<_>>();
                TableRow::new(cells)
            })
            .collect();
        let widths: Vec<Constraint> = snapshot
            .columns
            .iter()
            .map(|_| Constraint::Min(8))
            .collect();
        f.render_widget(Table::new(rows, widths).header(header), inner);
    }
}
