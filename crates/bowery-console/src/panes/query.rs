//! SQL Query pane — the flagship view. Operators type `SELECT ...`
//! at the input prompt; the pane dispatches the query to the
//! current relay via `bowery_cli::exec::sql` with a [`CollectSink`]
//! and renders the resulting rows as an aligned ratatui table.
//!
//! Slice C-2 scope: single-relay only (no fan-out yet — that wires
//! up alongside the Map pane in C-5). One in-flight query at a
//! time; new submits while a query is running are rejected with a
//! "still running" status.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bowery_cli::exec::{self, CollectSink, CollectedRow};
use bowery_proto::SqlValueKind;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row as TableRow, Table};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::app::Relay;
use crate::theme;

/// Per-query result the pane renders into its output panel.
#[derive(Debug)]
pub(crate) enum QueryStatus {
    Idle,
    Running {
        sql: String,
        started: Instant,
    },
    Rendered {
        sql: String,
        result: CollectSink,
        latency: Duration,
    },
    Error {
        sql: String,
        message: String,
    },
}

#[derive(Debug)]
pub(crate) struct QueryPane {
    pub(crate) status: QueryStatus,
    /// Held while a query is in flight so concurrent submits are
    /// rejected loudly. Same lock the engine task takes when it
    /// publishes the result.
    in_flight: Arc<Mutex<()>>,
}

impl QueryPane {
    pub(crate) fn new() -> Self {
        Self {
            status: QueryStatus::Idle,
            in_flight: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) fn render(&self, f: &mut Frame<'_>, area: Rect) {
        let block = Block::default().borders(Borders::ALL).title("Query");
        let inner = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(inner);

        // Status line.
        let status_line = match &self.status {
            QueryStatus::Idle => "ready".to_string(),
            QueryStatus::Running { sql, started } => {
                format!(
                    "running ({:.1}s)  · {}",
                    started.elapsed().as_secs_f64(),
                    truncate(sql, 80)
                )
            }
            QueryStatus::Rendered {
                sql,
                result,
                latency,
            } => format!(
                "{} rows in {:.0} ms · {}",
                result.rows.len(),
                latency.as_secs_f64() * 1000.0,
                truncate(sql, 80)
            ),
            QueryStatus::Error { sql, message } => {
                format!("ERROR — {} · {}", truncate(message, 80), truncate(sql, 60))
            }
        };
        let status_widget = Paragraph::new(status_line).style(match &self.status {
            QueryStatus::Error { .. } => theme::error(),
            _ => theme::dim(),
        });
        f.render_widget(status_widget, chunks[0]);

        match &self.status {
            QueryStatus::Rendered { result, .. } => render_table(f, chunks[1], result),
            QueryStatus::Error { message, .. } => {
                f.render_widget(
                    Paragraph::new(message.clone()).style(theme::error()),
                    chunks[1],
                );
            }
            QueryStatus::Running { .. } => {
                f.render_widget(
                    Paragraph::new("waiting for rows…").style(theme::dim()),
                    chunks[1],
                );
            }
            QueryStatus::Idle => {
                f.render_widget(
                    Paragraph::new(
                        "Type a SELECT statement at the prompt below and press Enter.\nExamples:\n  SELECT pretty_name FROM os_version;\n  SELECT pid, name, rss_bytes FROM processes ORDER BY rss_bytes DESC LIMIT 10;\n  SELECT bowery_file_sha256_hex('/usr/bin/sshd');",
                    )
                    .style(theme::dim()),
                    chunks[1],
                );
            }
        }
    }

    /// Submit the SQL on the input bar. Returns immediately;
    /// completion arrives via the `engine_tx` channel as a
    /// [`crate::app::EngineEvent::QueryDone`] event.
    pub(crate) fn submit(
        &mut self,
        sql: &str,
        relay: Relay,
        operator_key: std::path::PathBuf,
        timeout: Duration,
        engine_tx: mpsc::Sender<crate::app::EngineEvent>,
    ) {
        if matches!(self.status, QueryStatus::Running { .. }) {
            self.status = QueryStatus::Error {
                sql: sql.to_string(),
                message: "another query is still running; wait or restart".into(),
            };
            return;
        }
        let started = Instant::now();
        self.status = QueryStatus::Running {
            sql: sql.to_string(),
            started,
        };
        let lock = self.in_flight.clone();
        let sql_for_task = sql.to_string();
        tokio::spawn(async move {
            let _guard = lock.lock().await;
            let mut sink = CollectSink::default();
            let outcome = exec::sql(
                operator_key,
                relay.addr,
                relay.fp_hex.clone(),
                relay.pubkey_b64.clone(),
                Vec::new(),
                sql_for_task.clone(),
                timeout,
                false,
                &mut sink,
            )
            .await;
            let event = match outcome {
                Ok(()) => crate::app::EngineEvent::QueryDone {
                    sql: sql_for_task,
                    result: Ok(sink),
                    latency: started.elapsed(),
                },
                Err(e) => crate::app::EngineEvent::QueryDone {
                    sql: sql_for_task,
                    result: Err(format!("{e:#}")),
                    latency: started.elapsed(),
                },
            };
            let _ = engine_tx.send(event).await;
        });
    }

    /// Wire callback for an [`crate::app::EngineEvent::QueryDone`].
    pub(crate) fn on_done(
        &mut self,
        sql: String,
        result: Result<CollectSink, String>,
        latency: Duration,
    ) {
        self.status = match result {
            Ok(result) => QueryStatus::Rendered {
                sql,
                result,
                latency,
            },
            Err(message) => QueryStatus::Error { sql, message },
        };
    }
}

fn render_table(f: &mut Frame<'_>, area: Rect, sink: &CollectSink) {
    if sink.columns.is_empty() {
        f.render_widget(Paragraph::new("(no rows)").style(theme::dim()), area);
        return;
    }
    let header = TableRow::new(
        sink.columns
            .iter()
            .map(|c| Cell::from(c.clone()))
            .collect::<Vec<_>>(),
    )
    .style(theme::header_row());

    let rows: Vec<TableRow> = sink
        .rows
        .iter()
        .map(|r: &CollectedRow| {
            let cells = r
                .values
                .iter()
                .map(|v| Cell::from(render_value(v)))
                .collect::<Vec<_>>();
            TableRow::new(cells)
        })
        .collect();

    let widths: Vec<Constraint> = sink.columns.iter().map(|_| Constraint::Min(8)).collect();
    let table = Table::new(rows, widths)
        .header(header)
        .style(Style::default());
    f.render_widget(table, area);
}

fn render_value(v: &bowery_proto::SqlValue) -> String {
    match &v.value {
        Some(SqlValueKind::Integer(i)) => i.to_string(),
        Some(SqlValueKind::Real(r)) => format!("{r}"),
        Some(SqlValueKind::Text(s)) => s.clone(),
        Some(SqlValueKind::Blob(b)) => format!("<{} bytes>", b.len()),
        None => "NULL".to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.replace('\n', " ")
    } else {
        let mut iter = s.chars();
        let head: String = iter.by_ref().take(max - 1).collect();
        format!("{head}…")
    }
}
