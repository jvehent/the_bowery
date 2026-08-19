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

use bowery_cli::exec::{self, CollectSink};
use bowery_proto::SqlValueKind;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::widgets::{Block, Borders, Paragraph};
use tokio::sync::Mutex;

use crate::browse::Browser;
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
    /// Cursor + viewport over the current result's rows.
    browser: Browser,
    /// Held while a query is in flight so concurrent submits are
    /// rejected loudly. Same lock the engine task takes when it
    /// publishes the result.
    in_flight: Arc<Mutex<()>>,
    /// Scroll offset for the idle catalogue, which is far taller than
    /// any pane. Without it only the first screenful is reachable and
    /// the reference is only a reference to its own first page.
    idle_scroll: u16,
}

impl QueryPane {
    pub(crate) fn new() -> Self {
        Self {
            status: QueryStatus::Idle,
            browser: Browser::default(),
            in_flight: Arc::new(Mutex::new(())),
            idle_scroll: 0,
        }
    }

    /// Is the catalogue on screen? Arrow keys scroll it rather than
    /// moving a row cursor that has no rows to move over.
    pub(crate) fn showing_catalog(&self) -> bool {
        matches!(self.status, QueryStatus::Idle)
    }

    pub(crate) fn scroll_catalog(&mut self, delta: i32) {
        let next = i64::from(self.idle_scroll) + i64::from(delta);
        self.idle_scroll = u16::try_from(next.max(0)).unwrap_or(u16::MAX);
    }

    pub(crate) fn render(&mut self, f: &mut Frame<'_>, area: Rect) {
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
            QueryStatus::Rendered { result, .. } => crate::panes::render_sink_table(
                f,
                chunks[1],
                result,
                &mut self.browser,
                "↑↓ move  ⏎ row detail",
            ),
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
                // An empty prompt is where "querying is hard" actually
                // bites: the operator knows SQL and does not know that
                // `bowery_events` exists or that `ts_unix_ms` is
                // milliseconds. So the idle screen is the reference,
                // shown at the one moment somebody is looking for
                // something to type.
                f.render_widget(
                    Paragraph::new(catalog_lines())
                        .scroll((self.idle_scroll, 0))
                        .wrap(ratatui::widgets::Wrap { trim: false }),
                    chunks[1],
                );
            }
        }
    }

    /// Full-screen detail for the selected result row.
    pub(crate) fn render_detail(&mut self, f: &mut Frame<'_>, area: Rect) {
        let QueryStatus::Rendered { result, .. } = &self.status else {
            return;
        };
        crate::panes::render_sink_detail(f, area, result, &mut self.browser, "Query row", "");
    }

    pub(crate) fn browser_mut(&mut self) -> &mut Browser {
        &mut self.browser
    }

    /// The selected row's `(column, value)` pairs, for the detail
    /// overlay's pivots. `None` when there is no rendered result.
    pub(crate) fn selected_row(&self) -> Option<Vec<(String, String)>> {
        let QueryStatus::Rendered { result, .. } = &self.status else {
            return None;
        };
        let row = result.rows.get(self.browser.selected()?)?;
        Some(
            result
                .columns
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let v = row
                        .values
                        .get(i)
                        .map_or_else(|| "NULL".to_string(), render_value);
                    (c.clone(), v)
                })
                .collect(),
        )
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
                false, // console renders its own view: no stderr trace
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
        self.browser.home();
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

pub(crate) fn render_value(v: &bowery_proto::SqlValue) -> String {
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

/// The catalogue, laid out for reading: questions first, because that
/// is how somebody arrives at it, then the schema they will need once
/// they start editing one.
fn catalog_lines() -> String {
    use bowery_cli::catalog::{EXAMPLES, TABLES, squash};
    use std::fmt::Write as _;

    let mut out = String::from(
        "Type a SELECT at the prompt below. ↑↓ scrolls this reference.\n\n\
         ── questions, and the query that answers each ──\n\n",
    );
    for ex in EXAMPLES {
        let _ = writeln!(out, "  {}\n    {}\n", ex.question, squash(ex.sql));
    }
    out.push_str("── tables ──\n\n");
    for t in TABLES {
        let _ = writeln!(out, "  {}  — {}\n    {}\n", t.name, t.about, t.columns);
    }
    out.push_str(
        "`:schema` asks this agent for its live table list, which is authoritative if the\n\
         above has drifted.\n",
    );
    out
}
