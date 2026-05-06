//! Doctor pane — local readiness check (kernel version, BPF-LSM,
//! BTF, bpffs, lsm= cmdline, …) plus a remote `SELECT 1` smoke
//! against the current relay so the operator can confirm both
//! their workstation *and* the agent in one place.
//!
//! Local checks come from `bowery_cli::doctor::run()`. Remote
//! check is `exec::sql("SELECT 1 AS one")`.

use std::time::Duration;

use bowery_cli::doctor::{self, Check, Report, Status};
use bowery_cli::exec::{self, CollectSink};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use tokio::sync::mpsc;

use crate::app::{EngineEvent, Relay};
use crate::theme;

#[derive(Debug, Default)]
pub(crate) struct DoctorPane {
    pub(crate) local: Option<Report>,
    pub(crate) remote: RemoteState,
}

#[derive(Debug, Default)]
pub(crate) enum RemoteState {
    #[default]
    Idle,
    Running,
    Ok(Duration),
    Failed(String),
}

impl DoctorPane {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Run both checks. Local one is synchronous (it only reads
    /// /proc and /sys); the remote SQL smoke is async.
    pub(crate) fn refresh(
        &mut self,
        relay: Relay,
        operator_key: std::path::PathBuf,
        engine_tx: mpsc::Sender<EngineEvent>,
    ) {
        self.local = Some(doctor::run());
        self.remote = RemoteState::Running;
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let mut sink = CollectSink::default();
            let outcome = exec::sql(
                operator_key,
                relay.addr,
                relay.fp_hex.clone(),
                relay.pubkey_b64.clone(),
                Vec::new(),
                "SELECT 1 AS one".to_string(),
                Duration::from_secs(5),
                false,
                &mut sink,
            )
            .await;
            let result = match outcome {
                Ok(()) => Ok(started.elapsed()),
                Err(e) => Err(format!("{e:#}")),
            };
            let _ = engine_tx.send(EngineEvent::DoctorRemoteDone(result)).await;
        });
    }

    pub(crate) fn on_remote_done(&mut self, result: Result<Duration, String>) {
        self.remote = match result {
            Ok(d) => RemoteState::Ok(d),
            Err(e) => RemoteState::Failed(e),
        };
    }

    pub(crate) fn render(&self, f: &mut Frame<'_>, area: Rect) {
        let block = Block::default().borders(Borders::ALL).title("Doctor");
        let inner = block.inner(area);
        f.render_widget(block, area);

        let mut lines: Vec<Line> = Vec::new();
        match &self.local {
            None => lines.push(Line::from(Span::styled(
                "press 6 to run / r to refresh",
                theme::dim(),
            ))),
            Some(report) => {
                lines.push(Line::from(Span::styled("LOCAL", theme::dim())));
                for c in &report.checks {
                    lines.push(render_check(c));
                }
                let verdict_style = if report.verdict == doctor::Verdict::Ready {
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else {
                    theme::error()
                };
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("verdict: {:?}", report.verdict),
                    verdict_style,
                )));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("REMOTE", theme::dim())));
        let remote_line = match &self.remote {
            RemoteState::Idle => Line::from(Span::styled("not run", theme::dim())),
            RemoteState::Running => Line::from(Span::styled(
                "running SELECT 1 against relay…",
                theme::dim(),
            )),
            RemoteState::Ok(d) => Line::from(Span::styled(
                format!("OK · relay round-trip in {} ms", d.as_millis()),
                Style::default().fg(Color::Green),
            )),
            RemoteState::Failed(e) => {
                Line::from(Span::styled(format!("FAIL · {e}"), theme::error()))
            }
        };
        lines.push(remote_line);

        f.render_widget(Paragraph::new(lines), inner);
    }
}

fn render_check(c: &Check) -> Line<'static> {
    let (icon, style) = match c.status {
        Status::Pass => (
            " OK ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Status::Warn => ("WARN", Style::default().fg(Color::Yellow)),
        Status::Fail => (
            "FAIL",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Status::Unknown => (" N/A", Style::default().fg(Color::DarkGray)),
    };
    Line::from(vec![
        Span::styled(format!("[{icon}] "), style),
        Span::raw(format!("{:<24}", c.name)),
        Span::styled(c.detail.clone(), theme::dim()),
    ])
}
