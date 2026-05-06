//! Top-level application state — owns the panes, current relay,
//! input editor, and palette modal. Drives the ratatui render
//! loop.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use bowery_cli::exec::CollectSink;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use tokio::sync::mpsc;

use crate::input::{InputAction, InputState};
use crate::palette::PaletteCommand;
use crate::panes::query::QueryPane;
use crate::panes::{PaneId, stub};
use crate::theme;

#[derive(Debug, Clone)]
pub(crate) struct Relay {
    pub(crate) addr: SocketAddr,
    pub(crate) fp_hex: String,
    pub(crate) pubkey_b64: String,
}

#[derive(Debug)]
pub(crate) struct AppArgs {
    pub(crate) operator_key: PathBuf,
    pub(crate) agent_addr: SocketAddr,
    pub(crate) agent_fp: String,
    pub(crate) agent_pubkey_b64: String,
    pub(crate) default_timeout: Duration,
}

#[derive(Debug)]
pub(crate) enum InputMode {
    /// Typing into the active pane's prompt.
    Pane,
    /// `:command` palette modal.
    Palette,
}

/// Events the engine pushes to the UI loop.
#[derive(Debug)]
pub(crate) enum EngineEvent {
    QueryDone {
        sql: String,
        result: Result<CollectSink, String>,
        latency: Duration,
    },
}

pub(crate) struct App {
    pub(crate) operator_key: PathBuf,
    pub(crate) default_timeout: Duration,
    pub(crate) relay: Relay,

    pub(crate) current_pane: PaneId,
    pub(crate) query_pane: QueryPane,

    pub(crate) input: InputState,
    pub(crate) input_mode: InputMode,

    pub(crate) status_message: Option<String>,
    pub(crate) should_quit: bool,

    pub(crate) engine_tx: mpsc::Sender<EngineEvent>,
    pub(crate) engine_rx: mpsc::Receiver<EngineEvent>,
}

impl App {
    pub(crate) fn new(args: AppArgs) -> Self {
        let (engine_tx, engine_rx) = mpsc::channel(64);
        Self {
            operator_key: args.operator_key,
            default_timeout: args.default_timeout,
            relay: Relay {
                addr: args.agent_addr,
                fp_hex: args.agent_fp,
                pubkey_b64: args.agent_pubkey_b64,
            },
            current_pane: PaneId::Query,
            query_pane: QueryPane::new(),
            input: InputState::new(),
            input_mode: InputMode::Pane,
            status_message: None,
            should_quit: false,
            engine_tx,
            engine_rx,
        }
    }

    pub(crate) async fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        let mut term_events = EventStream::new();
        terminal.draw(|f| self.render(f))?;

        while !self.should_quit {
            tokio::select! {
                ev = term_events.next() => {
                    let Some(ev) = ev else { break };
                    if let Ok(Event::Key(k)) = ev
                        && k.kind == KeyEventKind::Press
                    {
                        self.handle_key(k);
                    }
                }
                eng = self.engine_rx.recv() => {
                    if let Some(eng) = eng {
                        self.handle_engine_event(eng);
                    }
                }
            }
            terminal.draw(|f| self.render(f))?;
        }
        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent) {
        // Global shortcuts that bypass the input editor.
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                self.should_quit = true;
                return;
            }
            (KeyCode::Char(c), KeyModifiers::NONE)
                if matches!(self.input_mode, InputMode::Pane)
                    && self.input.buffer.is_empty()
                    && PaneId::from_hotkey(c).is_some() =>
            {
                if let Some(p) = PaneId::from_hotkey(c) {
                    self.current_pane = p;
                    return;
                }
            }
            (KeyCode::Char(':'), KeyModifiers::NONE)
                if matches!(self.input_mode, InputMode::Pane) && self.input.buffer.is_empty() =>
            {
                self.input_mode = InputMode::Palette;
                self.input.clear();
                return;
            }
            _ => {}
        }

        match self.input.handle_key(key) {
            InputAction::Submit(line) => match self.input_mode {
                InputMode::Pane => self.dispatch_pane_submit(&line),
                InputMode::Palette => self.dispatch_palette(&line),
            },
            InputAction::Cancel => {
                self.input.clear();
                self.input_mode = InputMode::Pane;
                self.status_message = None;
            }
            InputAction::Edited | InputAction::Passthrough => {}
        }
    }

    fn dispatch_pane_submit(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }
        match self.current_pane {
            PaneId::Query => {
                self.query_pane.submit(
                    trimmed,
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.default_timeout,
                    self.engine_tx.clone(),
                );
            }
            other => {
                self.status_message =
                    Some(format!("input not yet wired for pane {}", other.label()));
            }
        }
    }

    fn dispatch_palette(&mut self, line: &str) {
        self.input_mode = InputMode::Pane;
        if line.trim().is_empty() {
            return;
        }
        match PaletteCommand::parse(line) {
            Ok(PaletteCommand::Quit) => {
                self.should_quit = true;
            }
            Ok(PaletteCommand::Connect { target, addr }) => {
                self.relay.fp_hex.clone_from(&target);
                if let Some(addr_s) = addr {
                    match addr_s.parse() {
                        Ok(parsed) => {
                            self.relay.addr = parsed;
                            self.status_message = Some(format!("relay → {target} @ {addr_s}"));
                        }
                        Err(e) => {
                            self.status_message = Some(format!("invalid addr {addr_s}: {e}"));
                        }
                    }
                } else {
                    self.status_message = Some(format!("relay fp → {target} (addr unchanged)"));
                }
            }
            Err(e) => {
                self.status_message = Some(e);
            }
        }
    }

    fn handle_engine_event(&mut self, ev: EngineEvent) {
        match ev {
            EngineEvent::QueryDone {
                sql,
                result,
                latency,
            } => {
                self.query_pane.on_done(sql, result, latency);
            }
        }
    }

    fn render(&self, f: &mut Frame<'_>) {
        let area = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // status bar
                Constraint::Length(1), // tabs
                Constraint::Min(0),    // pane
                Constraint::Length(3), // input
            ])
            .split(area);

        self.render_status_bar(f, chunks[0]);
        self.render_tabs(f, chunks[1]);
        self.render_pane(f, chunks[2]);
        self.render_input(f, chunks[3]);
    }

    fn render_status_bar(&self, f: &mut Frame<'_>, area: Rect) {
        let fp_short: String = self.relay.fp_hex.chars().take(16).collect();
        let txt = format!(
            " bowery │ relay={}  ({})  │ {} ",
            fp_short,
            self.relay.addr,
            self.status_message
                .as_deref()
                .unwrap_or("ready · :help · Ctrl-C quit")
        );
        f.render_widget(Paragraph::new(txt).style(theme::status_bar()), area);
    }

    fn render_tabs(&self, f: &mut Frame<'_>, area: Rect) {
        let mut spans = Vec::with_capacity(PaneId::ALL.len() * 2);
        for (i, p) in PaneId::ALL.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw(" "));
            }
            let label = format!(" [{}] {} ", p.hotkey(), p.label());
            let style = if *p == self.current_pane {
                theme::pane_title_active()
            } else {
                theme::pane_title_idle()
            };
            spans.push(Span::styled(label, style));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn render_pane(&self, f: &mut Frame<'_>, area: Rect) {
        match self.current_pane {
            PaneId::Query => self.query_pane.render(f, area),
            PaneId::Alerts => stub::render(f, area, "Alerts", "C-3"),
            PaneId::Audit => stub::render(f, area, "Audit", "C-3"),
            PaneId::Peers => stub::render(f, area, "Peers", "C-3"),
            PaneId::Doctor => stub::render(f, area, "Doctor", "C-4"),
            PaneId::Map => stub::render(f, area, "Map", "C-5"),
        }
    }

    fn render_input(&self, f: &mut Frame<'_>, area: Rect) {
        let prompt = match self.input_mode {
            InputMode::Pane => format!("{} > ", self.current_pane.label().to_lowercase()),
            InputMode::Palette => ": ".to_string(),
        };
        let block = Block::default().borders(Borders::ALL);
        let inner = block.inner(area);
        f.render_widget(block, area);
        let line = Line::from(vec![
            Span::styled(prompt.clone(), theme::input_prompt()),
            Span::raw(self.input.buffer.clone()),
        ]);
        f.render_widget(Paragraph::new(line), inner);
        // Best-effort cursor placement: prompt width + buffer prefix
        // up to the cursor offset, both measured by character count
        // (UTF-8 input fits within terminal cells well enough for
        // operator-style ASCII SQL).
        let prompt_chars = u16::try_from(prompt.chars().count()).unwrap_or(u16::MAX);
        let cursor_chars = u16::try_from(self.input.buffer[..self.input.cursor].chars().count())
            .unwrap_or(u16::MAX);
        let x = inner.x + prompt_chars + cursor_chars;
        let y = inner.y;
        f.set_cursor_position((x.min(inner.x + inner.width.saturating_sub(1)), y));
    }
}
