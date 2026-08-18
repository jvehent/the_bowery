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

use crate::browse::Browser;
use crate::input::{InputAction, InputState};
use crate::palette::PaletteCommand;
use crate::panes::PaneId;
use crate::panes::alerts::AlertsPane;
use crate::panes::audit::AuditPane;
use crate::panes::chat::ChatPane;
use crate::panes::doctor::DoctorPane;
use crate::panes::help::HelpPane;
use crate::panes::map::MapPane;
use crate::panes::peers::PeersPane;
use crate::panes::query::{QueryPane, QueryStatus};
use crate::panes::silences::SilencesPane;
use crate::theme;

#[derive(Debug, Clone)]
pub(crate) struct Relay {
    pub(crate) addr: SocketAddr,
    pub(crate) fp_hex: String,
    pub(crate) pubkey_b64: String,
}

pub(crate) struct AppArgs {
    pub(crate) operator_key: PathBuf,
    pub(crate) agent_addr: SocketAddr,
    pub(crate) agent_fp: String,
    pub(crate) agent_pubkey_b64: String,
    pub(crate) default_timeout: Duration,
    /// Mesh cluster, needed to sign an alert silence. `None` means the
    /// console can review silences but not mint them — better than
    /// guessing a cluster and having every agent refuse the result.
    pub(crate) cluster_id: Option<String>,
    /// Chat backend chosen at startup. Mock when the binary was
    /// built without `--features llm-llama-cpp` or the operator
    /// didn't pass `--chat-model`.
    pub(crate) chat_backend: std::sync::Arc<dyn bowery_llm::Chat>,
}

#[derive(Debug)]
pub(crate) enum InputMode {
    /// Typing into the active pane's prompt.
    Pane,
    /// `:command` palette modal.
    Palette,
    /// Full-screen detail overlay for the selected row. The list's
    /// selection is preserved underneath, so Esc returns you exactly
    /// where you were.
    Detail,
    /// Confirming a silence derived from the selected alert. Owns the
    /// keyboard, and only `y` proceeds — a record that turns detection
    /// off should not be one keystroke away from a stray Enter.
    Silence,
}

/// A silence an operator is being asked to confirm.
///
/// Held on the app rather than the pane because signing it needs the
/// relay and the operator key, and because the overlay outlives any one
/// pane render.
#[derive(Debug)]
pub(crate) struct SilenceDraft {
    pub(crate) spec: bowery_analysis::silence::SilenceSpec,
    pub(crate) episode_id: String,
    pub(crate) rationale: String,
    /// Episode ids this pattern would have covered. `None` while the
    /// query is still running — the operator should not be able to
    /// confirm before seeing it.
    pub(crate) radius: Option<Vec<String>>,
    pub(crate) error: Option<String>,
    pub(crate) pushing: bool,
    pub(crate) outcome: Option<String>,
}

/// Events the engine pushes to the UI loop.
#[derive(Debug)]
pub(crate) enum EngineEvent {
    QueryDone {
        sql: String,
        result: Result<CollectSink, String>,
        latency: Duration,
    },
    AlertsBatch {
        items: Vec<bowery_proto::Alert>,
        cursor_unix_ms: u64,
    },
    AlertsError(String),
    /// How many held alerts the pending silence would cover.
    SilenceRadius {
        result: Result<Vec<String>, String>,
    },
    /// The signed silence was pushed, or refused.
    SilencePushed {
        result: Result<String, String>,
    },
    AuditDone {
        result: Result<CollectSink, String>,
    },
    SilencesDone {
        result: Result<CollectSink, String>,
    },
    DoctorLocalDone(bowery_cli::doctor::Report),
    DoctorRemoteDone(Result<Duration, String>),
    MapDone {
        result: Result<CollectSink, String>,
    },
    ChatReply(Result<String, String>),
}

pub(crate) struct App {
    pub(crate) operator_key: PathBuf,
    pub(crate) default_timeout: Duration,
    /// Mesh cluster, needed to sign an alert silence. `None` means the
    /// console can review silences but not mint them — better than
    /// guessing a cluster and having every agent refuse the result.
    pub(crate) relay: Relay,

    pub(crate) current_pane: PaneId,
    pub(crate) query_pane: QueryPane,
    pub(crate) alerts_pane: AlertsPane,
    pub(crate) audit_pane: AuditPane,
    pub(crate) silences_pane: SilencesPane,
    /// The silence being confirmed, if the overlay is up.
    pub(crate) silence_draft: Option<SilenceDraft>,
    pub(crate) cluster_id: Option<String>,
    pub(crate) peers_pane: PeersPane,
    pub(crate) doctor_pane: DoctorPane,
    pub(crate) map_pane: MapPane,
    pub(crate) chat_pane: ChatPane,
    pub(crate) help_pane: HelpPane,

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
            alerts_pane: AlertsPane::new(),
            audit_pane: AuditPane::new(),
            cluster_id: args.cluster_id.clone(),
            silences_pane: SilencesPane::new(),
            silence_draft: None,
            peers_pane: PeersPane::new(),
            doctor_pane: DoctorPane::new(),
            map_pane: MapPane::new(),
            chat_pane: ChatPane::new(args.chat_backend),
            help_pane: HelpPane::new(),
            input: load_history_into_input(),
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

    /// Handle keys that operate above the input editor (pane
    /// switching, refresh, palette, help scroll, draft-run).
    /// Returns `true` if the key was consumed.
    fn handle_global_hotkey(&mut self, key: KeyEvent) -> bool {
        let pane_mode = matches!(self.input_mode, InputMode::Pane);
        let input_empty = self.input.buffer.is_empty();

        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                self.should_quit = true;
                return true;
            }
            (KeyCode::Char(c), KeyModifiers::NONE)
                if pane_mode && input_empty && PaneId::from_hotkey(c).is_some() =>
            {
                if let Some(p) = PaneId::from_hotkey(c) {
                    self.current_pane = p;
                    self.activate_pane();
                    return true;
                }
            }
            (KeyCode::Char('r'), KeyModifiers::NONE) if pane_mode && input_empty => {
                self.refresh_current_pane();
                return true;
            }
            (KeyCode::Char('?'), KeyModifiers::NONE) if pane_mode && input_empty => {
                self.current_pane = PaneId::Help;
                return true;
            }
            (KeyCode::Char('x'), KeyModifiers::NONE)
                if pane_mode && input_empty && self.current_pane == PaneId::Chat =>
            {
                if let Some(sql) = self.chat_pane.take_draft() {
                    self.current_pane = PaneId::Query;
                    self.query_pane.submit(
                        &sql,
                        self.relay.clone(),
                        self.operator_key.clone(),
                        self.default_timeout,
                        self.engine_tx.clone(),
                    );
                    self.status_message = Some("running draft SQL from chat".into());
                } else {
                    self.status_message = Some("no draft SQL to run".into());
                }
                return true;
            }
            (KeyCode::Char(':'), KeyModifiers::NONE) if pane_mode && input_empty => {
                self.input_mode = InputMode::Palette;
                self.input.clear();
                return true;
            }
            _ => {}
        }

        if self.handle_browse_keys(key, pane_mode, input_empty) {
            return true;
        }

        if pane_mode && self.current_pane == PaneId::Help {
            match (key.code, key.modifiers) {
                (KeyCode::PageDown, _) => {
                    self.help_pane.scroll_down(20);
                    return true;
                }
                (KeyCode::PageUp, _) => {
                    self.help_pane.scroll_up(20);
                    return true;
                }
                (KeyCode::Down, KeyModifiers::NONE) if input_empty => {
                    self.help_pane.scroll_down(1);
                    return true;
                }
                (KeyCode::Up, KeyModifiers::NONE) if input_empty => {
                    self.help_pane.scroll_up(1);
                    return true;
                }
                (KeyCode::Home, _) if input_empty => {
                    self.help_pane.home();
                    return true;
                }
                (KeyCode::End, _) if input_empty => {
                    self.help_pane.end();
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// Detail-overlay and row-navigation keys. Split out of
    /// `handle_global_hotkey` to keep that function readable.
    fn handle_browse_keys(&mut self, key: KeyEvent, pane_mode: bool, input_empty: bool) -> bool {
        // The silence overlay owns the keyboard, and only `y` proceeds.
        // A record that turns detection off should not be reachable by a
        // stray Enter on a list.
        if matches!(self.input_mode, InputMode::Silence) {
            if matches!(key.code, KeyCode::Char('y' | 'Y')) {
                self.confirm_silence();
            } else {
                self.input_mode = InputMode::Pane;
                self.silence_draft = None;
            }
            return true;
        }

        // Detail overlay owns the keyboard while it's up.
        if matches!(self.input_mode, InputMode::Detail) {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.input_mode = InputMode::Pane;
                    return true;
                }
                _ => {
                    if self.handle_detail_key(key) {
                        return true;
                    }
                    // Swallow everything else: a stray keystroke must not
                    // leak into the pane prompt behind the overlay.
                    return true;
                }
            }
        }

        // Row navigation for browsable panes. This has to be claimed here,
        // before InputState, because the editor consumes Up/Down for history
        // unconditionally (input.rs) — the same reason the Help block below
        // exists.
        if pane_mode
            && input_empty
            && self.current_pane == PaneId::Alerts
            && key.code == KeyCode::Char('s')
        {
            self.begin_silence();
            return true;
        }

        if pane_mode && input_empty && self.current_pane.is_browsable() {
            let page = 10;
            match (key.code, key.modifiers) {
                (KeyCode::Down, KeyModifiers::NONE) => {
                    if let Some(b) = self.browser_mut() {
                        b.next();
                    }
                    return true;
                }
                (KeyCode::Up, KeyModifiers::NONE) => {
                    if let Some(b) = self.browser_mut() {
                        b.prev();
                    }
                    return true;
                }
                (KeyCode::PageDown, _) => {
                    if let Some(b) = self.browser_mut() {
                        b.page_down(page);
                    }
                    return true;
                }
                (KeyCode::PageUp, _) => {
                    if let Some(b) = self.browser_mut() {
                        b.page_up(page);
                    }
                    return true;
                }
                (KeyCode::Home, _) => {
                    if let Some(b) = self.browser_mut() {
                        b.home();
                    }
                    return true;
                }
                (KeyCode::End, _) => {
                    if let Some(b) = self.browser_mut() {
                        b.end();
                    }
                    return true;
                }
                (KeyCode::Enter, _) if self.open_detail() => return true,
                _ => {}
            }
        }
        false
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if self.handle_global_hotkey(key) {
            return;
        }

        match self.input.handle_key(key) {
            InputAction::Submit(line) => match self.input_mode {
                InputMode::Pane => self.dispatch_pane_submit(&line),
                InputMode::Palette => self.dispatch_palette(&line),
                // Unreachable: the overlay swallows every key before the
                // editor sees it. Fail closed rather than submitting a
                // stale line into whichever pane is behind the overlay.
                InputMode::Detail | InputMode::Silence => {}
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
            PaneId::Chat => {
                if let Some(msg) = self.chat_pane.submit(trimmed, self.engine_tx.clone()) {
                    self.status_message = Some(msg);
                }
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
            Ok(PaletteCommand::PeersReload) => {
                self.peers_pane.reload();
                self.status_message = Some("peers manifest reloaded".into());
            }
            Ok(PaletteCommand::PeersAdd {
                name,
                fp,
                pubkey_b64,
            }) => {
                self.status_message = Some(match peers_add(&name, &fp, &pubkey_b64) {
                    Ok(()) => {
                        self.peers_pane.reload();
                        format!("added peer {name}")
                    }
                    Err(e) => format!("peers add failed: {e:#}"),
                });
            }
            Ok(PaletteCommand::PeersRemove { fp }) => {
                self.status_message = Some(match peers_remove(&fp) {
                    Ok(()) => {
                        self.peers_pane.reload();
                        format!("removed peer {fp}")
                    }
                    Err(e) => format!("peers remove failed: {e:#}"),
                });
            }
            Ok(PaletteCommand::ExportQuery { path }) => {
                self.status_message = Some(match export_query(&self.query_pane.status, &path) {
                    Ok(n) => format!("exported {n} rows to {path}"),
                    Err(e) => format!("export failed: {e:#}"),
                });
            }
            Err(e) => {
                self.status_message = Some(e);
            }
        }
    }

    fn activate_pane(&mut self) {
        match self.current_pane {
            PaneId::Alerts => {
                self.alerts_pane.ensure_poller(
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.engine_tx.clone(),
                );
            }
            PaneId::Audit => {
                self.audit_pane.ensure_loaded(
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.engine_tx.clone(),
                );
            }
            PaneId::Silences => {
                self.silences_pane.ensure_loaded(
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.engine_tx.clone(),
                );
            }
            PaneId::Peers => {
                self.peers_pane.reload();
            }
            PaneId::Doctor if self.doctor_pane.local.is_none() => {
                self.doctor_pane.refresh(
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.engine_tx.clone(),
                );
            }
            PaneId::Map => {
                self.map_pane.ensure_loaded(
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.engine_tx.clone(),
                );
            }
            _ => {}
        }
    }

    /// The active pane's cursor, when it has one.
    fn browser_mut(&mut self) -> Option<&mut Browser> {
        // Every arm of `PaneId::is_browsable` must appear here. A pane
        // that claims to be browsable without a browser has its arrow
        // keys *consumed* by `handle_browse_keys` and dropped on the
        // floor — worse than not claiming browsability at all.
        match self.current_pane {
            PaneId::Alerts => Some(self.alerts_pane.browser_mut()),
            PaneId::Query => Some(self.query_pane.browser_mut()),
            PaneId::Audit => Some(self.audit_pane.browser_mut()),
            PaneId::Silences => Some(self.silences_pane.browser_mut()),
            PaneId::Peers => Some(self.peers_pane.browser_mut()),
            PaneId::Map => Some(self.map_pane.browser_mut()),
            PaneId::Doctor | PaneId::Chat | PaneId::Help => None,
        }
    }

    /// Open the detail overlay for the active pane's selection.
    /// Returns false when there's nothing selected, so the key falls
    /// through instead of opening an empty overlay.
    fn open_detail(&mut self) -> bool {
        let has_selection = match self.current_pane {
            PaneId::Alerts => self.alerts_pane.selected_alert().is_some(),
            PaneId::Query => self.query_pane.selected_row().is_some(),
            PaneId::Audit => self.audit_pane.has_rows(),
            PaneId::Silences => self.silences_pane.has_rows(),
            PaneId::Peers => self.peers_pane.selected_peer().is_some(),
            PaneId::Map => self.map_pane.has_rows(),
            PaneId::Doctor | PaneId::Chat | PaneId::Help => false,
        };
        if has_selection {
            self.input_mode = InputMode::Detail;
        }
        has_selection
    }

    /// Keys handled while a detail overlay is open (pivots). Returns
    /// true if the key did something.
    /// Keys handled while a detail overlay is open. Pivots land here in
    /// a later slice; today the overlay is read-only and only Esc/q
    /// (handled by the caller) exits.
    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    /// Cross-pane pivots from inside a detail overlay: turn the record
    /// under the cursor into the query you'd otherwise have to type by
    /// hand, and jump to the Query pane with it already running.
    ///
    /// This is the investigative core of the redesign — a detail view
    /// that can only be read is a dead end.
    fn handle_detail_key(&mut self, key: KeyEvent) -> bool {
        let KeyCode::Char(c) = key.code else {
            return false;
        };
        let Some(sql) = self.pivot_sql(c) else {
            return false;
        };
        self.run_pivot(&sql);
        true
    }

    /// The query a pivot key maps to for the current pane's selection,
    /// or `None` when the key isn't a pivot or the record lacks the
    /// field it needs (an alert with no `exe_path` has nothing to stat).
    fn pivot_sql(&self, c: char) -> Option<String> {
        match self.current_pane {
            PaneId::Alerts => {
                let alert = self.alerts_pane.selected_alert()?.clone();
                let exe = alert.exe_path.clone();
                match c {
                    'a' => Some(format!(
                        "SELECT seq, ts_unix_ms, action_id, outcome_kind FROM bowery_audit \
                         WHERE episode_id = {}",
                        sql_literal(&alert.episode_id)
                    )),
                    'b' if !alert.exe_sha256_hex.is_empty() => Some(format!(
                        "SELECT sha256_hex, first_seen_unix, last_seen_unix, seen_count \
                         FROM bowery_baseline_binaries WHERE sha256_hex = {}",
                        sql_literal(&alert.exe_sha256_hex)
                    )),
                    'p' if !exe.is_empty() => Some(format!(
                        "SELECT pid, ppid, uid, name, exe_path, cmdline FROM processes \
                         WHERE exe_path = {}",
                        sql_literal(&exe)
                    )),
                    'f' if !exe.is_empty() => Some(format!(
                        "SELECT bowery_file_exists({p}) AS exists_now, \
                                bowery_file_size({p}) AS size, \
                                bowery_file_mode({p}) AS mode, \
                                bowery_file_owner_uid({p}) AS uid, \
                                bowery_file_mtime_unix({p}) AS mtime, \
                                bowery_file_sha256_hex({p}) AS sha256",
                        p = sql_literal(&exe)
                    )),
                    _ => None,
                }
            }
            PaneId::Peers => {
                let fp = self.peers_pane.selected_peer()?.fp.clone();
                pivot_by_fingerprint(c, &fp)
            }
            PaneId::Map => {
                let fp = self.map_pane.selected_fingerprint()?;
                pivot_by_fingerprint(c, &fp)
            }
            PaneId::Query
            | PaneId::Audit
            | PaneId::Silences
            | PaneId::Doctor
            | PaneId::Chat
            | PaneId::Help => None,
        }
    }

    /// Leave the overlay, switch to Query, and run `sql` there.
    fn run_pivot(&mut self, sql: &str) {
        self.input_mode = InputMode::Pane;
        self.current_pane = PaneId::Query;
        self.query_pane.submit(
            sql,
            self.relay.clone(),
            self.operator_key.clone(),
            self.default_timeout,
            self.engine_tx.clone(),
        );
        self.status_message = Some(format!("pivot: {}", truncate_status(sql)));
    }

    fn refresh_current_pane(&mut self) {
        match self.current_pane {
            PaneId::Alerts => {
                // Picks up peers added since launch, so a newly-named
                // agent stops showing as a bare fingerprint.
                self.alerts_pane.reload_agent_names();
            }
            PaneId::Audit => {
                self.audit_pane.refresh(
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.engine_tx.clone(),
                );
            }
            PaneId::Silences => {
                self.silences_pane.refresh(
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.engine_tx.clone(),
                );
            }
            PaneId::Peers => {
                self.peers_pane.reload();
            }
            PaneId::Doctor => {
                self.doctor_pane.refresh(
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.engine_tx.clone(),
                );
            }
            PaneId::Map => {
                self.map_pane.refresh(
                    self.relay.clone(),
                    self.operator_key.clone(),
                    self.engine_tx.clone(),
                );
            }
            _ => {}
        }
    }

    fn handle_engine_event(&mut self, ev: EngineEvent) {
        match ev {
            EngineEvent::QueryDone {
                sql,
                result,
                latency,
            } => self.query_pane.on_done(sql, result, latency),
            EngineEvent::AlertsBatch {
                items,
                cursor_unix_ms,
            } => self.alerts_pane.on_batch(items, cursor_unix_ms),
            EngineEvent::AlertsError(e) => self.alerts_pane.on_error(e),
            EngineEvent::SilenceRadius { result } => {
                if let Some(d) = self.silence_draft.as_mut() {
                    match result {
                        Ok(rows) => d.radius = Some(rows),
                        Err(e) => d.error = Some(e),
                    }
                }
            }
            EngineEvent::SilencePushed { result } => {
                if let Some(d) = self.silence_draft.as_mut() {
                    d.pushing = false;
                    match result {
                        Ok(msg) => d.outcome = Some(msg),
                        Err(e) => d.error = Some(e),
                    }
                }
            }
            EngineEvent::AuditDone { result } => self.audit_pane.on_done(result),
            EngineEvent::SilencesDone { result } => self.silences_pane.on_done(result),
            EngineEvent::DoctorLocalDone(report) => self.doctor_pane.on_local_done(report),
            EngineEvent::DoctorRemoteDone(result) => self.doctor_pane.on_remote_done(result),
            EngineEvent::MapDone { result } => self.map_pane.on_done(result),
            EngineEvent::ChatReply(result) => self.chat_pane.on_reply(result),
        }
    }

    fn render(&mut self, f: &mut Frame<'_>) {
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

    /// Derive a silence from the selected alert and start confirming it.
    ///
    /// The pattern is derived rather than typed: an episode id names one
    /// occurrence and will never recur, so what gets signed is the rule,
    /// the binary's hash and the path that alert stands for.
    fn begin_silence(&mut self) {
        let Some(alert) = self.alerts_pane.selected_alert().cloned() else {
            return;
        };
        let spec = bowery_analysis::silence::SilenceSpec {
            rule_id: alert.rule_id.clone(),
            exe_sha256_hex: alert.exe_sha256_hex.clone(),
            exe_path: alert.exe_path.clone(),
            host_fp_hex: String::new(),
        };
        if spec.constrains() == 0 {
            self.status_message = Some("that alert carries nothing to key a silence on".into());
            return;
        }
        self.silence_draft = Some(SilenceDraft {
            spec: spec.clone(),
            episode_id: alert.episode_id.clone(),
            rationale: alert.rationale.clone(),
            radius: None,
            error: None,
            pushing: false,
            outcome: None,
        });
        self.input_mode = InputMode::Silence;

        // Ask what it would have covered. The operator sees this before
        // being asked to confirm, which is the whole safety property.
        let mut wheres = vec!["1=1".to_string()];
        for (col, val) in [
            ("rule_id", &spec.rule_id),
            ("exe_sha256_hex", &spec.exe_sha256_hex),
            ("exe_path", &spec.exe_path),
        ] {
            if !val.is_empty() {
                wheres.push(format!("{col} = {}", sql_literal(val)));
            }
        }
        let sql = format!(
            "SELECT episode_id FROM bowery_alerts WHERE {} ORDER BY ts_unix_ms DESC",
            wheres.join(" AND ")
        );
        let (relay, key_path, tx) = (
            self.relay.clone(),
            self.operator_key.clone(),
            self.engine_tx.clone(),
        );
        tokio::spawn(async move {
            let mut sink = bowery_cli::exec::CollectSink::default();
            let outcome = bowery_cli::exec::sql(
                key_path,
                relay.addr,
                relay.fp_hex.clone(),
                relay.pubkey_b64.clone(),
                Vec::new(),
                sql,
                std::time::Duration::from_secs(10),
                false,
                false,
                &mut sink,
            )
            .await;
            let result = match outcome {
                Ok(()) => Ok(sink
                    .rows
                    .iter()
                    .filter_map(|r| {
                        r.values.first().map(|v| match &v.value {
                            Some(bowery_proto::SqlValueKind::Text(t)) => t.clone(),
                            _ => String::new(),
                        })
                    })
                    .collect::<Vec<String>>()),
                Err(e) => Err(format!("{e:#}")),
            };
            let _ = tx.send(EngineEvent::SilenceRadius { result }).await;
        });
    }

    /// Sign and push the drafted silence.
    fn confirm_silence(&mut self) {
        let Some(draft) = self.silence_draft.as_mut() else {
            return;
        };
        if draft.radius.is_none() || draft.pushing || draft.outcome.is_some() {
            // Not yet shown what it covers, already in flight, or done.
            return;
        }
        draft.pushing = true;
        let spec = draft.spec.clone();
        let episode = draft.episode_id.clone();
        let (relay, key_path, tx) = (
            self.relay.clone(),
            self.operator_key.clone(),
            self.engine_tx.clone(),
        );
        let Some(cluster) = self.cluster_id.clone() else {
            draft.pushing = false;
            draft.error = Some(
                "no --cluster-id given, so a silence cannot be signed: agents refuse one \
                 issued for a different mesh"
                    .into(),
            );
            return;
        };
        tokio::spawn(async move {
            let result = push_silence(relay, key_path, cluster, spec, episode).await;
            let _ = tx
                .send(EngineEvent::SilencePushed {
                    result: result.map_err(|e| format!("{e:#}")),
                })
                .await;
        });
    }

    /// The silence confirmation overlay.
    ///
    /// Renders the *derived pattern* and what it would have covered, in
    /// that order, because those are the two facts an operator needs and
    /// the second is the one they will not think to ask for. `y` is the
    /// only key that proceeds.
    fn render_silence_overlay(&mut self, f: &mut Frame<'_>, area: Rect) {
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Paragraph};

        let Some(d) = self.silence_draft.as_ref() else {
            return;
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Silence this finding — y confirms, any other key cancels");
        let inner = block.inner(area);
        f.render_widget(block, area);

        let mut lines = vec![
            Line::from(Span::styled("this alert", theme::detail_label())),
            Line::from(truncate(&d.rationale, 160)),
            Line::from(""),
            Line::from(Span::styled(
                "would be silenced by the pattern",
                theme::detail_label(),
            )),
            Line::from(format!("  rule    {}", or_any(&d.spec.rule_id))),
            Line::from(format!("  binary  {}", or_any(&d.spec.exe_sha256_hex))),
            Line::from(format!("  path    {}", or_any(&d.spec.exe_path))),
            Line::from("  host    every host in the mesh"),
            Line::from("  effect  silenced entirely, for 90 days"),
            Line::from(""),
        ];

        match (&d.error, &d.outcome, &d.radius) {
            (Some(e), _, _) => lines.push(Line::from(Span::styled(e.clone(), theme::error()))),
            (_, Some(msg), _) => lines.push(Line::from(Span::styled(
                format!("pushed: {msg}"),
                theme::detail_label(),
            ))),
            (_, _, None) => lines.push(Line::from(Span::styled(
                "counting what this would cover…",
                theme::dim(),
            ))),
            (_, _, Some(rows)) => {
                lines.push(Line::from(Span::styled(
                    format!(
                        "it would have covered {} of the alerts this agent holds:",
                        rows.len()
                    ),
                    theme::detail_label(),
                )));
                for episode in rows.iter().take(6) {
                    lines.push(Line::from(format!("  {episode}")));
                }
                if rows.len() > 6 {
                    lines.push(Line::from(format!("  … and {} more", rows.len() - 6)));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(if d.pushing {
                    Span::styled("signing and pushing…", theme::dim())
                } else {
                    Span::styled("press y to sign and push", theme::hint())
                }));
            }
        }
        f.render_widget(Paragraph::new(lines), inner);
    }

    fn render_pane(&mut self, f: &mut Frame<'_>, area: Rect) {
        if matches!(self.input_mode, InputMode::Silence) {
            self.render_silence_overlay(f, area);
            return;
        }
        if matches!(self.input_mode, InputMode::Detail) {
            match self.current_pane {
                PaneId::Alerts => {
                    self.alerts_pane.render_detail(f, area);
                    return;
                }
                PaneId::Query => {
                    self.query_pane.render_detail(f, area);
                    return;
                }
                PaneId::Audit => {
                    self.audit_pane.render_detail(f, area);
                    return;
                }
                PaneId::Silences => {
                    self.silences_pane.render_detail(f, area);
                    return;
                }
                PaneId::Peers => {
                    self.peers_pane.render_detail(f, area);
                    return;
                }
                PaneId::Map => {
                    self.map_pane.render_detail(f, area);
                    return;
                }
                // Not browsable, so `open_detail` never sets Detail mode
                // for these; fall through to the normal render.
                PaneId::Doctor | PaneId::Chat | PaneId::Help => {}
            }
        }
        match self.current_pane {
            PaneId::Query => self.query_pane.render(f, area),
            PaneId::Alerts => self.alerts_pane.render(f, area),
            PaneId::Audit => self.audit_pane.render(f, area),
            PaneId::Silences => self.silences_pane.render(f, area),
            PaneId::Peers => self.peers_pane.render(f, area),
            PaneId::Doctor => self.doctor_pane.render(f, area),
            PaneId::Map => self.map_pane.render(f, area),
            PaneId::Chat => self.chat_pane.render(f, area),
            PaneId::Help => self.help_pane.render(f, area),
        }
    }

    fn render_input(&self, f: &mut Frame<'_>, area: Rect) {
        let prompt = match self.input_mode {
            InputMode::Pane => format!("{} > ", self.current_pane.label().to_lowercase()),
            InputMode::Palette => ": ".to_string(),
            InputMode::Detail => "detail (Esc back) > ".to_string(),
            InputMode::Silence => "silence? ".to_string(),
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

impl Drop for App {
    fn drop(&mut self) {
        // Persist input history on every clean exit (Ctrl-C / :quit /
        // panic-after-restore). Best-effort: a write failure shouldn't
        // crash the operator's terminal teardown, so we ignore errors.
        let _ = save_history(&self.input.history);
    }
}

fn history_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        std::path::PathBuf::from(home)
            .join(".bowery")
            .join("console-history"),
    )
}

fn load_history_into_input() -> InputState {
    let mut state = InputState::new();
    if let Some(path) = history_path()
        && let Ok(contents) = std::fs::read_to_string(&path)
    {
        state.history = contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
    }
    state
}

fn save_history(history: &[String]) -> std::io::Result<()> {
    let Some(path) = history_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = history.join("\n");
    std::fs::write(path, body)
}

fn peers_add(name: &str, fp: &str, pubkey_b64: &str) -> anyhow::Result<()> {
    let path = bowery_cli::peers::default_path()?;
    // Console palette add is fan-out-oriented (no reachability addr);
    // use `bowery peers add --addr` on the CLI to record a whisper addr.
    bowery_cli::peers::add(&path, name, fp, pubkey_b64, None)
}

fn peers_remove(fp: &str) -> anyhow::Result<()> {
    let path = bowery_cli::peers::default_path()?;
    bowery_cli::peers::remove(&path, fp)
}

fn export_query(status: &QueryStatus, path: &str) -> anyhow::Result<usize> {
    use std::io::Write as _;
    let QueryStatus::Rendered { result, .. } = status else {
        anyhow::bail!("no rendered query result to export — run a query first");
    };
    let mut file = std::fs::File::create(path)?;
    // First line: column-name array.
    let cols: Vec<String> = result
        .columns
        .iter()
        .map(|c| format!("\"{}\"", json_escape(c)))
        .collect();
    writeln!(file, "[{}]", cols.join(","))?;
    for row in &result.rows {
        let mut parts: Vec<String> = Vec::with_capacity(row.values.len());
        for (i, v) in row.values.iter().enumerate() {
            let key = result.columns.get(i).map_or("col", String::as_str);
            parts.push(format!("\"{}\":{}", json_escape(key), value_to_json(v)));
        }
        writeln!(file, "{{{}}}", parts.join(","))?;
    }
    Ok(result.rows.len())
}

fn value_to_json(v: &bowery_proto::SqlValue) -> String {
    use bowery_proto::SqlValueKind;
    match &v.value {
        Some(SqlValueKind::Integer(i)) => i.to_string(),
        Some(SqlValueKind::Real(r)) => r.to_string(),
        Some(SqlValueKind::Text(s)) => format!("\"{}\"", json_escape(s)),
        Some(SqlValueKind::Blob(b)) => format!("\"<{} bytes>\"", b.len()),
        None => "null".into(),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Quote a value as a SQL string literal.
///
/// Every pivot interpolates values that came off the wire from an agent
/// — an exe path, a rationale, a fingerprint. An embedded single quote
/// would otherwise terminate the literal early and change the statement,
/// so double it, per the SQL standard. The surface is read-only, but a
/// broken query is still a broken pivot.
fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Pivots available from any pane whose selection is a peer fingerprint
/// (Peers, Map), so the two stay in step by construction.
fn pivot_by_fingerprint(key: char, fp: &str) -> Option<String> {
    match key {
        'n' => Some(format!(
            "SELECT episode_id, ts_unix_ms, suspicion, exe_path, confirmed \
             FROM bowery_alerts WHERE originator_fp_hex = {}",
            sql_literal(fp)
        )),
        'm' => Some(format!(
            "SELECT fingerprint_hex, whisper_addr, agent_version, pinned, \
                    has_role_vector, has_bloom_advert \
             FROM bowery_mesh_peers WHERE fingerprint_hex = {}",
            sql_literal(fp)
        )),
        _ => None,
    }
}

fn truncate_status(s: &str) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= 60 {
        flat
    } else {
        format!("{}…", flat.chars().take(59).collect::<String>())
    }
}

/// Show a wildcard field as such rather than as a blank.
fn or_any(value: &str) -> String {
    if value.is_empty() {
        "(any)".to_string()
    } else {
        value.to_string()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}…")
}

/// Sign and push a silence derived in the console.
///
/// A ninety-day expiry and a stock reason, because the console is for
/// judging a finding quickly; anything needing a hand-written
/// justification or a different lifetime is a job for
/// `bowery alerts silence`, which takes both.
async fn push_silence(
    relay: Relay,
    operator_key: PathBuf,
    cluster_id: String,
    spec: bowery_analysis::silence::SilenceSpec,
    episode_id: String,
) -> anyhow::Result<String> {
    use bowery_crypto::Identity;

    let identity = Identity::load(&operator_key)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    let mut silence = bowery_proto::AlertSilence {
        id: spec.id(&cluster_id),
        cluster_id: cluster_id.clone(),
        rule_id: spec.rule_id.clone(),
        exe_sha256_hex: spec.exe_sha256_hex.clone(),
        exe_path: spec.exe_path.clone(),
        host_fp: Vec::new(),
        weight_permille: 0,
        reason: format!("silenced from the console, from {episode_id}"),
        issued_unix_ms: now,
        expires_unix_ms: now + 90 * 24 * 60 * 60 * 1000,
        operator_fp: identity.fingerprint().as_bytes().to_vec(),
        sig: Vec::new(),
    };
    let input = silence
        .to_signing_input()
        .ok_or_else(|| anyhow::anyhow!("could not build the signing input"))?;
    silence.sig = identity.sign(&input).to_bytes().to_vec();
    let id = silence.id.clone();

    bowery_cli::exec::silence_push(
        &bowery_cli::silence::Target {
            operator_key,
            addr: relay.addr,
            fp_hex: relay.fp_hex.clone(),
            pubkey_b64: relay.pubkey_b64.clone(),
            peer_pubkeys_b64: Vec::new(),
            timeout: std::time::Duration::from_secs(10),
        },
        &silence,
        true,
        3,
    )
    .await?;
    Ok(format!("{id} applied"))
}

#[cfg(test)]
mod pivot_tests {
    use super::*;

    #[test]
    fn sql_literal_escapes_embedded_quotes() {
        assert_eq!(sql_literal("/tmp/x"), "'/tmp/x'");
        // Pivots interpolate agent-supplied paths. Without doubling, the
        // literal would terminate early and the rest would be parsed as
        // SQL.
        assert_eq!(sql_literal("/tmp/it's"), "'/tmp/it''s'");
        assert_eq!(
            sql_literal("' OR 1=1 --"),
            "''' OR 1=1 --'",
            "a quote-led payload must stay inside the literal"
        );
        assert_eq!(sql_literal(""), "''");
    }

    #[test]
    fn fingerprint_pivots_cover_the_advertised_keys_and_nothing_else() {
        let fp = "ab".repeat(32);
        for key in ['n', 'm'] {
            let sql = pivot_by_fingerprint(key, &fp)
                .unwrap_or_else(|| panic!("advertised key {key} produced no query"));
            assert!(sql.contains(&format!("'{fp}'")), "fp must be bound: {sql}");
        }
        // Keys the hint line does not advertise must not silently do
        // something — that asymmetry is what made the first slice
        // confusing.
        for key in ['a', 'b', 'q', 'z'] {
            assert!(pivot_by_fingerprint(key, &fp).is_none(), "key {key} leaked");
        }
    }

    #[test]
    fn truncate_status_flattens_and_bounds() {
        let long = format!("SELECT {}", "x".repeat(200));
        let out = truncate_status(&long);
        assert!(out.chars().count() <= 60, "status line stayed long: {out}");
        assert_eq!(
            truncate_status("SELECT a\n  FROM b"),
            "SELECT a FROM b",
            "multi-line SQL must flatten; a newline would break the bar"
        );
    }
}
