//! `bowery-console` — interactive ncurses operator workspace for
//! The Bowery, modeled after Mozilla's mig-console. Wraps the
//! library exports of `bowery-cli` so every operation the CLI can
//! do is also available inside the console — but driven through
//! ratatui panes, hotkeys, and a `:command` palette.
//!
//! Phases (see DESIGN, console section):
//!   C-2 (this slice): skeleton, status bar, Query pane, palette.
//!   C-3 → C-5: Alerts / Audit / Peers / Doctor / Map.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

mod app;
mod input;
mod palette;
mod panes;
mod theme;

use app::{App, AppArgs};

/// CLI flags the console accepts at launch. Most are agent-targeting
/// — same as `bowery exec sql` — and act as the initial relay.
/// Operators can switch relays at runtime via `:connect`.
#[derive(Parser, Debug)]
#[command(version, about = "The Bowery interactive operator console", long_about = None)]
struct Args {
    /// Path to the operator identity key.
    #[arg(long, default_value = "~/.bowery/operator.key")]
    operator_key: PathBuf,

    /// `host:port` of the relay agent to dial first.
    #[arg(long)]
    agent_addr: String,

    /// Hex fingerprint of the relay agent.
    #[arg(long)]
    agent_fp: String,

    /// Base64 verifying key of the relay agent.
    #[arg(long)]
    agent_pubkey_b64: String,

    /// Per-query default timeout. The agent enforces its own
    /// stricter cap.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    timeout: Duration,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let operator_key = expand_tilde(&args.operator_key);
    let agent_addr = args
        .agent_addr
        .parse()
        .with_context(|| format!("parsing --agent-addr {:?}", args.agent_addr))?;

    let app_args = AppArgs {
        operator_key,
        agent_addr,
        agent_fp: args.agent_fp,
        agent_pubkey_b64: args.agent_pubkey_b64,
        default_timeout: args.timeout,
    };

    // Raw-mode + alternate-screen guard. Restore on every exit path,
    // including panic — ratatui won't do this for us.
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alt screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("construct terminal")?;

    let result = run_app(&mut terminal, app_args);

    // Always tear down, regardless of run_app's outcome.
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, args: AppArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    runtime.block_on(async move {
        let mut app = App::new(args);
        app.run(terminal).await
    })
}

/// Expand a leading `~` in a path to `$HOME`. The default
/// `~/.bowery/operator.key` value is parsed by clap as a literal
/// path — we expand here so users see the same behavior they'd
/// get from a shell.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(format!("{home}/{rest}"));
    }
    path.to_path_buf()
}
