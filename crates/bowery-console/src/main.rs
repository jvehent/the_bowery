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

    /// Path to a Gemma 4 GGUF for the Chat pane. When set (and the
    /// console is built with `--features llm-llama-cpp`), the Chat
    /// pane loads this model instead of falling back to the mock
    /// backend. Default: `~/.bowery/models/gemma-4-e2b-it-q4_k_m.gguf`
    /// — fetch with `bowery model fetch gemma-4-e2b-it-q4_k_m`.
    #[arg(long)]
    chat_model: Option<PathBuf>,

    /// Context length for the chat model. Gemma 4 E2B supports up
    /// to 128K, but 8K is plenty for SQL-grounded chat and keeps
    /// RAM usage bounded.
    #[arg(long, default_value_t = 8192)]
    chat_n_ctx: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let operator_key = expand_tilde(&args.operator_key);
    let agent_addr = args
        .agent_addr
        .parse()
        .with_context(|| format!("parsing --agent-addr {:?}", args.agent_addr))?;
    let chat_model = args
        .chat_model
        .map(|p| expand_tilde(&p))
        .or_else(default_chat_model_path);
    let chat_n_ctx = args.chat_n_ctx;
    let timeout = args.timeout;
    let agent_fp = args.agent_fp;
    let agent_pubkey_b64 = args.agent_pubkey_b64;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    // Build the chat backend before we enter the alt screen so any
    // model-load failure prints cleanly.
    let chat_backend = runtime.block_on(build_chat_backend(chat_model, chat_n_ctx));

    let app_args = AppArgs {
        operator_key,
        agent_addr,
        agent_fp,
        agent_pubkey_b64,
        default_timeout: timeout,
        chat_backend,
    };

    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alt screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("construct terminal")?;

    let result = runtime.block_on(async move {
        let mut app = App::new(app_args);
        app.run(&mut terminal).await
    });

    disable_raw_mode().ok();
    let mut stdout = io::stdout();
    execute!(stdout, LeaveAlternateScreen).ok();

    result
}

fn default_chat_model_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".bowery")
            .join("models")
            .join("gemma-4-e2b-it-q4_k_m.gguf")
    })
}

#[cfg(feature = "llm-llama-cpp")]
async fn build_chat_backend(
    model_path: Option<PathBuf>,
    n_ctx: u32,
) -> std::sync::Arc<dyn bowery_llm::Chat> {
    use bowery_llm::{LlamaCppChat, LlamaCppChatConfig, MockChat};

    eprintln!("Chat backend: llm-llama-cpp feature is ON (Gemma 4 ready).");
    let Some(mut path) = model_path else {
        eprintln!("no chat model configured (try --chat-model). Falling back to mock chat.");
        return std::sync::Arc::new(MockChat);
    };

    if !path.exists() {
        match prompt_and_fetch_gemma(&path) {
            Ok(Some(downloaded)) => {
                path = downloaded;
            }
            Ok(None) => {
                eprintln!(
                    "Falling back to mock chat — fetch later with `bowery model fetch gemma-4-e2b-it-q4_k_m`."
                );
                return std::sync::Arc::new(MockChat);
            }
            Err(e) => {
                eprintln!("model download failed: {e:#}. Falling back to mock chat.");
                return std::sync::Arc::new(MockChat);
            }
        }
    }

    let cfg = LlamaCppChatConfig {
        model_path: path,
        n_ctx,
        ..LlamaCppChatConfig::default()
    };
    match LlamaCppChat::new(cfg).await {
        Ok(chat) => std::sync::Arc::new(chat),
        Err(e) => {
            eprintln!("chat model load failed: {e}. Falling back to mock chat.");
            std::sync::Arc::new(MockChat)
        }
    }
}

/// Ask the operator on stdin whether to download the Gemma 4 GGUF
/// when the configured `--chat-model` path doesn't exist. Returns
/// `Ok(Some(path))` when the download succeeded, `Ok(None)` when
/// the operator declined, `Err(_)` on download failure.
///
/// Runs *before* the terminal enters raw mode so a normal y/N
/// prompt works and any progress output streams cleanly.
#[cfg(feature = "llm-llama-cpp")]
fn prompt_and_fetch_gemma(missing_path: &Path) -> anyhow::Result<Option<PathBuf>> {
    use std::io::{Write as _, stdin, stdout};

    const MODEL_NAME: &str = "gemma-4-e2b-it-q4_k_m";
    const APPROX_SIZE_GB: u64 = 3; // q4_k_m is 3.11 GiB per the unsloth repo listing

    println!();
    println!("The Chat pane needs Gemma 4 (GGUF, ~{APPROX_SIZE_GB} GB).");
    println!("  expected at:  {}", missing_path.display());
    println!("  registry id:  {MODEL_NAME}");
    print!("Download now? [y/N] ");
    stdout().flush().ok();

    let mut answer = String::new();
    stdin().read_line(&mut answer)?;
    let yes = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    if !yes {
        return Ok(None);
    }

    // Always download into the canonical cache directory so the
    // file lands at `~/.bowery/models/<name>.gguf`. If the
    // operator passed a custom `--chat-model`, we still drop the
    // download into the canonical spot and surface the new path —
    // moving GBs around to satisfy a non-default flag would be
    // surprising.
    let out_dir = bowery_cli::model::default_out_dir()?;
    println!(
        "==> downloading to {} (this can take a while)",
        out_dir.display()
    );
    bowery_cli::model::fetch(MODEL_NAME, &out_dir, false)?;
    let downloaded = out_dir.join(format!("{MODEL_NAME}.gguf"));
    if !downloaded.exists() {
        anyhow::bail!(
            "fetch reported success but {} is missing",
            downloaded.display()
        );
    }
    Ok(Some(downloaded))
}

#[cfg(not(feature = "llm-llama-cpp"))]
#[allow(clippy::unused_async)] // signature mirrors the llama-cpp variant
async fn build_chat_backend(
    _model_path: Option<PathBuf>,
    _n_ctx: u32,
) -> std::sync::Arc<dyn bowery_llm::Chat> {
    eprintln!();
    eprintln!("─── Chat backend: MOCK ─────────────────────────────────────────────────");
    eprintln!("This bowery-console was built WITHOUT --features llm-llama-cpp, so the");
    eprintln!("Chat pane will use a deterministic mock that just echoes your message.");
    eprintln!();
    eprintln!("To get the real Gemma 4 chatbot, rebuild with the feature on:");
    eprintln!();
    eprintln!("    cargo build --release --features llm-llama-cpp -p bowery-console");
    eprintln!();
    eprintln!("On the test VM, the same flag is passed automatically by:");
    eprintln!();
    eprintln!("    ./scripts/xtest run-console");
    eprintln!();
    eprintln!("(or `xtest build` / `xtest ci`, which both also do the LLM-on build).");
    eprintln!("────────────────────────────────────────────────────────────────────────");
    eprintln!();
    std::sync::Arc::new(bowery_llm::MockChat)
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
