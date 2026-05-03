//! Thin entrypoint: parse args, init logging, build an [`Agent`], run until
//! a termination signal arrives.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use bowery_agent::{Agent, Config};
use bowery_crypto::Identity;
use bowery_events::source::NoopEventSource;
use clap::Parser;
use tracing::{error, info};

const DEFAULT_CONFIG_PATH: &str = "/etc/bowery/agent.toml";

#[derive(Parser, Debug)]
#[command(version, about = "The Bowery agent daemon", long_about = None)]
struct Args {
    /// Path to the agent configuration file.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Override the identity key path from config.
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Emit logs as JSON (machine-readable). Default is human-friendly.
    #[arg(long)]
    log_json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    init_tracing(args.log_json);

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = ?e, "agent exited with error");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<()> {
    let config = Config::load(&args.config)
        .with_context(|| format!("loading config from {}", args.config.display()))?;

    let identity_path = args
        .identity
        .clone()
        .unwrap_or_else(|| config.identity.path.clone());

    let (identity, generated) = Identity::load_or_generate(&identity_path)
        .with_context(|| format!("identity at {}", identity_path.display()))?;
    let identity = Arc::new(identity);

    if generated {
        info!(
            fingerprint = %identity.fingerprint(),
            path = %identity_path.display(),
            "generated new identity key on first start"
        );
    } else {
        info!(
            fingerprint = %identity.fingerprint(),
            path = %identity_path.display(),
            "loaded existing identity key"
        );
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("bowery-agent")
        .build()
        .context("building tokio runtime")?;

    runtime.block_on(async {
        // Phase 2 placeholder: no real event source until the BPF loader
        // lands. Replace with the eBPF source once the kernel-side work
        // is wired up.
        let agent = Agent::start(config, identity, Box::new(NoopEventSource))
            .await
            .context("starting agent")?;
        wait_for_shutdown().await?;
        agent.shutdown().await.context("shutting down agent")?;
        Ok::<(), anyhow::Error>(())
    })?;

    info!("bowery-agent shut down cleanly");
    Ok(())
}

async fn wait_for_shutdown() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;

    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM, shutting down"),
        _ = sigint.recv()  => info!("received SIGINT, shutting down"),
    }
    Ok(())
}

fn init_tracing(json: bool) {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if json {
        fmt()
            .with_env_filter(filter)
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .init();
    } else {
        fmt().with_env_filter(filter).compact().init();
    }
}
