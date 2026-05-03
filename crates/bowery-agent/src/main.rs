//! Thin entrypoint: parse args, init logging, build an [`Agent`], run until
//! a termination signal arrives.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use bowery_agent::{Agent, Config};
use bowery_crypto::Identity;
use bowery_ebpf_loader::BpfEventSource;
use bowery_events::source::{EventSource, NoopEventSource};
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
        // Try to attach the BPF source. If the BPF object isn't installed
        // (host without KRSI, packaging miss, or in-tree dev without
        // running build-ebpf), fall back to NoopEventSource and run with
        // baseline+mesh+heartbeat only.
        let event_source: Box<dyn EventSource> = match BpfEventSource::from_default_locations() {
            Ok(src) => {
                info!(path = %src.obj_path().display(), "attached BPF event source");
                Box::new(src)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "BPF event source unavailable; running without kernel events"
                );
                Box::new(NoopEventSource)
            }
        };

        // Pick the LLM backend. With `--features llm-llama-cpp` and a
        // `[llm.llama_cpp]` block in the config, we load Qwen3-0.6B
        // via llama.cpp; otherwise the Agent's default mock is used.
        let agent = match build_llm(&config).await? {
            Some(llm) => Agent::start_with_llm(config, identity, event_source, llm)
                .await
                .context("starting agent (llama-cpp)")?,
            None => Agent::start(config, identity, event_source)
                .await
                .context("starting agent")?,
        };
        wait_for_shutdown().await?;
        agent.shutdown().await.context("shutting down agent")?;
        Ok::<(), anyhow::Error>(())
    })?;

    info!("bowery-agent shut down cleanly");
    Ok(())
}

/// Construct the optional real LLM backend. Returns `None` when the
/// agent should use its default (mock) analyzer.
///
/// Without `--features llm-llama-cpp`, this is a no-op that warns if
/// the operator configured `[llm.llama_cpp]` anyway (so a misconfigured
/// build doesn't silently fall back to mock).
#[cfg(feature = "llm-llama-cpp")]
async fn build_llm(config: &Config) -> Result<Option<Arc<dyn bowery_llm::LlmAnalyzer>>> {
    use bowery_llm::{LlamaCppAnalyzer, LlamaCppConfig};

    let Some(toml) = &config.llm.llama_cpp else {
        return Ok(None);
    };

    let llama_cfg = LlamaCppConfig {
        model_path: toml.model_path.clone(),
        n_ctx: toml.n_ctx,
        n_threads: toml.n_threads,
        n_gpu_layers: toml.n_gpu_layers,
        max_tokens: toml.max_tokens,
        temperature: toml.temperature,
    };
    info!(
        model = %llama_cfg.model_path.display(),
        n_ctx = llama_cfg.n_ctx,
        n_threads = llama_cfg.n_threads,
        "loading Qwen3 GGUF via llama-cpp"
    );
    let analyzer = LlamaCppAnalyzer::new(llama_cfg)
        .await
        .context("loading Qwen3 model")?;
    Ok(Some(Arc::new(analyzer) as Arc<dyn bowery_llm::LlmAnalyzer>))
}

// Without the feature this function does no I/O, but the call site
// awaits it (so the feature-on variant can use `.await`). Allow the
// "unused async" lint just here.
#[cfg(not(feature = "llm-llama-cpp"))]
#[allow(clippy::unused_async)]
async fn build_llm(config: &Config) -> Result<Option<Arc<dyn bowery_llm::LlmAnalyzer>>> {
    if config.llm.llama_cpp.is_some() {
        tracing::warn!(
            "[llm.llama_cpp] is set but the binary was built without \
             --features llm-llama-cpp; falling back to the mock LLM"
        );
    }
    Ok(None)
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
