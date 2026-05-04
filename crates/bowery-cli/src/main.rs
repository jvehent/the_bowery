//! `bowery` — operator CLI for The Bowery.
//!
//! Phase 0 surface: identity-key management.
//! Phase 2.5 addition: `bowery doctor` host-readiness check.
//! Subsequent phases add `query`, `hunt`, `alerts tail`, `action ...`,
//! `authorization grant`, `model push`, etc.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use bowery_crypto::Identity;
use clap::{Parser, Subcommand};

mod alerts;
mod doctor;

#[derive(Parser, Debug)]
#[command(
    name = "bowery",
    version,
    about = "The Bowery operator CLI",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage operator identity keys.
    #[command(subcommand)]
    Key(KeyCommand),

    /// Check whether this host is ready to run a Bowery agent.
    ///
    /// Probes kernel version, BPF-LSM, BTF, bpffs, lsm= cmdline, and
    /// kernel config. Exit code is 0 when ready (warnings allowed) and 1
    /// when one or more checks fail.
    Doctor {
        /// Emit results as JSON instead of human-readable.
        #[arg(long)]
        json: bool,
    },

    /// Drain (and optionally follow) an agent's operator inbox.
    ///
    /// Authenticates with the operator key (must be configured on the
    /// target agent's `[operators] pubkeys_b64` list). The agent's TLS
    /// fingerprint and pubkey must be passed explicitly — operators
    /// don't ride the TOFU pin store.
    Alerts {
        #[command(subcommand)]
        sub: AlertsCommand,
    },
}

#[derive(Subcommand, Debug)]
enum AlertsCommand {
    /// Print every alert in the agent's inbox since the cursor, then exit
    /// (or, with --follow, re-poll every `--interval`).
    Tail {
        /// Path to the operator's identity key file.
        #[arg(long)]
        operator_key: PathBuf,
        /// Agent's whisper bind address (e.g. `127.0.0.1:9902`).
        #[arg(long)]
        agent_addr: SocketAddr,
        /// Hex-encoded fingerprint of the agent's identity key.
        #[arg(long)]
        agent_fp: String,
        /// Base64-encoded Ed25519 verifying key of the agent (the
        /// pubkey half of its identity). Used for the TLS pinning.
        #[arg(long)]
        agent_pubkey_b64: String,
        /// Cursor: only return alerts with `ts_unix_ms >= since-ms`.
        /// `0` means "the entire inbox".
        #[arg(long, default_value_t = 0)]
        since_ms: u64,
        /// Re-poll the agent every `--interval` instead of exiting.
        #[arg(long)]
        follow: bool,
        /// Polling interval for `--follow`. Accepts humantime
        /// expressions like `2s`, `500ms`.
        #[arg(long, default_value = "2s", value_parser = parse_duration)]
        interval: Duration,
        /// Emit alerts as one JSON object per line instead of human-
        /// readable.
        #[arg(long)]
        json: bool,
    },
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| e.to_string())
}

#[derive(Subcommand, Debug)]
enum KeyCommand {
    /// Generate a new operator identity key and write it to the given path.
    Generate {
        /// Path to write the new key. Refuses to overwrite an existing file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the fingerprint of an identity key file.
    Fingerprint {
        /// Path to the key file.
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

impl Cli {
    fn run(self) -> Result<ExitCode> {
        match self.command {
            Command::Key(KeyCommand::Generate { out }) => {
                key_generate(&out)?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Key(KeyCommand::Fingerprint { path }) => {
                key_fingerprint(&path)?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Doctor { json } => doctor_cmd(json),
            Command::Alerts {
                sub:
                    AlertsCommand::Tail {
                        operator_key,
                        agent_addr,
                        agent_fp,
                        agent_pubkey_b64,
                        since_ms,
                        follow,
                        interval,
                        json,
                    },
            } => {
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::WARN)
                    .with_target(false)
                    .with_writer(std::io::stderr)
                    .init();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("building tokio runtime")?;
                runtime.block_on(alerts::run(
                    operator_key,
                    agent_addr,
                    agent_fp,
                    agent_pubkey_b64,
                    since_ms,
                    follow,
                    interval,
                    json,
                ))?;
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}

fn key_generate(path: &PathBuf) -> Result<()> {
    let identity = Identity::generate();
    identity
        .save(path)
        .with_context(|| format!("writing identity to {}", path.display()))?;
    println!("wrote identity to {}", path.display());
    println!("fingerprint: {}", identity.fingerprint());
    Ok(())
}

fn key_fingerprint(path: &PathBuf) -> Result<()> {
    let identity = Identity::load(path)
        .with_context(|| format!("loading identity from {}", path.display()))?;
    println!("{}", identity.fingerprint());
    Ok(())
}

fn doctor_cmd(json: bool) -> Result<ExitCode> {
    let report = doctor::run();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        doctor::print_human(&report);
    }
    Ok(match report.verdict {
        doctor::Verdict::Ready => ExitCode::SUCCESS,
        doctor::Verdict::NotReady => ExitCode::FAILURE,
    })
}
