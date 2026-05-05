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
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_crypto::Identity;
use clap::{Parser, Subcommand, ValueEnum};

mod alerts;
mod audit;
mod doctor;
mod exec;
mod model;
mod peers;

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

    /// Fetch and validate LLM model artifacts (GGUF files) from a
    /// curated registry. Models are written to a local cache directory
    /// the agent reads at startup; nothing is downloaded at agent
    /// runtime or compile time.
    Model {
        #[command(subcommand)]
        sub: ModelCommand,
    },

    /// Validate an agent's signed audit log.
    ///
    /// The agent emits one Ed25519-signed envelope per action attempt
    /// when `[response] audit_log_path` is configured. This command
    /// verifies every line against the host's pubkey and exits non-
    /// zero on the first failure (signature or parse error).
    Audit {
        #[command(subcommand)]
        sub: AuditCommand,
    },

    /// Send a typed operator command to an agent and print the result.
    ///
    /// Phase 6b. Each subcommand maps to one
    /// [`bowery_proto::OperatorCommandBody`] variant. The CLI
    /// authenticates with the operator key (must be in the agent's
    /// `[operators] pubkeys_b64` list) and TLS-pins the agent the
    /// same way `alerts tail` does.
    Exec {
        #[command(subcommand)]
        sub: ExecCommand,
    },

    /// Manage the operator-side peer manifest at
    /// `~/.bowery/peers.toml`. Each entry is the fingerprint +
    /// pubkey of an agent that may respond to a fan-out query;
    /// `bowery exec sql --fanout` auto-loads them into the
    /// operator's verifier resolver so peer-sealed `SqlChunk`
    /// envelopes verify cleanly.
    Peers {
        #[command(subcommand)]
        sub: PeersCommand,
    },
}

#[derive(Subcommand, Debug)]
enum PeersCommand {
    /// Add or replace an entry in the manifest. Replaces by `fp`
    /// (fingerprint) if one already exists.
    Add {
        /// Operator-friendly label (e.g. `web-1`, `db-primary`).
        #[arg(long)]
        name: String,
        /// Hex-encoded 32-byte agent fingerprint.
        #[arg(long)]
        fp: String,
        /// Base64-encoded Ed25519 verifying key.
        #[arg(long)]
        pubkey_b64: String,
        /// Manifest path. Default `$HOME/.bowery/peers.toml`.
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Remove an entry by fingerprint. Idempotent.
    Remove {
        /// Hex-encoded fingerprint to remove.
        #[arg(long)]
        fp: String,
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Print every entry in the manifest.
    List {
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum ExecCommand {
    /// Run a native Bowery SQL query (Phase-9 surface) against the
    /// agent's `bowery-sql` engine. The agent streams the response
    /// in chunks; the CLI prints rows as they arrive.
    Sql {
        /// Path to the operator's identity key file.
        #[arg(long)]
        operator_key: PathBuf,
        /// Agent's whisper bind address (e.g. `127.0.0.1:9902`).
        #[arg(long)]
        agent_addr: SocketAddr,
        /// Hex-encoded fingerprint of the agent's identity key.
        #[arg(long)]
        agent_fp: String,
        /// Base64-encoded Ed25519 verifying key of the agent.
        #[arg(long)]
        agent_pubkey_b64: String,
        /// SQL string evaluated by `bowery-sql` against the
        /// agent's native Phase-9 tables (e.g. `processes`,
        /// `listening_ports`, `users`).
        #[arg(long)]
        sql: String,
        /// Wall-clock deadline for the agent-side query. Accepts
        /// humantime expressions (`5s`, `30s`, `2m`).
        #[arg(long, default_value = "10s", value_parser = parse_duration)]
        timeout: Duration,
        /// Phase-9 slice 7: when set, the dialled agent acts as a
        /// **relay** and dispatches the query to its pinned peers
        /// in parallel. Rows from each agent are tagged with the
        /// agent's fingerprint (extra `_agent_fp` column in
        /// output). Without this flag, only the directly-dialled
        /// agent runs the query.
        ///
        /// Phase-9 final-1: with fanout=true, each peer seals its
        /// `SqlChunk` envelopes for the operator directly, so the
        /// operator must know the peer's pubkey to verify the
        /// signature. Pass `--peer-pubkey-b64 <base64>` once per
        /// peer you expect to respond. Peers whose pubkey isn't
        /// supplied will surface as `BadSignature` rejections.
        #[arg(long)]
        fanout: bool,
        /// Base64-encoded Ed25519 verifying key of a peer that may
        /// respond to a fan-out query. Repeat for each peer you
        /// trust; the operator-side verifier registers all of
        /// them in its resolver. Ignored unless `--fanout` is
        /// set.
        #[arg(long = "peer-pubkey-b64")]
        peer_pubkeys_b64: Vec<String>,
        /// Output format. `tsv` (default) streams one row per
        /// line, tab-separated. `json` streams one object per
        /// line preceded by a column-name array. `table` buffers
        /// the full result and renders an aligned ASCII table at
        /// the end (don't use with multi-million-row queries —
        /// it'll OOM the operator's terminal).
        #[arg(long, default_value_t = SqlFormat::Tsv)]
        format: SqlFormat,
    },
    /// Run a SQL query via the agent's optional subprocess
    /// `sysquery` handler (must be enabled in the agent config and
    /// the binary present on disk). Returns the wrapped binary's
    /// JSON output verbatim.
    Sysquery {
        /// Path to the operator's identity key file.
        #[arg(long)]
        operator_key: PathBuf,
        /// Agent's whisper bind address (e.g. `127.0.0.1:9902`).
        #[arg(long)]
        agent_addr: SocketAddr,
        /// Hex-encoded fingerprint of the agent's identity key.
        #[arg(long)]
        agent_fp: String,
        /// Base64-encoded Ed25519 verifying key of the agent.
        #[arg(long)]
        agent_pubkey_b64: String,
        /// SQL string. Read-only by convention; the agent may
        /// additionally refuse the query at policy-check time.
        #[arg(long)]
        sql: String,
        /// Wall-clock deadline for the agent-side handler. Accepts
        /// humantime expressions (e.g. `5s`, `30s`, `2m`).
        #[arg(long, default_value = "10s", value_parser = parse_duration)]
        timeout: Duration,
        /// Emit the result as a single JSON object (full envelope
        /// shape) instead of just the wrapped binary's JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommand {
    /// Verify every envelope in `path` against the agent's pubkey.
    ///
    /// Exit code is 0 when all entries verify and 1 when any entry
    /// fails (signature mismatch, parse error, or fingerprint
    /// mismatch). The host pubkey can be supplied either as base64
    /// (paste from `bowery key info`) or via the agent's identity
    /// file path.
    Verify {
        /// Path to the agent's audit log (newline-delimited JSON).
        path: PathBuf,
        /// Base64-encoded Ed25519 verifying key of the agent host.
        /// Mutually exclusive with `--pubkey-from`.
        #[arg(long)]
        pubkey_b64: Option<String>,
        /// Path to the agent's identity file. The pubkey is derived
        /// from it. Mutually exclusive with `--pubkey-b64`.
        #[arg(long)]
        pubkey_from: Option<PathBuf>,
        /// Emit one JSON object per audit line instead of human
        /// output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ModelCommand {
    /// List the curated set of known models.
    List,
    /// Download a model into the local cache (default
    /// `$HOME/.bowery/models/`). Validates the GGUF magic + size and,
    /// when the registry pins one, the sha256 hash.
    Fetch {
        /// Registry name (see `bowery model list`). E.g.
        /// `qwen3-0.6b-q4_k_m`.
        name: String,
        /// Output directory. Defaults to `$HOME/.bowery/models/`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Re-download even if a same-named file is already present.
        #[arg(long)]
        force: bool,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum SqlFormat {
    /// Tab-separated values, one row per line. Streams.
    Tsv,
    /// One JSON object per row, column-name array on first line.
    /// Streams.
    Json,
    /// Aligned ASCII table. Buffered — emitted on stream close.
    Table,
}

impl std::fmt::Display for SqlFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tsv => "tsv",
            Self::Json => "json",
            Self::Table => "table",
        })
    }
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
    /// Print fingerprint + base64 pubkey for an existing key file.
    /// Useful when populating an agent's `[operators] pubkeys_b64`
    /// list or wiring `bowery alerts tail`'s `--agent-pubkey-b64`
    /// flag.
    Info {
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
    #[allow(clippy::too_many_lines)] // top-level CLI dispatch; one arm per subcommand
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
            Command::Key(KeyCommand::Info { path }) => {
                key_info(&path)?;
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
            Command::Model {
                sub: ModelCommand::List,
            } => {
                model::list();
                Ok(ExitCode::SUCCESS)
            }
            Command::Model {
                sub: ModelCommand::Fetch { name, out, force },
            } => {
                let out_dir = match out {
                    Some(p) => p,
                    None => model::default_out_dir()?,
                };
                model::fetch(&name, &out_dir, force)?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Audit {
                sub:
                    AuditCommand::Verify {
                        path,
                        pubkey_b64,
                        pubkey_from,
                        json,
                    },
            } => audit::verify(&path, pubkey_b64, pubkey_from, json),
            Command::Exec {
                sub:
                    ExecCommand::Sysquery {
                        operator_key,
                        agent_addr,
                        agent_fp,
                        agent_pubkey_b64,
                        sql,
                        timeout,
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
                runtime.block_on(exec::sysquery(
                    operator_key,
                    agent_addr,
                    agent_fp,
                    agent_pubkey_b64,
                    sql,
                    timeout,
                    json,
                ))?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Exec {
                sub:
                    ExecCommand::Sql {
                        operator_key,
                        agent_addr,
                        agent_fp,
                        agent_pubkey_b64,
                        sql,
                        timeout,
                        fanout,
                        peer_pubkeys_b64,
                        format,
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
                runtime.block_on(exec::sql(
                    operator_key,
                    agent_addr,
                    agent_fp,
                    agent_pubkey_b64,
                    peer_pubkeys_b64,
                    sql,
                    timeout,
                    fanout,
                    format,
                ))?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Peers { sub } => {
                let path = match peers_path_for(&sub) {
                    Some(p) => p,
                    None => peers::default_path()?,
                };
                match sub {
                    PeersCommand::Add {
                        name,
                        fp,
                        pubkey_b64,
                        ..
                    } => peers::add(&path, &name, &fp, &pubkey_b64)?,
                    PeersCommand::Remove { fp, .. } => peers::remove(&path, &fp)?,
                    PeersCommand::List { .. } => peers::list(&path)?,
                }
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}

fn peers_path_for(cmd: &PeersCommand) -> Option<PathBuf> {
    match cmd {
        PeersCommand::Add { path, .. }
        | PeersCommand::Remove { path, .. }
        | PeersCommand::List { path } => path.clone(),
    }
}

fn key_generate(path: &PathBuf) -> Result<()> {
    let identity = Identity::generate();
    identity
        .save(path)
        .with_context(|| format!("writing identity to {}", path.display()))?;
    let pubkey_b64 = BASE64.encode(identity.verifying_key().as_bytes());
    println!("wrote identity to {}", path.display());
    println!("fingerprint: {}", identity.fingerprint());
    println!("pubkey_b64:  {pubkey_b64}");
    Ok(())
}

fn key_fingerprint(path: &PathBuf) -> Result<()> {
    let identity = Identity::load(path)
        .with_context(|| format!("loading identity from {}", path.display()))?;
    println!("{}", identity.fingerprint());
    Ok(())
}

fn key_info(path: &PathBuf) -> Result<()> {
    let identity = Identity::load(path)
        .with_context(|| format!("loading identity from {}", path.display()))?;
    let pubkey_b64 = BASE64.encode(identity.verifying_key().as_bytes());
    println!("path:        {}", path.display());
    println!("fingerprint: {}", identity.fingerprint());
    println!("pubkey_b64:  {pubkey_b64}");
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
