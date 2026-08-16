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
use clap::{Parser, Subcommand};

use bowery_cli::{alerts, audit, doctor, exec, mesh_trust, model, notify, peers, virustotal};

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

    /// Look a SHA-256 up on `VirusTotal`.
    ///
    /// Hashes only — no file is ever uploaded. Be aware that a lookup
    /// discloses to `VirusTotal`, and to anyone with Intelligence access,
    /// that somebody is investigating this hash. Adversaries watch VT
    /// for their own samples, so for a suspected targeted implant this
    /// is a decision to make deliberately rather than a reflex.
    ///
    /// Agents never do this: it would put an API key on every monitored
    /// host and disclose findings before an operator had decided to.
    Vt {
        /// Hex SHA-256 of the binary. `bowery alerts` prints these.
        sha256: String,
        /// File containing only the API key, mode 0600.
        #[arg(long, default_value = "~/.bowery/virustotal.key")]
        api_key_file: PathBuf,
    },

    /// Email new alerts to an operator who isn't watching a console.
    ///
    /// Drains every agent in the peer manifest over the same signed
    /// transport `bowery alerts` uses, filters by the rules in the
    /// notify config, and sends ONE digest. Single-shot by design: run
    /// it from a systemd timer, which is what holds the CLI open on
    /// your behalf.
    ///
    /// Sends nothing when nothing is new, so a timer can fire often.
    Notify {
        /// Operator identity key used to sign the Subscribe.
        #[arg(long, default_value = "~/.bowery/operator.key")]
        operator_key: PathBuf,
        /// Notify config (SMTP + filters).
        #[arg(long, default_value = "~/.bowery/notify.toml")]
        config: PathBuf,
        /// Peer manifest naming the agents to poll.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Where per-agent delivery cursors are kept.
        #[arg(long, default_value = "~/.bowery/notify-cursor.json")]
        cursor_file: PathBuf,
        /// Compose and print the message without sending, and without
        /// advancing cursors. Needs no SMTP credential.
        #[arg(long)]
        dry_run: bool,
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

    /// Mesh trust (Phase 3): admit agents to the mesh with signed
    /// membership grants, and eject compromised ones with signed
    /// revocations.
    ///
    /// Both are offline signing operations — nothing here talks to the
    /// network, so they work from an air-gapped key holder.
    #[command(subcommand)]
    Trust(TrustCommand),
}

#[derive(Subcommand, Debug)]
enum TrustCommand {
    /// Mint an operator-signed membership grant admitting one agent to
    /// one cluster.
    ///
    /// Copy the output to the agent and point `[known_neighbors]
    /// grant_path` at it. The agent gossips it so peers running
    /// `enrollment = "grant"` can verify and pin it.
    Grant {
        /// Path to the operator's identity key file.
        #[arg(long)]
        operator_key: PathBuf,
        /// Hex-encoded fingerprint of the agent being admitted.
        #[arg(long)]
        agent_fp: String,
        /// Mesh cluster id. Must match the agent's `[mesh] cluster_id`.
        #[arg(long, default_value = "bowery")]
        cluster_id: String,
        /// Validity window (`30d`, `1y`). Omit for a grant that never
        /// expires.
        #[arg(long, value_parser = parse_duration)]
        valid_for: Option<Duration>,
        /// Write here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Mint an operator-signed revocation ejecting one agent from the
    /// mesh, permanently.
    ///
    /// There is no un-revoke: re-admitting a rebuilt host means giving
    /// it a new identity key.
    Revoke {
        #[arg(long)]
        operator_key: PathBuf,
        /// Hex-encoded fingerprint of the agent being ejected.
        #[arg(long)]
        agent_fp: String,
        #[arg(long, default_value = "bowery")]
        cluster_id: String,
        /// Operator note, carried in the revocation for the audit trail.
        #[arg(long, default_value = "revoked by operator")]
        reason: String,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Also deliver it: dial this agent and push the revocation.
        /// Requires --agent-fp-target and --agent-pubkey-b64.
        #[arg(long)]
        agent_addr: Option<SocketAddr>,
        /// Fingerprint of the agent to dial (NOT the one being revoked).
        #[arg(long)]
        relay_fp: Option<String>,
        /// Base64 verifying key of the agent being dialled.
        #[arg(long)]
        relay_pubkey_b64: Option<String>,
        /// Verifying keys of peers that may report back under --fanout.
        /// `~/.bowery/peers.toml` entries are loaded automatically; use
        /// this for agents not in the manifest.
        #[arg(long = "peer-pubkey-b64")]
        peer_pubkeys_b64: Vec<String>,
        /// Propagate onward through the mesh from the dialled agent.
        /// Each hop applies the revocation and forwards it only if it
        /// was new, so a flood converges instead of echoing.
        #[arg(long)]
        fanout: bool,
        /// Hop budget for propagation (clamped to 8 by the agent).
        #[arg(long, default_value_t = 4)]
        ttl: u32,
        #[arg(long, default_value = "10s", value_parser = parse_duration)]
        timeout: Duration,
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
        /// Optional whisper address (`host:port`, e.g.
        /// `100.64.0.5:9902`). Enables `bowery peers check` and
        /// direct per-agent queries. Omit for fan-out-only entries.
        #[arg(long)]
        addr: Option<String>,
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
    /// Dial every peer with an address and report reachability
    /// (QUIC handshake + cert pin + operator auth + `SELECT 1`).
    Check {
        /// Operator identity key used to authenticate the probe.
        #[arg(long)]
        operator_key: PathBuf,
        /// Per-agent dial deadline (`5s`, `10s`, …).
        #[arg(long, default_value = "5s", value_parser = parse_duration)]
        timeout: Duration,
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
        /// agent's name and fingerprint (extra `_agent_name` and
        /// `_agent_fp` columns in output). Without this flag, only the directly-dialled
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

        /// Narrate the envelopes exchanged with the mesh.
        ///
        /// Fan-out is the one path where "fewer rows than I expected"
        /// has several very different causes — a peer that never
        /// replied, one that returned an error, a relay that closed
        /// early — and the results alone cannot tell them apart. This
        /// shows each chunk as it arrives, flags any peer whose
        /// self-declared `agent_fp` disagrees with the key that signed
        /// it, and prints a per-agent row tally at the end.
        ///
        /// Writes to stderr, so redirecting stdout still gives a clean
        /// result file.
        #[arg(long)]
        verbose_whisper: bool,
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
    /// Distribute a YARA rule file to an agent, scan the given targets
    /// with it, and optionally propagate it across the whisper mesh.
    ///
    /// The rule travels inside the operator-signed command, so every
    /// agent it reaches verifies *your* signature over the exact rule
    /// bytes and targets — a relaying agent can drop a rule but cannot
    /// forge or alter one.
    Yara {
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
        /// Path to the `.yar` rule file to distribute.
        #[arg(long)]
        rules: PathBuf,
        /// Absolute path (file or directory) for the agents to scan.
        /// Repeat for several. Omit to store + propagate without
        /// scanning.
        #[arg(long = "target")]
        targets: Vec<String>,
        /// Wall-clock deadline for the agent-side scan.
        #[arg(long, default_value = "30s", value_parser = parse_duration)]
        timeout: Duration,
        /// Propagate the rule through the mesh: each agent forwards it
        /// to its pinned peers until the hop budget (`--ttl`) runs out.
        /// Agents drop pushes they've already handled, so a cyclic mesh
        /// terminates instead of looping.
        #[arg(long)]
        fanout: bool,
        /// Hop budget for `--fanout`. Each agent decrements it before
        /// forwarding; agents also clamp it to their own configured
        /// maximum.
        #[arg(long, default_value_t = 4)]
        ttl: u32,
        /// Base64-encoded Ed25519 verifying key of a peer that may
        /// report back. Repeat per peer. `~/.bowery/peers.toml` is
        /// loaded automatically; this extends it for one-off pushes.
        #[arg(long = "peer-pubkey-b64")]
        peer_pubkeys_b64: Vec<String>,
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

// SqlFormat now lives in `bowery_cli::exec` so the library can
// expose it to console-style consumers; the binary references it
// through the same path.
pub use bowery_cli::exec::SqlFormat;

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
            Command::Trust(TrustCommand::Grant {
                operator_key,
                agent_fp,
                cluster_id,
                valid_for,
                out,
            }) => {
                mesh_trust::mint_grant(&operator_key, &agent_fp, &cluster_id, valid_for, out)?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Trust(TrustCommand::Revoke {
                operator_key,
                agent_fp,
                cluster_id,
                reason,
                out,
                agent_addr,
                relay_fp,
                relay_pubkey_b64,
                peer_pubkeys_b64,
                fanout,
                ttl,
                timeout,
            }) => {
                let encoded = mesh_trust::mint_revocation(
                    &operator_key,
                    &agent_fp,
                    &cluster_id,
                    &reason,
                    out,
                    agent_addr.is_none(),
                )?;
                let Some(addr) = agent_addr else {
                    return Ok(ExitCode::SUCCESS);
                };
                let (Some(fp), Some(pubkey)) = (relay_fp, relay_pubkey_b64) else {
                    anyhow::bail!(
                        "--agent-addr also needs --relay-fp and --relay-pubkey-b64 \
                         (the agent being DIALLED, not the one being revoked)"
                    );
                };
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("building tokio runtime")?;
                runtime.block_on(exec::revoke_push(
                    operator_key,
                    addr,
                    fp,
                    pubkey,
                    peer_pubkeys_b64,
                    encoded,
                    timeout,
                    fanout,
                    ttl,
                ))?;
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
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
                    )
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
            Command::Vt {
                sha256,
                api_key_file,
            } => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("building tokio runtime")?;
                let key = virustotal::read_api_key(&notify::expand_tilde(&api_key_file))?;
                let client = virustotal::VtClient::new(key)?;
                let verdict = runtime.block_on(client.lookup(&sha256));
                println!("{}", verdict.summary());
                // Exit code carries the verdict so a script can branch:
                // 0 clean, 1 flagged, 2 unknown or unavailable. Absence
                // of a detection is not the same as a clean bill, so
                // "unknown" is deliberately not 0.
                Ok(match verdict {
                    virustotal::Verdict::Clean { .. } => ExitCode::SUCCESS,
                    virustotal::Verdict::Malicious { .. } => ExitCode::from(1),
                    _ => ExitCode::from(2),
                })
            }
            Command::Notify {
                operator_key,
                config,
                manifest,
                cursor_file,
                dry_run,
            } => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
                    )
                    .with_target(false)
                    .with_writer(std::io::stderr)
                    .init();
                let manifest_path = match manifest {
                    Some(p) => p,
                    None => peers::default_path()?,
                };
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("building tokio runtime")?;
                runtime.block_on(notify::run(&notify::RunArgs {
                    operator_key: notify::expand_tilde(&operator_key),
                    config_path: notify::expand_tilde(&config),
                    manifest_path,
                    cursor_path: notify::expand_tilde(&cursor_file),
                    dry_run,
                }))?;
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
                    ExecCommand::Sql {
                        operator_key,
                        agent_addr,
                        agent_fp,
                        agent_pubkey_b64,
                        sql,
                        timeout,
                        fanout,
                        verbose_whisper,
                        peer_pubkeys_b64,
                        format,
                    },
            } => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
                    )
                    .with_target(false)
                    .with_writer(std::io::stderr)
                    .init();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("building tokio runtime")?;
                let mut sink = exec::make_stdout_sink(format, fanout);
                runtime.block_on(exec::sql(
                    operator_key,
                    agent_addr,
                    agent_fp,
                    agent_pubkey_b64,
                    peer_pubkeys_b64,
                    sql,
                    timeout,
                    fanout,
                    verbose_whisper,
                    sink.as_mut(),
                ))?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Exec {
                sub:
                    ExecCommand::Yara {
                        operator_key,
                        agent_addr,
                        agent_fp,
                        agent_pubkey_b64,
                        rules,
                        targets,
                        timeout,
                        fanout,
                        ttl,
                        peer_pubkeys_b64,
                    },
            } => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
                    )
                    .with_target(false)
                    .with_writer(std::io::stderr)
                    .init();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("building tokio runtime")?;
                runtime.block_on(exec::yara(
                    operator_key,
                    agent_addr,
                    agent_fp,
                    agent_pubkey_b64,
                    peer_pubkeys_b64,
                    rules,
                    targets,
                    timeout,
                    fanout,
                    ttl,
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
                        addr,
                        ..
                    } => peers::add(&path, &name, &fp, &pubkey_b64, addr.as_deref())?,
                    PeersCommand::Remove { fp, .. } => peers::remove(&path, &fp)?,
                    PeersCommand::List { .. } => peers::list(&path)?,
                    PeersCommand::Check {
                        operator_key,
                        timeout,
                        ..
                    } => {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .context("building tokio runtime")?;
                        let all_ok =
                            runtime.block_on(peers::check(&path, &operator_key, timeout))?;
                        return Ok(if all_ok {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        });
                    }
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
        | PeersCommand::List { path }
        | PeersCommand::Check { path, .. } => path.clone(),
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
