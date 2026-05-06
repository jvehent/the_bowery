//! Agent configuration file.
//!
//! Loaded from a TOML file. Missing config files yield safe defaults; extra
//! unknown fields are rejected so typos don't silently no-op.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const DEFAULT_IDENTITY_PATH: &str = "/var/lib/bowery/identity.key";
const DEFAULT_KNOWN_NEIGHBORS_PATH: &str = "/var/lib/bowery/known_neighbors.json";
const DEFAULT_BASELINE_PATH: &str = "/var/lib/bowery/baseline.db";
// Phase-8 hardening (H4): a 7-day default TOFU window meant any
// attacker on the chitchat UDP port had a week to race-publish a
// synthetic identity and get permanently pinned. 2 hours is short
// enough that bootstrap must be a deliberate operator activity but
// long enough that fleet-wide rolling restarts don't all need to
// happen within minutes.
const DEFAULT_BOOTSTRAP_WINDOW_HOURS: u64 = 2;
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;
const DEFAULT_ROLE_PUBLISH_INTERVAL_SECS: u64 = 60;
const DEFAULT_LLM_INVOCATION_THRESHOLD: f32 = 0.7;
const DEFAULT_LLM_QUEUE_CAPACITY: usize = 32;
const DEFAULT_LLM_REQUEST_DEADLINE_SECS: u64 = 10;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub known_neighbors: KnownNeighborsConfig,
    #[serde(default)]
    pub mesh: MeshConfig,
    #[serde(default)]
    pub whisper: WhisperConfig,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    #[serde(default)]
    pub baseline: BaselineConfig,
    #[serde(default)]
    pub role: RoleConfig,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub operators: OperatorsConfig,
    #[serde(default)]
    pub inbox: InboxConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub bloom: BloomConfig,
    #[serde(default)]
    pub response: ResponseConfig,
    #[serde(default)]
    pub sql: SqlConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Path to the agent's Ed25519 identity key file (mode 0600).
    pub path: PathBuf,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_IDENTITY_PATH),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownNeighborsConfig {
    /// Path to the persistent TOFU pinning store (mode 0600).
    pub path: PathBuf,
    /// Window during which newly-discovered peers are auto-pinned. Recorded
    /// on disk so restarts don't reset it.
    #[serde(with = "humantime_serde", default = "default_bootstrap_window")]
    pub bootstrap_window: Duration,
    /// Hard cap on the number of pinned peers. Defends against
    /// chitchat-mesh-flood attacks that race-publish synthetic
    /// identities during the bootstrap window. Default 1024.
    #[serde(default = "default_max_pinned_peers")]
    pub max_pinned_peers: usize,
}

impl Default for KnownNeighborsConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_KNOWN_NEIGHBORS_PATH),
            bootstrap_window: default_bootstrap_window(),
            max_pinned_peers: default_max_pinned_peers(),
        }
    }
}

fn default_max_pinned_peers() -> usize {
    1024
}

fn default_bootstrap_window() -> Duration {
    Duration::from_secs(DEFAULT_BOOTSTRAP_WINDOW_HOURS * 3600)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    /// UDP socket the chitchat gossip server listens on. `0.0.0.0:9901` by default.
    #[serde(default = "default_mesh_listen_addr")]
    pub listen_addr: SocketAddr,
    /// Address other peers should use to reach us. Defaults to `listen_addr`.
    #[serde(default)]
    pub advertise_addr: Option<SocketAddr>,
    /// Seed nodes (`host:port`).
    #[serde(default)]
    pub seeds: Vec<String>,
    /// Cluster identifier; peers with mismatched cluster ids ignore each other.
    #[serde(default)]
    pub cluster_id: Option<String>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_mesh_listen_addr(),
            advertise_addr: None,
            seeds: Vec::new(),
            cluster_id: None,
        }
    }
}

fn default_mesh_listen_addr() -> SocketAddr {
    "0.0.0.0:9901".parse().expect("static addr parses")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhisperConfig {
    /// UDP socket the QUIC server binds to. `0.0.0.0:9902` by default.
    #[serde(default = "default_whisper_bind_addr")]
    pub bind_addr: SocketAddr,
    #[serde(default)]
    pub qa: WhisperQaConfig,
}

impl Default for WhisperConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_whisper_bind_addr(),
            qa: WhisperQaConfig::default(),
        }
    }
}

fn default_whisper_bind_addr() -> SocketAddr {
    "0.0.0.0:9902".parse().expect("static addr parses")
}

/// Phase-5 whisper Q&A tunables.
///
/// On a verdict whose suspicion meets or exceeds `threshold`, the agent
/// asks `fanout` of its most role-similar pinned peers whether they've
/// observed the same artifact, with a hard `timeout` per peer. Lowering
/// the threshold yields more queries (and more privacy spend); raising
/// the fanout yields more corroboration but slower aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhisperQaConfig {
    /// Verdict suspicion at which we trigger a Q&A round. Defaults to
    /// `0.6`, which is high enough to be uncommon during steady state
    /// but low enough that something the LLM might want to weigh in on
    /// will also trigger neighborhood corroboration.
    #[serde(default = "default_whisper_qa_threshold")]
    pub threshold: f32,
    /// Number of peers to ask per round.
    #[serde(default = "default_whisper_qa_fanout")]
    pub fanout: usize,
    /// Per-peer ask timeout.
    #[serde(with = "humantime_serde", default = "default_whisper_qa_timeout")]
    pub timeout: Duration,
    /// Minimum cosine similarity for a peer to be considered. `0.0`
    /// means "anything not anti-correlated"; raise it for stricter
    /// neighborhood scoping.
    #[serde(default = "default_whisper_qa_min_similarity")]
    pub min_similarity: f32,
}

impl Default for WhisperQaConfig {
    fn default() -> Self {
        Self {
            threshold: default_whisper_qa_threshold(),
            fanout: default_whisper_qa_fanout(),
            timeout: default_whisper_qa_timeout(),
            min_similarity: default_whisper_qa_min_similarity(),
        }
    }
}

fn default_whisper_qa_threshold() -> f32 {
    0.6
}
fn default_whisper_qa_fanout() -> usize {
    5
}
fn default_whisper_qa_timeout() -> Duration {
    Duration::from_secs(5)
}
fn default_whisper_qa_min_similarity() -> f32 {
    0.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineConfig {
    /// Path to the `SQLite` baseline database. The literal string `:memory:`
    /// keeps the baseline in RAM (useful for tests and ephemeral agents).
    pub path: PathBuf,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_BASELINE_PATH),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatConfig {
    /// Interval between heartbeat sweeps. 30s by default.
    #[serde(with = "humantime_serde", default = "default_heartbeat_interval")]
    pub interval: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: default_heartbeat_interval(),
        }
    }
}

fn default_heartbeat_interval() -> Duration {
    Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    /// Interval at which the agent recomputes and publishes its role
    /// vector via the mesh KV. 60s by default.
    #[serde(with = "humantime_serde", default = "default_role_publish_interval")]
    pub publish_interval: Duration,
}

impl Default for RoleConfig {
    fn default() -> Self {
        Self {
            publish_interval: default_role_publish_interval(),
        }
    }
}

fn default_role_publish_interval() -> Duration {
    Duration::from_secs(DEFAULT_ROLE_PUBLISH_INTERVAL_SECS)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmConfig {
    /// Pre-filter suspicion above which the LLM is invoked. Below this,
    /// the analyzer's verdict is taken as final.
    #[serde(default = "default_llm_threshold")]
    pub invocation_threshold: f32,
    /// Maximum pending LLM requests. New requests beyond this drop the
    /// oldest pending one to keep the pipeline unblocked.
    #[serde(default = "default_llm_queue_capacity")]
    pub queue_capacity: usize,
    /// Per-request deadline. Requests slower than this are abandoned.
    #[serde(with = "humantime_serde", default = "default_llm_request_deadline")]
    pub request_deadline: Duration,
    /// Optional: switch from the default mock backend to a real local
    /// LLM. When set and the binary was built with `--features
    /// llm-llama-cpp`, the agent loads a Qwen3-0.6B GGUF and runs
    /// inference via llama.cpp.
    #[serde(default)]
    pub llama_cpp: Option<LlamaCppConfigToml>,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            invocation_threshold: default_llm_threshold(),
            queue_capacity: default_llm_queue_capacity(),
            request_deadline: default_llm_request_deadline(),
            llama_cpp: None,
        }
    }
}

/// Mirror of `bowery_llm::LlamaCppConfig` shaped for TOML deserialisation.
/// Kept separate so the agent's config crate doesn't pull in the llama-cpp
/// build dep just to define this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlamaCppConfigToml {
    /// Path to the Qwen3-0.6B GGUF file.
    pub model_path: PathBuf,
    /// Context window in tokens.
    #[serde(default = "default_llama_n_ctx")]
    pub n_ctx: u32,
    /// CPU threads. 0 → llama.cpp default.
    #[serde(default)]
    pub n_threads: i32,
    /// GPU layers to offload (0 = pure CPU).
    #[serde(default)]
    pub n_gpu_layers: u32,
    /// Maximum tokens generated per request.
    #[serde(default = "default_llama_max_tokens")]
    pub max_tokens: usize,
    /// Sampling temperature.
    #[serde(default = "default_llama_temperature")]
    pub temperature: f32,
}

fn default_llama_n_ctx() -> u32 {
    4096
}
fn default_llama_max_tokens() -> usize {
    256
}
fn default_llama_temperature() -> f32 {
    0.2
}

fn default_llm_threshold() -> f32 {
    DEFAULT_LLM_INVOCATION_THRESHOLD
}

fn default_llm_queue_capacity() -> usize {
    DEFAULT_LLM_QUEUE_CAPACITY
}

fn default_llm_request_deadline() -> Duration {
    Duration::from_secs(DEFAULT_LLM_REQUEST_DEADLINE_SECS)
}

// ---------------------------------------------------------------------------
// Operator I/O — Phase 6a.
// ---------------------------------------------------------------------------

/// Trusted operator public keys. Each entry is a base64-encoded
/// 32-byte Ed25519 verifying key (the same format `bowery key
/// fingerprint` prints alongside the fingerprint). The agent will
/// accept signed `Subscribe` envelopes from any of these keys; all
/// other senders are rejected, even if the connection's TLS cert
/// successfully completed (operators can ride the same accept loop
/// as peer agents thanks to `CompositeResolver`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorsConfig {
    /// Base64-encoded operator verifying keys.
    #[serde(default)]
    pub pubkeys_b64: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxConfig {
    /// Maximum number of buffered alerts. Older entries are evicted
    /// FIFO at capacity.
    #[serde(default = "default_inbox_capacity")]
    pub capacity: usize,
    /// Per-alert TTL in the inbox.
    #[serde(with = "humantime_serde", default = "default_inbox_retention")]
    pub retention: Duration,
}

impl Default for InboxConfig {
    fn default() -> Self {
        Self {
            capacity: default_inbox_capacity(),
            retention: default_inbox_retention(),
        }
    }
}

fn default_inbox_capacity() -> usize {
    crate::inbox::DEFAULT_CAPACITY
}
fn default_inbox_retention() -> Duration {
    crate::inbox::DEFAULT_RETENTION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsConfig {
    /// Suspicion threshold (in `[0, 1]`) at which an LLM verdict is
    /// transcribed into an Alert and pushed to the operator inbox.
    /// Defaults to `0.7` — high enough that low-noise verdicts don't
    /// fill the inbox during steady state.
    #[serde(default = "default_alert_threshold")]
    pub threshold: f32,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            threshold: default_alert_threshold(),
        }
    }
}

fn default_alert_threshold() -> f32 {
    0.7
}

/// Phase-5 bloom-advert publisher tunables.
///
/// Each agent periodically gossips a bloom filter of its local tier-1
/// fingerprints via the mesh KV. Receivers compare epoch counters and
/// keep only the highest-epoch advert per peer; the rest are
/// discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BloomConfig {
    /// How often to recompute and re-publish the local advert.
    /// Default 60s — same cadence as role-vector publication.
    #[serde(with = "humantime_serde", default = "default_bloom_publish_interval")]
    pub publish_interval: Duration,
    /// Filter size in bits. Must be a multiple of 8 and within
    /// `bowery_whisper::fingerprint::MAX_BIT_COUNT`. Defaults to
    /// 65 536 bits (8 KiB on the wire), tuned for ~1 % FP rate at
    /// ~6 800 inserted items.
    #[serde(default = "default_bloom_bit_count")]
    pub bit_count: usize,
    /// Number of hash positions per insert (k). Tuned alongside
    /// `bit_count` for the same target FP rate. Defaults to 6.
    #[serde(default = "default_bloom_k")]
    pub k: u8,
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self {
            publish_interval: default_bloom_publish_interval(),
            bit_count: default_bloom_bit_count(),
            k: default_bloom_k(),
        }
    }
}

fn default_bloom_publish_interval() -> Duration {
    Duration::from_mins(1)
}

/// Phase-7 response-engine config.
///
/// `engine` selects the executor implementation:
/// - `"noop"` (default) — observe-only. Records every action request
///   as `Suppressed { reason }` and never touches the host. The right
///   default for any newly-rolled host until the operator has
///   validated the LLM's `suggested_actions` quality.
/// - `"process-kill"` — wraps `nix::sys::signal::kill`. On a
///   permitted `KillProcess` action, sends `SIGKILL` to the target
///   pid. The agent process needs `CAP_KILL` (root) to signal
///   processes it doesn't own.
///
/// `policy_path` points at a TOML policy file. When unset, the
/// agent uses `ResponsePolicy::default()` (deny-all) — i.e. even the
/// `process-kill` engine never actually signals anyone until an
/// operator has spelled out which action ids are permitted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseConfig {
    #[serde(default)]
    pub policy_path: Option<PathBuf>,
    #[serde(default)]
    pub engine: ResponseEngineKind,
    /// Phase-7 slice 4: signed audit-envelope log. When set, every
    /// `execute(&action)` call produces an Ed25519-signed
    /// [`AuditEnvelope`](bowery_response::AuditEnvelope) appended to
    /// this newline-delimited JSON file. When unset, the agent uses
    /// the [`NoopSink`](bowery_response::NoopSink) and emits no
    /// audit log.
    #[serde(default)]
    pub audit_log_path: Option<PathBuf>,
}

/// Phase-9: native SQL surface tunables. All fields
/// default-friendly so an existing `agent.toml` without a
/// `[sql]` block keeps working.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlConfig {
    /// SECURITY-AUDIT-PHASE9 F-8: when `true`, the `processes`
    /// table populates the `cmdline` column with the full argv.
    /// argv routinely contains DB connection strings, API
    /// tokens passed via `--token=…`, secrets, and `$HOME`
    /// paths — exposing it across a fan-out leaks credentials
    /// to operators authorised on the relay but not the peer.
    /// Default `false`.
    #[serde(default)]
    pub expose_cmdline: bool,
    /// SECURITY-AUDIT-PHASE9 F-13: maximum number of operator
    /// queries that may run concurrently per agent. Each query
    /// builds a fresh in-memory `SQLite` + registers all 13+ tables;
    /// concurrent operators scale that linearly. The semaphore
    /// holds back queries past the cap until earlier ones drain.
    /// Default `4`.
    #[serde(default = "default_max_concurrent_queries")]
    pub max_concurrent_queries: usize,
    /// Hard ceiling on per-query wall-clock timeout. The
    /// operator's requested timeout is clamped to
    /// `min(operator_request, max_timeout)`; defends against a
    /// compromised operator key hanging the host with a
    /// deliberately long-running query. Default `30s`.
    #[serde(with = "humantime_serde", default = "default_sql_max_timeout")]
    pub max_timeout: Duration,
}

impl Default for SqlConfig {
    fn default() -> Self {
        Self {
            expose_cmdline: false,
            max_concurrent_queries: default_max_concurrent_queries(),
            max_timeout: default_sql_max_timeout(),
        }
    }
}

fn default_max_concurrent_queries() -> usize {
    4
}

fn default_sql_max_timeout() -> Duration {
    Duration::from_secs(30)
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseEngineKind {
    /// Observe-only. Never executes.
    #[default]
    Noop,
    /// `SIGKILL`-via-`nix`. Real enforcement. Requires `CAP_KILL`.
    ProcessKill,
    /// BPF-LSM `bprm_check_security` hook + userspace
    /// `BLOCKED_COMMS` map. Implements `block_exec` autonomously.
    /// Requires `CAP_BPF` + `CAP_SYS_ADMIN` and a kernel with
    /// `CONFIG_BPF_LSM=y` and `bpf` in the active LSM cmdline.
    BpfLsm,
}
fn default_bloom_bit_count() -> usize {
    bowery_whisper::fingerprint::DEFAULT_BIT_COUNT
}
fn default_bloom_k() -> u8 {
    bowery_whisper::fingerprint::DEFAULT_K
}

impl Config {
    /// Load the config file. If it doesn't exist, returns defaults.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                toml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
}

// Tiny inline `humantime_serde` shim — accepts strings like "30s" or "7d".
mod humantime_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(d: &Duration, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(&format!("{}s", d.as_secs()))
    }

    pub(super) fn deserialize<'de, D>(de: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }

    fn parse_duration(s: &str) -> Result<Duration, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty duration".into());
        }
        let (num, suffix) = s.split_at(s.len() - 1);
        let n: u64 = num
            .parse()
            .map_err(|e| format!("invalid duration `{s}`: {e}"))?;
        let secs = match suffix {
            "s" => n,
            "m" => n * 60,
            "h" => n * 3600,
            "d" => n * 86_400,
            other => return Err(format!("unknown duration suffix `{other}` in `{s}`")),
        };
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(&dir.path().join("missing.toml")).unwrap();
        assert_eq!(cfg.identity.path, PathBuf::from(DEFAULT_IDENTITY_PATH));
        assert_eq!(
            cfg.known_neighbors.path,
            PathBuf::from(DEFAULT_KNOWN_NEIGHBORS_PATH)
        );
        assert_eq!(
            cfg.heartbeat.interval,
            Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS)
        );
    }

    #[test]
    fn parses_bootstrap_window_human_string() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(
            &path,
            r#"
[identity]
path = "/tmp/id"

[known_neighbors]
path = "/tmp/kn"
bootstrap_window = "7d"

[heartbeat]
interval = "5s"
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(
            cfg.known_neighbors.bootstrap_window,
            Duration::from_hours(7 * 24)
        );
        assert_eq!(cfg.heartbeat.interval, Duration::from_secs(5));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, "nonsense = 1\n").unwrap();
        assert!(Config::load(&path).is_err());
    }
}
