//! Agent configuration file.
//!
//! Loaded from a TOML file. Missing config files yield safe defaults; extra
//! unknown fields are rejected so typos don't silently no-op.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bowery_analysis::RuleSeverity;
use bowery_events::FileOp;
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
    #[serde(default)]
    pub monitor: MonitorConfig,
    #[serde(default)]
    pub yara: YaraConfig,
    #[serde(default)]
    pub eventlog: EventLogConfig,
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
    /// How a peer earns a pin. See [`EnrollmentPolicy`].
    #[serde(default)]
    pub enrollment: EnrollmentPolicy,
    /// Path to this agent's own operator-signed membership grant
    /// (`bowery enroll grant` writes one). Published into the mesh KV so
    /// peers can verify it. Absent under `tofu`; required under `grant`
    /// or no peer will pin this agent.
    #[serde(default)]
    pub grant_path: Option<PathBuf>,
    /// File of operator-signed revocations — one base64 `Revocation`
    /// per line, exactly as `bowery trust revoke` emits. Every line is
    /// re-verified against the configured operator keys on load, so the
    /// file carries no authority of its own: editing it can remove a
    /// revocation but cannot manufacture one. Consulted on every pin,
    /// and revoked peers are evicted at startup.
    #[serde(default = "default_revocations_path")]
    pub revocations_path: PathBuf,
}

/// How a peer earns a pin.
///
/// `Tofu` is the historical behaviour and remains the default so that
/// upgrading an existing fleet doesn't partition it — but it is the
/// weaker mode, and deliberately so named that it reads as a choice
/// rather than an absence of one. Gossip is unauthenticated UDP, so
/// under `Tofu` "can reach port 9901 during the bootstrap window" *is*
/// the admission control.
///
/// `Grant` requires an operator-signed [`bowery_proto::MembershipGrant`]
/// naming the peer's own fingerprint and this cluster. Migration is
/// gradual: issue grants to every agent first, confirm via
/// `SELECT fingerprint_hex, grant_state FROM bowery_mesh_peers`, then
/// flip the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnrollmentPolicy {
    /// Pin any peer seen gossiping during the bootstrap window.
    #[default]
    Tofu,
    /// Pin only peers presenting a valid operator-signed grant.
    Grant,
}

fn default_revocations_path() -> PathBuf {
    PathBuf::from("/var/lib/bowery/revocations.b64")
}

impl Default for KnownNeighborsConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_KNOWN_NEIGHBORS_PATH),
            bootstrap_window: default_bootstrap_window(),
            max_pinned_peers: default_max_pinned_peers(),
            enrollment: EnrollmentPolicy::default(),
            grant_path: None,
            revocations_path: default_revocations_path(),
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
    /// Address gossiped to mesh peers as this node's whisper dial target
    /// (what a relay dials for fan-out). Defaults to the bound socket's
    /// `local_addr()` when unset — which is unroutable if `bind_addr` is a
    /// wildcard like `0.0.0.0:9902`. On a tailnet, bind the wildcard for
    /// boot robustness and set this to the node's routable `100.x:9902`.
    #[serde(default)]
    pub advertise_addr: Option<SocketAddr>,
    #[serde(default)]
    pub qa: WhisperQaConfig,
}

impl Default for WhisperConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_whisper_bind_addr(),
            advertise_addr: None,
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
    /// How many peers must report **never seen it** for an alert to be
    /// confirmed by the neighbourhood.
    ///
    /// Polarity is deliberate and easy to get backwards: a peer that
    /// *has* seen the binary argues it's a normal fleet artifact, so
    /// confirmation is driven by peers that have NOT. Non-responders
    /// never count — silence isn't evidence. Set to 0 to disable
    /// confirmation entirely.
    #[serde(default = "default_whisper_qa_quorum")]
    pub quorum: usize,
    /// Ceiling on Q&A rounds in flight at once. Each round dials up to
    /// `fanout` peers, so an exec storm on a busy host would otherwise
    /// spawn unbounded concurrent rounds and turn one noisy machine into
    /// a mesh-wide amplifier. Rounds over the ceiling are shed, not
    /// queued — a late confirmation is worth less than a responsive
    /// agent, and the underlying alert is already delivered either way.
    #[serde(default = "default_whisper_qa_max_concurrent_rounds")]
    pub max_concurrent_rounds: usize,
}

impl Default for WhisperQaConfig {
    fn default() -> Self {
        Self {
            threshold: default_whisper_qa_threshold(),
            fanout: default_whisper_qa_fanout(),
            timeout: default_whisper_qa_timeout(),
            min_similarity: default_whisper_qa_min_similarity(),
            quorum: default_whisper_qa_quorum(),
            max_concurrent_rounds: default_whisper_qa_max_concurrent_rounds(),
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
/// Two independent neighbours that have never seen the binary. One is
/// too easy to satisfy on a small mesh; the default `fanout` of 5 makes
/// two reachable without demanding a large fleet.
const fn default_whisper_qa_max_concurrent_rounds() -> usize {
    4
}

fn default_whisper_qa_quorum() -> usize {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineConfig {
    /// Path to the `SQLite` baseline database. The literal string `:memory:`
    /// keeps the baseline in RAM (useful for tests and ephemeral agents).
    pub path: PathBuf,
}

/// `[eventlog]` — the append-only local history the SQL surface queries.
///
/// On by default: an event log that ships disabled records nothing on
/// the day you need it, and the whole point is that history exists
/// *before* the investigation starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventLogConfig {
    /// Record events at all. Turning this off keeps the SQL views
    /// registered (queries return zero rows) rather than making them
    /// vanish, so a query written against a recording host doesn't
    /// error out against a non-recording one.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path to the `SQLite` event log. `:memory:` keeps it in RAM.
    #[serde(default = "default_eventlog_path")]
    pub path: PathBuf,
    /// Drop rows older than this. `0s` disables the age bound.
    #[serde(with = "humantime_serde", default = "default_eventlog_retention")]
    pub retention: Duration,
    /// Hard row ceiling, oldest-first. This is the bound that actually
    /// protects a small disk — age alone is unbounded in the bad case,
    /// since an exec storm can write more in an hour than a quiet week.
    ///
    /// At roughly 200 bytes/row, the 500k default is ~100 MB. Raise it
    /// on a server; on an SD-card-backed Pi, consider lowering it (and
    /// note that sustained recording is write wear regardless).
    #[serde(default = "default_eventlog_max_rows")]
    pub max_rows: u64,
    /// How often retention + WAL checkpointing run.
    ///
    /// This is not a query-lag window: the SQL surface reads
    /// un-checkpointed rows too, so events are queryable within
    /// milliseconds of being written. The interval only governs how
    /// promptly retention reclaims space and how large the WAL is
    /// allowed to grow.
    #[serde(with = "humantime_serde", default = "default_eventlog_maintenance")]
    pub maintenance_interval: Duration,
    /// In-flight buffer between the event pipeline and the disk writer.
    ///
    /// When full, events are *dropped* rather than blocking the
    /// pipeline — a stalled sensor is worse than a gap, and the drop
    /// count is exposed via `bowery_eventlog_status` so the gap is
    /// never silent.
    #[serde(default = "default_eventlog_queue")]
    pub queue_capacity: usize,
}

impl Default for EventLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_eventlog_path(),
            retention: default_eventlog_retention(),
            max_rows: default_eventlog_max_rows(),
            maintenance_interval: default_eventlog_maintenance(),
            queue_capacity: default_eventlog_queue(),
        }
    }
}

const fn default_true() -> bool {
    true
}

fn default_eventlog_path() -> PathBuf {
    PathBuf::from("/var/lib/bowery/events.db")
}

const fn default_eventlog_retention() -> Duration {
    // `from_days` is not const-stable yet; hours is.
    Duration::from_hours(7 * 24)
}

const fn default_eventlog_max_rows() -> u64 {
    500_000
}

const fn default_eventlog_maintenance() -> Duration {
    Duration::from_mins(5)
}

const fn default_eventlog_queue() -> usize {
    4096
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

/// Operator-configurable monitoring: watch specific files (via userspace
/// inotify) and add operator-defined process detections to the analyzer.
/// Both lists default empty — the feature is off until the operator adds
/// rules. Query the effective rules over SQL via `bowery_monitor_rules`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorConfig {
    /// File-integrity rules: a change to `path` matching any of `ops` emits
    /// an alert. Always alerts on match (an operator watch is explicit).
    #[serde(default)]
    pub file_rules: Vec<FileRule>,
    /// Process-detection rules layered onto the analyzer's built-in rules;
    /// they contribute to the exec suspicion score (so `[alerts] threshold`
    /// applies via their severity, like the built-ins).
    #[serde(default)]
    pub process_rules: Vec<ProcessRule>,
}

/// One watched-file rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRule {
    /// Stable id used in the alert rationale. Derived from `path` if omitted.
    #[serde(default)]
    pub id: Option<String>,
    /// Absolute path to watch (a specific file — not a glob or directory).
    pub path: PathBuf,
    /// Which change classes fire. Default: modify/attrib/delete/move.
    #[serde(default = "default_file_ops")]
    pub ops: Vec<FileOp>,
    /// Severity carried on the emitted alert. Default `high`.
    #[serde(default = "default_monitor_severity")]
    pub severity: RuleSeverity,
}

/// One operator process-detection rule. Every matcher that is set must hit
/// (AND); an all-empty rule is rejected at load so it can't match everything.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRule {
    /// Stable id used in the rule-hit rationale. Derived if omitted.
    #[serde(default)]
    pub id: Option<String>,
    /// `exe_path` starts with this prefix (e.g. `/usr/bin/nc`).
    #[serde(default)]
    pub exe_prefix: Option<String>,
    /// `task->comm` equals this exactly (kernel truncates comm to 15 bytes).
    #[serde(default)]
    pub comm: Option<String>,
    /// Any argv element contains this substring.
    #[serde(default)]
    pub arg_substr: Option<String>,
    /// Severity → suspicion weight (high=0.9, medium=0.6, …). Default `high`.
    #[serde(default = "default_monitor_severity")]
    pub severity: RuleSeverity,
}

/// Operator-distributed YARA rules: where they're stored and the caps that
/// bound how much an operator (or a compromised relay replaying a push) can
/// make an agent hold and scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YaraConfig {
    /// Directory holding distributed rules + their index. Written 0600.
    #[serde(default = "default_yara_path")]
    pub path: PathBuf,
    /// Maximum rules retained. A push beyond this is refused rather than
    /// silently evicting detection content an operator is relying on.
    #[serde(default = "default_yara_max_rules")]
    pub max_rules: usize,
    /// Per-rule byte cap. Must stay well under the 64 KiB transport frame
    /// cap, since the rule travels inside a signed operator command.
    #[serde(default = "default_yara_max_rule_bytes")]
    pub max_rule_bytes: usize,
    /// Hard cap on hops a `fanout` push may traverse, applied even if an
    /// operator asks for more — the structural bound on mesh amplification.
    #[serde(default = "default_yara_max_ttl")]
    pub max_ttl: u32,
    /// Concurrent scan jobs. Scanning is CPU-heavy and runs on the blocking
    /// pool; this keeps a fleet-wide push from pinning every core.
    #[serde(default = "default_yara_max_concurrent_scans")]
    pub max_concurrent_scans: usize,
    /// Per-file size cap when scanning; larger files are skipped and noted
    /// in the report's `errors`.
    #[serde(default = "default_yara_max_file_bytes")]
    pub max_file_bytes: u64,
    /// Maximum files visited per scan target.
    #[serde(default = "default_yara_max_files_per_scan")]
    pub max_files_per_scan: usize,
    /// Maximum directory recursion depth per scan target.
    #[serde(default = "default_yara_max_depth")]
    pub max_depth: usize,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            path: default_yara_path(),
            max_rules: default_yara_max_rules(),
            max_rule_bytes: default_yara_max_rule_bytes(),
            max_ttl: default_yara_max_ttl(),
            max_concurrent_scans: default_yara_max_concurrent_scans(),
            max_file_bytes: default_yara_max_file_bytes(),
            max_files_per_scan: default_yara_max_files_per_scan(),
            max_depth: default_yara_max_depth(),
        }
    }
}

fn default_yara_path() -> PathBuf {
    PathBuf::from("/var/lib/bowery/yara")
}

fn default_yara_max_rules() -> usize {
    256
}

/// 48 KiB — comfortably inside the 64 KiB frame cap once the envelope
/// signature, operator authorization, and proto framing are accounted for.
fn default_yara_max_rule_bytes() -> usize {
    48 * 1024
}

fn default_yara_max_ttl() -> u32 {
    8
}

fn default_yara_max_concurrent_scans() -> usize {
    2
}

fn default_yara_max_file_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_yara_max_files_per_scan() -> usize {
    20_000
}

fn default_yara_max_depth() -> usize {
    16
}

fn default_file_ops() -> Vec<FileOp> {
    vec![FileOp::Modify, FileOp::Attrib, FileOp::Delete, FileOp::Move]
}

fn default_monitor_severity() -> RuleSeverity {
    RuleSeverity::High
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
