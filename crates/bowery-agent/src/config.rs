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
const DEFAULT_BOOTSTRAP_WINDOW_HOURS: u64 = 24 * 7; // 7 days
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
}

impl Default for KnownNeighborsConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_KNOWN_NEIGHBORS_PATH),
            bootstrap_window: default_bootstrap_window(),
        }
    }
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
}

impl Default for WhisperConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_whisper_bind_addr(),
        }
    }
}

fn default_whisper_bind_addr() -> SocketAddr {
    "0.0.0.0:9902".parse().expect("static addr parses")
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
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            invocation_threshold: default_llm_threshold(),
            queue_capacity: default_llm_queue_capacity(),
            request_deadline: default_llm_request_deadline(),
        }
    }
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
