//! Agent configuration file.
//!
//! Phase 0: the only required setting is the identity-key path. Future phases
//! add mesh seeds, eBPF tuning, LLM resource caps, baseline DB path, etc.
//! Missing config files yield safe defaults; extra unknown fields are
//! rejected so typos don't silently no-op.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const DEFAULT_IDENTITY_PATH: &str = "/var/lib/bowery/identity.key";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    #[serde(default)]
    pub(crate) identity: IdentityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityConfig {
    /// Path to the agent's Ed25519 identity key file (mode 0600).
    pub(crate) path: PathBuf,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_IDENTITY_PATH),
        }
    }
}

impl Config {
    /// Load the config file. If it doesn't exist, returns defaults.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                toml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
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
    }

    #[test]
    fn round_trip_minimal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, "[identity]\npath = \"/tmp/test.key\"\n").unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.identity.path, PathBuf::from("/tmp/test.key"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, "nonsense = 1\n").unwrap();
        assert!(Config::load(&path).is_err());
    }
}
