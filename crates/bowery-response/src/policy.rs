//! Operator-controlled response policy.
//!
//! The policy answers a single Phase-7 question: *"may the engine
//! execute this action id without operator approval?"* It is loaded
//! from a TOML file at agent startup and held immutable for the
//! agent's lifetime. Live reload, signed-update, and per-host scoping
//! are explicitly out of scope for v1.
//!
//! Default-deny is the entire ergonomic story:
//!
//! - An empty / missing `[response]` block in `agent.toml` produces
//!   [`ResponsePolicy::default()`], which permits *nothing*.
//! - The fastest way to opt in to a specific autonomous action is
//!   `allowed_actions = ["kill_process"]`, which the agent will
//!   parse + accept iff `kill_process` is in [`Action::known_ids`].
//!
//! Future shape (sketched in DESIGN.md §9.2): each entry will be a
//! richer struct with a `condition` (e.g. `score >= 0.9`), a `ttl`,
//! and a per-host signature. We're storing strings today so the
//! migration is a `String → struct` change and not a schema overhaul.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

use crate::action::Action;

/// Operator-controlled gate for autonomous actions.
///
/// `default()` is the safe choice — empty `allowed_actions`,
/// `disabled = false`. With this default, every action the LLM
/// suggests is rejected by [`ResponsePolicy::permits`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePolicy {
    /// Action ids permitted for autonomous execution. Anything not
    /// in this list is rejected. Entries that don't match a known
    /// action id (typos, removed actions) are kept in the policy
    /// but flagged via [`ResponsePolicy::warnings`] so operators
    /// don't silently lose coverage on a typo.
    #[serde(default)]
    pub allowed_actions: Vec<String>,

    /// Per-host kill switch. When set, [`ResponsePolicy::permits`]
    /// returns `false` regardless of `allowed_actions`. Useful as
    /// the "panic, halt all autonomy" lever during incidents.
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Error)]
pub enum PolicyLoadError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("toml parse error in {path}: {source}")]
    Parse {
        path: std::path::PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

impl ResponsePolicy {
    /// Load a policy from disk. A missing file produces the safe
    /// default (deny-all); other I/O errors propagate so the operator
    /// notices a permission mistake rather than silently losing
    /// authorisation entries.
    pub fn load(path: &Path) -> Result<Self, PolicyLoadError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).map_err(|source| PolicyLoadError::Parse {
                path: path.to_path_buf(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(path = %path.display(), "response policy file missing; defaulting to deny-all");
                Ok(Self::default())
            }
            Err(source) => Err(PolicyLoadError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// True iff the engine is allowed to execute an action carrying
    /// `id` autonomously. Always false when `disabled = true`.
    pub fn permits(&self, id: &str) -> bool {
        if self.disabled {
            return false;
        }
        self.allowed_actions.iter().any(|s| s == id)
    }

    /// Strings in `allowed_actions` that don't match any known
    /// action id. Operators see these in startup logs so a typo
    /// doesn't quietly leave a host with no coverage.
    pub fn warnings(&self) -> Vec<String> {
        let known = Action::known_ids();
        self.allowed_actions
            .iter()
            .filter(|s| !known.contains(&s.as_str()))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_is_deny_all() {
        let p = ResponsePolicy::default();
        assert!(!p.permits("kill_process"));
        assert!(!p.permits("anything"));
    }

    #[test]
    fn permits_allows_listed_ids() {
        let p = ResponsePolicy {
            allowed_actions: vec!["kill_process".into()],
            disabled: false,
        };
        assert!(p.permits("kill_process"));
        assert!(!p.permits("block_exec"));
    }

    #[test]
    fn disabled_overrides_allowed_actions() {
        let p = ResponsePolicy {
            allowed_actions: vec!["kill_process".into()],
            disabled: true,
        };
        assert!(!p.permits("kill_process"));
    }

    #[test]
    fn warnings_lists_unknown_action_ids() {
        let p = ResponsePolicy {
            allowed_actions: vec![
                "kill_process".into(),
                "isolate_host".into(),  // typo / future action
                "page_oncall".into(),   // never supported
            ],
            disabled: false,
        };
        let mut w = p.warnings();
        w.sort();
        assert_eq!(w, vec!["isolate_host", "page_oncall"]);
    }

    #[test]
    fn load_missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing-policy.toml");
        let p = ResponsePolicy::load(&path).expect("missing file is deny-all default");
        assert_eq!(p, ResponsePolicy::default());
    }

    #[test]
    fn load_round_trips_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
allowed_actions = ["kill_process"]
disabled = false
"#
        )
        .unwrap();
        let p = ResponsePolicy::load(&path).expect("parses");
        assert_eq!(p.allowed_actions, vec!["kill_process".to_string()]);
        assert!(!p.disabled);
        assert!(p.permits("kill_process"));
    }

    #[test]
    fn load_rejects_unknown_top_level_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(
            &path,
            "allowed_actions = []
nonsense_field = true
",
        )
        .unwrap();
        let err = ResponsePolicy::load(&path).expect_err("strict parsing rejects extras");
        assert!(
            matches!(err, PolicyLoadError::Parse { .. }),
            "expected Parse error, got {err:?}"
        );
    }
}
