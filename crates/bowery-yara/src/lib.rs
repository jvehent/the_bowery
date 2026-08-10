//! YARA scanning for The Bowery.
//!
//! Two builds of the same API:
//!
//! - **`engine` feature on** — real scanning via libyara (the `yara`
//!   crate). Chosen over the pure-Rust `yara-x` because the agent's
//!   systemd sandbox sets `MemoryDenyWriteExecute=yes`: yara-x compiles
//!   rules to WASM and JITs them, which that (deliberately hardened)
//!   setting forbids. libyara is a bytecode interpreter.
//! - **feature off (default)** — a stub whose every operation returns
//!   [`YaraError::EngineUnavailable`]. Agents still accept, persist, and
//!   propagate rules across the mesh; they just don't execute them. This
//!   keeps the static aarch64-musl Pi build free of a C dependency.
//!
//! Scanning is CPU-heavy and blocking. This crate is deliberately
//! synchronous — callers are expected to run [`Rules::scan_path`] on a
//! blocking pool with their own concurrency cap and timeout.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum YaraError {
    #[error("yara engine not compiled in (build with --features yara)")]
    EngineUnavailable,
    #[error("yara rule compilation failed: {0}")]
    Compile(String),
    #[error("yara scan failed for {path}: {reason}")]
    Scan { path: PathBuf, reason: String },
}

/// One rule match against one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub rule_name: String,
    pub path: PathBuf,
    pub tags: Vec<String>,
}

/// Caps applied to a scan. Load-bearing, not decoration: a pushed rule
/// runs on every agent in the mesh, so an unbounded walk is a fleet-wide
/// CPU sink.
#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    /// Files larger than this are skipped (and reported).
    pub max_file_bytes: u64,
    /// Maximum files visited per target.
    pub max_files: usize,
    /// Maximum directory recursion depth.
    pub max_depth: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * 1024 * 1024,
            max_files: 20_000,
            max_depth: 16,
        }
    }
}

/// Outcome of scanning one target path.
#[derive(Debug, Default, Clone)]
pub struct ScanOutcome {
    pub matches: Vec<Match>,
    /// Files actually scanned (after caps).
    pub scanned: u32,
    /// Non-fatal problems: unreadable entries, skipped oversized files,
    /// caps hit. Surfaced to the operator so a partial scan is never
    /// silently reported as a clean one.
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Real engine
// ---------------------------------------------------------------------------

#[cfg(feature = "engine")]
mod imp {
    use super::{Match, ScanLimits, ScanOutcome, YaraError};
    use std::path::Path;

    /// `yara::Rules` has no `Debug`, so print the compiled-rules handle
    /// opaquely rather than dropping `Debug` from our public API.
    pub struct Rules(yara::Rules);

    impl std::fmt::Debug for Rules {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Rules(<compiled yara rules>)")
        }
    }

    impl Rules {
        pub fn compile(source: &str) -> Result<Self, YaraError> {
            // Never panics on a bad rule: libyara returns an error we
            // surface to the operator. (The release profile is
            // panic=abort, so a panic here would take the agent down.)
            let compiler = yara::Compiler::new()
                .map_err(|e| YaraError::Compile(e.to_string()))?
                .add_rules_str(source)
                .map_err(|e| YaraError::Compile(e.to_string()))?;
            let rules = compiler
                .compile_rules()
                .map_err(|e| YaraError::Compile(e.to_string()))?;
            Ok(Self(rules))
        }

        pub fn scan_file(&self, path: &Path, timeout_secs: i32) -> Result<Vec<Match>, YaraError> {
            let results = self
                .0
                .scan_file(path, timeout_secs)
                .map_err(|e| YaraError::Scan {
                    path: path.to_path_buf(),
                    reason: e.to_string(),
                })?;
            Ok(results
                .into_iter()
                .map(|r| Match {
                    rule_name: r.identifier.to_string(),
                    path: path.to_path_buf(),
                    tags: r.tags.into_iter().map(ToString::to_string).collect(),
                })
                .collect())
        }
    }

    pub fn engine_available() -> bool {
        true
    }

    pub(super) fn scan_one(
        rules: &Rules,
        path: &Path,
        limits: ScanLimits,
        timeout_secs: i32,
        out: &mut ScanOutcome,
    ) {
        match std::fs::metadata(path) {
            Ok(md) if md.len() > limits.max_file_bytes => {
                out.errors
                    .push(format!("{}: skipped ({} bytes)", path.display(), md.len()));
                return;
            }
            Ok(_) => {}
            Err(e) => {
                out.errors.push(format!("{}: {e}", path.display()));
                return;
            }
        }
        match rules.scan_file(path, timeout_secs) {
            Ok(m) => {
                out.scanned += 1;
                out.matches.extend(m);
            }
            Err(e) => out.errors.push(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Stub (feature off)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "engine"))]
mod imp {
    use super::{Match, ScanLimits, ScanOutcome, YaraError};
    use std::path::Path;

    /// Placeholder with the same shape as the real engine so callers
    /// compile unchanged; every operation reports the engine is absent.
    #[derive(Debug)]
    pub struct Rules;

    impl Rules {
        pub fn compile(_source: &str) -> Result<Self, YaraError> {
            Err(YaraError::EngineUnavailable)
        }

        pub fn scan_file(&self, _path: &Path, _timeout_secs: i32) -> Result<Vec<Match>, YaraError> {
            Err(YaraError::EngineUnavailable)
        }
    }

    pub fn engine_available() -> bool {
        false
    }

    pub(super) fn scan_one(
        _rules: &Rules,
        _path: &Path,
        _limits: ScanLimits,
        _timeout_secs: i32,
        out: &mut ScanOutcome,
    ) {
        out.errors.push("yara engine not compiled in".to_string());
    }
}

pub use imp::{Rules, engine_available};

impl Rules {
    /// Scan a file, or walk a directory scanning each regular file within
    /// the configured caps. Never follows symlinks (a symlinked directory
    /// could otherwise loop or escape the target).
    pub fn scan_path(&self, root: &Path, limits: ScanLimits, timeout_secs: i32) -> ScanOutcome {
        let mut out = ScanOutcome::default();
        let md = match std::fs::symlink_metadata(root) {
            Ok(md) => md,
            Err(e) => {
                out.errors.push(format!("{}: {e}", root.display()));
                return out;
            }
        };
        if md.file_type().is_symlink() {
            out.errors
                .push(format!("{}: skipped (symlink)", root.display()));
            return out;
        }
        if md.is_file() {
            imp::scan_one(self, root, limits, timeout_secs, &mut out);
            return out;
        }
        if md.is_dir() {
            self.walk(root, limits, timeout_secs, 0, &mut out);
            return out;
        }
        out.errors.push(format!(
            "{}: not a regular file or directory",
            root.display()
        ));
        out
    }

    fn walk(
        &self,
        dir: &Path,
        limits: ScanLimits,
        timeout_secs: i32,
        depth: usize,
        out: &mut ScanOutcome,
    ) {
        if depth > limits.max_depth {
            out.errors
                .push(format!("{}: max depth reached", dir.display()));
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                out.errors.push(format!("{}: {e}", dir.display()));
                return;
            }
        };
        for entry in entries {
            if out.scanned as usize >= limits.max_files {
                out.errors
                    .push(format!("file cap reached ({})", limits.max_files));
                return;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    out.errors.push(format!("{}: {e}", dir.display()));
                    continue;
                }
            };
            let path = entry.path();
            // symlink_metadata: never traverse links while walking.
            let Ok(md) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if md.file_type().is_symlink() {
                continue;
            }
            if md.is_dir() {
                // Recurse into the same outcome so `scanned` (and thus the
                // file cap) accounts for the whole walk, not per-directory.
                self.walk(&path, limits, timeout_secs, depth + 1, out);
            } else if md.is_file() {
                imp::scan_one(self, &path, limits, timeout_secs, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_reports_engine_unavailable_when_feature_off() {
        if engine_available() {
            return; // engine build covers the real path in its own tests
        }
        let err = Rules::compile("rule x { condition: true }").unwrap_err();
        assert!(matches!(err, YaraError::EngineUnavailable), "{err}");
    }

    #[cfg(feature = "engine")]
    #[test]
    fn compiles_and_matches_a_known_string() {
        let dir = tempfile::tempdir().unwrap();
        let hit = dir.path().join("hit.bin");
        let miss = dir.path().join("miss.bin");
        std::fs::write(&hit, b"xx BOWERY_CANARY_STRING xx").unwrap();
        std::fs::write(&miss, b"nothing to see here").unwrap();

        let rules = Rules::compile(
            r#"rule canary : test { strings: $a = "BOWERY_CANARY_STRING" condition: $a }"#,
        )
        .expect("rule compiles");

        let out = rules.scan_path(dir.path(), ScanLimits::default(), 10);
        assert_eq!(out.scanned, 2, "both files scanned: {:?}", out.errors);
        assert_eq!(out.matches.len(), 1, "exactly one match");
        assert_eq!(out.matches[0].rule_name, "canary");
        assert_eq!(out.matches[0].path, hit);
        assert!(out.matches[0].tags.contains(&"test".to_string()));
    }

    #[cfg(feature = "engine")]
    #[test]
    fn bad_rule_errors_instead_of_panicking() {
        // panic=abort in release: a panic here would kill the agent.
        let err = Rules::compile("this is not yara").unwrap_err();
        assert!(matches!(err, YaraError::Compile(_)), "{err}");
    }
}
