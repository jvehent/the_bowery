//! Persistent store for operator-distributed YARA rules.
//!
//! Rules arrive over the signed operator-command channel (possibly relayed
//! through the mesh) and are content-addressed by the lowercase hex SHA-256
//! of their bytes, so the same rule pushed twice — or arriving twice by
//! different mesh paths — stores once.
//!
//! Layout under the configured directory (default `/var/lib/bowery/yara`):
//!
//! ```text
//!   index.json          metadata for every stored rule (0600)
//!   <rule_id>.yar       the raw rule source (0600)
//! ```
//!
//! Persistence follows the [`KnownNeighbors`](bowery_whisper::known_neighbors)
//! pattern: 0600 mode, write-to-temp + atomic rename, and a load-on-open that
//! tolerates a missing store (first run) but not a malformed one.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

/// Mode for everything we write: rules are operator-supplied detection
/// content, readable only by the agent user.
const FILE_MODE: u32 = 0o600;
const INDEX_NAME: &str = "index.json";
const INDEX_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum YaraStoreError {
    #[error("yara store io at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("yara store index malformed: {0}")]
    Malformed(String),
    #[error("unsupported yara index version {0}")]
    UnsupportedVersion(u32),
    #[error("rule {rule_id} is {len} bytes; max is {max}")]
    TooLarge {
        rule_id: String,
        len: usize,
        max: usize,
    },
    #[error("rule_id {claimed} does not match the SHA-256 of the rule bytes ({actual})")]
    RuleIdMismatch { claimed: String, actual: String },
    #[error("store is at capacity ({max} rules)")]
    AtCapacity { max: usize },
}

type Result<T> = std::result::Result<T, YaraStoreError>;

/// Metadata for one stored rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRule {
    /// Lowercase hex SHA-256 of the rule bytes; also the filename stem.
    pub rule_id: String,
    pub bytes_len: u64,
    pub received_unix: u64,
    /// Fingerprint (hex) of the operator whose signature authorised this
    /// rule — not the relaying peer that happened to deliver it.
    pub source_operator_fp: String,
    /// The push's request id, retained for provenance/debugging (loop
    /// prevention itself lives in the in-memory seen-set).
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexFile {
    version: u32,
    rules: Vec<StoredRule>,
}

/// On-disk set of distributed YARA rules.
#[derive(Debug)]
pub struct YaraStore {
    dir: PathBuf,
    max_rules: usize,
    max_rule_bytes: usize,
    /// `rule_id` → metadata. Rule *bodies* stay on disk and are read on
    /// demand; only metadata is held in memory.
    rules: std::sync::RwLock<HashMap<String, StoredRule>>,
}

impl YaraStore {
    /// Open (or create) the store. A missing directory/index is a normal
    /// first run; a malformed index is an error rather than silent data
    /// loss.
    pub fn open(dir: impl AsRef<Path>, max_rules: usize, max_rule_bytes: usize) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let index_path = dir.join(INDEX_NAME);
        let rules = if index_path.exists() {
            let contents =
                fs::read_to_string(&index_path).map_err(|source| YaraStoreError::Io {
                    path: index_path.clone(),
                    source,
                })?;
            let file: IndexFile = serde_json::from_str(&contents)
                .map_err(|e| YaraStoreError::Malformed(e.to_string()))?;
            if file.version != INDEX_VERSION {
                return Err(YaraStoreError::UnsupportedVersion(file.version));
            }
            file.rules
                .into_iter()
                .map(|r| (r.rule_id.clone(), r))
                .collect()
        } else {
            HashMap::new()
        };
        Ok(Self {
            dir,
            max_rules,
            max_rule_bytes,
            rules: std::sync::RwLock::new(rules),
        })
    }

    /// Content address for rule bytes — the canonical `rule_id`.
    pub fn rule_id_for(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    pub fn contains(&self, rule_id: &str) -> bool {
        self.rules
            .read()
            .expect("yara store poisoned")
            .contains_key(rule_id)
    }

    pub fn len(&self) -> usize {
        self.rules.read().expect("yara store poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Metadata for every stored rule, sorted by id for stable output
    /// (the `bowery_yara_rules` SQL view renders this).
    pub fn list(&self) -> Vec<StoredRule> {
        let guard = self.rules.read().expect("yara store poisoned");
        let mut out: Vec<StoredRule> = guard.values().cloned().collect();
        out.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        out
    }

    /// Read one rule's source from disk.
    pub fn load_bytes(&self, rule_id: &str) -> Result<Vec<u8>> {
        let path = self.rule_path(rule_id);
        fs::read(&path).map_err(|source| YaraStoreError::Io { path, source })
    }

    /// Persist a rule. Idempotent: re-storing a known `rule_id` is a
    /// no-op returning `false`, which is what makes mesh propagation
    /// converge (the same rule arriving by several paths writes once).
    ///
    /// Verifies the claimed `rule_id` against the actual content hash so a
    /// relaying agent can't file a rule under someone else's id.
    pub fn store(
        &self,
        rule_id: &str,
        bytes: &[u8],
        source_operator_fp: &str,
        request_id: &str,
        received_unix: u64,
    ) -> Result<bool> {
        if bytes.len() > self.max_rule_bytes {
            return Err(YaraStoreError::TooLarge {
                rule_id: rule_id.to_string(),
                len: bytes.len(),
                max: self.max_rule_bytes,
            });
        }
        let actual = Self::rule_id_for(bytes);
        if actual != rule_id {
            return Err(YaraStoreError::RuleIdMismatch {
                claimed: rule_id.to_string(),
                actual,
            });
        }
        {
            let guard = self.rules.read().expect("yara store poisoned");
            if guard.contains_key(rule_id) {
                return Ok(false);
            }
            if guard.len() >= self.max_rules {
                return Err(YaraStoreError::AtCapacity {
                    max: self.max_rules,
                });
            }
        }

        fs::create_dir_all(&self.dir).map_err(|source| YaraStoreError::Io {
            path: self.dir.clone(),
            source,
        })?;
        let path = self.rule_path(rule_id);
        write_atomic(&path, bytes)?;

        let entry = StoredRule {
            rule_id: rule_id.to_string(),
            bytes_len: bytes.len() as u64,
            received_unix,
            source_operator_fp: source_operator_fp.to_string(),
            request_id: request_id.to_string(),
        };
        {
            let mut guard = self.rules.write().expect("yara store poisoned");
            guard.insert(rule_id.to_string(), entry);
        }
        self.save_index()?;
        Ok(true)
    }

    fn rule_path(&self, rule_id: &str) -> PathBuf {
        // rule_id is a verified 64-char hex digest (see `store`), so it
        // can't contain path separators or traversal sequences.
        self.dir.join(format!("{rule_id}.yar"))
    }

    fn save_index(&self) -> Result<()> {
        let file = IndexFile {
            version: INDEX_VERSION,
            rules: self.list(),
        };
        let contents = serde_json::to_string_pretty(&file)
            .map_err(|e| YaraStoreError::Malformed(e.to_string()))?;
        write_atomic(&self.dir.join(INDEX_NAME), contents.as_bytes())
    }
}

/// Bounded record of push requests this agent has already handled, keyed
/// by `(operator_fp, request_id)`.
///
/// This is the loop-prevention guarantee for mesh propagation: a cyclic
/// pinned-peer graph (A→B→C→A, or simply two peers pinned to each other)
/// would otherwise bounce a push forever. TTL bounds the blast radius
/// structurally; this bounds it *exactly*, so each agent handles a given
/// push once no matter how many paths reach it.
///
/// Entries expire so a long-lived agent doesn't accumulate ids forever,
/// and the map is capped so a hostile flood of distinct request ids can't
/// grow it without bound (oldest entries are evicted first).
#[derive(Debug)]
pub struct YaraSeen {
    inner: std::sync::Mutex<SeenInner>,
    ttl: std::time::Duration,
    max_entries: usize,
}

#[derive(Debug)]
struct SeenInner {
    /// key → when it was first seen.
    seen: HashMap<(String, String), std::time::Instant>,
}

impl YaraSeen {
    pub fn new(ttl: std::time::Duration, max_entries: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(SeenInner {
                seen: HashMap::new(),
            }),
            ttl,
            max_entries,
        }
    }

    /// Record `(operator_fp, request_id)` and report whether it is new.
    /// `false` means "already handled — drop this push", which is what
    /// terminates propagation loops.
    pub fn check_and_record(&self, operator_fp: &str, request_id: &str) -> bool {
        let now = std::time::Instant::now();
        let mut guard = self.inner.lock().expect("yara seen poisoned");
        // Drop expired entries first so a steady trickle of pushes keeps
        // the map small without a background task.
        guard
            .seen
            .retain(|_, first| now.duration_since(*first) < self.ttl);
        if guard.seen.len() >= self.max_entries {
            // Evict the oldest so a flood of distinct ids can't grow the
            // map without bound.
            if let Some(oldest) = guard
                .seen
                .iter()
                .min_by_key(|(_, first)| **first)
                .map(|(k, _)| k.clone())
            {
                guard.seen.remove(&oldest);
            }
        }
        let key = (operator_fp.to_string(), request_id.to_string());
        guard.seen.insert(key, now).is_none()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("yara seen poisoned").seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Write `bytes` to `path` at 0600 via temp + atomic rename, so a crash
/// mid-write can't leave a truncated rule or index behind.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let tmp = path.with_extension("tmp");
    // Clean up any leftover temp from a crashed prior write.
    if tmp.exists()
        && let Err(e) = fs::remove_file(&tmp)
    {
        warn!(path = %tmp.display(), error = %e, "could not remove stale yara temp file");
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(FILE_MODE)
        .open(&tmp)
        .map_err(|source| YaraStoreError::Io {
            path: tmp.clone(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| YaraStoreError::Io {
        path: tmp.clone(),
        source,
    })?;
    file.sync_all().map_err(|source| YaraStoreError::Io {
        path: tmp.clone(),
        source,
    })?;
    drop(file);
    fs::rename(&tmp, path).map_err(|source| YaraStoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn store(dir: &Path) -> YaraStore {
        YaraStore::open(dir, 16, 4096).unwrap()
    }

    #[test]
    fn store_round_trips_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let bytes = b"rule demo { condition: true }";
        let id = YaraStore::rule_id_for(bytes);

        assert!(
            s.store(&id, bytes, "op", "req-1", 100).unwrap(),
            "first store writes"
        );
        assert!(s.contains(&id));
        assert_eq!(s.load_bytes(&id).unwrap(), bytes);

        // The same rule arriving again (e.g. by another mesh path) is a
        // no-op — this is what makes propagation converge.
        assert!(
            !s.store(&id, bytes, "op", "req-2", 200).unwrap(),
            "second store is a no-op"
        );
        assert_eq!(s.len(), 1);

        // Metadata survives a reopen.
        let s2 = store(dir.path());
        assert!(s2.contains(&id));
        assert_eq!(s2.list()[0].request_id, "req-1");
    }

    #[test]
    fn rule_files_are_0600() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let bytes = b"rule r { condition: true }";
        let id = YaraStore::rule_id_for(bytes);
        s.store(&id, bytes, "op", "r", 1).unwrap();

        for name in [format!("{id}.yar"), INDEX_NAME.to_string()] {
            let mode = fs::metadata(dir.path().join(&name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, FILE_MODE, "{name} must be 0600, got {mode:o}");
        }
    }

    #[test]
    fn rejects_rule_id_that_does_not_match_content() {
        // A relaying agent must not be able to file rule bytes under a
        // different id (e.g. shadowing a known-good rule).
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let err = s
            .store(&"a".repeat(64), b"rule x { condition: true }", "op", "r", 1)
            .unwrap_err();
        assert!(
            matches!(err, YaraStoreError::RuleIdMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn rejects_oversized_rule() {
        let dir = tempfile::tempdir().unwrap();
        let s = YaraStore::open(dir.path(), 16, 8).unwrap();
        let bytes = b"this is definitely longer than eight bytes";
        let id = YaraStore::rule_id_for(bytes);
        let err = s.store(&id, bytes, "op", "r", 1).unwrap_err();
        assert!(matches!(err, YaraStoreError::TooLarge { .. }), "{err}");
    }

    #[test]
    fn seen_set_drops_repeats_and_expires() {
        let seen = YaraSeen::new(std::time::Duration::from_mins(1), 8);
        // First delivery is handled; a second by another mesh path isn't.
        assert!(seen.check_and_record("op", "req-1"), "first is new");
        assert!(!seen.check_and_record("op", "req-1"), "repeat is dropped");
        // A different request from the same operator is still new.
        assert!(seen.check_and_record("op", "req-2"));
        // Same request id from a *different* operator is a distinct push.
        assert!(seen.check_and_record("op2", "req-1"));
    }

    #[test]
    fn seen_set_evicts_when_full() {
        // A flood of distinct request ids must not grow the map without
        // bound.
        let seen = YaraSeen::new(std::time::Duration::from_mins(1), 4);
        for i in 0..50 {
            seen.check_and_record("op", &format!("req-{i}"));
        }
        assert!(seen.len() <= 4, "capped, got {}", seen.len());
    }

    #[test]
    fn seen_set_forgets_after_ttl() {
        let seen = YaraSeen::new(std::time::Duration::from_millis(50), 8);
        assert!(seen.check_and_record("op", "req"));
        std::thread::sleep(std::time::Duration::from_millis(80));
        // After the TTL an operator can legitimately re-push the same id.
        assert!(
            seen.check_and_record("op", "req"),
            "expired entry is new again"
        );
    }

    #[test]
    fn enforces_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let s = YaraStore::open(dir.path(), 1, 4096).unwrap();
        let a = b"rule a { condition: true }";
        let b = b"rule b { condition: false }";
        s.store(&YaraStore::rule_id_for(a), a, "op", "r", 1)
            .unwrap();
        let err = s
            .store(&YaraStore::rule_id_for(b), b, "op", "r", 2)
            .unwrap_err();
        assert!(matches!(err, YaraStoreError::AtCapacity { .. }), "{err}");
    }
}
