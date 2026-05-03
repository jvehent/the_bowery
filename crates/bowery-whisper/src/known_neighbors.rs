//! TOFU (trust-on-first-use) store for pinned neighbor identities.
//!
//! Phase 1c semantics: during the configured bootstrap window after first
//! start, newly-discovered peers are auto-pinned. Outside that window,
//! unknown fingerprints are refused — only an operator-signed
//! `add-neighbor` (later phase) can extend the pin set.
//!
//! On disk: a JSON envelope at mode 0600. Atomic writes (write-temp +
//! rename). The bootstrap window's expiry is persisted, so reopens after
//! restart preserve the same window deadline.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_crypto::Fingerprint;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::envelope::FingerprintResolver;

const FILE_MODE: u32 = 0o600;
const FILE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("known_neighbors file is malformed: {0}")]
    Malformed(String),

    #[error(
        "known_neighbors file at {path} has insecure permissions {mode:o}; expected {FILE_MODE:o}"
    )]
    InsecurePermissions { path: PathBuf, mode: u32 },

    #[error("unsupported file version {0}")]
    UnsupportedVersion(u32),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    NewlyPinned,
    AlreadyPinned,
    BootstrapClosed,
}

#[derive(Debug, Clone)]
struct Peer {
    verifying_key: VerifyingKey,
    pinned_at: SystemTime,
}

/// Persistent set of pinned neighbor fingerprints.
#[derive(Debug)]
pub struct KnownNeighbors {
    path: PathBuf,
    state: RwLock<HashMap<Fingerprint, Peer>>,
    bootstrap_until: SystemTime,
}

impl KnownNeighbors {
    /// Open the store. If the file is absent, a fresh in-memory store is
    /// created and the bootstrap window starts now. If the file exists, the
    /// previously-recorded bootstrap deadline is preserved (so restarts
    /// don't reset the window).
    pub fn open(path: impl AsRef<Path>, bootstrap_window: Duration) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if !path.exists() {
            return Ok(Self {
                path,
                state: RwLock::new(HashMap::new()),
                bootstrap_until: SystemTime::now() + bootstrap_window,
            });
        }

        let metadata = fs::metadata(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != FILE_MODE {
            return Err(Error::InsecurePermissions { path, mode });
        }

        let contents = fs::read_to_string(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        let file: StoreFile =
            serde_json::from_str(&contents).map_err(|e| Error::Malformed(e.to_string()))?;
        if file.version != FILE_VERSION {
            return Err(Error::UnsupportedVersion(file.version));
        }

        let bootstrap_until = parse_rfc3339(&file.bootstrap_until)?;
        let mut state = HashMap::with_capacity(file.peers.len());
        for entry in file.peers {
            let vk = decode_verifying_key(&entry.verifying_key)?;
            let stored_fp = Fingerprint::from_hex(&entry.fingerprint)
                .map_err(|e| Error::Malformed(format!("fingerprint: {e}")))?;
            let derived_fp = Fingerprint::from_verifying_key(&vk);
            if stored_fp != derived_fp {
                return Err(Error::Malformed(
                    "stored fingerprint does not match verifying key".into(),
                ));
            }
            let pinned_at = parse_rfc3339(&entry.pinned_at)?;
            state.insert(
                derived_fp,
                Peer {
                    verifying_key: vk,
                    pinned_at,
                },
            );
        }

        Ok(Self {
            path,
            state: RwLock::new(state),
            bootstrap_until,
        })
    }

    pub fn bootstrap_active(&self) -> bool {
        SystemTime::now() < self.bootstrap_until
    }

    pub fn count(&self) -> usize {
        self.state.read().expect("known_neighbors poisoned").len()
    }

    pub fn fingerprints(&self) -> Vec<Fingerprint> {
        self.state
            .read()
            .expect("known_neighbors poisoned")
            .keys()
            .copied()
            .collect()
    }

    /// Try to pin a peer's verifying key.
    ///
    /// - If already pinned, returns `AlreadyPinned`.
    /// - If unknown and within bootstrap window, pins and writes to disk.
    /// - If unknown and outside the window, returns `BootstrapClosed`.
    pub fn try_pin(&self, vk: &VerifyingKey) -> Result<PinOutcome> {
        let fp = Fingerprint::from_verifying_key(vk);

        if self
            .state
            .read()
            .expect("known_neighbors poisoned")
            .contains_key(&fp)
        {
            return Ok(PinOutcome::AlreadyPinned);
        }
        if !self.bootstrap_active() {
            return Ok(PinOutcome::BootstrapClosed);
        }

        {
            let mut state = self.state.write().expect("known_neighbors poisoned");
            // Re-check under write lock to handle the rare double-pin race.
            if state.contains_key(&fp) {
                return Ok(PinOutcome::AlreadyPinned);
            }
            state.insert(
                fp,
                Peer {
                    verifying_key: *vk,
                    pinned_at: SystemTime::now(),
                },
            );
        }
        self.save()?;
        Ok(PinOutcome::NewlyPinned)
    }

    fn save(&self) -> Result<()> {
        let state = self.state.read().expect("known_neighbors poisoned");
        let bootstrap_until_str = format_rfc3339(self.bootstrap_until)?;
        let mut peers: Vec<PinnedPeerFile> = state
            .iter()
            .map(|(fp, peer)| {
                Ok(PinnedPeerFile {
                    fingerprint: fp.to_hex(),
                    verifying_key: BASE64.encode(peer.verifying_key.as_bytes()),
                    pinned_at: format_rfc3339(peer.pinned_at)?,
                })
            })
            .collect::<Result<_>>()?;
        peers.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));

        let file = StoreFile {
            version: FILE_VERSION,
            bootstrap_until: bootstrap_until_str,
            peers,
        };
        let contents =
            serde_json::to_string_pretty(&file).map_err(|e| Error::Malformed(e.to_string()))?;

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| Error::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let tmp = tmp_path_for(&self.path);
        // Best-effort cleanup of any leftover temp from a crashed prior write.
        let _ = fs::remove_file(&tmp);
        write_with_mode(&tmp, contents.as_bytes(), FILE_MODE)?;
        fs::rename(&tmp, &self.path).map_err(|source| Error::Io {
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }
}

impl FingerprintResolver for KnownNeighbors {
    fn resolve(&self, fp: &Fingerprint) -> Option<VerifyingKey> {
        self.state
            .read()
            .expect("known_neighbors poisoned")
            .get(fp)
            .map(|p| p.verifying_key)
    }
}

// ---------------------------------------------------------------------------
// On-disk schema
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    bootstrap_until: String,
    peers: Vec<PinnedPeerFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PinnedPeerFile {
    fingerprint: String,
    verifying_key: String,
    pinned_at: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_verifying_key(s: &str) -> Result<VerifyingKey> {
    let bytes = BASE64
        .decode(s.as_bytes())
        .map_err(|e| Error::Malformed(format!("base64: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed(format!("expected 32-byte vk, got {}", bytes.len())))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| Error::Malformed(format!("verifying key: {e}")))
}

fn parse_rfc3339(s: &str) -> Result<SystemTime> {
    let dt = OffsetDateTime::parse(s, &Rfc3339).map_err(|e| Error::Malformed(e.to_string()))?;
    Ok(dt.into())
}

fn format_rfc3339(ts: SystemTime) -> Result<String> {
    let dt: OffsetDateTime = ts.into();
    dt.format(&Rfc3339)
        .map_err(|e| Error::Malformed(e.to_string()))
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let mut name = p
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".tmp");
    p.set_file_name(name);
    p
}

fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)
        .map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_crypto::Identity;

    fn store_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("known_neighbors.json")
    }

    #[test]
    fn pins_new_peer_within_bootstrap_window() {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownNeighbors::open(store_path(&dir), Duration::from_mins(1)).unwrap();
        let id = Identity::generate();
        assert_eq!(
            store.try_pin(&id.verifying_key()).unwrap(),
            PinOutcome::NewlyPinned
        );
        assert_eq!(store.count(), 1);
        assert!(store.fingerprints().contains(&id.fingerprint()));
    }

    #[test]
    fn second_pin_returns_already_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownNeighbors::open(store_path(&dir), Duration::from_mins(1)).unwrap();
        let id = Identity::generate();
        store.try_pin(&id.verifying_key()).unwrap();
        assert_eq!(
            store.try_pin(&id.verifying_key()).unwrap(),
            PinOutcome::AlreadyPinned
        );
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn pins_persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(&dir);
        let id = Identity::generate();
        {
            let store = KnownNeighbors::open(&path, Duration::from_hours(1)).unwrap();
            store.try_pin(&id.verifying_key()).unwrap();
        }
        let store = KnownNeighbors::open(&path, Duration::from_hours(1)).unwrap();
        assert_eq!(store.count(), 1);
        assert!(
            store
                .resolve(&id.fingerprint())
                .is_some_and(|vk| vk == id.verifying_key())
        );
    }

    #[test]
    fn bootstrap_deadline_is_preserved_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(&dir);
        // Use a very short window. Pin one peer to force a save.
        {
            let store = KnownNeighbors::open(&path, Duration::from_millis(50)).unwrap();
            store
                .try_pin(&Identity::generate().verifying_key())
                .unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));
        // Reopen with a long window. Bootstrap is closed because the
        // deadline written to disk has elapsed.
        let store = KnownNeighbors::open(&path, Duration::from_hours(1)).unwrap();
        assert!(!store.bootstrap_active());
        assert_eq!(
            store
                .try_pin(&Identity::generate().verifying_key())
                .unwrap(),
            PinOutcome::BootstrapClosed
        );
    }

    #[test]
    fn rejects_loose_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(&dir);
        let store = KnownNeighbors::open(&path, Duration::from_mins(1)).unwrap();
        store
            .try_pin(&Identity::generate().verifying_key())
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = KnownNeighbors::open(&path, Duration::from_mins(1)).unwrap_err();
        assert!(matches!(err, Error::InsecurePermissions { .. }));
    }

    #[test]
    fn rejects_fingerprint_mismatch_in_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(&dir);
        let store = KnownNeighbors::open(&path, Duration::from_mins(1)).unwrap();
        store
            .try_pin(&Identity::generate().verifying_key())
            .unwrap();
        let mut json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        // Swap fingerprint to a different (valid hex) value.
        json["peers"][0]["fingerprint"] = serde_json::Value::String("00".repeat(32));
        fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();
        // Permission bits got reset by `fs::write`; restore.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let err = KnownNeighbors::open(&path, Duration::from_mins(1)).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
    }

    #[test]
    fn resolver_returns_pinned_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownNeighbors::open(store_path(&dir), Duration::from_mins(1)).unwrap();
        let id = Identity::generate();
        store.try_pin(&id.verifying_key()).unwrap();
        assert_eq!(store.resolve(&id.fingerprint()), Some(id.verifying_key()));
        assert_eq!(store.resolve(&Identity::generate().fingerprint()), None);
    }
}
