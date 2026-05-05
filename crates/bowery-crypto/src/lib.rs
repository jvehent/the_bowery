//! Identity keys, signing, and fingerprints for The Bowery.
//!
//! Each agent and each operator owns exactly one Ed25519 identity keypair.
//! Across the mesh, a key is referred to by its 32-byte SHA-256
//! [`Fingerprint`] of the verifying (public) key.
//!
//! Phase 0 scope: in-memory keys, on-disk persistence with strict permission
//! checks, and signing helpers. TPM sealing and key rotation are deferred to
//! later phases (see DESIGN.md §8.2).

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{SECRET_KEY_LENGTH, Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroize;

/// Required mode for an identity key file.
const KEY_FILE_MODE: u32 = 0o600;

/// Schema version we currently emit. Loaders accept exactly this version.
const CURRENT_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("identity file is malformed: {0}")]
    Malformed(String),

    #[error("unsupported identity-file version {0}; this build supports {CURRENT_VERSION}")]
    UnsupportedVersion(u32),

    #[error(
        "identity file at {path} has insecure permissions {mode:o}; expected {KEY_FILE_MODE:o}"
    )]
    InsecurePermissions { path: PathBuf, mode: u32 },

    #[error("identity file already exists at {0}; refusing to overwrite")]
    AlreadyExists(PathBuf),

    #[error("signature verification failed")]
    BadSignature,
}

pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// SHA-256 fingerprint of a verifying (public) key. 32 bytes.
///
/// Displayed as 64 lowercase hex characters. This is the agent's stable
/// identity across the mesh.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(vk.as_bytes());
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-character lowercase-hex fingerprint.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| Error::Malformed(format!("invalid hex fingerprint: {e}")))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed(format!("expected 32 bytes, got {}", bytes.len())))?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// An agent's (or operator's) local identity: an Ed25519 keypair.
///
/// Holds the private key in memory; zeroized on drop via `ed25519-dalek`'s
/// `zeroize` feature. Not `Clone` on purpose — there should be exactly one
/// copy of the private key per process.
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a fresh keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_verifying_key(&self.verifying_key())
    }

    /// Sign a message with this identity.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Verify a detached Ed25519 signature against a verifying key.
    ///
    /// Uses `verify_strict` to reject malleable `s` components and small-
    /// order/torsion `R` components (RFC 8032 §5.1.7). The lenient `verify`
    /// path would let an attacker who captured one valid signature produce
    /// a second, distinct-bytes signature for the same message — which is
    /// safe today because nothing keys on signature bytes, but a footgun
    /// for any future use case that does.
    pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<()> {
        vk.verify_strict(msg, sig).map_err(|_| Error::BadSignature)
    }

    /// Persist to disk as a TOML envelope with mode 0600. Refuses to overwrite
    /// an existing file. Writes are atomic (write-temp + rename).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            return Err(Error::AlreadyExists(path.to_path_buf()));
        }

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| Error::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let mut secret_bytes = self.signing_key.to_bytes();
        let private_key_b64 = BASE64.encode(secret_bytes);
        secret_bytes.zeroize();

        let envelope = IdentityFile {
            version: CURRENT_VERSION,
            algorithm: "ed25519".to_string(),
            created: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|e| Error::Malformed(e.to_string()))?,
            fingerprint: self.fingerprint().to_hex(),
            private_key: private_key_b64,
        };

        let body =
            toml::to_string_pretty(&envelope).map_err(|e| Error::Malformed(e.to_string()))?;
        let header =
            "# Bowery identity key — KEEP SECRET, mode 0600.\n# Auto-generated; do not edit.\n\n";
        let contents = format!("{header}{body}");

        let tmp = tmp_path_for(path);
        write_with_mode(&tmp, contents.as_bytes(), KEY_FILE_MODE)?;
        fs::rename(&tmp, path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    /// Load an identity from disk. Refuses to load if file mode is not 0600,
    /// or if the on-disk fingerprint doesn't match the recomputed one.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = fs::metadata(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != KEY_FILE_MODE {
            return Err(Error::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }

        let contents = fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let envelope: IdentityFile =
            toml::from_str(&contents).map_err(|e| Error::Malformed(e.to_string()))?;

        if envelope.version != CURRENT_VERSION {
            return Err(Error::UnsupportedVersion(envelope.version));
        }
        if envelope.algorithm != "ed25519" {
            return Err(Error::Malformed(format!(
                "unsupported algorithm: {}",
                envelope.algorithm
            )));
        }

        let mut decoded = BASE64
            .decode(envelope.private_key.as_bytes())
            .map_err(|e| Error::Malformed(format!("base64 decode failed: {e}")))?;
        if decoded.len() != SECRET_KEY_LENGTH {
            decoded.zeroize();
            return Err(Error::Malformed(format!(
                "expected {SECRET_KEY_LENGTH}-byte private key, got {}",
                decoded.len()
            )));
        }

        let mut bytes = [0u8; SECRET_KEY_LENGTH];
        bytes.copy_from_slice(&decoded);
        decoded.zeroize();

        let signing_key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();

        let identity = Self::from_signing_key(signing_key);

        if identity.fingerprint().to_hex() != envelope.fingerprint {
            return Err(Error::Malformed(
                "stored fingerprint does not match private key".into(),
            ));
        }
        Ok(identity)
    }

    /// Load if the file exists, otherwise generate a fresh identity, save it,
    /// and return it. The boolean is `true` when a new key was generated.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<(Self, bool)> {
        let path = path.as_ref();
        if path.exists() {
            Ok((Self::load(path)?, false))
        } else {
            let id = Self::generate();
            id.save(path)?;
            Ok((id, true))
        }
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// On-disk envelope
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    algorithm: String,
    created: String,
    fingerprint: String,
    private_key: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

    #[test]
    fn fingerprint_is_sha256_of_pubkey() {
        let id = Identity::generate();
        let vk = id.verifying_key();
        let mut hasher = Sha256::new();
        hasher.update(vk.as_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(id.fingerprint().as_bytes(), &expected);
    }

    #[test]
    fn fingerprint_hex_roundtrip() {
        let id = Identity::generate();
        let fp = id.fingerprint();
        let parsed = Fingerprint::from_hex(&fp.to_hex()).unwrap();
        assert_eq!(fp, parsed);
    }

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();
        let msg = b"the bowery is watching";
        let sig = id.sign(msg);
        Identity::verify(&id.verifying_key(), msg, &sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let id = Identity::generate();
        let sig = id.sign(b"original");
        assert!(matches!(
            Identity::verify(&id.verifying_key(), b"tampered", &sig),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let original = Identity::generate();
        original.save(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE, "key file must be mode 0600");

        let loaded = Identity::load(&path).unwrap();
        assert_eq!(original.fingerprint(), loaded.fingerprint());
        assert_eq!(
            original.signing_key().to_bytes(),
            loaded.signing_key().to_bytes()
        );
    }

    #[test]
    fn save_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        Identity::generate().save(&path).unwrap();
        let err = Identity::generate().save(&path).unwrap_err();
        assert!(matches!(err, Error::AlreadyExists(_)));
    }

    #[test]
    fn load_rejects_loose_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        Identity::generate().save(&path).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = Identity::load(&path).unwrap_err();
        assert!(matches!(err, Error::InsecurePermissions { .. }));
    }

    #[test]
    fn load_or_generate_first_then_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let (first, generated) = Identity::load_or_generate(&path).unwrap();
        assert!(generated);

        let (second, generated_again) = Identity::load_or_generate(&path).unwrap();
        assert!(!generated_again);
        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn load_detects_fingerprint_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        Identity::generate().save(&path).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let tampered = raw.replace(
            "fingerprint = \"",
            "fingerprint = \"00000000000000000000000000000000000000000000000000000000000000",
        );
        fs::write(&path, tampered).unwrap();

        let err = Identity::load(&path).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
    }
}
