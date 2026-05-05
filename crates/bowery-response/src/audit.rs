//! Signed audit envelopes for executed [`Action`]s.
//!
//! Phase-7 slice 4. Every time the response engine completes an
//! `execute(&action)` call — whether the outcome was `Executed`,
//! `AlreadyGone`, or `Suppressed` — the agent constructs an
//! [`AuditRecord`], signs it with the host's Ed25519 identity, and
//! hands the resulting [`AuditEnvelope`] to an [`AuditSink`].
//!
//! The point isn't secrecy (operators reading the local sink already
//! trust the host); it's *tamper evidence*. A future per-host
//! attacker who can write the audit log can't forge entries without
//! the host's signing key, and operators can verify a sample of
//! envelopes against the host's pinned verifying key to confirm the
//! action stream wasn't selectively edited.
//!
//! Canonical encoding is `serde_json::to_vec` over [`AuditRecord`]
//! with fields in declaration order. The signature covers
//! `AUDIT_SIG_DOMAIN || canonical_record_bytes` — the domain prefix
//! prevents cross-protocol confusion if Bowery identity keys are
//! reused for other signed payloads.
//!
//! On disk, [`JsonlFileSink`] writes one envelope per line in
//! newline-delimited JSON. Each write fsyncs before returning so an
//! agent crash mid-write doesn't lose the most recent entry.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bowery_crypto::{Fingerprint, Identity};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::warn;

use crate::action::{Action, ActionOutcome};

/// Domain-separation prefix for audit-envelope signatures.
///
/// Sig input is `AUDIT_SIG_DOMAIN || serde_json::to_vec(record)`.
/// Keep this in sync with whatever verifier tooling consumes the
/// log (`bowery audit verify` once Phase 7 wraps).
pub const AUDIT_SIG_DOMAIN: &[u8] = b"bowery/audit/envelope/v1";

/// Canonical, signable record of one action attempt.
///
/// Field order matters: `serde_json` emits fields in declaration
/// order, and the verifier reconstructs the canonical bytes by
/// re-serialising. Reordering fields here is a wire-format break.
///
/// **Chain fields** (`seq`, `prev_sig_hex`) form a hash-chain across
/// every record a single host produces. The Phase-8 H9 fix makes
/// audit logs deletion-resistant: a verifier walking the file can
/// detect missing entries (gap in `seq`) and selectively-edited
/// entries (broken `prev_sig_hex` link). Without these fields, an
/// attacker with write access could `sed -i '/episode-evil/d'`
/// inconvenient lines and the per-line signatures still verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Schema version. Verifiers reject unknown versions.
    pub version: u32,
    /// Hex-encoded fingerprint of the host that produced the entry.
    /// 64 lowercase hex chars (SHA-256 of the verifying key).
    pub host_fp_hex: String,
    /// Per-host monotonic sequence number. First entry is `seq = 0`,
    /// every subsequent entry strictly increments. Gap detection in
    /// `bowery audit verify` exits non-zero on missing entries.
    pub seq: u64,
    /// Hex-encoded sig of the previous entry, or empty string for the
    /// first entry. Forms a hash chain — re-ordering, deleting, or
    /// substituting any prior entry breaks the chain.
    pub prev_sig_hex: String,
    /// Stable engine identifier (`"noop"`, `"process-kill"`,
    /// `"bpf-lsm"`).
    pub engine: String,
    /// Episode id the action was decided for.
    pub episode_id: String,
    /// Stable action id (`"kill_process"`, `"block_exec"`, …).
    pub action_id: String,
    /// Typed action payload — included so the audit entry stands
    /// alone, without needing to cross-reference the originating
    /// alert.
    pub action: Action,
    /// What the engine returned.
    pub outcome: ActionOutcome,
    /// Wall-clock time the entry was produced. Distinct from
    /// `outcome.at_unix_ms` so reviewers can tell when the engine
    /// ran vs. when the side-effect was timestamped.
    pub recorded_at_unix_ms: u64,
}

impl AuditRecord {
    /// Current schema version. Phase-8 H9 bumped this from 1 to 2 to
    /// add the `seq` and `prev_sig_hex` chain fields. v1 envelopes
    /// (pre-Phase-8) won't verify under this build — there are no
    /// production deployments to migrate.
    pub const VERSION: u32 = 2;

    /// Build a record without chain fields populated. The sink fills
    /// in `seq` and `prev_sig_hex` at write time. Stamps
    /// `recorded_at_unix_ms` with the current wall clock; tests that
    /// need determinism use [`Self::with_now`].
    pub fn new(
        host_fp: &Fingerprint,
        engine: &str,
        episode_id: &str,
        action: Action,
        outcome: ActionOutcome,
    ) -> Self {
        Self::with_now(
            host_fp,
            engine,
            episode_id,
            action,
            outcome,
            current_unix_ms(),
        )
    }

    pub fn with_now(
        host_fp: &Fingerprint,
        engine: &str,
        episode_id: &str,
        action: Action,
        outcome: ActionOutcome,
        recorded_at_unix_ms: u64,
    ) -> Self {
        let action_id = action.id().to_string();
        Self {
            version: Self::VERSION,
            host_fp_hex: host_fp.to_hex(),
            seq: 0,
            prev_sig_hex: String::new(),
            engine: engine.to_string(),
            episode_id: episode_id.to_string(),
            action_id,
            action,
            outcome,
            recorded_at_unix_ms,
        }
    }

    fn signing_input(&self) -> Result<Vec<u8>, AuditError> {
        let body = serde_json::to_vec(self).map_err(AuditError::Encode)?;
        let mut buf = Vec::with_capacity(AUDIT_SIG_DOMAIN.len() + body.len());
        buf.extend_from_slice(AUDIT_SIG_DOMAIN);
        buf.extend_from_slice(&body);
        Ok(buf)
    }
}

/// A signed audit record, ready to be persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEnvelope {
    pub record: AuditRecord,
    /// Hex-encoded 64-byte Ed25519 signature over
    /// `AUDIT_SIG_DOMAIN || serde_json(record)`.
    pub sig_hex: String,
}

impl AuditEnvelope {
    /// Sign `record` with `identity`'s key.
    pub fn sign(record: AuditRecord, identity: &Identity) -> Result<Self, AuditError> {
        let input = record.signing_input()?;
        let sig = identity.sign(&input);
        Ok(Self {
            record,
            sig_hex: hex::encode(sig.to_bytes()),
        })
    }

    /// Verify the signature against `vk`. Returns `Ok(())` only when
    /// the host fingerprint embedded in the record also matches `vk`
    /// — a record signed by host A but claiming to come from host B
    /// is rejected.
    pub fn verify(&self, vk: &VerifyingKey) -> Result<(), AuditError> {
        if self.record.version != AuditRecord::VERSION {
            return Err(AuditError::UnsupportedVersion(self.record.version));
        }
        let claimed_fp = Fingerprint::from_hex(&self.record.host_fp_hex)
            .map_err(|e| AuditError::MalformedFingerprint(e.to_string()))?;
        let actual_fp = Fingerprint::from_verifying_key(vk);
        if claimed_fp != actual_fp {
            return Err(AuditError::FingerprintMismatch);
        }
        let sig_bytes = hex::decode(&self.sig_hex)
            .map_err(|e| AuditError::MalformedSignature(e.to_string()))?;
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            AuditError::MalformedSignature(format!("expected 64 bytes, got {}", sig_bytes.len()))
        })?;
        let sig = Signature::from_bytes(&sig_arr);
        let input = self.record.signing_input()?;
        // Strict mode (RFC 8032 §5.1.7) — reject malleable / small-order
        // signatures. Cheap defense against any future tooling that
        // indexes audit entries by sig bytes.
        vk.verify_strict(&input, &sig)
            .map_err(|_| AuditError::BadSignature)
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit json encoding failed: {0}")]
    Encode(#[source] serde_json::Error),

    #[error("unsupported audit envelope version {0}")]
    UnsupportedVersion(u32),

    #[error("malformed host fingerprint: {0}")]
    MalformedFingerprint(String),

    #[error("malformed audit signature: {0}")]
    MalformedSignature(String),

    #[error("envelope's host_fp_hex does not match the verifying key")]
    FingerprintMismatch,

    #[error("audit signature verification failed")]
    BadSignature,

    #[error("audit sink io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

// ---------------------------------------------------------------------------
// Sink trait
// ---------------------------------------------------------------------------

/// Anywhere an [`AuditEnvelope`] can be written.
///
/// Implementations own chain state (per-host monotonic seq + previous
/// sig) and apply it inside `record_signed`. `write` is a lower-level
/// API that takes a pre-signed envelope; production callers should
/// prefer `record_signed`.
///
/// Durability contract: a method that returns `Ok(())` means the
/// envelope survives a crash. The [`JsonlFileSink`] enforces this by
/// fsyncing every line.
#[async_trait]
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Write a pre-signed envelope as-is. Used by tests; production
    /// callers go through `record_signed`.
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError>;

    /// Build a record with the next chain fields (`seq` + `prev_sig_hex`)
    /// supplied by the sink, sign it with `identity`, and persist.
    /// This is the API the agent uses for every action attempt.
    ///
    /// Default implementation assigns `seq = 0` / `prev_sig_hex = ""`
    /// and writes — fine for sinks that don't care about chain
    /// integrity (e.g. `NoopSink`). Sinks that want deletion-resistance
    /// override this to maintain real chain state.
    async fn record_signed(
        &self,
        identity: &Identity,
        record: AuditRecord,
    ) -> Result<(), AuditError> {
        let envelope = AuditEnvelope::sign(record, identity)?;
        self.write(&envelope).await
    }
}

/// `/dev/null`-equivalent sink. Drops envelopes silently. Useful for
/// tests and for hosts where audit-logging is intentionally off.
#[derive(Debug, Default)]
pub struct NoopSink;

#[async_trait]
impl AuditSink for NoopSink {
    async fn write(&self, _envelope: &AuditEnvelope) -> Result<(), AuditError> {
        Ok(())
    }
}

/// Per-host hash-chain state. The first entry has `seq = 0` and an
/// empty `prev_sig_hex`; every subsequent entry sets `seq` to one
/// more than the previous and copies the previous entry's `sig_hex`
/// into `prev_sig_hex`. The signature covers both fields.
#[derive(Debug, Default, Clone)]
struct ChainState {
    next_seq: u64,
    last_sig_hex: String,
}

/// Newline-delimited JSON file. Each line is a serialised
/// [`AuditEnvelope`]. Writes are serialised through a single mutex
/// (file + chain state) and fsynced before returning.
pub struct JsonlFileSink {
    path: PathBuf,
    /// File + chain state guarded together so `seq`/`prev_sig` and the
    /// on-disk write happen as a single critical section. Keeping the
    /// Mutex wrap simple costs nothing — write lock hold time is one
    /// fsync, dwarfed by disk latency anyway.
    state: Mutex<JsonlState>,
}

struct JsonlState {
    file: File,
    chain: ChainState,
}

impl JsonlFileSink {
    /// Open `path` in append mode, creating it if missing. Recovers
    /// chain state by reading the existing log (if any) and
    /// extracting the `seq` + `sig_hex` of the last well-formed
    /// envelope. A truncated final line is logged at warn! level
    /// but doesn't fail open: the operator's `bowery audit verify`
    /// surfaces the partial-line condition separately.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();

        let chain = recover_chain_state(&path).await?;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|source| AuditError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            path,
            state: Mutex::new(JsonlState { file, chain }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for JsonlFileSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonlFileSink")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Recover the chain state from an existing audit log file. Reads
/// every line, parses, takes the last well-formed envelope's
/// `(seq, sig_hex)` as the resume point. Truncated/garbage lines
/// after the last good one are tolerated — the next signed entry's
/// `prev_sig_hex` will reference whatever the last clean entry was,
/// which `bowery audit verify` will then flag as a chain break IF
/// the operator believes the partial line is forged. (If they
/// believe it's a crash artifact, they truncate the file to the
/// last newline-terminated line and re-verify.)
async fn recover_chain_state(path: &Path) -> Result<ChainState, AuditError> {
    use tokio::io::AsyncReadExt;

    let mut state = ChainState::default();
    let Ok(mut file) = tokio::fs::File::open(path).await else {
        return Ok(state);
    };
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .await
        .map_err(|source| AuditError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    for line in buf.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEnvelope>(line) {
            Ok(env) => {
                state.next_seq = env.record.seq.saturating_add(1);
                state.last_sig_hex.clone_from(&env.sig_hex);
            }
            Err(_) => {
                // Garbage line. Don't update chain state; the next
                // recorded entry's prev_sig_hex still refers to the
                // last good entry, so the chain remains coherent
                // post-crash (modulo the unparseable line which the
                // verifier will flag).
                tracing::warn!(
                    path = %path.display(),
                    "audit log contains an unparseable line during chain-state recovery; \
                     subsequent entries chain off the previous well-formed line"
                );
            }
        }
    }
    Ok(state)
}

#[async_trait]
impl AuditSink for JsonlFileSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let mut line = serde_json::to_vec(envelope).map_err(AuditError::Encode)?;
        line.push(b'\n');
        let mut state = self.state.lock().await;
        state
            .file
            .write_all(&line)
            .await
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        state
            .file
            .sync_data()
            .await
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        // Update chain state from the envelope we just wrote so that
        // subsequent record_signed calls chain off it.
        state.chain.next_seq = envelope.record.seq.saturating_add(1);
        state.chain.last_sig_hex.clone_from(&envelope.sig_hex);
        Ok(())
    }

    async fn record_signed(
        &self,
        identity: &Identity,
        mut record: AuditRecord,
    ) -> Result<(), AuditError> {
        // Take the lock once for the whole sign+write+state-update so
        // the seq/prev_sig the envelope is signed over matches what
        // ends up in the file, even under concurrent record_signed
        // calls.
        let mut state = self.state.lock().await;
        record.seq = state.chain.next_seq;
        record.prev_sig_hex.clone_from(&state.chain.last_sig_hex);
        let envelope = AuditEnvelope::sign(record, identity)?;
        let mut line = serde_json::to_vec(&envelope).map_err(AuditError::Encode)?;
        line.push(b'\n');
        state
            .file
            .write_all(&line)
            .await
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        state
            .file
            .sync_data()
            .await
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        state.chain.next_seq = envelope.record.seq.saturating_add(1);
        state.chain.last_sig_hex.clone_from(&envelope.sig_hex);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Convenience: produce + write in one call
// ---------------------------------------------------------------------------

/// Build, sign, and persist a single audit entry. Logs (but does not
/// propagate) sink errors so a transient disk problem can't stall the
/// LLM-outcomes loop.
///
/// Routes through `AuditSink::record_signed` so the sink can fill in
/// the chain fields (`seq`, `prev_sig_hex`) before signing.
pub async fn record(
    sink: &Arc<dyn AuditSink>,
    identity: &Identity,
    engine: &str,
    episode_id: &str,
    action: Action,
    outcome: ActionOutcome,
) {
    let host_fp = identity.fingerprint();
    let record = AuditRecord::new(&host_fp, engine, episode_id, action, outcome);
    if let Err(e) = sink.record_signed(identity, record).await {
        warn!(error = %e, "audit: sink write failed; entry dropped");
    }
}

fn current_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn sample_record(host_fp: &Fingerprint) -> AuditRecord {
        AuditRecord::with_now(
            host_fp,
            "process-kill",
            "ep-test",
            Action::KillProcess {
                pid: 4242,
                episode_id: "ep-test".into(),
            },
            ActionOutcome::Executed {
                at_unix_ms: 1_700_000_000_000,
            },
            1_700_000_000_500,
        )
    }

    #[test]
    fn sign_and_verify_round_trips() {
        let id = Identity::generate();
        let env =
            AuditEnvelope::sign(sample_record(&id.fingerprint()), &id).expect("sign succeeds");
        env.verify(&id.verifying_key()).expect("verify succeeds");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer = Identity::generate();
        let other = Identity::generate();
        let env = AuditEnvelope::sign(sample_record(&signer.fingerprint()), &signer).unwrap();
        let err = env
            .verify(&other.verifying_key())
            .expect_err("different key should fail");
        // The envelope claims signer's fingerprint, so the mismatch is
        // caught before the signature check.
        assert!(matches!(err, AuditError::FingerprintMismatch));
    }

    #[test]
    fn verify_rejects_tampered_record() {
        let id = Identity::generate();
        let mut env =
            AuditEnvelope::sign(sample_record(&id.fingerprint()), &id).expect("sign succeeds");
        env.record.episode_id = "ep-tampered".into();
        let err = env
            .verify(&id.verifying_key())
            .expect_err("tampering should invalidate signature");
        assert!(matches!(err, AuditError::BadSignature));
    }

    #[test]
    fn verify_rejects_unknown_version() {
        let id = Identity::generate();
        let mut env =
            AuditEnvelope::sign(sample_record(&id.fingerprint()), &id).expect("sign succeeds");
        env.record.version = 99;
        let err = env.verify(&id.verifying_key()).expect_err("v99 rejected");
        assert!(matches!(err, AuditError::UnsupportedVersion(99)));
    }

    #[tokio::test]
    async fn jsonl_sink_appends_one_line_per_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::open(&path).await.unwrap();

        let id = Identity::generate();
        let env1 = AuditEnvelope::sign(sample_record(&id.fingerprint()), &id).expect("sign");
        let env2 = AuditEnvelope::sign(sample_record(&id.fingerprint()), &id).expect("sign");
        sink.write(&env1).await.unwrap();
        sink.write(&env2).await.unwrap();
        drop(sink);

        let f = std::fs::File::open(&path).unwrap();
        let lines: Vec<String> = BufReader::new(f).lines().map(|l| l.unwrap()).collect();
        assert_eq!(lines.len(), 2);
        // Each line round-trips back to an envelope.
        let parsed: AuditEnvelope = serde_json::from_str(&lines[0]).unwrap();
        parsed.verify(&id.verifying_key()).unwrap();
        let parsed2: AuditEnvelope = serde_json::from_str(&lines[1]).unwrap();
        parsed2.verify(&id.verifying_key()).unwrap();
    }

    #[tokio::test]
    async fn record_helper_writes_to_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink: Arc<dyn AuditSink> = Arc::new(JsonlFileSink::open(&path).await.unwrap());
        let id = Identity::generate();

        record(
            &sink,
            &id,
            "noop",
            "ep-1",
            Action::KillProcess {
                pid: 1,
                episode_id: "ep-1".into(),
            },
            ActionOutcome::suppressed("policy denied"),
        )
        .await;

        let contents = std::fs::read_to_string(&path).unwrap();
        let env: AuditEnvelope = serde_json::from_str(contents.trim()).unwrap();
        env.verify(&id.verifying_key()).unwrap();
        assert_eq!(env.record.engine, "noop");
        assert_eq!(env.record.action_id, "kill_process");
    }

    #[tokio::test]
    async fn noop_sink_drops_silently() {
        let sink = NoopSink;
        let id = Identity::generate();
        let env = AuditEnvelope::sign(sample_record(&id.fingerprint()), &id).unwrap();
        sink.write(&env).await.unwrap();
    }

    /// Phase-8 H9: every entry past the first carries `seq` strictly
    /// greater than the previous entry's, and `prev_sig_hex` matches
    /// the previous entry's `sig_hex`. The first entry has `seq=0`
    /// and empty `prev_sig`.
    #[tokio::test]
    async fn record_signed_builds_a_hash_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink: Arc<dyn AuditSink> = Arc::new(JsonlFileSink::open(&path).await.unwrap());
        let id = Identity::generate();

        for i in 0..3 {
            let action = Action::KillProcess {
                pid: 100 + i,
                episode_id: format!("ep-{i}"),
            };
            record(
                &sink,
                &id,
                "noop",
                &format!("ep-{i}"),
                action,
                ActionOutcome::suppressed("test"),
            )
            .await;
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        let envs: Vec<AuditEnvelope> = contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(envs.len(), 3);

        // First entry: seq=0, empty prev_sig.
        assert_eq!(envs[0].record.seq, 0);
        assert!(envs[0].record.prev_sig_hex.is_empty());
        envs[0].verify(&id.verifying_key()).unwrap();

        // Subsequent entries: seq+1, prev_sig matches previous sig_hex.
        for i in 1..3 {
            assert_eq!(envs[i].record.seq, i as u64);
            assert_eq!(envs[i].record.prev_sig_hex, envs[i - 1].sig_hex);
            envs[i].verify(&id.verifying_key()).unwrap();
        }
    }

    /// Phase-8 H9: chain state survives sink restart (re-open of the
    /// same file). The recovered `next_seq` and `last_sig_hex` are
    /// drawn from the last well-formed envelope in the existing log.
    #[tokio::test]
    async fn chain_state_recovers_across_sink_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let id = Identity::generate();

        // First sink: write two entries, drop.
        {
            let sink: Arc<dyn AuditSink> = Arc::new(JsonlFileSink::open(&path).await.unwrap());
            for i in 0..2 {
                let action = Action::KillProcess {
                    pid: 200 + i,
                    episode_id: format!("ep-r-{i}"),
                };
                record(
                    &sink,
                    &id,
                    "noop",
                    &format!("ep-r-{i}"),
                    action,
                    ActionOutcome::suppressed("test"),
                )
                .await;
            }
        }

        // Second sink: re-open, write one more entry. It should have
        // seq=2 and prev_sig_hex = previous entry's sig_hex.
        let prev_sig_after_first_run = {
            let contents = std::fs::read_to_string(&path).unwrap();
            let envs: Vec<AuditEnvelope> = contents
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            envs[envs.len() - 1].sig_hex.clone()
        };

        {
            let sink: Arc<dyn AuditSink> = Arc::new(JsonlFileSink::open(&path).await.unwrap());
            let action = Action::KillProcess {
                pid: 999,
                episode_id: "ep-after-restart".into(),
            };
            record(
                &sink,
                &id,
                "noop",
                "ep-after-restart",
                action,
                ActionOutcome::suppressed("test"),
            )
            .await;
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        let envs: Vec<AuditEnvelope> = contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(envs.len(), 3);
        assert_eq!(envs[2].record.seq, 2);
        assert_eq!(envs[2].record.prev_sig_hex, prev_sig_after_first_run);
        envs[2].verify(&id.verifying_key()).unwrap();
    }
}
