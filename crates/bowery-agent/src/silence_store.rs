//! Silences an agent honours, and how it decides to honour them.
//!
//! Verification, storage and match counting for
//! [`bowery_analysis::silence`]. The matching logic lives there and is
//! pure; this is the part that talks to a disk, a clock and an operator
//! key set.
//!
//! # Every check that keeps this safe is here
//!
//! A silence is the one record in the system whose effect is to stop
//! findings reaching a human, so the acceptance path is deliberately
//! paranoid and every rejection is named:
//!
//! - **Operator-signed**, verified against the agent's own `[operators]`
//!   set. A relaying peer can drop a silence but never forge one, the
//!   same property [`bowery_whisper::mesh_trust::verify_revocation`]
//!   gives revocations.
//! - **Cluster-bound**, so a staging silence cannot quiet production.
//! - **Must expire**, and must not already have.
//! - **Must constrain something.** A record whose match fields are all
//!   empty is refused at the door as well as being inert downstream —
//!   two independent guards, because this is the failure that would
//!   silence a fleet.
//! - **Weight is clamped** to at most full, so a malformed record cannot
//!   raise a score.
//!
//! An unverifiable line in the store file is logged and skipped rather
//! than fatal: one bad paste must not cost an agent every valid silence
//! it holds. That mirrors `RevocationStore`, and errs the same way — a
//! skipped silence means an alert is raised that would have been
//! suppressed, which is the safe direction here.
//!
//! # What is counted
//!
//! Every match increments a counter that `bowery_silences` reports. A
//! silence that has swallowed forty thousand alerts has to be visible as
//! such, or "the fleet is quiet" and "the fleet is muted" look the same
//! from the outside — which is the distinction this whole project keeps
//! insisting on, applied to the one feature that deliberately creates
//! absence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use bowery_analysis::silence::{AlertSubject, Silence, SilenceDecision, SilenceSet, SilenceSpec};
use bowery_crypto::Fingerprint;
use bowery_proto::AlertSilence;
use ed25519_dalek::{Signature, VerifyingKey};
use tracing::{info, warn};

/// Why a silence was refused.
///
/// Every variant is reported rather than folded into one error: an
/// operator whose silence did not take needs to know whether it was the
/// signature, the cluster, or the expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SilenceRejected {
    #[error("operator fingerprint or signature is not the right shape")]
    Malformed,
    #[error("signed by a key this agent does not trust as an operator")]
    UntrustedOperator,
    #[error("signature does not verify")]
    BadSignature,
    #[error("issued for a different mesh cluster")]
    ClusterMismatch,
    #[error("already expired")]
    Expired,
    #[error("never expires, which is not allowed")]
    NoExpiry,
    #[error("matches nothing, or everything — no field is constrained")]
    Unconstrained,
    #[error("the store is full")]
    Full,
}

/// One silence plus what it has actually done.
#[derive(Debug)]
struct Counted {
    matched: AtomicU64,
    last_matched_unix_ms: AtomicU64,
}

impl Default for Counted {
    fn default() -> Self {
        Self {
            matched: AtomicU64::new(0),
            last_matched_unix_ms: AtomicU64::new(0),
        }
    }
}

/// A silence as an operator sees it in `bowery_silences`.
#[derive(Debug, Clone)]
pub struct SilenceRow {
    pub id: String,
    pub rule_id: String,
    pub exe_sha256_hex: String,
    pub exe_path: String,
    pub host_fp_hex: String,
    pub weight: f32,
    pub reason: String,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub operator_fp_hex: String,
    pub matched: u64,
    /// `None` when it has never matched — distinct from "matched at the
    /// epoch", the same way the detection counters treat it.
    pub last_matched_unix_ms: Option<u64>,
}

/// The silences this agent honours.
pub struct SilenceStore {
    set: RwLock<SilenceSet>,
    /// Kept alongside the set rather than inside it so
    /// `bowery_analysis::silence` stays free of counters and clocks.
    counts: RwLock<HashMap<String, Counted>>,
    /// Everything needed to render a row, kept because
    /// `bowery_analysis::Silence` deliberately does not carry the
    /// operator or the raw record.
    meta: RwLock<HashMap<String, (String, AlertSilence)>>,
    path: PathBuf,
    cluster_id: String,
    max_entries: usize,
}

/// Deliberately partial: a store's whole contents in a log line would
/// be a wall of signed records, and the useful facts are where it lives
/// and how much it holds. `rows()` is the way to see inside it.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for SilenceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SilenceStore")
            .field("path", &self.path)
            .field("cluster_id", &self.cluster_id)
            .field("len", &self.len())
            .finish()
    }
}

impl SilenceStore {
    /// An empty store that never persists. For tests and for an agent
    /// with no configured path.
    #[must_use]
    pub fn in_memory(cluster_id: impl Into<String>) -> Self {
        Self {
            set: RwLock::new(SilenceSet::new()),
            counts: RwLock::new(HashMap::new()),
            meta: RwLock::new(HashMap::new()),
            path: PathBuf::new(),
            cluster_id: cluster_id.into(),
            max_entries: 4096,
        }
    }

    /// Load and re-verify every silence on disk.
    ///
    /// Re-verified rather than trusted: the file is on a host an
    /// attacker with root can edit, and a silence read back without
    /// checking its signature would let them write their own.
    pub fn load(
        path: impl AsRef<Path>,
        cluster_id: impl Into<String>,
        trusted_operators: &dyn Fn(&Fingerprint) -> Option<VerifyingKey>,
        now_unix_ms: u64,
    ) -> Self {
        let path = path.as_ref().to_path_buf();
        let store = Self {
            path: path.clone(),
            ..Self::in_memory(cluster_id)
        };
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return store;
        };
        let (mut kept, mut skipped) = (0_usize, 0_usize);
        for (lineno, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match decode(line)
                .and_then(|s| store.verify(&s, trusted_operators, now_unix_ms).map(|()| s))
            {
                Ok(silence) => {
                    store.insert_verified(&silence);
                    kept += 1;
                }
                Err(e) => {
                    skipped += 1;
                    warn!(
                        path = %path.display(),
                        line = lineno + 1,
                        error = %e,
                        "skipping unverifiable silence"
                    );
                }
            }
        }
        if kept > 0 || skipped > 0 {
            info!(kept, skipped, path = %path.display(), "loaded alert silences");
        }
        store
    }

    /// Check a silence without storing it.
    ///
    /// Separate from [`Self::accept`] so the operator command path can
    /// report *why* a push was refused without a partially-applied
    /// store.
    pub fn verify(
        &self,
        silence: &AlertSilence,
        trusted_operators: &dyn Fn(&Fingerprint) -> Option<VerifyingKey>,
        now_unix_ms: u64,
    ) -> Result<(), SilenceRejected> {
        if silence.cluster_id != self.cluster_id {
            return Err(SilenceRejected::ClusterMismatch);
        }
        if silence.expires_unix_ms == 0 {
            return Err(SilenceRejected::NoExpiry);
        }
        if silence.expires_unix_ms <= now_unix_ms {
            return Err(SilenceRejected::Expired);
        }
        if spec_of(silence).constrains() == 0 {
            return Err(SilenceRejected::Unconstrained);
        }

        let operator_fp: [u8; 32] = silence
            .operator_fp
            .as_slice()
            .try_into()
            .map_err(|_| SilenceRejected::Malformed)?;
        let vk = trusted_operators(&Fingerprint::from_bytes(operator_fp))
            .ok_or(SilenceRejected::UntrustedOperator)?;
        let sig: [u8; 64] = silence
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| SilenceRejected::BadSignature)?;
        let input = silence
            .to_signing_input()
            .ok_or(SilenceRejected::Malformed)?;
        bowery_crypto::Identity::verify(&vk, &input, &Signature::from_bytes(&sig))
            .map_err(|_| SilenceRejected::BadSignature)?;
        Ok(())
    }

    /// Verify, store and persist a silence.
    pub fn accept(
        &self,
        silence: &AlertSilence,
        trusted_operators: &dyn Fn(&Fingerprint) -> Option<VerifyingKey>,
        now_unix_ms: u64,
    ) -> Result<(), SilenceRejected> {
        self.verify(silence, trusted_operators, now_unix_ms)?;
        if self.len() >= self.max_entries && self.get(&silence.id).is_none() {
            return Err(SilenceRejected::Full);
        }
        let fresh = self.insert_verified(silence);
        if fresh {
            self.persist();
        }
        Ok(())
    }

    /// Insert a silence already known good. Returns whether it changed
    /// anything, so a redelivered copy does not rewrite the file.
    fn insert_verified(&self, silence: &AlertSilence) -> bool {
        let spec = spec_of(silence);
        let converted = Silence {
            id: silence.id.clone(),
            spec,
            // Clamped: a malformed record must not be able to raise a
            // score, only lower one. The clamp also bounds the cast —
            // 0..=1000 is exactly representable in f32.
            weight: f32::from(
                u16::try_from(silence.weight_permille.min(AlertSilence::FULL_WEIGHT)).unwrap_or(0),
            ) / 1000.0,
            reason: silence.reason.clone(),
            issued_unix_ms: silence.issued_unix_ms,
            expires_unix_ms: silence.expires_unix_ms,
        };
        let mut set = self.set.write().expect("silence set poisoned");
        let previous = set.get(&silence.id).cloned();
        set.insert(converted);
        let changed = set.get(&silence.id) != previous.as_ref();
        drop(set);
        if changed {
            self.meta.write().expect("silence meta poisoned").insert(
                silence.id.clone(),
                (hex_lower(&silence.operator_fp), silence.clone()),
            );
            self.counts
                .write()
                .expect("silence counts poisoned")
                .entry(silence.id.clone())
                .or_default();
        }
        changed
    }

    /// Decide what a silence does to an alert, and count the match.
    ///
    /// Counting here rather than at the call site means a suppressed
    /// alert is never invisible: it is absent from the inbox and present
    /// in `bowery_silences`.
    pub fn decide(
        &self,
        subject: &AlertSubject<'_>,
        suspicion: f32,
        now_unix_ms: u64,
    ) -> SilenceDecision {
        let decision =
            self.set
                .read()
                .expect("silence set poisoned")
                .decide(subject, suspicion, now_unix_ms);
        if let SilenceDecision::Damped { silence_id, .. } = &decision
            && let Some(c) = self
                .counts
                .read()
                .expect("silence counts poisoned")
                .get(silence_id)
        {
            c.matched.fetch_add(1, Ordering::Relaxed);
            c.last_matched_unix_ms.store(now_unix_ms, Ordering::Relaxed);
        }
        decision
    }

    /// Drop expired silences, and say how many went.
    pub fn sweep(&self, now_unix_ms: u64) -> usize {
        let dropped = self
            .set
            .write()
            .expect("silence set poisoned")
            .sweep(now_unix_ms);
        if dropped > 0 {
            let live: Vec<String> = self
                .set
                .read()
                .expect("silence set poisoned")
                .iter()
                .map(|s| s.id.clone())
                .collect();
            self.counts
                .write()
                .expect("silence counts poisoned")
                .retain(|id, _| live.contains(id));
            self.meta
                .write()
                .expect("silence meta poisoned")
                .retain(|id, _| live.contains(id));
            self.persist();
            info!(dropped, "expired alert silences swept");
        }
        dropped
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.set.read().expect("silence set poisoned").len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<Silence> {
        self.set
            .read()
            .expect("silence set poisoned")
            .get(id)
            .cloned()
    }

    /// Every silence, with what it has suppressed. Sorted by id so
    /// output is stable.
    #[must_use]
    pub fn rows(&self) -> Vec<SilenceRow> {
        let set = self.set.read().expect("silence set poisoned");
        let counts = self.counts.read().expect("silence counts poisoned");
        let meta = self.meta.read().expect("silence meta poisoned");
        let mut out: Vec<SilenceRow> = set
            .iter()
            .map(|s| {
                let (matched, last) = counts.get(&s.id).map_or((0, 0), |c| {
                    (
                        c.matched.load(Ordering::Relaxed),
                        c.last_matched_unix_ms.load(Ordering::Relaxed),
                    )
                });
                SilenceRow {
                    id: s.id.clone(),
                    rule_id: s.spec.rule_id.clone(),
                    exe_sha256_hex: s.spec.exe_sha256_hex.clone(),
                    exe_path: s.spec.exe_path.clone(),
                    host_fp_hex: s.spec.host_fp_hex.clone(),
                    weight: s.weight,
                    reason: s.reason.clone(),
                    issued_unix_ms: s.issued_unix_ms,
                    expires_unix_ms: s.expires_unix_ms,
                    operator_fp_hex: meta
                        .get(&s.id)
                        .map(|(op, _)| op.clone())
                        .unwrap_or_default(),
                    matched,
                    last_matched_unix_ms: (last > 0).then_some(last),
                }
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Write every held silence back, replacing the file.
    ///
    /// Whole-file rather than append: a sweep removes entries, and an
    /// append-only file would keep re-admitting expired silences on the
    /// next load until something rewrote it.
    fn persist(&self) {
        use base64::Engine as _;
        use prost::Message as _;

        if self.path.as_os_str().is_empty() {
            return;
        }
        let meta = self.meta.read().expect("silence meta poisoned");
        let mut out = String::new();
        out.push_str("# operator-signed alert silences; re-verified on load\n");
        for (_operator, record) in meta.values() {
            out.push_str(&base64::prelude::BASE64_STANDARD.encode(record.encode_to_vec()));
            out.push('\n');
        }
        drop(meta);
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&self.path, out) {
            warn!(path = %self.path.display(), error = %e, "could not persist alert silences");
        }
    }
}

fn spec_of(s: &AlertSilence) -> SilenceSpec {
    SilenceSpec {
        rule_id: s.rule_id.clone(),
        exe_sha256_hex: s.exe_sha256_hex.clone(),
        exe_path: s.exe_path.clone(),
        host_fp_hex: hex_lower(&s.host_fp),
    }
}

fn decode(line: &str) -> Result<AlertSilence, SilenceRejected> {
    use base64::Engine as _;
    use prost::Message as _;
    let raw = base64::prelude::BASE64_STANDARD
        .decode(line.as_bytes())
        .map_err(|_| SilenceRejected::Malformed)?;
    AlertSilence::decode(raw.as_slice()).map_err(|_| SilenceRejected::Malformed)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_crypto::Identity;

    const CLUSTER: &str = "prod";

    fn sign(operator: &Identity, mut s: AlertSilence) -> AlertSilence {
        s.operator_fp = operator.fingerprint().as_bytes().to_vec();
        let input = s.to_signing_input().expect("signable");
        s.sig = operator.sign(&input).to_bytes().to_vec();
        s
    }

    fn a_silence() -> AlertSilence {
        AlertSilence {
            id: "sil-1".into(),
            cluster_id: CLUSTER.into(),
            rule_id: "cred.read_netrc".into(),
            exe_sha256_hex: "8353a512".into(),
            exe_path: "/home/j/.netrc".into(),
            host_fp: Vec::new(),
            weight_permille: 0,
            reason: "git reads its own netrc".into(),
            issued_unix_ms: 1_000,
            expires_unix_ms: 100_000,
            operator_fp: Vec::new(),
            sig: Vec::new(),
        }
    }

    fn trusting(op: &Identity) -> impl Fn(&Fingerprint) -> Option<VerifyingKey> + '_ {
        move |fp| (*fp == op.fingerprint()).then(|| op.verifying_key())
    }

    fn subject<'a>() -> AlertSubject<'a> {
        AlertSubject {
            rule_id: "cred.read_netrc",
            exe_sha256_hex: "8353a512",
            exe_path: "/home/j/.netrc",
            host_fp_hex: "aabb",
        }
    }

    // -- acceptance -----------------------------------------------------

    #[test]
    fn a_properly_signed_silence_is_accepted_and_applies() {
        let op = Identity::generate();
        let store = SilenceStore::in_memory(CLUSTER);
        store
            .accept(&sign(&op, a_silence()), &trusting(&op), 5_000)
            .expect("accepted");
        assert!(matches!(
            store.decide(&subject(), 0.9, 5_000),
            SilenceDecision::Damped { .. }
        ));
    }

    /// The property that makes a relay unable to forge one.
    #[test]
    fn a_silence_from_an_untrusted_key_is_refused() {
        let op = Identity::generate();
        let attacker = Identity::generate();
        let store = SilenceStore::in_memory(CLUSTER);
        assert_eq!(
            store.accept(&sign(&attacker, a_silence()), &trusting(&op), 5_000),
            Err(SilenceRejected::UntrustedOperator)
        );
        assert!(store.is_empty());
    }

    #[test]
    fn a_tampered_silence_is_refused() {
        let op = Identity::generate();
        let mut signed = sign(&op, a_silence());
        // Widen the match after signing — the attack the signature exists
        // to stop.
        signed.exe_path = String::new();
        let store = SilenceStore::in_memory(CLUSTER);
        assert_eq!(
            store.accept(&signed, &trusting(&op), 5_000),
            Err(SilenceRejected::BadSignature)
        );
    }

    #[test]
    fn a_silence_for_another_cluster_is_refused() {
        let op = Identity::generate();
        let mut s = a_silence();
        s.cluster_id = "staging".into();
        let store = SilenceStore::in_memory(CLUSTER);
        assert_eq!(
            store.accept(&sign(&op, s), &trusting(&op), 5_000),
            Err(SilenceRejected::ClusterMismatch)
        );
    }

    #[test]
    fn an_expired_or_unexpiring_silence_is_refused() {
        let op = Identity::generate();
        let store = SilenceStore::in_memory(CLUSTER);

        let mut expired = a_silence();
        expired.expires_unix_ms = 4_000;
        assert_eq!(
            store.accept(&sign(&op, expired), &trusting(&op), 5_000),
            Err(SilenceRejected::Expired)
        );

        let mut forever = a_silence();
        forever.expires_unix_ms = 0;
        assert_eq!(
            store.accept(&sign(&op, forever), &trusting(&op), 5_000),
            Err(SilenceRejected::NoExpiry)
        );
    }

    /// Refused at the door as well as inert downstream. Two independent
    /// guards, because this is the one that would silence a fleet.
    #[test]
    fn a_silence_that_constrains_nothing_is_refused() {
        let op = Identity::generate();
        let mut s = a_silence();
        s.rule_id = String::new();
        s.exe_sha256_hex = String::new();
        s.exe_path = String::new();
        s.host_fp = Vec::new();
        let store = SilenceStore::in_memory(CLUSTER);
        assert_eq!(
            store.accept(&sign(&op, s), &trusting(&op), 5_000),
            Err(SilenceRejected::Unconstrained)
        );
    }

    /// A malformed record must not be able to raise a score.
    #[test]
    fn an_over_full_weight_is_clamped_rather_than_amplifying() {
        let op = Identity::generate();
        let mut s = a_silence();
        s.weight_permille = 50_000;
        let store = SilenceStore::in_memory(CLUSTER);
        store
            .accept(&sign(&op, s), &trusting(&op), 5_000)
            .expect("ok");
        match store.decide(&subject(), 0.5, 5_000) {
            SilenceDecision::Damped { to, .. } => assert!(to <= 0.5, "{to}"),
            SilenceDecision::Unaffected => panic!("should have matched"),
        }
    }

    // -- counting -------------------------------------------------------

    /// A silence that has swallowed thousands of alerts has to be
    /// visible as such, or "quiet" and "muted" look identical.
    #[test]
    fn matches_are_counted_and_reported() {
        let op = Identity::generate();
        let store = SilenceStore::in_memory(CLUSTER);
        store
            .accept(&sign(&op, a_silence()), &trusting(&op), 5_000)
            .expect("ok");
        for _ in 0..3 {
            store.decide(&subject(), 0.9, 6_000);
        }
        let rows = store.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].matched, 3);
        assert_eq!(rows[0].last_matched_unix_ms, Some(6_000));
        assert_eq!(rows[0].reason, "git reads its own netrc");
    }

    #[test]
    fn a_silence_that_never_matched_reports_no_timestamp() {
        let op = Identity::generate();
        let store = SilenceStore::in_memory(CLUSTER);
        store
            .accept(&sign(&op, a_silence()), &trusting(&op), 5_000)
            .expect("ok");
        assert_eq!(store.rows()[0].matched, 0);
        assert_eq!(store.rows()[0].last_matched_unix_ms, None);
    }

    // -- lifecycle ------------------------------------------------------

    #[test]
    fn sweeping_drops_expired_silences_and_their_counters() {
        let op = Identity::generate();
        let store = SilenceStore::in_memory(CLUSTER);
        store
            .accept(&sign(&op, a_silence()), &trusting(&op), 5_000)
            .expect("ok");
        assert_eq!(store.sweep(6_000), 0, "not yet expired");
        assert_eq!(store.sweep(200_000), 1);
        assert!(store.is_empty());
        assert!(store.rows().is_empty());
    }

    /// Re-verified on load, because the file lives on a host root can
    /// edit — a silence trusted because it was on disk would let an
    /// attacker write their own.
    #[test]
    fn silences_round_trip_through_a_file_and_are_reverified() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("silences.jsonl");
        let op = Identity::generate();

        let store = SilenceStore::load(&path, CLUSTER, &trusting(&op), 5_000);
        store
            .accept(&sign(&op, a_silence()), &trusting(&op), 5_000)
            .expect("ok");
        assert_eq!(store.len(), 1);

        let reloaded = SilenceStore::load(&path, CLUSTER, &trusting(&op), 5_000);
        assert_eq!(reloaded.len(), 1);
        assert!(matches!(
            reloaded.decide(&subject(), 0.9, 5_000),
            SilenceDecision::Damped { .. }
        ));

        // The same file under a key the agent does not trust yields
        // nothing at all.
        let stranger = Identity::generate();
        let refused = SilenceStore::load(&path, CLUSTER, &trusting(&stranger), 5_000);
        assert!(refused.is_empty());
    }

    /// One bad line must not cost an agent every valid silence it holds.
    #[test]
    fn a_corrupt_line_is_skipped_rather_than_fatal() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("silences.jsonl");
        let op = Identity::generate();

        let store = SilenceStore::load(&path, CLUSTER, &trusting(&op), 5_000);
        store
            .accept(&sign(&op, a_silence()), &trusting(&op), 5_000)
            .expect("ok");

        let mut raw = std::fs::read_to_string(&path).unwrap();
        raw.push_str("not-base64-at-all!!!\n");
        std::fs::write(&path, raw).unwrap();

        let reloaded = SilenceStore::load(&path, CLUSTER, &trusting(&op), 5_000);
        assert_eq!(reloaded.len(), 1, "the good line survives the bad one");
    }

    /// An expired silence on disk must not come back after a restart.
    #[test]
    fn an_expired_silence_is_not_reloaded() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("silences.jsonl");
        let op = Identity::generate();

        let store = SilenceStore::load(&path, CLUSTER, &trusting(&op), 5_000);
        store
            .accept(&sign(&op, a_silence()), &trusting(&op), 5_000)
            .expect("ok");

        let later = SilenceStore::load(&path, CLUSTER, &trusting(&op), 500_000);
        assert!(later.is_empty(), "expiry survives a restart");
    }

    #[test]
    fn a_reissue_replaces_rather_than_stacks() {
        let op = Identity::generate();
        let store = SilenceStore::in_memory(CLUSTER);
        store
            .accept(&sign(&op, a_silence()), &trusting(&op), 5_000)
            .expect("ok");
        let mut revoked = a_silence();
        revoked.weight_permille = AlertSilence::FULL_WEIGHT;
        revoked.issued_unix_ms = 9_000;
        store
            .accept(&sign(&op, revoked), &trusting(&op), 5_000)
            .expect("ok");
        assert_eq!(store.len(), 1);
        // Full weight leaves the score alone.
        match store.decide(&subject(), 0.9, 9_500) {
            SilenceDecision::Damped { to, .. } => assert!((to - 0.9).abs() < 1e-6, "{to}"),
            SilenceDecision::Unaffected => panic!("still matches, at full weight"),
        }
    }

    #[test]
    fn a_missing_file_is_an_empty_store_not_an_error() {
        let op = Identity::generate();
        let store = SilenceStore::load("/nonexistent/silences.jsonl", CLUSTER, &trusting(&op), 1);
        assert!(store.is_empty());
    }
}
