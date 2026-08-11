//! Phase-3 mesh trust: who is allowed to be a peer, and how one stops
//! being one.
//!
//! # The gap this closes
//!
//! Admission was trust-on-first-use over the gossip mesh: during the
//! bootstrap window an agent pinned any verifying key it saw gossiping.
//! But chitchat gossip is plain, unauthenticated UDP — anything that can
//! reach port 9901 can announce an arbitrary self-declared identity. So
//! "can send a UDP packet to this host during a window" was the whole of
//! admission control, and once pinned there was no way back out: a
//! pinned peer answers whisper questions (feeding quorum confirmation),
//! receives distributed YARA rules, and relays fan-out queries, forever.
//!
//! Two pieces fix that:
//!
//! - [`verify_grant`] — an operator-signed [`MembershipGrant`] admits a
//!   peer. Agents already trust operator public keys, so a grant needs
//!   no new trust root and no enrollment handshake: it rides the same
//!   gossip KV as the role vector and is verified offline.
//! - [`RevocationStore`] — an operator-signed [`Revocation`] ejects one,
//!   permanently.
//!
//! # Why verification is fussy
//!
//! A grant is published in plaintext gossip and is *meant* to be
//! readable, so it can be harvested off the wire. Every check below
//! exists to make a harvested grant useless to anyone else:
//! it is bound to one `agent_fp`, to one `cluster_id`, and optionally to
//! a time window.

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;

use base64::prelude::Engine as _;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use bowery_crypto::Fingerprint;
use bowery_proto::{MembershipGrant, Revocation};
use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use crate::known_neighbors::{Error as KnError, Result as KnResult};

const FILE_MODE: u32 = 0o600;

/// Why a grant was refused. Every variant is a distinct attack the check
/// defeats, so they are reported separately rather than collapsed into a
/// single "invalid" — an operator debugging enrollment needs to know
/// *which* check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GrantError {
    #[error("grant has a malformed agent or operator fingerprint")]
    MalformedFingerprint,
    #[error("grant is signed by an operator key this agent does not trust")]
    UntrustedOperator,
    #[error("grant signature is invalid")]
    BadSignature,
    #[error("grant is for a different agent identity")]
    IdentityMismatch,
    #[error("grant is for a different mesh cluster")]
    ClusterMismatch,
    #[error("grant has expired")]
    Expired,
}

/// Verify an operator-signed membership grant against the identity that
/// actually presented it.
///
/// `presenter` is the fingerprint of the peer gossiping this grant, and
/// checking it against `grant.agent_fp` is the check that matters most:
/// grants travel in the clear, so without this binding any host could
/// replay a harvested grant under its own key and join the mesh.
///
/// `trusted_operators` resolves an operator fingerprint to its verifying
/// key — in practice the agent's configured `[operators] pubkeys_b64`.
pub fn verify_grant(
    grant: &MembershipGrant,
    presenter: &Fingerprint,
    cluster_id: &str,
    trusted_operators: &dyn Fn(&Fingerprint) -> Option<VerifyingKey>,
    now: SystemTime,
) -> Result<(), GrantError> {
    let agent_fp: [u8; 32] = grant
        .agent_fp
        .as_slice()
        .try_into()
        .map_err(|_| GrantError::MalformedFingerprint)?;
    let operator_fp_bytes: [u8; 32] = grant
        .operator_fp
        .as_slice()
        .try_into()
        .map_err(|_| GrantError::MalformedFingerprint)?;

    // Bind to the presenting identity before anything else: this is the
    // check that makes a publicly-readable grant non-transferable.
    if &agent_fp != presenter.as_bytes() {
        return Err(GrantError::IdentityMismatch);
    }
    if grant.cluster_id != cluster_id {
        return Err(GrantError::ClusterMismatch);
    }

    let now_ms = unix_ms(now);
    // `0` means no expiry.
    if grant.expires_unix_ms != 0 && now_ms > grant.expires_unix_ms {
        return Err(GrantError::Expired);
    }

    let operator_fp = Fingerprint::from_bytes(operator_fp_bytes);
    let vk = trusted_operators(&operator_fp).ok_or(GrantError::UntrustedOperator)?;

    let sig_bytes: [u8; 64] = grant
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| GrantError::BadSignature)?;
    let signing_input = grant
        .to_signing_input()
        .ok_or(GrantError::MalformedFingerprint)?;
    bowery_crypto::Identity::verify(&vk, &signing_input, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| GrantError::BadSignature)?;
    Ok(())
}

/// Verify an operator-signed revocation.
///
/// Deliberately *not* bound to a presenter: a revocation is about a
/// third party by definition, and any peer may legitimately relay it.
/// Its authority comes entirely from the operator signature, which is
/// also why relaying one can't be abused — a forged revocation cannot be
/// produced without an operator key.
pub fn verify_revocation(
    revocation: &Revocation,
    cluster_id: &str,
    trusted_operators: &dyn Fn(&Fingerprint) -> Option<VerifyingKey>,
) -> Result<Fingerprint, GrantError> {
    let agent_fp: [u8; 32] = revocation
        .agent_fp
        .as_slice()
        .try_into()
        .map_err(|_| GrantError::MalformedFingerprint)?;
    let operator_fp_bytes: [u8; 32] = revocation
        .operator_fp
        .as_slice()
        .try_into()
        .map_err(|_| GrantError::MalformedFingerprint)?;

    if revocation.cluster_id != cluster_id {
        return Err(GrantError::ClusterMismatch);
    }
    // Note: no expiry check. A revocation does not age out — see
    // `RevocationStore`.

    let operator_fp = Fingerprint::from_bytes(operator_fp_bytes);
    let vk = trusted_operators(&operator_fp).ok_or(GrantError::UntrustedOperator)?;
    let sig_bytes: [u8; 64] = revocation
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| GrantError::BadSignature)?;
    let signing_input = revocation
        .to_signing_input()
        .ok_or(GrantError::MalformedFingerprint)?;
    bowery_crypto::Identity::verify(&vk, &signing_input, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| GrantError::BadSignature)?;
    Ok(Fingerprint::from_bytes(agent_fp))
}

// ---------------------------------------------------------------------------
// Persistent revocation store
// ---------------------------------------------------------------------------

/// One revoked identity, as loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedEntry {
    pub fingerprint: String,
    pub issued_unix_ms: u64,
    pub reason: String,
    pub operator_fp: String,
}

/// Verified set of revoked agent identities, backed by a file of signed
/// revocations — one base64 `Revocation` per line.
///
/// The file holds the operator-signed artifacts themselves rather than a
/// digest of them, and every line is re-verified on load. That is the
/// whole design: the store has no authority of its own, so editing the
/// file can only *remove* trust decisions, never manufacture one. A
/// tampered or foreign line simply fails its signature check and is
/// skipped. It also means the artifact `bowery trust revoke` prints is
/// exactly what gets installed — no format conversion in between.
///
/// **There is no un-revoke.** An attacker who can make an agent forget a
/// revocation has undone the containment, so entries are only ever
/// appended; re-admitting a rebuilt host means giving it a fresh
/// identity key. Duplicates are harmless, which makes the file safe to
/// concatenate from any source.
#[derive(Debug)]
pub struct RevocationStore {
    state: RwLock<HashMap<Fingerprint, RevokedEntry>>,
    path: PathBuf,
}

impl RevocationStore {
    /// Load and verify every signed revocation in `path`.
    ///
    /// A missing file is an empty store. Lines that fail verification
    /// are logged and skipped rather than failing the load: one bad line
    /// pasted into the file must not cost an agent every *valid*
    /// revocation it already had.
    pub fn load_signed(
        path: impl AsRef<Path>,
        cluster_id: &str,
        trusted_operators: &dyn Fn(&Fingerprint) -> Option<VerifyingKey>,
    ) -> KnResult<Self> {
        let path = path.as_ref().to_path_buf();
        let store = Self {
            state: RwLock::new(HashMap::new()),
            path: path.clone(),
        };
        if !path.exists() {
            return Ok(store);
        }
        let raw = fs::read_to_string(&path).map_err(|source| KnError::Io {
            path: path.clone(),
            source,
        })?;
        for (lineno, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match decode_and_verify(line, cluster_id, trusted_operators) {
                Ok((fp, rev)) => {
                    store.record(fp, &rev);
                }
                Err(e) => tracing::warn!(
                    path = %path.display(),
                    line = lineno + 1,
                    error = %e,
                    "skipping unverifiable revocation"
                ),
            }
        }
        Ok(store)
    }

    /// In-memory store, for tests.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            state: RwLock::new(HashMap::new()),
            path: PathBuf::new(),
        }
    }

    pub fn is_revoked(&self, fp: &Fingerprint) -> bool {
        self.state
            .read()
            .expect("revocation store poisoned")
            .contains_key(fp)
    }

    pub fn len(&self) -> usize {
        self.state.read().expect("revocation store poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// All revocations, for the `bowery_revocations` SQL view.
    pub fn entries(&self) -> Vec<RevokedEntry> {
        let mut v: Vec<RevokedEntry> = self
            .state
            .read()
            .expect("revocation store poisoned")
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        v
    }

    /// Record an already-verified revocation in memory. Returns `true`
    /// if it was new.
    fn record(&self, fp: Fingerprint, revocation: &Revocation) -> bool {
        let mut state = self.state.write().expect("revocation store poisoned");
        if state.contains_key(&fp) {
            return false;
        }
        state.insert(
            fp,
            RevokedEntry {
                fingerprint: fp.to_hex(),
                issued_unix_ms: revocation.issued_unix_ms,
                reason: revocation.reason.clone(),
                operator_fp: hex_lower(&revocation.operator_fp),
            },
        );
        true
    }

    /// Record a verified revocation and append its signed form to the
    /// backing file, so it survives a restart.
    ///
    /// Returns `true` if it was new — which is what a propagating agent
    /// would use to decide whether to forward, so a revocation floods
    /// the mesh once and then stops.
    pub fn insert(&self, fp: Fingerprint, revocation: &Revocation) -> KnResult<bool> {
        if !self.record(fp, revocation) {
            return Ok(false);
        }
        if self.path.as_os_str().is_empty() {
            return Ok(true); // in-memory
        }
        let line =
            base64::prelude::BASE64_STANDARD.encode(prost::Message::encode_to_vec(revocation));
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| KnError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        // Append rather than rewrite: the file is a log of signed
        // artifacts, and appending can't corrupt the ones already there.
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(FILE_MODE)
            .open(&self.path)
            .map_err(|source| KnError::Io {
                path: self.path.clone(),
                source,
            })?;
        writeln!(f, "{line}").map_err(|source| KnError::Io {
            path: self.path.clone(),
            source,
        })?;
        Ok(true)
    }
}

/// Decode a base64 line and verify it, returning the revoked identity.
fn decode_and_verify(
    line: &str,
    cluster_id: &str,
    trusted_operators: &dyn Fn(&Fingerprint) -> Option<VerifyingKey>,
) -> Result<(Fingerprint, Revocation), GrantError> {
    use base64::Engine as _;
    let raw = base64::prelude::BASE64_STANDARD
        .decode(line.as_bytes())
        .map_err(|_| GrantError::MalformedFingerprint)?;
    let rev = <Revocation as prost::Message>::decode(raw.as_slice())
        .map_err(|_| GrantError::MalformedFingerprint)?;
    let fp = verify_revocation(&rev, cluster_id, trusted_operators)?;
    Ok((fp, rev))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bowery_crypto::Identity;

    use super::*;

    fn sign_grant(
        operator: &Identity,
        agent_fp: &Fingerprint,
        cluster: &str,
        expires_unix_ms: u64,
    ) -> MembershipGrant {
        let op_fp = operator.fingerprint();
        let issued = 1_700_000_000_000;
        let input = MembershipGrant::signing_input(
            agent_fp.as_bytes(),
            cluster,
            issued,
            expires_unix_ms,
            op_fp.as_bytes(),
        );
        let sig = operator.sign(&input);
        MembershipGrant {
            agent_fp: agent_fp.as_bytes().to_vec(),
            cluster_id: cluster.to_string(),
            issued_unix_ms: issued,
            expires_unix_ms,
            operator_fp: op_fp.as_bytes().to_vec(),
            sig: sig.to_bytes().to_vec(),
        }
    }

    fn resolver(operator: &Identity) -> impl Fn(&Fingerprint) -> Option<VerifyingKey> + use<> {
        let fp = operator.fingerprint();
        let vk = operator.verifying_key();
        move |q: &Fingerprint| (*q == fp).then_some(vk)
    }

    #[test]
    fn a_valid_grant_admits_the_agent_it_names() {
        let operator = Identity::generate();
        let agent = Identity::generate();
        let grant = sign_grant(&operator, &agent.fingerprint(), "prod", 0);
        assert_eq!(
            verify_grant(
                &grant,
                &agent.fingerprint(),
                "prod",
                &resolver(&operator),
                SystemTime::now()
            ),
            Ok(())
        );
    }

    /// The attack the `agent_fp` binding exists for: grants are
    /// published in plaintext gossip, so anyone can harvest one. It must
    /// be useless under a different key.
    #[test]
    fn a_harvested_grant_cannot_be_replayed_by_another_identity() {
        let operator = Identity::generate();
        let victim = Identity::generate();
        let attacker = Identity::generate();
        let grant = sign_grant(&operator, &victim.fingerprint(), "prod", 0);

        assert_eq!(
            verify_grant(
                &grant,
                &attacker.fingerprint(),
                "prod",
                &resolver(&operator),
                SystemTime::now()
            ),
            Err(GrantError::IdentityMismatch),
            "a grant must not admit whoever happens to present it"
        );
    }

    #[test]
    fn a_grant_for_another_cluster_is_refused() {
        let operator = Identity::generate();
        let agent = Identity::generate();
        let grant = sign_grant(&operator, &agent.fingerprint(), "staging", 0);
        assert_eq!(
            verify_grant(
                &grant,
                &agent.fingerprint(),
                "prod",
                &resolver(&operator),
                SystemTime::now()
            ),
            Err(GrantError::ClusterMismatch),
            "a staging grant must not admit a peer into production"
        );
    }

    #[test]
    fn a_grant_signed_by_an_unknown_operator_is_refused() {
        let real_operator = Identity::generate();
        let rogue = Identity::generate();
        let agent = Identity::generate();
        // Correctly signed — by the wrong key.
        let grant = sign_grant(&rogue, &agent.fingerprint(), "prod", 0);
        assert_eq!(
            verify_grant(
                &grant,
                &agent.fingerprint(),
                "prod",
                &resolver(&real_operator),
                SystemTime::now()
            ),
            Err(GrantError::UntrustedOperator)
        );
    }

    #[test]
    fn a_tampered_grant_fails_the_signature_check() {
        let operator = Identity::generate();
        let agent = Identity::generate();
        let mut grant = sign_grant(&operator, &agent.fingerprint(), "prod", 0);
        // Extend our own expiry — the field is covered by the signature.
        grant.expires_unix_ms = u64::MAX;
        assert_eq!(
            verify_grant(
                &grant,
                &agent.fingerprint(),
                "prod",
                &resolver(&operator),
                SystemTime::now()
            ),
            Err(GrantError::BadSignature)
        );
    }

    #[test]
    fn expiry_is_enforced_and_zero_means_never() {
        let operator = Identity::generate();
        let agent = Identity::generate();
        // Well after the expiry stamped below.
        let now = SystemTime::UNIX_EPOCH + Duration::from_hours(500_000);

        let expired = sign_grant(&operator, &agent.fingerprint(), "prod", 1_700_000_100_000);
        assert_eq!(
            verify_grant(
                &expired,
                &agent.fingerprint(),
                "prod",
                &resolver(&operator),
                now
            ),
            Err(GrantError::Expired)
        );

        let forever = sign_grant(&operator, &agent.fingerprint(), "prod", 0);
        assert_eq!(
            verify_grant(
                &forever,
                &agent.fingerprint(),
                "prod",
                &resolver(&operator),
                now
            ),
            Ok(())
        );
    }

    fn sign_revocation(operator: &Identity, agent_fp: &Fingerprint, cluster: &str) -> Revocation {
        let op_fp = operator.fingerprint();
        let issued = 1_700_000_000_000;
        let reason = "compromised".to_string();
        let input = Revocation::signing_input(
            agent_fp.as_bytes(),
            cluster,
            issued,
            &reason,
            op_fp.as_bytes(),
        );
        let sig = operator.sign(&input);
        Revocation {
            agent_fp: agent_fp.as_bytes().to_vec(),
            cluster_id: cluster.to_string(),
            issued_unix_ms: issued,
            reason,
            operator_fp: op_fp.as_bytes().to_vec(),
            sig: sig.to_bytes().to_vec(),
        }
    }

    #[test]
    fn a_valid_revocation_yields_its_target() {
        let operator = Identity::generate();
        let target = Identity::generate();
        let rev = sign_revocation(&operator, &target.fingerprint(), "prod");
        assert_eq!(
            verify_revocation(&rev, "prod", &resolver(&operator)),
            Ok(target.fingerprint())
        );
    }

    /// The whole point of signing revocations: a compromised *peer* must
    /// not be able to eject healthy agents from the mesh, which would be
    /// a fleet-wide denial of service.
    #[test]
    fn a_peer_cannot_forge_a_revocation() {
        let operator = Identity::generate();
        let compromised_peer = Identity::generate();
        let victim = Identity::generate();
        let forged = sign_revocation(&compromised_peer, &victim.fingerprint(), "prod");
        assert_eq!(
            verify_revocation(&forged, "prod", &resolver(&operator)),
            Err(GrantError::UntrustedOperator)
        );
    }

    #[test]
    fn store_is_idempotent_and_reports_novelty_for_propagation() {
        let operator = Identity::generate();
        let target = Identity::generate();
        let rev = sign_revocation(&operator, &target.fingerprint(), "prod");
        let store = RevocationStore::in_memory();

        assert!(!store.is_revoked(&target.fingerprint()));
        assert!(store.insert(target.fingerprint(), &rev).unwrap());
        assert!(store.is_revoked(&target.fingerprint()));
        assert!(
            !store.insert(target.fingerprint(), &rev).unwrap(),
            "a re-seen revocation must report false so propagation terminates"
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn signed_revocations_round_trip_through_a_file_and_are_reverified() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("revocations.b64");
        let operator = Identity::generate();
        let target = Identity::generate();
        let rev = sign_revocation(&operator, &target.fingerprint(), "prod");
        let resolve = resolver(&operator);

        {
            let store = RevocationStore::load_signed(&path, "prod", &resolve).unwrap();
            store.insert(target.fingerprint(), &rev).unwrap();
        }
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, FILE_MODE,
            "trust files must not be group/world readable"
        );

        let reopened = RevocationStore::load_signed(&path, "prod", &resolve).unwrap();
        assert!(
            reopened.is_revoked(&target.fingerprint()),
            "revocation must survive a restart — otherwise containment lapses on reboot"
        );
        assert_eq!(reopened.entries()[0].reason, "compromised");
    }

    /// The file carries the signed artifacts themselves, so it has no
    /// authority of its own: someone who can edit it can delete lines,
    /// but cannot invent a revocation for a healthy agent. That
    /// asymmetry is why the store re-verifies on every load.
    #[test]
    fn a_forged_line_in_the_file_is_skipped_without_losing_the_valid_ones() {
        use base64::Engine as _;
        use std::io::Write as _;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("revocations.b64");
        let operator = Identity::generate();
        let rogue = Identity::generate();
        let real_target = Identity::generate();
        let victim = Identity::generate();
        let resolve = resolver(&operator);

        {
            let store = RevocationStore::load_signed(&path, "prod", &resolve).unwrap();
            store
                .insert(
                    real_target.fingerprint(),
                    &sign_revocation(&operator, &real_target.fingerprint(), "prod"),
                )
                .unwrap();
        }
        {
            let forged = sign_revocation(&rogue, &victim.fingerprint(), "prod");
            let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(
                f,
                "{}",
                base64::prelude::BASE64_STANDARD.encode(prost::Message::encode_to_vec(&forged))
            )
            .unwrap();
            writeln!(f, "not-base64-at-all").unwrap();
        }

        let store = RevocationStore::load_signed(&path, "prod", &resolve).unwrap();
        assert!(
            store.is_revoked(&real_target.fingerprint()),
            "a bad line must not cost the agent its valid revocations"
        );
        assert!(
            !store.is_revoked(&victim.fingerprint()),
            "a revocation signed by an untrusted key must not eject a healthy agent"
        );
        assert_eq!(store.len(), 1);
    }
}
