//! Phase-9 final-1: operator-signed delegations that authorise a
//! relay agent to forward a `SqlQuery` to its pinned peers on
//! behalf of the original operator.
//!
//! See [`bowery_proto::OperatorAuthorization`] for the wire shape.
//! This module provides the signing + verification helpers; the
//! verification logic on the agent side lives in
//! [`bowery-agent`'s `respond_to_operator_command`] and uses the
//! same canonical input.

use bowery_crypto::{Fingerprint, Identity};
use bowery_proto::{OperatorAuthorization, OperatorCommand, OperatorCommandBody};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use prost::Message as _;
use sha2::{Digest, Sha256};

/// Build a signed [`OperatorAuthorization`] that authorises the
/// holder of `identity` to delegate `command` for `request_id`.
///
/// The returned authorisation:
///
/// - binds to `request_id` (must match the outer
///   `OperatorCommand.request_id`),
/// - binds to `command` via SHA-256 of its prost-encoded form, so
///   a relay can't substitute a different SQL string under an
///   authorisation issued for some other query,
/// - is timestamped with the current wall-clock to anchor the
///   skew check on the receiver,
/// - is signed by `identity`'s Ed25519 key.
///
/// Encode with `prost::Message::encode_to_vec` and assign to
/// `OperatorCommand.forwarded_from_operator`.
pub fn sign_operator_authorization(
    identity: &Identity,
    request_id: &str,
    command: &OperatorCommandBody,
) -> OperatorAuthorization {
    let operator_fp = identity.fingerprint();
    let ts_unix_ms = current_unix_ms();
    let command_digest = command_body_digest(command);

    let signing_input = OperatorAuthorization::signing_input(
        operator_fp.as_bytes(),
        ts_unix_ms,
        request_id,
        &command_digest,
    );
    let signature: Signature = identity.signing_key().sign(&signing_input);

    OperatorAuthorization {
        operator_fp: operator_fp.as_bytes().to_vec(),
        ts_unix_ms,
        request_id: request_id.to_string(),
        command_digest: command_digest.to_vec(),
        signature: signature.to_bytes().to_vec(),
    }
}

/// Verify an [`OperatorAuthorization`] against `operator_vk`.
/// Returns the verified operator fingerprint on success. The
/// caller is responsible for: confirming `operator_vk` belongs
/// to a key in the receiver's `[operators]` set, recomputing the
/// `command_digest` from the actual command being run, and
/// checking the timestamp skew.
///
/// This helper exists for unit tests + experimental tooling; the
/// agent's hot path inlines the equivalent checks.
pub fn verify_operator_authorization(
    auth: &OperatorAuthorization,
    operator_vk: &VerifyingKey,
) -> Result<Fingerprint, &'static str> {
    if auth.operator_fp.len() != 32 {
        return Err("bad operator_fp length");
    }
    if auth.command_digest.len() != 32 {
        return Err("bad command_digest length");
    }
    if auth.signature.len() != 64 {
        return Err("bad signature length");
    }
    let mut fp_arr = [0u8; 32];
    fp_arr.copy_from_slice(&auth.operator_fp);
    let mut digest_arr = [0u8; 32];
    digest_arr.copy_from_slice(&auth.command_digest);
    let signing_input = OperatorAuthorization::signing_input(
        &fp_arr,
        auth.ts_unix_ms,
        &auth.request_id,
        &digest_arr,
    );
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&auth.signature);
    let sig = Signature::from_bytes(&sig_arr);
    operator_vk
        .verify_strict(&signing_input, &sig)
        .map_err(|_| "signature verification failed")?;
    Ok(Fingerprint::from_bytes(fp_arr))
}

/// SHA-256 of a *normalised* `OperatorCommandBody`. Phase-9
/// final-1: the relay rewrites `SqlQuery.fanout` from `true` (the
/// operator's request) to `false` (the peer's view) for cycle
/// prevention; if we hashed the raw body the digest would change
/// at the relay hop and peer-side verification would fail.
///
/// Normalisation forces `fanout = false` and `peers = []` for
/// `Sql` bodies before encoding, so both the operator-side
/// signer and every verifier (relay + peer) compute the same
/// hash. `fanout` is fundamentally a dispatch instruction; it
/// doesn't change *what data the peer returns*, so excluding it
/// from the integrity binding is correct.
pub fn command_body_digest(body: &OperatorCommandBody) -> [u8; 32] {
    let normalised = match body {
        OperatorCommandBody::Sql(q) => OperatorCommandBody::Sql(bowery_proto::SqlQuery {
            sql: q.sql.clone(),
            fanout: false,
            peers: Vec::new(),
        }),
        OperatorCommandBody::Sysquery(_) => body.clone(),
    };
    let wrapper = OperatorCommand {
        request_id: String::new(),
        timeout_ms: 0,
        forwarded_from_operator: Vec::new(),
        command: Some(normalised),
    };
    let bytes = wrapper.encode_to_vec();
    Sha256::digest(&bytes).into()
}

fn current_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_proto::{SqlQuery, SysqueryQuery};

    #[test]
    fn signed_authorization_round_trips() {
        let id = Identity::generate();
        let body = OperatorCommandBody::Sql(SqlQuery {
            sql: "SELECT 1".into(),
            fanout: true,
            peers: Vec::new(),
        });
        let auth = sign_operator_authorization(&id, "req-1", &body);
        let fp = verify_operator_authorization(&auth, &id.verifying_key()).expect("verify");
        assert_eq!(fp, id.fingerprint());
    }

    #[test]
    fn tampered_request_id_fails_verification() {
        let id = Identity::generate();
        let body = OperatorCommandBody::Sql(SqlQuery {
            sql: "SELECT 1".into(),
            fanout: false,
            peers: Vec::new(),
        });
        let mut auth = sign_operator_authorization(&id, "req-1", &body);
        auth.request_id = "req-2".into();
        assert!(verify_operator_authorization(&auth, &id.verifying_key()).is_err());
    }

    #[test]
    fn different_command_body_fails_digest_match() {
        // Caller-side digest check (the agent-side flow) catches
        // a relay swapping the command. Here we just confirm two
        // different bodies produce different digests.
        let body_a = OperatorCommandBody::Sql(SqlQuery {
            sql: "SELECT 1".into(),
            fanout: false,
            peers: Vec::new(),
        });
        let body_b = OperatorCommandBody::Sysquery(SysqueryQuery {
            sql: "SELECT 1".into(),
        });
        assert_ne!(command_body_digest(&body_a), command_body_digest(&body_b));
    }
}
