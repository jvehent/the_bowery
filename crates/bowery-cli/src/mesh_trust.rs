//! Operator side of Phase-3 mesh trust: minting membership grants and
//! revocations.
//!
//! Both are offline operations — an operator signs a statement with the
//! same identity key that authorises commands, and the artifact is then
//! copied to the agent (a grant) or pushed to the fleet (a revocation).
//! Nothing here talks to the network, which is deliberate: minting must
//! work from an air-gapped key holder.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_crypto::{Fingerprint, Identity};
use bowery_proto::{MembershipGrant, Revocation};
use prost::Message as _;

/// Mint an operator-signed membership grant for `agent_fp`.
///
/// The grant is written base64-encoded, which is what the agent's
/// `[known_neighbors] grant_path` expects and what pastes cleanly into
/// a deploy script.
pub fn mint_grant(
    operator_key: &Path,
    agent_fp_hex: &str,
    cluster_id: &str,
    valid_for: Option<Duration>,
    out: Option<PathBuf>,
) -> Result<()> {
    let operator = Identity::load(operator_key)
        .with_context(|| format!("loading operator key {}", operator_key.display()))?;
    let agent_fp =
        Fingerprint::from_hex(agent_fp_hex).map_err(|e| anyhow!("invalid --agent-fp: {e}"))?;

    let issued_unix_ms = now_unix_ms();
    // `0` means never expires. An expiring grant limits the blast radius
    // of a leaked operator key, but a fleet whose grants lapse silently
    // partitions itself, so the default is deliberately no expiry and
    // the trade-off is the operator's to make.
    let expires_unix_ms = match valid_for {
        Some(d) => issued_unix_ms.saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        None => 0,
    };
    let operator_fp = operator.fingerprint();

    let signing_input = MembershipGrant::signing_input(
        agent_fp.as_bytes(),
        cluster_id,
        issued_unix_ms,
        expires_unix_ms,
        operator_fp.as_bytes(),
    );
    let sig = operator.sign(&signing_input);

    let grant = MembershipGrant {
        agent_fp: agent_fp.as_bytes().to_vec(),
        cluster_id: cluster_id.to_string(),
        issued_unix_ms,
        expires_unix_ms,
        operator_fp: operator_fp.as_bytes().to_vec(),
        sig: sig.to_bytes().to_vec(),
    };
    let encoded = BASE64.encode(grant.encode_to_vec());

    match out {
        Some(path) => {
            std::fs::write(&path, encoded.as_bytes())
                .with_context(|| format!("writing grant to {}", path.display()))?;
            println!("wrote membership grant to {}", path.display());
            println!("  agent    : {agent_fp}");
            println!("  cluster  : {cluster_id}");
            println!(
                "  expires  : {}",
                if expires_unix_ms == 0 {
                    "never".to_string()
                } else {
                    expires_unix_ms.to_string()
                }
            );
            println!(
                "\nOn the agent, set:\n  [known_neighbors]\n  grant_path = \"{}\"",
                path.display()
            );
        }
        None => println!("{encoded}"),
    }
    Ok(())
}

/// Mint an operator-signed revocation for `agent_fp`.
///
/// Emitting the artifact is separate from delivering it: a revocation
/// only takes effect on agents that actually receive it, which is why
/// `bowery_revocations` is queryable fleet-wide with `--fanout`.
pub fn mint_revocation(
    operator_key: &Path,
    agent_fp_hex: &str,
    cluster_id: &str,
    reason: &str,
    out: Option<PathBuf>,
) -> Result<()> {
    let operator = Identity::load(operator_key)
        .with_context(|| format!("loading operator key {}", operator_key.display()))?;
    let agent_fp =
        Fingerprint::from_hex(agent_fp_hex).map_err(|e| anyhow!("invalid --agent-fp: {e}"))?;
    let operator_fp = operator.fingerprint();
    let issued_unix_ms = now_unix_ms();

    let signing_input = Revocation::signing_input(
        agent_fp.as_bytes(),
        cluster_id,
        issued_unix_ms,
        reason,
        operator_fp.as_bytes(),
    );
    let sig = operator.sign(&signing_input);
    let revocation = Revocation {
        agent_fp: agent_fp.as_bytes().to_vec(),
        cluster_id: cluster_id.to_string(),
        issued_unix_ms,
        reason: reason.to_string(),
        operator_fp: operator_fp.as_bytes().to_vec(),
        sig: sig.to_bytes().to_vec(),
    };
    let encoded = BASE64.encode(revocation.encode_to_vec());

    match out {
        Some(path) => {
            std::fs::write(&path, encoded.as_bytes())
                .with_context(|| format!("writing revocation to {}", path.display()))?;
            println!("wrote revocation to {}", path.display());
        }
        None => println!("{encoded}"),
    }
    eprintln!(
        "\nNOTE: a revocation only binds agents that receive it. Install it in each\n\
         agent's [known_neighbors] revocations_path, then confirm fleet-wide with:\n  \
         bowery exec sql --fanout --sql \\\n    \
         \"SELECT fingerprint_hex FROM bowery_revocations WHERE fingerprint_hex = '{agent_fp}'\""
    );
    Ok(())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use bowery_whisper::mesh_trust::{GrantError, verify_grant, verify_revocation};
    use ed25519_dalek::VerifyingKey;

    use super::*;

    /// The CLI and the agent must agree byte-for-byte on the signing
    /// input. A mismatch would produce grants that mint cleanly and are
    /// rejected by every agent — the kind of bug that only shows up in
    /// the field.
    #[test]
    fn a_minted_grant_verifies_on_the_agent_side() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("operator.key");
        let operator = Identity::generate();
        operator.save(&key_path).unwrap();
        let agent = Identity::generate();
        let out = dir.path().join("grant.b64");

        mint_grant(
            &key_path,
            &agent.fingerprint().to_hex(),
            "prod",
            None,
            Some(out.clone()),
        )
        .unwrap();

        let encoded = std::fs::read_to_string(&out).unwrap();
        let raw = BASE64.decode(encoded.trim()).unwrap();
        let grant = MembershipGrant::decode(raw.as_slice()).unwrap();

        let op_fp = operator.fingerprint();
        let op_vk = operator.verifying_key();
        let resolve =
            move |fp: &Fingerprint| -> Option<VerifyingKey> { (*fp == op_fp).then_some(op_vk) };
        assert_eq!(
            verify_grant(
                &grant,
                &agent.fingerprint(),
                "prod",
                &resolve,
                SystemTime::now()
            ),
            Ok(())
        );
    }

    #[test]
    fn a_minted_grant_expires_when_asked_to() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("operator.key");
        let operator = Identity::generate();
        operator.save(&key_path).unwrap();
        let agent = Identity::generate();
        let out = dir.path().join("grant.b64");

        mint_grant(
            &key_path,
            &agent.fingerprint().to_hex(),
            "prod",
            Some(Duration::from_secs(1)),
            Some(out.clone()),
        )
        .unwrap();
        let raw = BASE64
            .decode(std::fs::read_to_string(&out).unwrap().trim())
            .unwrap();
        let grant = MembershipGrant::decode(raw.as_slice()).unwrap();

        let op_fp = operator.fingerprint();
        let op_vk = operator.verifying_key();
        let resolve =
            move |fp: &Fingerprint| -> Option<VerifyingKey> { (*fp == op_fp).then_some(op_vk) };
        let later = SystemTime::now() + Duration::from_hours(1);
        assert_eq!(
            verify_grant(&grant, &agent.fingerprint(), "prod", &resolve, later),
            Err(GrantError::Expired)
        );
    }

    #[test]
    fn a_minted_revocation_verifies_on_the_agent_side() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("operator.key");
        let operator = Identity::generate();
        operator.save(&key_path).unwrap();
        let target = Identity::generate();
        let out = dir.path().join("rev.b64");

        mint_revocation(
            &key_path,
            &target.fingerprint().to_hex(),
            "prod",
            "compromised via CVE-2026-1234",
            Some(out.clone()),
        )
        .unwrap();
        let raw = BASE64
            .decode(std::fs::read_to_string(&out).unwrap().trim())
            .unwrap();
        let rev = Revocation::decode(raw.as_slice()).unwrap();
        assert_eq!(rev.reason, "compromised via CVE-2026-1234");

        let op_fp = operator.fingerprint();
        let op_vk = operator.verifying_key();
        let resolve =
            move |fp: &Fingerprint| -> Option<VerifyingKey> { (*fp == op_fp).then_some(op_vk) };
        assert_eq!(
            verify_revocation(&rev, "prod", &resolve),
            Ok(target.fingerprint())
        );
    }
}
