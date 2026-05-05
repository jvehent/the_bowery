//! `bowery audit verify` — operator-side validator for an agent's
//! signed audit log.
//!
//! The agent (with `[response] audit_log_path = ...` set) appends one
//! JSON-encoded [`AuditEnvelope`] per action attempt. This subcommand
//! walks the file, verifies every envelope under the host's
//! verifying key, and reports a pass/fail summary. A single bad line
//! makes the whole run fail-noisy: tamper-evidence only works if
//! operators *act on* a mismatch.
//!
//! The host pubkey can come from:
//! - `--pubkey-b64 <base64>` — paste from `bowery key info` on the agent
//! - `--pubkey-from <path>` — point at the agent's identity-key file
//!
//! Use `--json` to emit machine-readable per-line results (one JSON
//! object per audit line).

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_crypto::Identity;
use bowery_response::AuditEnvelope;
use ed25519_dalek::VerifyingKey;
use serde::Serialize;

/// Per-line verification result, emitted by `--json`.
#[derive(Serialize)]
struct LineReport<'a> {
    line: usize,
    ok: bool,
    error: Option<String>,
    episode_id: Option<&'a str>,
    action_id: Option<&'a str>,
    engine: Option<&'a str>,
}

pub(crate) fn verify(
    path: &Path,
    pubkey_b64: Option<String>,
    pubkey_from: Option<PathBuf>,
    json: bool,
) -> Result<ExitCode> {
    let vk = load_pubkey(pubkey_b64, pubkey_from)?;

    let file = File::open(path).with_context(|| format!("opening audit log {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut total = 0usize;
    let mut ok = 0usize;
    let mut failed = 0usize;
    // Hash-chain tracking. The first entry is expected to have seq=0
    // and an empty prev_sig_hex; every subsequent entry strictly
    // increments seq by 1 and copies the previous entry's sig_hex
    // into its prev_sig_hex. Any deviation from this is a chain
    // break — either tampering or missing entries.
    let mut expected_seq: u64 = 0;
    let mut last_sig_hex: String = String::new();

    for (idx, line) in reader.lines().enumerate() {
        let lineno = idx + 1;
        let line = line.with_context(|| format!("reading {} line {lineno}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        total += 1;
        let parsed: Result<AuditEnvelope, _> = serde_json::from_str(&line);
        match parsed {
            Ok(env) => {
                let sig_check = env.verify(&vk);
                let chain_check = check_chain(&env, expected_seq, &last_sig_hex);
                let line_ok = sig_check.is_ok() && chain_check.is_ok();
                if line_ok {
                    ok += 1;
                    if json {
                        let report = LineReport {
                            line: lineno,
                            ok: true,
                            error: None,
                            episode_id: Some(&env.record.episode_id),
                            action_id: Some(&env.record.action_id),
                            engine: Some(&env.record.engine),
                        };
                        println!("{}", serde_json::to_string(&report)?);
                    }
                    // Advance chain tracking only on a clean line.
                    expected_seq = env.record.seq.saturating_add(1);
                    last_sig_hex.clone_from(&env.sig_hex);
                } else {
                    failed += 1;
                    let err_msg = match (sig_check, chain_check) {
                        (Err(e), _) => format!("signature: {e}"),
                        (_, Err(e)) => format!("chain: {e}"),
                        _ => unreachable!(),
                    };
                    if json {
                        let report = LineReport {
                            line: lineno,
                            ok: false,
                            error: Some(err_msg),
                            episode_id: Some(&env.record.episode_id),
                            action_id: Some(&env.record.action_id),
                            engine: Some(&env.record.engine),
                        };
                        println!("{}", serde_json::to_string(&report)?);
                    } else {
                        eprintln!(
                            "line {lineno}: VERIFY FAILED ({err_msg}) \
                             [episode={}, action={}, seq={}]",
                            env.record.episode_id, env.record.action_id, env.record.seq
                        );
                    }
                    // Don't advance chain tracking — subsequent entries
                    // are evaluated against the *last good* sig, so a
                    // single broken line doesn't cascade into "every
                    // line after this is also broken."
                }
            }
            Err(e) => {
                failed += 1;
                if json {
                    let report = LineReport {
                        line: lineno,
                        ok: false,
                        error: Some(format!("parse error: {e}")),
                        episode_id: None,
                        action_id: None,
                        engine: None,
                    };
                    println!("{}", serde_json::to_string(&report)?);
                } else {
                    eprintln!("line {lineno}: parse error: {e}");
                }
            }
        }
    }

    if !json {
        println!(
            "audit log {}: {total} entries, {ok} ok, {failed} failed",
            path.display()
        );
    }

    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Validate that `env` continues the hash chain rooted at
/// `(expected_seq, last_sig_hex)`. Returns descriptive `Err` strings
/// for inclusion in the verifier's per-line report.
fn check_chain(env: &AuditEnvelope, expected_seq: u64, last_sig_hex: &str) -> Result<(), String> {
    if env.record.seq != expected_seq {
        return Err(format!(
            "expected seq {expected_seq}, got {} (gap or out-of-order entries)",
            env.record.seq
        ));
    }
    if env.record.prev_sig_hex != last_sig_hex {
        return Err(format!(
            "prev_sig_hex doesn't match previous entry's sig (chain broken at seq {})",
            env.record.seq
        ));
    }
    Ok(())
}

fn load_pubkey(b64: Option<String>, from: Option<PathBuf>) -> Result<VerifyingKey> {
    match (b64, from) {
        (Some(b64), None) => {
            let bytes = BASE64
                .decode(b64.trim())
                .context("decoding --pubkey-b64 as base64")?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", bytes.len()))?;
            VerifyingKey::from_bytes(&arr).context("parsing verifying key")
        }
        (None, Some(path)) => {
            let identity = Identity::load(&path)
                .with_context(|| format!("loading identity from {}", path.display()))?;
            Ok(identity.verifying_key())
        }
        (Some(_), Some(_)) => {
            bail!("--pubkey-b64 and --pubkey-from are mutually exclusive")
        }
        (None, None) => bail!("provide --pubkey-b64 or --pubkey-from"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_response::{Action, ActionOutcome, AuditRecord};
    use std::io::Write;

    /// Append a single chained envelope to `path`. Returns the sig
    /// of the just-written envelope so callers can chain the next
    /// entry off it.
    fn write_envelope(
        path: &Path,
        identity: &Identity,
        episode: &str,
        seq: u64,
        prev_sig_hex: &str,
    ) -> String {
        let mut rec = AuditRecord::new(
            &identity.fingerprint(),
            "process-kill",
            episode,
            Action::KillProcess {
                pid: 1234,
                episode_id: episode.into(),
            },
            ActionOutcome::executed_now(),
        );
        rec.seq = seq;
        rec.prev_sig_hex = prev_sig_hex.to_string();
        let env = AuditEnvelope::sign(rec, identity).unwrap();
        let line = serde_json::to_string(&env).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(f, "{line}").unwrap();
        env.sig_hex
    }

    #[test]
    fn verify_succeeds_on_well_signed_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let id = Identity::generate();
        let sig_a = write_envelope(&log, &id, "ep-a", 0, "");
        let _sig_b = write_envelope(&log, &id, "ep-b", 1, &sig_a);

        let pubkey_b64 = BASE64.encode(id.verifying_key().as_bytes());
        let code = verify(&log, Some(pubkey_b64), None, true).unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    /// Phase-8 H9: a deleted line in the middle of the chain breaks
    /// `prev_sig_hex` linkage, and the verifier exits non-zero even
    /// though every individual signature still verifies.
    #[test]
    fn verify_fails_when_a_chain_link_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let id = Identity::generate();
        // Three legitimate entries.
        let sig_a = write_envelope(&log, &id, "ep-a", 0, "");
        let sig_b = write_envelope(&log, &id, "ep-b", 1, &sig_a);
        let _sig_c = write_envelope(&log, &id, "ep-c", 2, &sig_b);
        // Now rewrite the file with the middle entry deleted.
        let contents = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        std::fs::write(&log, format!("{}\n{}\n", lines[0], lines[2])).unwrap();

        let pubkey_b64 = BASE64.encode(id.verifying_key().as_bytes());
        let code = verify(&log, Some(pubkey_b64), None, true).unwrap();
        // Exit FAILURE — every individual sig still verifies, but the
        // chain is broken (entry 2 expected prev_sig = sig_a, got sig_b).
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    }

    #[test]
    fn verify_fails_on_wrong_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let id = Identity::generate();
        write_envelope(&log, &id, "ep-a", 0, "");

        let other = Identity::generate();
        let pubkey_b64 = BASE64.encode(other.verifying_key().as_bytes());
        let code = verify(&log, Some(pubkey_b64), None, true).unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    }

    #[test]
    fn verify_fails_on_corrupted_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let id = Identity::generate();
        write_envelope(&log, &id, "ep-a", 0, "");
        // Append a garbage line.
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(f, "{{not valid json").unwrap();

        let pubkey_b64 = BASE64.encode(id.verifying_key().as_bytes());
        let code = verify(&log, Some(pubkey_b64), None, true).unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    }

    #[test]
    fn load_pubkey_rejects_both_sources() {
        let err = load_pubkey(Some("aGVsbG8=".into()), Some(PathBuf::from("/tmp/x")))
            .expect_err("both sources should fail");
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn load_pubkey_requires_at_least_one_source() {
        let err = load_pubkey(None, None).expect_err("missing source");
        assert!(err.to_string().contains("provide"));
    }
}
