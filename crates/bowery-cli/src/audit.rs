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

    for (idx, line) in reader.lines().enumerate() {
        let lineno = idx + 1;
        let line = line.with_context(|| format!("reading {} line {lineno}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        total += 1;
        let parsed: Result<AuditEnvelope, _> = serde_json::from_str(&line);
        match parsed {
            Ok(env) => match env.verify(&vk) {
                Ok(()) => {
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
                }
                Err(e) => {
                    failed += 1;
                    if json {
                        let report = LineReport {
                            line: lineno,
                            ok: false,
                            error: Some(e.to_string()),
                            episode_id: Some(&env.record.episode_id),
                            action_id: Some(&env.record.action_id),
                            engine: Some(&env.record.engine),
                        };
                        println!("{}", serde_json::to_string(&report)?);
                    } else {
                        eprintln!(
                            "line {lineno}: VERIFY FAILED ({e}) [episode={}, action={}]",
                            env.record.episode_id, env.record.action_id
                        );
                    }
                }
            },
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

    fn write_envelope(path: &Path, identity: &Identity, episode: &str) {
        let rec = AuditRecord::new(
            &identity.fingerprint(),
            "process-kill",
            episode,
            Action::KillProcess {
                pid: 1234,
                episode_id: episode.into(),
            },
            ActionOutcome::executed_now(),
        );
        let env = AuditEnvelope::sign(rec, identity).unwrap();
        let line = serde_json::to_string(&env).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    #[test]
    fn verify_succeeds_on_well_signed_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let id = Identity::generate();
        write_envelope(&log, &id, "ep-a");
        write_envelope(&log, &id, "ep-b");

        let pubkey_b64 = BASE64.encode(id.verifying_key().as_bytes());
        let code = verify(&log, Some(pubkey_b64), None, true).unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn verify_fails_on_wrong_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let id = Identity::generate();
        write_envelope(&log, &id, "ep-a");

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
        write_envelope(&log, &id, "ep-a");
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
