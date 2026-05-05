//! `bowery exec` — send typed [`OperatorCommand`]s to an agent.
//!
//! Phase 6b. Mirrors the dial / seal / wait pattern from
//! [`crate::alerts`] — the operator-key authenticates the request,
//! the agent's pinned fingerprint authenticates the response. The
//! only differences:
//!
//! - The outbound envelope carries `OperatorCommand` instead of
//!   `Subscribe`.
//! - The inbound envelope carries `OperatorResult` (with a typed
//!   per-command body) instead of `Alerts`.
//! - One round-trip per invocation; no follow mode.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bowery_crypto::{Fingerprint, Identity};
use bowery_proto::{
    Body, OperatorCommand, OperatorCommandBody, OperatorResultBody, OsqueryQuery, WhisperPayload,
};
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::BoweryEndpoint;
use bowery_whisper::{Sealer, StaticResolver, Verifier};
use ed25519_dalek::VerifyingKey;

/// Send a single `osquery` command and print the result. Returns
/// `Ok(())` even when the agent's structured `Error` body comes back
/// — we surface it via `eprintln!` and a non-zero process exit at
/// the caller; transport-level failures (envelope parse, sig verify,
/// timeout) bubble up as `Err`.
#[allow(clippy::too_many_arguments)] // explicit binding from the CLI subcommand
pub(crate) async fn osquery(
    operator_key: PathBuf,
    target_addr: SocketAddr,
    target_fp_hex: String,
    target_pubkey_b64: String,
    sql: String,
    timeout: Duration,
    json: bool,
) -> Result<()> {
    let identity = Arc::new(
        Identity::load(&operator_key)
            .with_context(|| format!("loading operator key from {}", operator_key.display()))?,
    );

    let target_fp = parse_fingerprint(&target_fp_hex)?;
    let target_vk = parse_verifying_key(&target_pubkey_b64)?;
    let mut resolver = StaticResolver::new();
    let inserted_fp = resolver.insert(target_vk);
    if inserted_fp != target_fp {
        bail!("target_pubkey_b64 fingerprint {inserted_fp} doesn't match --agent-fp {target_fp}");
    }
    let resolver = Arc::new(resolver);

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let endpoint = BoweryEndpoint::bind(identity.clone(), accept_verifier, bind_addr)
        .context("binding operator-side endpoint")?;

    let operator_fp = identity.fingerprint();
    let sealer = Sealer::new(identity);
    let envelope_verifier = Verifier::new(resolver.clone(), operator_fp);

    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), target_fp));
    let conn = endpoint
        .dial(dial_verifier, target_addr)
        .await
        .with_context(|| format!("dialing agent at {target_addr}"))?;

    // request_id ties our response to this specific request — useful
    // when the operator runs multiple commands in flight against the
    // same agent.
    let request_id = format!("op-{}", current_unix_ms());
    let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);

    let cmd = OperatorCommand {
        request_id: request_id.clone(),
        timeout_ms,
        command: Some(OperatorCommandBody::Osquery(OsqueryQuery { sql })),
    };
    let outbound = sealer.seal_for(&target_fp, &WhisperPayload::operator_command(cmd));

    // Wrap the whole exchange in the operator-supplied deadline so
    // we don't hang on a stalled agent. The agent enforces its own
    // timeout on the handler side; the CLI timeout is generous (the
    // requested timeout + a small slack for the round-trip).
    let exchange_timeout = timeout + Duration::from_secs(2);
    let exchange = async {
        conn.send_envelope(&outbound)
            .await
            .context("sending OperatorCommand")?;
        let bytes = conn
            .recv_envelope()
            .await
            .context("awaiting OperatorResult")?;
        let opened = envelope_verifier
            .open(&bytes)
            .context("verifying OperatorResult envelope")?;
        Ok::<_, anyhow::Error>(opened)
    };
    let opened = match tokio::time::timeout(exchange_timeout, exchange).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            drop(conn);
            endpoint.close().await;
            return Err(e);
        }
        Err(_) => {
            drop(conn);
            endpoint.close().await;
            bail!("operator command timed out after {exchange_timeout:?}");
        }
    };

    let result = match opened.payload.body {
        Some(Body::OperatorResult(r)) => r,
        other => bail!("agent replied with unexpected body: {other:?}"),
    };

    if result.request_id != request_id {
        bail!(
            "agent echoed request_id={:?}, expected {:?}",
            result.request_id,
            request_id
        );
    }

    drop(conn);
    endpoint.close().await;

    print_result(&result, json)
}

fn print_result(result: &bowery_proto::OperatorResult, json: bool) -> Result<()> {
    match (&result.result, json) {
        (Some(OperatorResultBody::Osquery(o)), true) => {
            // `--json` mode emits the full envelope shape so callers
            // can pipe it through jq.
            println!(
                "{{\"request_id\":\"{}\",\"exit_code\":{},\"json\":{}}}",
                escape_json_string(&result.request_id),
                o.exit_code,
                if o.json.is_empty() { "null" } else { &o.json }
            );
        }
        (Some(OperatorResultBody::Osquery(o)), false) => {
            // Human mode prints the osquery JSON verbatim — the
            // operator can pipe through `jq` themselves.
            println!("{}", o.json);
            if o.exit_code != 0 {
                eprintln!("warning: osqueryi exited {}", o.exit_code);
            }
        }
        (Some(OperatorResultBody::Error(e)), _) => {
            eprintln!("agent refused command: {} ({})", e.message, e.kind);
            bail!("operator command failed: {}", e.kind);
        }
        (None, _) => bail!("agent returned an OperatorResult with no body"),
    }
    Ok(())
}

fn current_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn parse_fingerprint(s: &str) -> Result<Fingerprint> {
    if s.len() != 64 {
        bail!("fingerprint must be 64 hex chars (got {})", s.len());
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow!("invalid hex at byte {i}: {e}"))?;
    }
    Ok(Fingerprint::from_bytes(bytes))
}

fn parse_verifying_key(b64: &str) -> Result<VerifyingKey> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    let bytes = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| anyhow!("base64 decode: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("verifying key is {} bytes; expected 32", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("invalid Ed25519 pubkey: {e}"))
}

/// Minimal JSON string escaper — only used for the `--json` envelope
/// shape, where the only attacker-controlled string is the operator's
/// own `request_id` (we generated it). Keeps the dep graph free of a
/// full `serde_json` import for this one use.
fn escape_json_string(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
