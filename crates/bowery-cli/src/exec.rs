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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bowery_crypto::{Fingerprint, Identity};
use bowery_proto::{
    Body, OperatorCommand, OperatorCommandBody, OperatorResultBody, SqlChunk, SqlQuery,
    SqlValueKind, SysqueryQuery, WhisperPayload,
};
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::BoweryEndpoint;
use bowery_whisper::{Sealer, StaticResolver, Verifier};
use ed25519_dalek::VerifyingKey;

/// Send a single `sysquery` command and print the result. Returns
/// `Ok(())` even when the agent's structured `Error` body comes back
/// — we surface it via `eprintln!` and a non-zero process exit at
/// the caller; transport-level failures (envelope parse, sig verify,
/// timeout) bubble up as `Err`.
#[allow(clippy::too_many_arguments)] // explicit binding from the CLI subcommand
pub(crate) async fn sysquery(
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
        command: Some(OperatorCommandBody::Sysquery(SysqueryQuery { sql })),
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

/// Send a single Phase-9 SQL query and stream the rows back. Each
/// chunk envelope arrives on its own QUIC stream; the loop
/// terminates on the first chunk with `end = true` or on an
/// `Error` body. The exchange-level deadline is the operator-
/// supplied timeout plus a small slack — the agent enforces its
/// own timeout server-side and is the authority on "how long
/// before this query is killed".
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn sql(
    operator_key: PathBuf,
    target_addr: SocketAddr,
    target_fp_hex: String,
    target_pubkey_b64: String,
    sql: String,
    timeout: Duration,
    fanout: bool,
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

    let request_id = format!("op-{}", current_unix_ms());
    let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);

    let cmd = OperatorCommand {
        request_id: request_id.clone(),
        timeout_ms,
        command: Some(OperatorCommandBody::Sql(SqlQuery {
            sql,
            fanout,
            peers: Vec::new(),
        })),
    };
    let outbound = sealer.seal_for(&target_fp, &WhisperPayload::operator_command(cmd));

    let exchange_timeout = timeout + Duration::from_secs(2);
    let exchange = async {
        conn.send_envelope(&outbound)
            .await
            .context("sending OperatorCommand")?;

        // In fan-out mode the relay multiplexes per-peer streams,
        // each terminated with its own `end = true`; we keep
        // reading until the connection closes (the relay drops it
        // after all peers finished). In single-agent mode we stop
        // on the first `end = true`. We index column lists per
        // agent_fp so each peer's first chunk's column names
        // survive across that peer's batches.
        let mut printed_header = false;
        let mut columns_by_agent: HashMap<Vec<u8>, Vec<String>> = HashMap::new();
        let mut last_columns: Vec<String> = Vec::new();
        loop {
            let recv = conn.recv_envelope().await;
            let bytes = match recv {
                Ok(b) => b,
                Err(e) => {
                    if fanout {
                        // Connection close terminates the fan-out
                        // stream — the relay's done with peers.
                        return Ok::<(), anyhow::Error>(());
                    }
                    return Err(anyhow::Error::from(e).context("awaiting SqlChunk envelope"));
                }
            };
            let opened = envelope_verifier
                .open(&bytes)
                .context("verifying SqlChunk envelope")?;
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
            match result.result {
                Some(OperatorResultBody::SqlChunk(chunk)) => {
                    let SqlChunk {
                        columns: chunk_cols,
                        rows,
                        end,
                        agent_fp,
                    } = chunk;
                    let columns: &Vec<String> = if !chunk_cols.is_empty() {
                        columns_by_agent.insert(agent_fp.clone(), chunk_cols.clone());
                        last_columns = chunk_cols;
                        &last_columns
                    } else if let Some(existing) = columns_by_agent.get(&agent_fp) {
                        existing
                    } else {
                        // No columns for this peer yet (rare:
                        // empty terminal chunk before any rows).
                        &last_columns
                    };
                    if !printed_header && !columns.is_empty() {
                        print_sql_header(columns, json);
                        printed_header = true;
                    }
                    for row in rows {
                        print_sql_row(columns, &row, &agent_fp, fanout, json);
                    }
                    if end && !fanout {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
                Some(OperatorResultBody::Error(e)) => {
                    eprintln!("agent refused query: {} ({})", e.message, e.kind);
                    bail!("sql query failed: {}", e.kind);
                }
                Some(other) => bail!("unexpected OperatorResult body: {other:?}"),
                None => bail!("agent returned an OperatorResult with no body"),
            }
        }
    };
    let outcome = tokio::time::timeout(exchange_timeout, exchange).await;
    drop(conn);
    endpoint.close().await;
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => bail!("sql query timed out after {exchange_timeout:?}"),
    }
}

fn print_sql_header(columns: &[String], json: bool) {
    if json {
        // First line is a JSON array of column names so consumers
        // can demux the rest as `{col: val}` dicts. agent_fp is
        // emitted per row (when fan-out), not in this header — the
        // shape is intentionally identical between single-agent
        // and fan-out modes; the agent column appears as an extra
        // first cell when fan-out is on.
        let escaped: Vec<String> = columns
            .iter()
            .map(|c| format!("\"{}\"", escape_json_string(c)))
            .collect();
        println!("[{}]", escaped.join(","));
    } else {
        println!("{}", columns.join("\t"));
    }
}

fn print_sql_row(
    columns: &[String],
    row: &bowery_proto::SqlRow,
    agent_fp: &[u8],
    fanout: bool,
    json: bool,
) {
    let agent_hex = hex_fp(agent_fp);
    if json {
        let mut parts: Vec<String> = Vec::with_capacity(row.values.len() + usize::from(fanout));
        if fanout {
            parts.push(format!("\"_agent_fp\":\"{agent_hex}\""));
        }
        for (i, v) in row.values.iter().enumerate() {
            let key = columns.get(i).map_or("", String::as_str);
            parts.push(format!(
                "\"{}\":{}",
                escape_json_string(key),
                value_to_json(v)
            ));
        }
        println!("{{{}}}", parts.join(","));
    } else {
        let mut cells: Vec<String> = Vec::with_capacity(row.values.len() + usize::from(fanout));
        if fanout {
            cells.push(agent_hex);
        }
        cells.extend(row.values.iter().map(value_to_text));
        println!("{}", cells.join("\t"));
    }
}

fn hex_fp(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn value_to_text(v: &bowery_proto::SqlValue) -> String {
    match &v.value {
        None => String::new(),
        Some(SqlValueKind::Integer(i)) => i.to_string(),
        Some(SqlValueKind::Real(f)) => f.to_string(),
        Some(SqlValueKind::Text(s)) => s.clone(),
        Some(SqlValueKind::Blob(b)) => format!("<{} bytes>", b.len()),
    }
}

fn value_to_json(v: &bowery_proto::SqlValue) -> String {
    match &v.value {
        None => "null".to_string(),
        Some(SqlValueKind::Integer(i)) => i.to_string(),
        Some(SqlValueKind::Real(f)) => {
            // JSON disallows NaN/Inf; emit null for those.
            if f.is_finite() {
                f.to_string()
            } else {
                "null".to_string()
            }
        }
        Some(SqlValueKind::Text(s)) => format!("\"{}\"", escape_json_string(s)),
        Some(SqlValueKind::Blob(b)) => format!("\"<{} bytes>\"", b.len()),
    }
}

fn print_result(result: &bowery_proto::OperatorResult, json: bool) -> Result<()> {
    match (&result.result, json) {
        (Some(OperatorResultBody::Sysquery(o)), true) => {
            // `--json` mode emits the full envelope shape so callers
            // can pipe it through jq.
            println!(
                "{{\"request_id\":\"{}\",\"exit_code\":{},\"json\":{}}}",
                escape_json_string(&result.request_id),
                o.exit_code,
                if o.json.is_empty() { "null" } else { &o.json }
            );
        }
        (Some(OperatorResultBody::Sysquery(o)), false) => {
            // Human mode prints the wrapped binary's JSON verbatim
            // — the operator can pipe through `jq` themselves.
            println!("{}", o.json);
            if o.exit_code != 0 {
                eprintln!("warning: sysquery binary exited {}", o.exit_code);
            }
        }
        (Some(OperatorResultBody::Error(e)), _) => {
            eprintln!("agent refused command: {} ({})", e.message, e.kind);
            bail!("operator command failed: {}", e.kind);
        }
        (Some(OperatorResultBody::SqlChunk(_)), _) => {
            // The sysquery exec path is single-shot; receiving a
            // SqlChunk on it indicates a wire-protocol mismatch.
            bail!("agent replied to sysquery command with SqlChunk; protocol mismatch");
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
