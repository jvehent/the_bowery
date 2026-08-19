//! `bowery alerts tail` — drain an agent's operator inbox.
//!
//! Connects to a single agent over the existing whisper QUIC transport,
//! signs a `Subscribe { since_unix_ms }` envelope with the operator's
//! identity key, prints every alert returned, and (in `--follow`
//! mode) re-subscribes on a polling interval until ctrl-c.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bowery_crypto::{Fingerprint, Identity};
use bowery_proto::{Alert, Body, Subscribe, WhisperPayload};
use bowery_whisper::known_neighbors::KnownNeighbors;
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::BoweryEndpoint;
use bowery_whisper::{Sealer, StaticResolver, Verifier};
use ed25519_dalek::VerifyingKey;
use tokio::time::sleep;

/// Drain the inbox once and return `(alerts, new_cursor)`. Library
/// API used by the ncurses console — the binary's `tail` loop is a
/// thin wrapper around this.
pub async fn poll_once(
    operator_key: &std::path::Path,
    target_addr: SocketAddr,
    target_fp_hex: &str,
    target_pubkey_b64: &str,
    since_unix_ms: u64,
) -> Result<(Vec<Alert>, u64)> {
    let identity = Arc::new(
        Identity::load(operator_key)
            .with_context(|| format!("loading operator key from {}", operator_key.display()))?,
    );

    let target_fp = parse_fingerprint(target_fp_hex)?;
    let target_vk = parse_verifying_key(target_pubkey_b64)?;
    let mut resolver = StaticResolver::new();
    let inserted_fp = resolver.insert(target_vk);
    if inserted_fp != target_fp {
        bail!("target_pubkey_b64 fingerprint {inserted_fp} doesn't match --target-fp {target_fp}");
    }
    let resolver = Arc::new(resolver);

    // Bind the unspecified address (not loopback) so the kernel picks the
    // right source interface for `target_addr`; a `127.0.0.1`-bound socket
    // can't reach a remote tailnet/LAN peer. See exec::sql for the full
    // rationale. Match the target's address family.
    let bind_addr: SocketAddr = if target_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
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

    let outbound = sealer.seal_for(
        &target_fp,
        &WhisperPayload::subscribe(Subscribe {
            since_unix_ms,
            max_items: 0,
        }),
    );
    conn.send_envelope(&outbound)
        .await
        .context("sending Subscribe")?;

    // The agent chunks a large inbox across several `Alerts` envelopes so
    // none exceeds the transport frame cap; read until the final chunk
    // (`end = true`), accumulating items. A per-chunk timeout bounds the
    // wait and degrades gracefully (return what arrived) rather than
    // hanging — which also tolerates an older agent that sends a single
    // chunk without the `end` flag.
    let mut all_items: Vec<Alert> = Vec::new();
    let mut cursor = since_unix_ms;
    loop {
        let recv = tokio::time::timeout(Duration::from_secs(10), conn.recv_envelope()).await;
        let bytes = match recv {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => {
                if all_items.is_empty() {
                    return Err(anyhow::Error::from(e).context("awaiting Alerts response"));
                }
                break; // connection closed after some chunks → end of stream
            }
            Err(_elapsed) => {
                if all_items.is_empty() {
                    bail!("timed out awaiting Alerts response");
                }
                break; // no further chunk in time → return what we have
            }
        };
        let opened = envelope_verifier
            .open(&bytes)
            .context("verifying Alerts envelope")?;
        let alerts_payload = match opened.payload.body {
            Some(Body::Alerts(a)) => a,
            other => bail!("agent replied with unexpected body: {other:?}"),
        };
        let is_end = alerts_payload.end;
        let chunk_cursor = alerts_payload.cursor_unix_ms;
        all_items.extend(alerts_payload.items);
        if is_end {
            cursor = chunk_cursor;
            break;
        }
    }
    drop(conn);
    endpoint.close().await;
    let _ = std::any::type_name::<KnownNeighbors>();

    Ok((all_items, cursor))
}

/// Binary-side wrapper: drain the inbox and print to stdout. Loops
/// on `poll_interval` when `follow` is set.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    operator_key: PathBuf,
    target_addr: SocketAddr,
    target_fp_hex: String,
    target_pubkey_b64: String,
    since_unix_ms: u64,
    follow: bool,
    poll_interval: Duration,
    json: bool,
) -> Result<()> {
    let mut cursor = since_unix_ms;
    loop {
        let (items, next_cursor) = poll_once(
            &operator_key,
            target_addr,
            &target_fp_hex,
            &target_pubkey_b64,
            cursor,
        )
        .await?;
        for alert in &items {
            if json {
                println!("{}", alert_to_json(alert));
            } else {
                print_human(alert);
            }
        }
        cursor = next_cursor;
        if !follow {
            return Ok(());
        }
        sleep(poll_interval).await;
    }
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

fn print_human(alert: &Alert) {
    let originator = if alert.originator_fp.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&alert.originator_fp);
        Fingerprint::from_bytes(arr).to_string()
    } else {
        format!("malformed-fp({} bytes)", alert.originator_fp.len())
    };
    println!(
        "[{ts}] suspicion={s:.2} ep={ep} from={fp}",
        ts = alert.ts_unix_ms,
        s = alert.suspicion,
        ep = alert.episode_id,
        fp = &originator[..16],
    );
    if !alert.exe_path.is_empty() {
        println!("    exe : {}", alert.exe_path);
    }
    if !alert.exe_sha256_hex.is_empty() {
        println!("    sha : {}", alert.exe_sha256_hex);
    }
    println!("    why : {}", alert.rationale);
    for attr in &alert.context {
        println!("    {:<4}: {}", attr.key, attr.value);
    }
    if !alert.suggested_actions.is_empty() {
        println!("    sug : {}", alert.suggested_actions.join(", "));
    }
    if let Some(c) = alert.confirmation {
        let verdict = if c.confirmed {
            "CONFIRMED"
        } else {
            "not confirmed"
        };
        println!(
            "    mesh: {verdict} — {unseen}/{asked} peers have no record of this \
             (quorum {q}; {seen} do, {rf} declined, {nr} did not reply)",
            unseen = c.peers_unseen,
            asked = c.peers_asked,
            q = c.quorum,
            seen = c.peers_seen,
            rf = c.peers_refused,
            nr = c.peers_no_reply,
        );
    }
}

fn alert_to_json(alert: &Alert) -> String {
    // Manual JSON to avoid pulling Serialize on the prost types.
    let originator_hex = alert
        .originator_fp
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
    let actions = alert
        .suggested_actions
        .iter()
        .map(|a| format!("\"{}\"", json_escape(a)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"ts_unix_ms\":{ts},\"originator_fp\":\"{fp}\",\"episode_id\":\"{ep}\",\
         \"exe_sha256_hex\":\"{sha}\",\"exe_path\":\"{exe}\",\"suspicion\":{sus},\
         \"rationale\":\"{rat}\",\"suggested_actions\":[{act}],\"backend\":\"{be}\",\
         \"confirmation\":{conf}}}",
        ts = alert.ts_unix_ms,
        fp = originator_hex,
        ep = json_escape(&alert.episode_id),
        sha = json_escape(&alert.exe_sha256_hex),
        exe = json_escape(&alert.exe_path),
        sus = alert.suspicion,
        rat = json_escape(&alert.rationale),
        act = actions,
        be = json_escape(&alert.backend),
        conf = confirmation_to_json(alert.confirmation.as_ref()),
    )
}

/// Confirmation as a nested JSON object, or `null` when no whisper round
/// ran for this alert. `null` rather than a zeroed object so downstream
/// tooling can tell "not asked" from "asked and nobody agreed".
fn confirmation_to_json(c: Option<&bowery_proto::AlertConfirmation>) -> String {
    match c {
        None => "null".to_string(),
        Some(c) => format!(
            "{{\"confirmed\":{conf},\"quorum\":{q},\"peers_asked\":{asked},\
             \"peers_unseen\":{unseen},\"peers_seen\":{seen},\"peers_no_reply\":{nr},\
             \"peers_refused\":{rf}}}",
            conf = c.confirmed,
            q = c.quorum,
            asked = c.peers_asked,
            unseen = c.peers_unseen,
            seen = c.peers_seen,
            nr = c.peers_no_reply,
            rf = c.peers_refused,
        ),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod json_tests {
    use super::*;

    fn base() -> Alert {
        Alert {
            originator_fp: vec![0xab; 32],
            rule_id: "cred.read_netrc".into(),
            episode_id: "ep-1".into(),
            exe_sha256_hex: "cd".repeat(32),
            exe_path: "/tmp/pay\"load".into(), // embedded quote — escaping must hold
            suspicion: 0.875,
            rationale: "line1\nline2".into(),
            suggested_actions: vec!["kill_process".into()],
            ts_unix_ms: 1_786_622_341_123,
            backend: "llama-cpp/qwen3".into(),
            confirmation: None,
            context: Vec::new(),
        }
    }

    /// The JSON here is built by `format!`, not serde, so a missing comma
    /// or brace would ship as malformed output that only breaks in the
    /// operator's `jq` pipeline. Parse it back to prove the shape.
    #[test]
    fn alert_json_is_parseable_with_and_without_confirmation() {
        let unconfirmed: serde_json::Value =
            serde_json::from_str(&alert_to_json(&base())).expect("unconfirmed alert must be JSON");
        assert!(
            unconfirmed["confirmation"].is_null(),
            "no whisper round must serialise as null, not a zeroed object"
        );
        assert_eq!(unconfirmed["exe_path"], "/tmp/pay\"load");
        assert_eq!(unconfirmed["rationale"], "line1\nline2");

        let mut a = base();
        a.confirmation = Some(bowery_proto::AlertConfirmation {
            peers_incomparable: 0,
            peers_asked: 5,
            peers_unseen: 4,
            peers_seen: 1,
            peers_no_reply: 0,
            peers_refused: 0,
            quorum: 2,
            confirmed: true,
        });
        let v: serde_json::Value =
            serde_json::from_str(&alert_to_json(&a)).expect("confirmed alert must be JSON");
        assert_eq!(v["confirmation"]["confirmed"], true);
        assert_eq!(v["confirmation"]["peers_unseen"], 4);
        assert_eq!(v["confirmation"]["peers_seen"], 1);
        assert_eq!(v["confirmation"]["quorum"], 2);
    }
}
