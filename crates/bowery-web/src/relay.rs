//! What the server needs to reach the fleet, and how it asks.
//!
//! One relay agent is dialled for every live query, exactly as the
//! terminal console does it — the agent is the entry point to the mesh
//! and answers for itself or fans out to its peers.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

pub(crate) struct Relay {
    pub operator_key: PathBuf,
    pub addr: SocketAddr,
    pub fp_hex: String,
    pub pubkey_b64: String,
    pub cluster_id: Option<String>,
    pub timeout: Duration,
    pub archive_path: PathBuf,
    pub version: &'static str,
}

/// A query result in the shape the browser wants: named columns and
/// rows of JSON scalars.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    /// Which agent produced each row, short hex. Empty string for a
    /// single-agent query, so the browser can tell "one host answered"
    /// from "this host answered" without guessing.
    pub agents: Vec<String>,
}

impl Relay {
    /// Run one SQL statement against the relay (or the whole fleet).
    ///
    /// # Errors
    /// Propagates transport, signature and agent-side SQL errors.
    pub(crate) async fn query(&self, sql: &str, fanout: bool) -> Result<Table> {
        let mut sink = bowery_cli::exec::CollectSink::default();
        bowery_cli::exec::sql(
            self.operator_key.clone(),
            self.addr,
            self.fp_hex.clone(),
            self.pubkey_b64.clone(),
            // A fan-out answer arrives in envelopes each peer sealed
            // for itself, so the relay's key alone cannot verify it —
            // without these the whole mesh view fails with "unknown
            // sender fingerprint". Found by running it, not by reading
            // the signature.
            if fanout { peer_pubkeys() } else { Vec::new() },
            sql.to_string(),
            self.timeout,
            fanout,
            false,
            &mut sink,
        )
        .await?;
        Ok(Table {
            columns: sink.columns,
            agents: sink.rows.iter().map(|r| short_hex(&r.agent_fp)).collect(),
            rows: sink
                .rows
                .iter()
                .map(|r| r.values.iter().map(value_to_json).collect())
                .collect(),
        })
    }
}

/// Verifying keys for every peer in the operator's manifest.
///
/// Empty when there is no manifest, which is the right answer rather
/// than an error: a single-agent query needs none, and a fan-out
/// against an empty manifest fails loudly at the first peer-sealed
/// envelope, which is a clearer message than one invented here.
fn peer_pubkeys() -> Vec<String> {
    bowery_cli::peers::default_path()
        .ok()
        .and_then(|p| bowery_cli::peers::Manifest::load(&p).ok())
        .map(|m| m.peers.into_iter().map(|p| p.pubkey_b64).collect())
        .unwrap_or_default()
}

/// First eight bytes of a fingerprint, lowercase hex.
///
/// The same prefix the whisper verdict keys use (`peer.<16 hex>`), so
/// a row's agent and an alert's peer verdict can be matched up in the
/// browser without carrying 64 characters around.
#[must_use]
pub(crate) fn short_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().take(8).fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// `SQLite` scalars as JSON.
///
/// NULL stays null rather than becoming an empty string: "this agent
/// has no record" and "this agent recorded an empty value" are
/// different answers, and the whole confirmation block depends on
/// being able to tell them apart.
fn value_to_json(v: &bowery_proto::SqlValue) -> serde_json::Value {
    use bowery_proto::SqlValueKind as K;
    match &v.value {
        Some(K::Integer(i)) => serde_json::Value::from(*i),
        Some(K::Real(f)) => serde_json::Number::from_f64(*f)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Some(K::Text(t)) => serde_json::Value::from(t.clone()),
        // Rendered, not dropped: a blob column is usually a hash, and
        // an operator looking at one needs something to copy.
        Some(K::Blob(b)) => serde_json::Value::from(format!("0x{}", hex_all(b))),
        None => serde_json::Value::Null,
    }
}

fn hex_all(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_stays_null_rather_than_becoming_an_empty_string() {
        // "no record" and "empty value" are different answers, and the
        // confirmation block is read by telling them apart.
        let v = bowery_proto::SqlValue { value: None };
        assert_eq!(value_to_json(&v), serde_json::Value::Null);
        let empty = bowery_proto::SqlValue {
            value: Some(bowery_proto::SqlValueKind::Text(String::new())),
        };
        assert_eq!(value_to_json(&empty), serde_json::Value::from(""));
        assert_ne!(value_to_json(&v), value_to_json(&empty));
    }

    #[test]
    fn scalars_round_trip_into_json() {
        use bowery_proto::SqlValueKind as K;
        let cases = [
            (K::Integer(42), serde_json::json!(42)),
            (K::Real(0.5), serde_json::json!(0.5)),
            (K::Text("hi".into()), serde_json::json!("hi")),
            (K::Blob(vec![0xde, 0xad]), serde_json::json!("0xdead")),
        ];
        for (kind, want) in cases {
            let got = value_to_json(&bowery_proto::SqlValue { value: Some(kind) });
            assert_eq!(got, want);
        }
    }

    /// A NaN or infinity has no JSON spelling; null beats a panic and
    /// beats a silently wrong number.
    #[test]
    fn an_unrepresentable_float_becomes_null_rather_than_a_lie() {
        let v = bowery_proto::SqlValue {
            value: Some(bowery_proto::SqlValueKind::Real(f64::NAN)),
        };
        assert_eq!(value_to_json(&v), serde_json::Value::Null);
    }

    #[test]
    fn the_short_fingerprint_matches_the_whisper_verdict_key_width() {
        // Alert context keys are `peer.<16 hex>` — eight bytes.
        let fp = vec![0xaf, 0xb9, 0x90, 0x24, 0x84, 0xe6, 0xf4, 0xba, 0x12, 0x99];
        assert_eq!(short_hex(&fp), "afb9902484e6f4ba");
        assert_eq!(short_hex(&fp).len(), 16);
        assert_eq!(short_hex(&[]), "");
    }
}
