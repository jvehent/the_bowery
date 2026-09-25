//! The JSON surface the browser talks to.
//!
//! Deliberately thin. Every endpoint is either a SQL statement against
//! the relay or a read of the operator-side archive, because that is
//! exactly what the terminal console does — two front ends over one
//! set of facts beats two front ends that disagree.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::assets;
use crate::relay::{Relay, Table};

type Shared = Arc<Relay>;

pub(crate) fn router(relay: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(css))
        .route("/app.js", get(js))
        .route("/api/health", get(health))
        .route("/api/query", post(query))
        .route("/api/alerts", get(alerts))
        .route("/api/alerts/{episode}", get(alert_detail))
        .route("/api/peers", get(peers))
        .route("/api/mesh", get(mesh))
        .route("/api/table/{name}", get(table))
        .with_state(relay)
}

/// An error the browser can render without guessing.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        // `{:#}` so the chain is preserved: "sql query failed" alone
        // tells an operator nothing, and the agent's own reason is
        // always the interesting half.
        Self(StatusCode::BAD_GATEWAY, format!("{e:#}"))
    }
}

type ApiResult<T> = Result<T, ApiError>;

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        assets::INDEX_HTML,
    )
}

async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        assets::APP_CSS,
    )
}

async fn js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        assets::APP_JS,
    )
}

#[derive(Serialize)]
struct Health {
    version: &'static str,
    relay_addr: String,
    relay_fp: String,
    cluster_id: Option<String>,
    archive: String,
}

async fn health(State(r): State<Shared>) -> Json<Health> {
    Json(Health {
        version: r.version,
        relay_addr: r.addr.to_string(),
        relay_fp: r.fp_hex.clone(),
        cluster_id: r.cluster_id.clone(),
        archive: r.archive_path.display().to_string(),
    })
}

#[derive(Deserialize)]
struct QueryBody {
    sql: String,
    #[serde(default)]
    fanout: bool,
}

async fn query(State(r): State<Shared>, Json(body): Json<QueryBody>) -> ApiResult<Json<Table>> {
    if body.sql.trim().is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "empty query".into()));
    }
    Ok(Json(r.query(&body.sql, body.fanout).await?))
}

#[derive(Deserialize)]
struct TableParams {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    fanout: bool,
}

fn default_limit() -> usize {
    200
}

/// Every table the catalogue knows, by name.
///
/// An allowlist rather than string interpolation: the name lands in a
/// SQL statement, and the browser is not a trusted author of one even
/// when the browser is ours.
async fn table(
    State(r): State<Shared>,
    Path(name): Path<String>,
    Query(p): Query<TableParams>,
) -> ApiResult<Json<Table>> {
    let known = bowery_cli::catalog::table_names();
    if !known.contains(&name.as_str()) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("unknown table `{name}`; known: {}", known.join(", ")),
        ));
    }
    let limit = p.limit.clamp(1, 5000);
    Ok(Json(
        r.query(&format!("SELECT * FROM {name} LIMIT {limit}"), p.fanout)
            .await?,
    ))
}

// ---------------------------------------------------------------------
// Alerts — from the archive, because that is where the context lives
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct AlertParams {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    confirmed_only: bool,
}

/// What a peer said, pulled out of the alert's context.
#[derive(Serialize)]
struct PeerVerdict {
    /// Short fingerprint, as the context key spells it.
    fp: String,
    verdict: String,
    /// Coarse classification, so the graph can colour an edge without
    /// re-parsing prose in three places.
    stance: &'static str,
}

#[derive(Serialize)]
struct AlertView {
    episode_id: String,
    agent_fp: String,
    agent_name: Option<String>,
    ts_unix_ms: u64,
    rule_id: String,
    suspicion: f64,
    exe_path: Option<String>,
    exe_sha256: Option<String>,
    rationale: String,
    model_explanation: Option<String>,
    backend: Option<String>,
    confirmed: Option<bool>,
    peers_asked: Option<u32>,
    peers_seen: Option<u32>,
    peers_unseen: Option<u32>,
    peers_familiar: Option<u32>,
    context: BTreeMap<String, String>,
    peer_verdicts: Vec<PeerVerdict>,
}

/// Classify a peer's answer into something a graph edge can be drawn
/// from.
///
/// Prose, because that is what the responder wrote and the operator
/// reads. The classification is a convenience for colour, never the
/// record: the verdict string itself is carried through untouched.
fn stance_of(verdict: &str) -> &'static str {
    let v = verdict.to_ascii_lowercase();
    if v.starts_with("declined") || v.contains("cannot compare") {
        "refused"
    } else if v.contains("built differently") || v.contains("routinely") {
        "familiar"
    } else if v.contains("has this exact") || v.contains("times)") {
        "seen"
    } else if v.contains("no record") || v.contains("never") {
        "unseen"
    } else {
        "other"
    }
}

fn to_view(row: &bowery_cli::archive::Row) -> AlertView {
    let context: BTreeMap<String, String> =
        serde_json::from_str(&row.context_json).unwrap_or_default();
    let peer_verdicts = context
        .iter()
        .filter_map(|(k, v)| {
            k.strip_prefix("peer.").map(|fp| PeerVerdict {
                fp: fp.to_string(),
                verdict: v.clone(),
                stance: stance_of(v),
            })
        })
        .collect();
    AlertView {
        episode_id: row.episode_id.clone(),
        agent_fp: row.agent_fp.clone(),
        agent_name: row.agent_name.clone(),
        ts_unix_ms: row.ts_unix_ms,
        rule_id: row.rule_id.clone().unwrap_or_default(),
        suspicion: row.suspicion,
        exe_path: row.exe_path.clone(),
        exe_sha256: row.exe_sha256.clone(),
        rationale: row.rationale.clone().unwrap_or_default(),
        model_explanation: row.model_explanation.clone(),
        backend: row.backend.clone(),
        confirmed: row.confirmed,
        peers_asked: row.peers_asked,
        peers_seen: row.peers_seen,
        peers_unseen: row.peers_unseen,
        peers_familiar: row.peers_familiar,
        context,
        peer_verdicts,
    }
}

fn open_archive(r: &Relay) -> ApiResult<bowery_cli::archive::Archive> {
    bowery_cli::archive::Archive::open(&r.archive_path).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("opening {}: {e:#}", r.archive_path.display()),
        )
    })
}

async fn alerts(
    State(r): State<Shared>,
    Query(p): Query<AlertParams>,
) -> ApiResult<Json<Vec<AlertView>>> {
    let archive = open_archive(&r)?;
    let filter = bowery_cli::archive::Filter {
        limit: p.limit.clamp(1, 2000),
        text: p.text,
        rule_id: p.rule_id,
        confirmed_only: p.confirmed_only,
        ..Default::default()
    };
    let rows = archive
        .query(&filter)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    Ok(Json(rows.iter().map(to_view).collect()))
}

async fn alert_detail(
    State(r): State<Shared>,
    Path(episode): Path<String>,
) -> ApiResult<Json<Vec<AlertView>>> {
    let archive = open_archive(&r)?;
    // Every version, not the collapsed one. An episode's history is
    // the point of this view: the pre-filter alert, the whisper round
    // that superseded it, the model's reading of the result. Showing
    // only the last would hide the reasoning that produced it.
    let filter = bowery_cli::archive::Filter {
        limit: 100,
        text: Some(episode.clone()),
        all_versions: true,
        ..Default::default()
    };
    let rows = archive
        .query(&filter)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    let mut views: Vec<AlertView> = rows
        .iter()
        .filter(|r| r.episode_id == episode)
        .map(to_view)
        .collect();
    views.sort_by_key(|v| v.ts_unix_ms);
    if views.is_empty() {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("no archived alert for episode `{episode}`"),
        ));
    }
    Ok(Json(views))
}

// ---------------------------------------------------------------------
// Peers and the mesh graph
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct PeerEntry {
    name: String,
    fp: String,
    short_fp: String,
    addr: Option<String>,
}

async fn peers() -> ApiResult<Json<Vec<PeerEntry>>> {
    let path = bowery_cli::peers::default_path()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    let list = bowery_cli::peers::Manifest::load(&path)
        .map(|m| m.peers)
        .unwrap_or_default();
    Ok(Json(
        list.into_iter()
            .map(|p| PeerEntry {
                short_fp: p.fp.chars().take(16).collect(),
                name: p.name,
                fp: p.fp,
                addr: p.addr,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
struct MeshNode {
    fp: String,
    short_fp: String,
    name: Option<String>,
    platform: Option<String>,
    version: Option<String>,
    /// True when this node answered for itself, rather than only being
    /// named by somebody else's gossip view.
    reporting: bool,
}

#[derive(Serialize)]
struct MeshEdge {
    from: String,
    to: String,
    pinned: bool,
    grant_state: Option<String>,
}

#[derive(Serialize)]
struct MeshGraph {
    nodes: Vec<MeshNode>,
    edges: Vec<MeshEdge>,
    /// Agents that did not answer the fan-out at all.
    ///
    /// Carried explicitly because a missing node and a silent one look
    /// identical on a picture, and they are opposite facts: one is not
    /// in the mesh, the other is and is not talking.
    silent: Vec<String>,
}

/// Build the graph from every agent's own view of its neighbours.
///
/// Fan-out, not a single relay's opinion: a mesh drawn from one host's
/// gossip table is that host's belief, and the interesting failures —
/// a partition, a peer one side can see and the other cannot — are
/// exactly the ones a single view cannot show.
async fn mesh(State(r): State<Shared>) -> ApiResult<Json<MeshGraph>> {
    let names: BTreeMap<String, String> = bowery_cli::peers::default_path()
        .ok()
        .and_then(|p| bowery_cli::peers::Manifest::load(&p).ok())
        .map(|m| m.peers)
        .unwrap_or_default()
        .into_iter()
        .map(|p| (p.fp.chars().take(16).collect::<String>(), p.name))
        .collect();

    let t = r
        .query(
            "SELECT fingerprint_hex, agent_version, platform, pinned, grant_state \
             FROM bowery_mesh_peers",
            true,
        )
        .await?;

    let col = |name: &str| t.columns.iter().position(|c| c == name);
    let (c_fp, c_ver, c_plat, c_pin, c_grant) = (
        col("fingerprint_hex"),
        col("agent_version"),
        col("platform"),
        col("pinned"),
        col("grant_state"),
    );

    let mut nodes: BTreeMap<String, MeshNode> = BTreeMap::new();
    let mut edges = Vec::new();
    let text = |row: &[serde_json::Value], i: Option<usize>| -> Option<String> {
        i.and_then(|i| row.get(i))
            .and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Null => None,
                other => Some(other.to_string()),
            })
            .filter(|s| !s.is_empty())
    };

    for (row, observer) in t.rows.iter().zip(t.agents.iter()) {
        // A single-agent answer carries no agent fingerprint; the
        // observer is then the relay we dialled.
        let from = if observer.is_empty() {
            r.fp_hex.chars().take(16).collect::<String>()
        } else {
            observer.clone()
        };
        nodes.entry(from.clone()).or_insert_with(|| MeshNode {
            short_fp: from.clone(),
            fp: from.clone(),
            name: names.get(&from).cloned(),
            platform: None,
            version: None,
            reporting: true,
        });
        nodes.get_mut(&from).expect("just inserted").reporting = true;

        let Some(to_full) = text(row, c_fp) else {
            continue;
        };
        let to: String = to_full.chars().take(16).collect();
        let entry = nodes.entry(to.clone()).or_insert_with(|| MeshNode {
            short_fp: to.clone(),
            fp: to_full.clone(),
            name: names.get(&to).cloned(),
            platform: None,
            version: None,
            reporting: false,
        });
        // Whoever gossiped it knows the platform and version; fill the
        // node in from the first observer that had them.
        if entry.platform.is_none() {
            entry.platform = text(row, c_plat);
        }
        if entry.version.is_none() {
            entry.version = text(row, c_ver);
        }
        edges.push(MeshEdge {
            from,
            to,
            pinned: matches!(c_pin.and_then(|i| row.get(i)), Some(v) if truthy(v)),
            grant_state: text(row, c_grant),
        });
    }

    // Anyone in the manifest that no observer reported and that did
    // not answer for itself.
    let silent = names
        .iter()
        .filter(|(fp, _)| !nodes.contains_key(*fp))
        .map(|(_, name)| name.clone())
        .collect();

    Ok(Json(MeshGraph {
        nodes: nodes.into_values().collect(),
        edges,
        silent,
    }))
}

fn truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_i64().is_some_and(|i| i != 0),
        serde_json::Value::String(s) => s == "1" || s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stance is drawn from what the responder actually wrote.
    ///
    /// These are the real strings `peer_verdicts` produces — a denial,
    /// a familiar build, an exact sighting, a refusal — taken from the
    /// live fleet's archive rather than invented.
    #[test]
    fn a_peer_verdict_is_classified_from_its_own_words() {
        assert_eq!(
            stance_of("has this program, built differently — same package, 23 build(s) run here"),
            "familiar"
        );
        assert_eq!(stance_of("has this exact binary (4 times)"), "seen");
        assert_eq!(
            stance_of("declined: history does not cover that window"),
            "refused"
        );
        assert_eq!(stance_of("cannot compare: runs aarch64"), "refused");
        assert_eq!(stance_of("no record of it"), "unseen");
        // Anything unrecognised is its own bucket rather than being
        // rounded into a denial — the alarming answer must never be
        // the default for text nobody parsed.
        assert_eq!(
            stance_of("something new the responder learned to say"),
            "other"
        );
    }

    #[test]
    fn peer_verdicts_are_lifted_out_of_the_context_and_the_rest_is_kept() {
        let row = bowery_cli::archive::Row {
            agent_fp: "aa".into(),
            agent_name: Some("otter1".into()),
            episode_id: "ep-1".into(),
            ts_unix_ms: 1,
            archived_ms: 1,
            rule_id: Some("baseline.rarity".into()),
            suspicion: 0.9,
            exe_path: Some("/usr/bin/cat".into()),
            exe_sha256: None,
            rationale: Some("why".into()),
            backend: Some("pre-filter".into()),
            confirmed: Some(false),
            peers_asked: Some(2),
            peers_unseen: Some(0),
            peers_seen: Some(0),
            peers_incomparable: Some(0),
            peers_familiar: Some(2),
            model_explanation: None,
            context_json: r#"{"peer.afb9902484e6f4ba":"has this program, built differently — same package, 23 build(s) run here","argv":"cat x"}"#.into(),
        };
        let v = to_view(&row);
        assert_eq!(v.peer_verdicts.len(), 1, "one peer spoke");
        assert_eq!(v.peer_verdicts[0].fp, "afb9902484e6f4ba");
        assert_eq!(v.peer_verdicts[0].stance, "familiar");
        // And the rest of the context survives — argv is most of what
        // an operator triages by.
        assert_eq!(v.context.get("argv").map(String::as_str), Some("cat x"));
    }

    /// A malformed context must not take the alert down with it.
    #[test]
    fn an_unreadable_context_still_yields_an_alert() {
        let mut row = bowery_cli::archive::Row {
            context_json: "{not json".into(),
            ..sample_row()
        };
        row.rule_id = Some("cred.read_shadow".into());
        let v = to_view(&row);
        assert!(v.context.is_empty());
        assert!(v.peer_verdicts.is_empty());
        assert_eq!(v.rule_id, "cred.read_shadow", "the alert itself survives");
    }

    fn sample_row() -> bowery_cli::archive::Row {
        bowery_cli::archive::Row {
            agent_fp: "aa".into(),
            agent_name: None,
            episode_id: "ep".into(),
            ts_unix_ms: 0,
            archived_ms: 0,
            rule_id: None,
            suspicion: 0.0,
            exe_path: None,
            exe_sha256: None,
            rationale: None,
            backend: None,
            confirmed: None,
            peers_asked: None,
            peers_unseen: None,
            peers_seen: None,
            peers_incomparable: None,
            peers_familiar: None,
            model_explanation: None,
            context_json: "{}".into(),
        }
    }

    #[test]
    fn sqlite_truthiness_covers_what_the_agent_actually_sends() {
        assert!(truthy(&serde_json::json!(1)));
        assert!(!truthy(&serde_json::json!(0)));
        assert!(truthy(&serde_json::json!(true)));
        assert!(!truthy(&serde_json::json!(null)));
    }
}
