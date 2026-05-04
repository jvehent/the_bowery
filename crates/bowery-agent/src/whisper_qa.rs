//! Phase-5 whisper Q&A wiring inside the agent.
//!
//! Two pieces:
//!
//! - [`spawn_whisper_qa_task`]: receives high-suspicion triggers from the
//!   pipeline, computes the local role vector, picks the top-K most
//!   role-similar pinned peers, asks each in parallel, aggregates
//!   answers, and emits [`AgentEvent::WhisperContextReady`].
//! - [`aggregate_local_sighting`]: scans the baseline for binaries
//!   whose tier-1 fingerprint matches a question, used by the responder
//!   side (in [`crate::agent::handle_connection`]) to build replies.
//!
//! What this layer does not own:
//! - Q&A protocol framing (see `bowery_whisper::qa`)
//! - Tier-1 derivation / bloom (see `bowery_whisper::fingerprint`)
//! - Peer ranking (see `bowery_analysis::peer_select`)
//! - Mesh peer discovery (see `bowery_mesh::Mesh`)

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bowery_analysis::{RoleFeatures, RoleVector, peer_select};
use bowery_baseline::Baseline;
use bowery_crypto::Fingerprint;
use bowery_mesh::{Mesh, PeerInfo};
use bowery_whisper::fingerprint::Tier1Fingerprint;
use bowery_whisper::known_neighbors::KnownNeighbors;
use bowery_whisper::qa::{self, AskError, LocalSighting};
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::BoweryEndpoint;
use bowery_whisper::{Sealer, Verifier};
use futures::future::join_all;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::agent::AgentEvent;
use crate::config::WhisperQaConfig;

// ---------------------------------------------------------------------------
// Pipeline → Q&A trigger channel.
// ---------------------------------------------------------------------------

/// Trigger emitted by the pipeline when a verdict crosses the Q&A
/// suspicion threshold. The Q&A task computes the tier-1 fingerprint
/// from `sha`, picks peers, and runs the round.
#[derive(Debug, Clone)]
pub(crate) struct WhisperQaTrigger {
    pub episode_id: String,
    pub sha: [u8; 32],
    pub suspicion: f32,
}

/// Per-peer summary of a single round. `None` for `sighting` means the
/// peer didn't reply (timeout, dial failure, malformed response).
#[derive(Debug, Clone)]
pub struct PeerSighting {
    pub peer: Fingerprint,
    pub similarity: f32,
    pub sighting: Option<qa::LocalSighting>,
    pub note: String,
}

/// Bundle attached to [`AgentEvent::WhisperContextReady`].
#[derive(Debug, Clone)]
pub struct WhisperContext {
    pub episode_id: String,
    pub tier1_fp: Tier1Fingerprint,
    pub peers: Vec<PeerSighting>,
    /// Total `seen_count` summed across all replying peers.
    pub total_seen_count: u64,
    /// Number of peers whose `sighting.seen_count` is non-zero.
    pub corroborating_peers: usize,
}

// ---------------------------------------------------------------------------
// Local-side aggregation (for the responder).
// ---------------------------------------------------------------------------

/// Scan the baseline and aggregate sightings whose tier-1 fingerprint
/// matches `target`. Returns `LocalSighting::default()` (i.e.
/// `seen_count == 0`) if the baseline has no matching rows.
///
/// O(n) over the binary table; fine at fleet sizes we care about (a
/// host's own binary set is bounded). If this becomes a hotspot we'll
/// add an indexed `tier1` column to the baseline schema.
pub fn aggregate_local_sighting(baseline: &Baseline, target: Tier1Fingerprint) -> LocalSighting {
    let mut seen_count = 0u64;
    let mut first_seen_unix_ms = u64::MAX;
    let mut last_seen_unix_ms = 0u64;
    let mut hits = 0u64;

    let _ = baseline.for_each_binary(|rec| {
        if Tier1Fingerprint::derive(&rec.sha256) != target {
            return;
        }
        hits += 1;
        seen_count = seen_count.saturating_add(rec.seen_count);
        let first = rec
            .first_seen
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        let last = rec
            .last_seen
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        first_seen_unix_ms = first_seen_unix_ms.min(first);
        last_seen_unix_ms = last_seen_unix_ms.max(last);
    });

    if hits == 0 {
        return LocalSighting::default();
    }
    LocalSighting {
        seen_count,
        first_seen_unix_ms,
        last_seen_unix_ms,
    }
}

// ---------------------------------------------------------------------------
// Q&A round task.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // keeps the wiring explicit at the call site
pub(crate) fn spawn_whisper_qa_task(
    mut triggers: mpsc::Receiver<WhisperQaTrigger>,
    endpoint: BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: Arc<Sealer>,
    mesh: Arc<Mesh>,
    baseline: Arc<Baseline>,
    qa_cfg: WhisperQaConfig,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                trigger = triggers.recv() => {
                    let Some(trigger) = trigger else { break };
                    let endpoint = endpoint.clone();
                    let kn = kn.clone();
                    let sealer = sealer.clone();
                    let mesh = mesh.clone();
                    let baseline = baseline.clone();
                    let qa_cfg = qa_cfg.clone();
                    let events_tx = events_tx.clone();
                    // Each round runs in its own task so a slow peer
                    // can't block the next trigger.
                    tokio::spawn(async move {
                        run_round(
                            trigger,
                            endpoint,
                            kn,
                            sealer,
                            mesh,
                            baseline,
                            qa_cfg,
                            events_tx,
                        )
                        .await;
                    });
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // intentionally one cohesive round
async fn run_round(
    trigger: WhisperQaTrigger,
    endpoint: BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: Arc<Sealer>,
    mesh: Arc<Mesh>,
    baseline: Arc<Baseline>,
    qa_cfg: WhisperQaConfig,
    events_tx: broadcast::Sender<AgentEvent>,
) {
    let tier1 = Tier1Fingerprint::derive(&trigger.sha);
    debug!(
        episode = %trigger.episode_id,
        suspicion = trigger.suspicion,
        tier1 = %tier1,
        "starting whisper Q&A round"
    );

    // Compute local role vector for similarity ranking. Cheap (a single
    // baseline scan + 8x32 matmul); recomputing per-round avoids
    // having to keep a long-lived shared cache across async tasks.
    let local_role = match RoleFeatures::from_baseline(&baseline) {
        Ok(features) => RoleVector::from_features(&features),
        Err(e) => {
            warn!(error = %e, "could not compute local role vector; skipping Q&A round");
            return;
        }
    };

    // Snapshot the live mesh, drop unpinned peers + ourselves, decode
    // each peer's role vector. Peers without a published role vector
    // are skipped — without it we can't rank them, and we'd rather not
    // ask randomly.
    let local_fp = endpoint.fingerprint();
    let mut candidates: Vec<(PeerInfo, RoleVector)> = Vec::new();
    for peer in mesh.peers() {
        if peer.fingerprint == local_fp {
            continue;
        }
        if !kn.has_pinned(&peer.fingerprint) {
            continue;
        }
        let Some(rv_b64) = peer.role_vector.as_deref() else {
            continue;
        };
        let Some(rv) = RoleVector::from_base64(rv_b64) else {
            warn!(peer = %peer.fingerprint, "peer published a malformed role vector; skipping");
            continue;
        };
        candidates.push((peer, rv));
    }

    if candidates.is_empty() {
        debug!(episode = %trigger.episode_id, "no candidate peers for whisper Q&A round");
        let _ = events_tx.send(AgentEvent::WhisperContextReady(WhisperContext {
            episode_id: trigger.episode_id,
            tier1_fp: tier1,
            peers: Vec::new(),
            total_seen_count: 0,
            corroborating_peers: 0,
        }));
        return;
    }

    let ranked = peer_select::rank_by_similarity(
        &local_role,
        candidates,
        qa_cfg.fanout,
        qa_cfg.min_similarity,
    );

    let envelope_verifier = Arc::new(Verifier::new(kn.clone()));

    let asks = ranked
        .into_iter()
        .map(|(peer, similarity)| {
            let endpoint = endpoint.clone();
            let kn = kn.clone();
            let sealer = sealer.clone();
            let envelope_verifier = envelope_verifier.clone();
            let timeout = qa_cfg.timeout;
            async move {
                let outcome = ask_one(
                    &endpoint,
                    kn,
                    &sealer,
                    &envelope_verifier,
                    &peer,
                    tier1,
                    timeout,
                )
                .await;
                (peer, similarity, outcome)
            }
        })
        .collect::<Vec<_>>();

    let results = join_all(asks).await;

    let mut peers = Vec::with_capacity(results.len());
    let mut total_seen_count = 0u64;
    let mut corroborating_peers = 0usize;
    for (peer, similarity, outcome) in results {
        match outcome {
            Ok(answer) => {
                let seen = answer.seen_count;
                let note = answer.note.clone();
                let sighting = LocalSighting {
                    seen_count: seen,
                    first_seen_unix_ms: answer.first_seen_unix_ms,
                    last_seen_unix_ms: answer.last_seen_unix_ms,
                };
                if seen > 0 {
                    corroborating_peers += 1;
                    total_seen_count = total_seen_count.saturating_add(seen);
                }
                peers.push(PeerSighting {
                    peer: peer.fingerprint,
                    similarity,
                    sighting: Some(sighting),
                    note,
                });
            }
            Err(e) => {
                debug!(peer = %peer.fingerprint, error = %e, "whisper ask failed");
                peers.push(PeerSighting {
                    peer: peer.fingerprint,
                    similarity,
                    sighting: None,
                    note: String::new(),
                });
            }
        }
    }

    info!(
        episode = %trigger.episode_id,
        peers = peers.len(),
        corroborating = corroborating_peers,
        total_seen = total_seen_count,
        "whisper Q&A round complete"
    );

    let _ = events_tx.send(AgentEvent::WhisperContextReady(WhisperContext {
        episode_id: trigger.episode_id,
        tier1_fp: tier1,
        peers,
        total_seen_count,
        corroborating_peers,
    }));
}

async fn ask_one(
    endpoint: &BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: &Sealer,
    envelope_verifier: &Verifier<Arc<KnownNeighbors>>,
    peer: &PeerInfo,
    tier1: Tier1Fingerprint,
    timeout: Duration,
) -> Result<bowery_proto::Answer, AskError> {
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(kn, peer.fingerprint));
    let conn = endpoint
        .dial(dial_verifier, peer.whisper_addr)
        .await
        .map_err(AskError::Transport)?;
    let question = qa::build_question(tier1, timeout, "");
    let answer = qa::ask(&conn, sealer, envelope_verifier, question, timeout).await?;
    Ok(answer)
}

// ---------------------------------------------------------------------------
// Helper: KnownNeighbors lookup wrapper.
// ---------------------------------------------------------------------------

/// Convenience extension to ask "is this fingerprint pinned?" without
/// pulling in the `FingerprintResolver` trait at the call site.
trait HasPinned {
    fn has_pinned(&self, fp: &Fingerprint) -> bool;
}

impl HasPinned for KnownNeighbors {
    fn has_pinned(&self, fp: &Fingerprint) -> bool {
        self.fingerprints().iter().any(|f| f == fp)
    }
}

/// Compute current wall-clock millis. Matches the encoding used by
/// `qa::build_question` so the responder side can compare directly.
#[allow(dead_code)] // reserved for future ttl-aware logging
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_local_sighting_returns_default_when_baseline_empty() {
        let baseline = Baseline::open_in_memory().unwrap();
        let fp = Tier1Fingerprint::derive(&[1u8; 32]);
        let s = aggregate_local_sighting(&baseline, fp);
        assert_eq!(s, LocalSighting::default());
    }

    #[test]
    fn aggregate_local_sighting_finds_matching_sha() {
        let baseline = Baseline::open_in_memory().unwrap();
        let target_sha = [42u8; 32];
        let other_sha = [99u8; 32];
        baseline.upsert_binary(&target_sha).unwrap();
        baseline.upsert_binary(&target_sha).unwrap();
        baseline.upsert_binary(&other_sha).unwrap();
        let target_tier1 = Tier1Fingerprint::derive(&target_sha);
        let s = aggregate_local_sighting(&baseline, target_tier1);
        assert_eq!(s.seen_count, 2);
        assert!(s.last_seen_unix_ms >= s.first_seen_unix_ms);
    }

    #[test]
    fn aggregate_local_sighting_zero_when_no_match() {
        let baseline = Baseline::open_in_memory().unwrap();
        baseline.upsert_binary(&[1u8; 32]).unwrap();
        let unrelated = Tier1Fingerprint::derive(b"not present");
        let s = aggregate_local_sighting(&baseline, unrelated);
        assert_eq!(s.seen_count, 0);
    }
}
