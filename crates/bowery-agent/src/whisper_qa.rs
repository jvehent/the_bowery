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

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_analysis::{RoleFeatures, RoleVector, peer_select};
use bowery_baseline::Baseline;
use bowery_crypto::Fingerprint;
use bowery_llm::{AnalysisContext, Submitter};
use bowery_mesh::{Mesh, PeerInfo};
use bowery_proto::BloomAdvert;
use bowery_whisper::fingerprint::{BloomFilter, Tier1Fingerprint};
use bowery_whisper::known_neighbors::KnownNeighbors;
use bowery_whisper::qa::{self, AskError, LocalSighting};
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::BoweryEndpoint;
use bowery_whisper::{Sealer, Verifier};
use futures::future::join_all;
use prost::Message as _;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::agent::{AgentEvent, LlmShedReason};
use crate::config::WhisperQaConfig;

// ---------------------------------------------------------------------------
// Pipeline → Q&A trigger channel.
// ---------------------------------------------------------------------------

/// Trigger emitted by the pipeline when a verdict crosses the Q&A
/// suspicion threshold. The Q&A task computes the tier-1 fingerprint
/// from `sha`, runs the whisper round, then submits the carried
/// [`AnalysisContext`] to the LLM with peer sightings injected as
/// `extra` entries — so the LLM's rationale can reference
/// neighborhood corroboration.
///
/// `episode_id` is duplicated from `ctx.pre_verdict.episode_id` so
/// log messages don't have to deref through the verdict.
#[derive(Debug, Clone)]
pub(crate) struct WhisperQaTrigger {
    pub episode_id: String,
    pub sha: [u8; 32],
    pub ctx: AnalysisContext,
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
    /// Number of role-similar candidates we skipped *before* dialing
    /// because their bloom advert ruled out the tier-1 fingerprint.
    /// Useful for sizing how much round-trip budget the asker-side
    /// bloom check is saving in production.
    pub peers_skipped_by_bloom: usize,
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
    llm_submitter: Submitter,
    llm_threshold: f32,
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
                    let llm_submitter = llm_submitter.clone();
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
                            llm_submitter,
                            llm_threshold,
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
    llm_submitter: Submitter,
    llm_threshold: f32,
    events_tx: broadcast::Sender<AgentEvent>,
) {
    let tier1 = Tier1Fingerprint::derive(&trigger.sha);
    let pre_suspicion = trigger.ctx.pre_verdict.suspicion;
    debug!(
        episode = %trigger.episode_id,
        suspicion = pre_suspicion,
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
        let context = WhisperContext {
            episode_id: trigger.episode_id.clone(),
            tier1_fp: tier1,
            peers: Vec::new(),
            total_seen_count: 0,
            corroborating_peers: 0,
            peers_skipped_by_bloom: 0,
        };
        finish_round(
            trigger,
            context,
            pre_suspicion,
            &llm_submitter,
            llm_threshold,
            &events_tx,
        );
        return;
    }

    let ranked = peer_select::rank_by_similarity(
        &local_role,
        candidates,
        qa_cfg.fanout,
        qa_cfg.min_similarity,
    );

    // Asker-side bloom-advert filter. A peer whose advert is present
    // and parseable AND `!contains(tier1)` definitely hasn't seen the
    // artifact (modulo bloom collisions, which are vanishingly rare in
    // the *negative* direction — bloom filters never produce false
    // negatives). Skipping these saves a QUIC dial per peer.
    let mut peers_skipped_by_bloom = 0usize;
    let ranked: Vec<_> = ranked
        .into_iter()
        .filter(|(peer, _)| {
            if bloom_says_definitely_no(peer, tier1) {
                peers_skipped_by_bloom += 1;
                debug!(
                    episode = %trigger.episode_id,
                    peer = %peer.fingerprint,
                    "skipping dial — peer advert excludes this tier1"
                );
                false
            } else {
                true
            }
        })
        .collect();

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
        skipped_by_bloom = peers_skipped_by_bloom,
        "whisper Q&A round complete"
    );

    let context = WhisperContext {
        episode_id: trigger.episode_id.clone(),
        tier1_fp: tier1,
        peers,
        total_seen_count,
        corroborating_peers,
        peers_skipped_by_bloom,
    };
    finish_round(
        trigger,
        context,
        pre_suspicion,
        &llm_submitter,
        llm_threshold,
        &events_tx,
    );
}

/// After the whisper round, broadcast the [`WhisperContext`] event,
/// inject neighborhood sightings into the trigger's `AnalysisContext`,
/// and submit to the LLM if the verdict still clears the LLM
/// threshold. Pulled out of `run_round` so both the empty-candidates
/// fast path and the normal path share a single decision point.
fn finish_round(
    trigger: WhisperQaTrigger,
    context: WhisperContext,
    pre_suspicion: f32,
    llm_submitter: &Submitter,
    llm_threshold: f32,
    events_tx: &broadcast::Sender<AgentEvent>,
) {
    let mut ctx = trigger.ctx;
    inject_whisper_context(&mut ctx, &context);

    // Broadcast the round result for observers (tests, dashboards). We
    // emit *before* the LLM submission so subscribers see the round
    // even when the LLM is shed or the threshold isn't met.
    let _ = events_tx.send(AgentEvent::WhisperContextReady(context));

    if pre_suspicion >= llm_threshold {
        let episode_id = ctx.pre_verdict.episode_id.clone();
        if let Err(reason) = llm_submitter.submit(ctx) {
            let _ = events_tx.send(AgentEvent::LlmShed {
                episode_id,
                reason: LlmShedReason::from(reason),
            });
        }
    }
}

/// Render a [`WhisperContext`] as `extra` entries on an
/// [`AnalysisContext`] so the LLM prompt picks them up. The renderer
/// keeps the summary terse — one `neighborhood` line for the round as
/// a whole, plus one line per corroborating peer with its similarity
/// score and observation count. Non-corroborating responders and
/// non-responders are intentionally omitted to keep the prompt focused.
pub(crate) fn inject_whisper_context(ctx: &mut AnalysisContext, ctx_in: &WhisperContext) {
    let asked = ctx_in.peers.len();
    let summary = format!(
        "asked {asked} peer{plural}, {corroborating} corroborating, {total} total observations across them",
        plural = if asked == 1 { "" } else { "s" },
        corroborating = ctx_in.corroborating_peers,
        total = ctx_in.total_seen_count,
    );
    ctx.extra.push(("neighborhood".to_string(), summary));

    for peer in &ctx_in.peers {
        let Some(sighting) = peer.sighting else {
            continue;
        };
        if sighting.seen_count == 0 {
            continue;
        }
        let key = format!("peer.{}", short_fp(&peer.peer));
        let value = format!(
            "seen {} times (similarity {:.2})",
            sighting.seen_count, peer.similarity,
        );
        ctx.extra.push((key, value));
    }
}

/// First 16 hex chars of a fingerprint — short enough for log lines
/// and prompt entries, long enough to disambiguate within a fleet.
fn short_fp(fp: &Fingerprint) -> String {
    let s = fp.to_string();
    s.chars().take(16).collect()
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
// Asker-side bloom-advert filter
// ---------------------------------------------------------------------------

/// Returns `true` only when `peer`'s bloom advert is present, fully
/// parseable, and `!contains(tier1)` — i.e. the peer has *definitely*
/// not observed anything matching this tier-1 fingerprint. Bloom
/// filters can produce false positives (peer says yes, actually no)
/// but never false negatives (peer says no, actually yes), so a `true`
/// return here is safe to act on.
///
/// In every uncertain case (no advert published yet, base64 decode
/// fails, prost decode fails, advert dimensions reject) we return
/// `false` and the asker proceeds with a normal dial. The optimization
/// is best-effort.
fn bloom_says_definitely_no(peer: &PeerInfo, tier1: Tier1Fingerprint) -> bool {
    let Some(advert_b64) = peer.bloom_advert.as_deref() else {
        return false;
    };
    let Ok(raw) = BASE64.decode(advert_b64.as_bytes()) else {
        warn!(peer = %peer.fingerprint, "peer published a non-base64 bloom advert; ignoring");
        return false;
    };
    let Ok(advert) = BloomAdvert::decode(raw.as_slice()) else {
        warn!(peer = %peer.fingerprint, "peer published a malformed bloom advert; ignoring");
        return false;
    };
    let Ok(k) = u8::try_from(advert.k) else {
        warn!(peer = %peer.fingerprint, k = advert.k, "peer's advert k out of range");
        return false;
    };
    let bit_count = advert.bit_count as usize;
    let Ok(filter) = BloomFilter::from_bytes(advert.bits, bit_count, k) else {
        warn!(peer = %peer.fingerprint, "peer's bloom advert dimensions rejected");
        return false;
    };
    !filter.contains(tier1)
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

    /// Build a `PeerInfo` whose `bloom_advert` is a base64'd
    /// `BloomAdvert` containing exactly the listed tier-1 fingerprints.
    /// Returns `(peer_info, tier1_in, tier1_out)` so the test can ask
    /// "what's a member?" and "what's not?" without rebuilding the
    /// filter.
    fn peer_with_bloom(seeds: &[&[u8]]) -> PeerInfo {
        use bowery_proto::BloomAdvert;
        use prost::Message as _;

        let mut filter = BloomFilter::with_defaults();
        for s in seeds {
            filter.insert(Tier1Fingerprint::derive(s));
        }
        let advert = BloomAdvert {
            epoch: 1,
            bit_count: u32::try_from(filter.bit_count()).unwrap(),
            k: u32::from(filter.k()),
            bits: filter.as_bytes().to_vec(),
        };
        let b64 = BASE64.encode(advert.encode_to_vec());
        PeerInfo {
            fingerprint: bowery_crypto::Fingerprint::from_bytes([0xab; 32]),
            verifying_key: ed25519_dalek::VerifyingKey::from_bytes(&[
                // Arbitrary valid Ed25519 public key; the helper
                // doesn't care about it. Generated once via
                // `Identity::generate()`.
                0x3a, 0x4f, 0x77, 0x16, 0xd5, 0x3e, 0x9c, 0x6c, 0x76, 0x4b, 0x44, 0x49, 0x12, 0x91,
                0xfa, 0x9d, 0x6f, 0x1b, 0xea, 0x4d, 0x21, 0x66, 0xa2, 0xa6, 0xc5, 0xe4, 0xa1, 0xab,
                0x6b, 0x06, 0xc9, 0x07,
            ])
            .expect("valid pubkey"),
            whisper_addr: "127.0.0.1:0".parse().unwrap(),
            agent_version: "0.0.1".into(),
            role_vector: None,
            bloom_advert: Some(b64),
        }
    }

    #[test]
    fn bloom_says_definitely_no_skips_only_proven_negatives() {
        let peer = peer_with_bloom(&[b"alpha", b"beta"]);
        // Members → maybe-yes, don't skip.
        assert!(!bloom_says_definitely_no(
            &peer,
            Tier1Fingerprint::derive(b"alpha")
        ));
        assert!(!bloom_says_definitely_no(
            &peer,
            Tier1Fingerprint::derive(b"beta")
        ));
        // Non-member → definite no, skip.
        assert!(bloom_says_definitely_no(
            &peer,
            Tier1Fingerprint::derive(b"never-inserted-payload")
        ));
    }

    #[test]
    fn bloom_says_definitely_no_returns_false_when_advert_absent() {
        let mut peer = peer_with_bloom(&[]);
        peer.bloom_advert = None;
        assert!(!bloom_says_definitely_no(
            &peer,
            Tier1Fingerprint::derive(b"anything")
        ));
    }

    #[test]
    fn bloom_says_definitely_no_returns_false_on_garbage_advert() {
        let mut peer = peer_with_bloom(&[]);
        peer.bloom_advert = Some("not!base64!at!all".into());
        assert!(!bloom_says_definitely_no(
            &peer,
            Tier1Fingerprint::derive(b"anything")
        ));
    }

    #[test]
    fn inject_whisper_context_adds_neighborhood_summary() {
        use bowery_analysis::{BinaryScore, Verdict};

        let pre_verdict = Verdict {
            episode_id: "ep-1".into(),
            suspicion: 0.9,
            score: BinaryScore {
                value: 1.0,
                baseline_seen_count: 0,
                reason: "x".into(),
            },
            rule_hits: Vec::new(),
        };
        let mut ctx = AnalysisContext::new(pre_verdict);

        let corroborating = bowery_crypto::Fingerprint::from_bytes([0xaa; 32]);
        let zero_sighting = bowery_crypto::Fingerprint::from_bytes([0xbb; 32]);
        let no_response = bowery_crypto::Fingerprint::from_bytes([0xcc; 32]);
        let context = WhisperContext {
            episode_id: "ep-1".into(),
            tier1_fp: Tier1Fingerprint::derive(b"x"),
            peers: vec![
                PeerSighting {
                    peer: corroborating,
                    similarity: 0.95,
                    sighting: Some(LocalSighting {
                        seen_count: 12,
                        first_seen_unix_ms: 1,
                        last_seen_unix_ms: 2,
                    }),
                    note: String::new(),
                },
                PeerSighting {
                    peer: zero_sighting,
                    similarity: 0.80,
                    sighting: Some(LocalSighting::default()), // no observation
                    note: String::new(),
                },
                PeerSighting {
                    peer: no_response,
                    similarity: 0.70,
                    sighting: None, // didn't reply
                    note: String::new(),
                },
            ],
            total_seen_count: 12,
            corroborating_peers: 1,
            peers_skipped_by_bloom: 0,
        };

        inject_whisper_context(&mut ctx, &context);

        let nbr = ctx
            .extra
            .iter()
            .find(|(k, _)| k == "neighborhood")
            .expect("neighborhood entry");
        assert!(nbr.1.contains("3 peers"));
        assert!(nbr.1.contains("1 corroborating"));
        assert!(nbr.1.contains("12"));

        let peer_keys: Vec<&str> = ctx
            .extra
            .iter()
            .filter_map(|(k, _)| k.strip_prefix("peer."))
            .collect();
        // Only the corroborating peer (seen_count > 0) shows up.
        assert_eq!(peer_keys.len(), 1);
        assert!(peer_keys[0].starts_with(&corroborating.to_string()[..16]));
    }
}
