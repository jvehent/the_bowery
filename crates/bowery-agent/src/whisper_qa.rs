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

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_analysis::{RoleFeatures, RoleVector, peer_select};
use bowery_baseline::Baseline;
use bowery_crypto::Fingerprint;
use bowery_llm::{AnalysisContext, Submitter};
use bowery_mesh::{Mesh, PeerInfo};
use bowery_proto::{AlertConfirmation, BloomAdvert};
use bowery_whisper::fingerprint::{BloomFilter, Tier1Fingerprint};
use bowery_whisper::known_neighbors::KnownNeighbors;
use bowery_whisper::pool::PeerConnections;
use bowery_whisper::qa::{self, AskError, LocalSighting};
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::{Sealer, Verifier};
use futures::future::join_all;
use prost::Message as _;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::agent::{AgentEvent, LlmShedReason, leading_rule_id};
use crate::config::WhisperQaConfig;
use crate::inbox::AlertInbox;

// ---------------------------------------------------------------------------
// Pipeline → Q&A trigger channel.
/// Everything `finish_round` needs to raise a confirmed alert, grouped
/// so the round plumbing doesn't grow another six parameters.
#[derive(Clone)]
pub(crate) struct ConfirmSink {
    pub inbox: Arc<AlertInbox>,
    pub originator_fp: Fingerprint,
    pub alert_threshold: f32,
    pub backend_label: String,
    /// Peers that must report *never seen it*. Zero disables
    /// confirmation.
    pub quorum: usize,
    /// Actions held back at decision time, waiting on this round.
    ///
    /// Released when the neighbourhood confirms, dropped with a
    /// recorded reason when it does not — never silently forgotten,
    /// because an action that was decided and not carried out is
    /// exactly what an operator reads the audit trail to find.
    pub pending: Arc<crate::pending_actions::PendingActions>,
    /// Where a released action goes. `None` on a build with no response
    /// engine wired, in which case nothing is ever parked either.
    pub release_tx: Option<mpsc::Sender<crate::pending_actions::Release>>,
}

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

/// What one peer said in a round.
///
/// Three states, not two. `Option<LocalSighting>` used to carry this,
/// and the missing third state is what let two agents with empty
/// baselines confirm every alert their neighbour raised: a peer that
/// cannot answer and a peer that answered "no" were the same value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerReply {
    /// Looked, and reports what it found. `seen_count == 0` here is the
    /// real "never seen it" — evidence.
    Observed(qa::LocalSighting),
    /// Answered, but declined: too little observed for its "no" to mean
    /// anything. Carries the responder's reason.
    Refused(String),
    /// Answered, and is watching, but cannot be compared against.
    ///
    /// A peer on another architecture does not have — cannot have — the
    /// asker's binary: the same program compiled for a different target
    /// is a different file with a different hash. Its "never seen it"
    /// is true of every binary that exists and is evidence of nothing.
    ///
    /// Carries the responder's platform so an operator reading the
    /// alert can see *why* it could not speak.
    Incomparable { platform: String },
    /// Does not have this file, and does have this program.
    ///
    /// The answer the round could not previously express. A peer on
    /// another architecture will never hold the asker's hash, but it
    /// holds `dash` from package `dash` just the same — measured on the
    /// reference fleet, three hosts share zero hashes and seven
    /// packages. Treating that as "never seen it" is what confirmed the
    /// system shell as an anomaly.
    ///
    /// Not a sighting either: the file genuinely differs, and saying so
    /// keeps "I have this exact binary" distinct from "I have this
    /// program". Only the first is an identity claim about a file.
    Familiar {
        pkg_builds: u32,
        /// Matched on the path rather than the package — weaker, since
        /// a path is a location an attacker picks.
        by_path_only: bool,
    },
    /// Timed out, failed to dial, or replied unintelligibly.
    Silent,
}

impl PeerReply {
    /// The sighting, if the peer actually looked.
    #[must_use]
    pub fn observed(&self) -> Option<qa::LocalSighting> {
        match self {
            Self::Observed(s) => Some(*s),
            Self::Refused(_) | Self::Incomparable { .. } | Self::Familiar { .. } | Self::Silent => {
                None
            }
        }
    }
}

/// Per-peer summary of a single round.
#[derive(Debug, Clone)]
pub struct PeerSighting {
    pub peer: Fingerprint,
    pub similarity: f32,
    pub reply: PeerReply,
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

/// How much a host must have observed before its "never seen it" is
/// worth counting.
///
/// Two bounds, because one is not enough and we learned that the
/// expensive way. Breadth alone (`min_binaries`) is satisfied within a
/// minute of boot, and a host that has run 40 binaries in its first
/// afternoon truthfully reports "never seen it" about nearly everything
/// its neighbours run. Age alone would let a host that booted a week ago
/// and executed nothing vote on everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageBar {
    /// Distinct binaries observed. A floor against a just-started agent.
    pub min_binaries: u64,
    /// How long the baseline has been accumulating, measured from the
    /// oldest observation. This is the bound that actually matters: it
    /// is the difference between "I watch this fleet and your binary is
    /// not part of it" and "I have not been here long enough to know".
    pub min_age: Duration,
}

/// What this host can honestly say about a tier-1 fingerprint.
///
/// The distinction is the whole point: `Observed(zero)` and
/// `Insufficient` both mean "I have no record", and only the first is
/// evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalKnowledge {
    /// This host has observed enough for "never seen it" to be
    /// informative. The sighting may still be zero — that is the
    /// finding.
    Observed(LocalSighting),
    /// Too little observed to have an opinion. Carries both measures so
    /// the refusal can say which bound it missed.
    Insufficient { binaries: u64, age: Duration },
}

/// What this host knows about a program it does not have the file for.
///
/// Answered from the descriptor store, which is why slice 2 had to come
/// first: `binaries` is keyed on the hash and records nothing about
/// what a hash *was*, so before descriptors existed the only possible
/// answer to "do you have this program" was the hash comparison that
/// already failed.
///
/// Package before path, and never path alone as an explanation: a path
/// is a location an attacker chooses, while a package is an identity
/// the distribution assigned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgramKnowledge {
    /// This host has the same package, at some build.
    pub pkg_match: bool,
    /// Distinct hashes held for that package.
    pub pkg_builds: u32,
    /// This host has something at the same path, at some hash.
    pub path_match: bool,
}

/// Look up a program by package, then by path.
///
/// Both lookups are indexed and bounded; neither scans the baseline.
#[must_use]
pub fn program_knowledge(baseline: &Baseline, pkg: &str, exe_path: &str) -> ProgramKnowledge {
    let mut out = ProgramKnowledge::default();
    if !pkg.is_empty()
        && let Ok(hashes) = baseline.hashes_for_package(pkg, 64)
        && !hashes.is_empty()
    {
        out.pkg_match = true;
        out.pkg_builds = u32::try_from(hashes.len()).unwrap_or(u32::MAX);
    }
    if !exe_path.is_empty()
        && let Ok(hashes) = baseline.hashes_for_path(exe_path, 8)
        && !hashes.is_empty()
    {
        out.path_match = true;
    }
    out
}

/// Scan the baseline once, answering both "how much have I observed?"
/// and "have I seen this?".
///
/// **The count is not decoration.** A host whose baseline is empty
/// answers `seen_count: 0` to every question, and a quorum of
/// "never seen it" is exactly what confirms an alert — so an agent with
/// a broken event source silently rubber-stamps every alert its
/// neighbours raise. That is not hypothetical: it was found running on
/// a live fleet, confirming `/usr/bin/ssh` as an anomaly by unanimous
/// agreement of two hosts that had observed nothing whatsoever.
///
/// Below `min_binaries` this returns [`LocalKnowledge::Insufficient`]
/// and the responder refuses instead of answering zero. Both facts come
/// from the same scan because the scan is the expensive part.
///
/// O(n) over the binary table; fine at fleet sizes we care about (a
/// host's own binary set is bounded). If this becomes a hotspot we'll
/// add an indexed `tier1` column to the baseline schema.
pub fn local_knowledge(
    baseline: &Baseline,
    target: Tier1Fingerprint,
    bar: CoverageBar,
) -> LocalKnowledge {
    let mut seen_count = 0u64;
    let mut first_seen_unix_ms = u64::MAX;
    let mut last_seen_unix_ms = 0u64;
    let mut hits = 0u64;
    let mut observed_binaries = 0u64;
    let mut oldest_first_seen: Option<SystemTime> = None;

    let _ = baseline.for_each_binary(|rec| {
        observed_binaries += 1;
        oldest_first_seen = Some(match oldest_first_seen {
            Some(prev) if prev <= rec.first_seen => prev,
            _ => rec.first_seen,
        });
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

    // How long this baseline has been accumulating.
    let age = oldest_first_seen
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or(Duration::ZERO);

    // A hit outranks both bounds: if we have actually seen the binary,
    // saying so is always honest and always useful, however little else
    // we have observed. Only a *negative* answer needs standing.
    if hits == 0 && (observed_binaries < bar.min_binaries || age < bar.min_age) {
        return LocalKnowledge::Insufficient {
            binaries: observed_binaries,
            age,
        };
    }
    if hits == 0 {
        return LocalKnowledge::Observed(LocalSighting::default());
    }
    LocalKnowledge::Observed(LocalSighting {
        seen_count,
        first_seen_unix_ms,
        last_seen_unix_ms,
    })
}

/// Back-compat shim: aggregate sightings without the coverage check.
///
/// Only for callers that have already established coverage some other
/// way. Prefer [`local_knowledge`] — answering from this directly is
/// how the blind-witness bug happened.
#[must_use]
pub fn aggregate_local_sighting(baseline: &Baseline, target: Tier1Fingerprint) -> LocalSighting {
    let no_bar = CoverageBar {
        min_binaries: 0,
        min_age: Duration::ZERO,
    };
    match local_knowledge(baseline, target, no_bar) {
        LocalKnowledge::Observed(s) => s,
        // Unreachable with min_binaries == 0, but a total is still the
        // honest zero here.
        LocalKnowledge::Insufficient { .. } => LocalSighting::default(),
    }
}

// ---------------------------------------------------------------------------
// Q&A round task.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // keeps the wiring explicit at the call site
pub(crate) fn spawn_whisper_qa_task(
    mut triggers: mpsc::Receiver<WhisperQaTrigger>,
    pool: PeerConnections,
    kn: Arc<KnownNeighbors>,
    sealer: Arc<Sealer>,
    mesh: Arc<Mesh>,
    baseline: Arc<Baseline>,
    qa_cfg: WhisperQaConfig,
    llm_submitter: Submitter,
    llm_threshold: f32,
    events_tx: broadcast::Sender<AgentEvent>,
    confirm: ConfirmSink,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    // Shed-not-queue: a full semaphore drops the round rather than
    // parking the trigger, so a burst can't build a backlog that keeps
    // dialling peers long after the exec storm that caused it is over.
    let round_permits = Arc::new(tokio::sync::Semaphore::new(
        qa_cfg.max_concurrent_rounds.max(1),
    ));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                trigger = triggers.recv() => {
                    let Some(trigger) = trigger else { break };
                    let Ok(permit) = round_permits.clone().try_acquire_owned() else {
                        warn!(
                            max = qa_cfg.max_concurrent_rounds,
                            "whisper Q&A rounds at capacity; shedding trigger"
                        );
                        continue;
                    };
                    let pool = pool.clone();
                    let kn = kn.clone();
                    let sealer = sealer.clone();
                    let mesh = mesh.clone();
                    let baseline = baseline.clone();
                    let qa_cfg = qa_cfg.clone();
                    let llm_submitter = llm_submitter.clone();
                    let events_tx = events_tx.clone();
                    let confirm = confirm.clone();
                    // Each round runs in its own task so a slow peer
                    // can't block the next trigger.
                    tokio::spawn(async move {
                        run_round(
                            trigger,
                            pool,
                            kn,
                            sealer,
                            mesh,
                            baseline,
                            qa_cfg,
                            llm_submitter,
                            llm_threshold,
                            events_tx,
                            confirm,
                        )
                        .await;
                        drop(permit);
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
    pool: PeerConnections,
    kn: Arc<KnownNeighbors>,
    sealer: Arc<Sealer>,
    mesh: Arc<Mesh>,
    baseline: Arc<Baseline>,
    qa_cfg: WhisperQaConfig,
    llm_submitter: Submitter,
    llm_threshold: f32,
    events_tx: broadcast::Sender<AgentEvent>,
    confirm: ConfirmSink,
) {
    let tier1 = Tier1Fingerprint::derive(&trigger.sha);
    let pre_suspicion = trigger.ctx.pre_verdict.suspicion;

    // What this binary is, from our own descriptor store — the record
    // slice 2 writes on first sight. Asking peers about the hash alone
    // is the question that cannot be answered across architectures;
    // this is what lets them answer "same program, different build".
    //
    // Falls back to the exec's path when no descriptor exists yet,
    // which is the case for a binary whose very first execution
    // triggered this round.
    let subject = std::sync::Arc::new({
        let sha = trigger.sha;
        let baseline = baseline.clone();
        let d = tokio::task::spawn_blocking(move || baseline.descriptor(&sha))
            .await
            .ok()
            .and_then(std::result::Result::ok)
            .flatten();
        ProgramSubject {
            pkg: d.as_ref().and_then(|d| d.pkg.clone()).unwrap_or_default(),
            exe_path: d
                .and_then(|d| d.exe_path)
                .or_else(|| {
                    trigger
                        .ctx
                        .exe_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                })
                .unwrap_or_default(),
        }
    });
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
    let local_fp = pool.local_fingerprint();
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
            &confirm,
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
    //
    // It stands down when confirmation is enabled, and that is not an
    // oversight — it is the whole reason this branch exists:
    //
    //   1. It would skip exactly the peers a quorum needs. Confirmation
    //      counts peers that have NEVER seen the binary, and this filter
    //      removes precisely those from the round. Left on, `peers_unseen`
    //      would sit at ~0 forever and nothing would ever confirm.
    //   2. Its input is unauthenticated. Bloom adverts ride plain
    //      chitchat KV gossip — no envelope, no signature. As a dial-
    //      avoidance hint a forged advert costs one skipped query; as
    //      quorum evidence it would let anyone who can reach the mesh
    //      manufacture CONFIRMED alerts. Confirmation is only ever built
    //      from signed `Answer` envelopes.
    //
    // The cost is a few extra RPCs over already-pooled connections,
    // bounded by `fanout`.
    let mut peers_skipped_by_bloom = 0usize;
    let ranked: Vec<_> = if qa_cfg.quorum > 0 {
        ranked
    } else {
        ranked
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
            .collect()
    };

    let envelope_verifier = Arc::new(Verifier::new(kn.clone(), local_fp));

    let asks = ranked
        .into_iter()
        .map(|(peer, similarity)| {
            let subject = subject.clone();
            let pool = pool.clone();
            let kn = kn.clone();
            let sealer = sealer.clone();
            let envelope_verifier = envelope_verifier.clone();
            let timeout = qa_cfg.timeout;
            async move {
                let outcome = ask_one(
                    AskCtx {
                        pool: &pool,
                        kn,
                        sealer: &sealer,
                        envelope_verifier: &envelope_verifier,
                        tier1,
                        subject: subject.as_ref(),
                        timeout,
                    },
                    &peer,
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
    let asker_platform = bowery_proto::platform_key();
    for (peer, similarity, outcome) in results {
        let (reply, note) = match outcome {
            // A peer that declined is not a peer that said no. Checked
            // before `seen_count`, because a refusing responder leaves
            // the count at its zero default and reading that as "never
            // seen it" is precisely the bug this field exists to close.
            Ok(answer) if !answer.refused.is_empty() => {
                debug!(
                    peer = %peer.fingerprint,
                    reason = %answer.refused,
                    "peer declined to answer a whisper question"
                );
                (PeerReply::Refused(answer.refused.clone()), answer.note)
            }
            // A peer that reports having seen it is believed whatever
            // platform it is on — a positive sighting only needs the
            // hashes to match, and if they match the platforms are
            // compatible by construction. Checked before comparability
            // so a cross-architecture peer that somehow *does* have the
            // binary still counts in the direction that argues benign.
            Ok(answer) if answer.seen_count > 0 => {
                corroborating_peers += 1;
                total_seen_count = total_seen_count.saturating_add(answer.seen_count);
                (
                    PeerReply::Observed(LocalSighting {
                        seen_count: answer.seen_count,
                        first_seen_unix_ms: answer.first_seen_unix_ms,
                        last_seen_unix_ms: answer.last_seen_unix_ms,
                    }),
                    answer.note,
                )
            }
            // "Never seen it" only means something from a peer that
            // could have seen it. On another architecture it is true of
            // every binary in existence, so it is not evidence — and an
            // unknown platform is treated the same way, because a peer
            // too old to say which it is cannot be assumed compatible.
            //
            // Failing this direction costs a confirmation that does not
            // happen. Failing the other way is what confirmed
            // /usr/bin/dash 2/2 on a live fleet.
            // Recognised the program, just not this build. Checked
            // before comparability, because it is an answer a
            // cross-architecture peer *can* give — and the only useful
            // one it has. A peer that says "I have dash too, mine is
            // aarch64" has told us something; demoting it to
            // incomparable would throw away the whole point of asking.
            Ok(answer) if answer.pkg_match || answer.path_match => {
                debug!(
                    peer = %peer.fingerprint,
                    pkg_builds = answer.pkg_builds,
                    by_path_only = !answer.pkg_match,
                    "peer has the same program at a different build"
                );
                (
                    PeerReply::Familiar {
                        pkg_builds: answer.pkg_builds,
                        by_path_only: !answer.pkg_match,
                    },
                    answer.note,
                )
            }
            Ok(answer) if !comparable(&asker_platform, &answer.platform) => {
                debug!(
                    peer = %peer.fingerprint,
                    peer_platform = %answer.platform,
                    asker_platform = %asker_platform,
                    "peer cannot be compared against; not counting its answer as evidence"
                );
                (
                    PeerReply::Incomparable {
                        platform: if answer.platform.is_empty() {
                            "unknown".to_string()
                        } else {
                            answer.platform.clone()
                        },
                    },
                    answer.note,
                )
            }
            Ok(answer) => (
                PeerReply::Observed(LocalSighting {
                    seen_count: 0,
                    first_seen_unix_ms: answer.first_seen_unix_ms,
                    last_seen_unix_ms: answer.last_seen_unix_ms,
                }),
                answer.note,
            ),
            Err(e) => {
                debug!(peer = %peer.fingerprint, error = %e, "whisper ask failed");
                (PeerReply::Silent, String::new())
            }
        };
        peers.push(PeerSighting {
            peer: peer.fingerprint,
            similarity,
            reply,
            note,
        });
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
        &confirm,
    );
}

/// After the whisper round, broadcast the [`WhisperContext`] event,
/// inject neighborhood sightings into the trigger's `AnalysisContext`,
/// and submit to the LLM if the verdict still clears the LLM
/// threshold. Pulled out of `run_round` so both the empty-candidates
/// fast path and the normal path share a single decision point.
/// Turn a round's per-peer answers into a confirmation verdict.
///
/// **Polarity is the whole point and is easy to invert.** A peer that
/// answers `seen_count > 0` is saying "I have this binary too", which
/// argues it's a normal fleet artifact — evidence *against* the alert.
/// Confirmation therefore counts peers that have **never** seen it:
/// a binary none of your role-similar neighbours has is anomalous for
/// this fleet. Both counts are reported so an operator can tell
/// "nobody has this" from "everybody has this" rather than reading one
/// opaque number.
///
/// Non-responders are counted separately and never satisfy a quorum:
/// a peer that timed out told us nothing, and treating silence as
/// agreement would let an offline neighbourhood manufacture
/// confirmations.
pub fn quorum_verdict(peers: &[PeerSighting], quorum: usize) -> AlertConfirmation {
    let mut unseen = 0u32;
    let mut seen = 0u32;
    let mut no_reply = 0u32;
    let mut refused = 0u32;
    let mut incomparable = 0u32;
    let mut familiar = 0u32;
    for p in peers {
        match &p.reply {
            PeerReply::Observed(s) if s.seen_count > 0 => seen += 1,
            PeerReply::Observed(_) => unseen += 1,
            PeerReply::Refused(_) => refused += 1,
            PeerReply::Incomparable { .. } => incomparable += 1,
            PeerReply::Familiar { .. } => familiar += 1,
            PeerReply::Silent => no_reply += 1,
        }
    }
    let quorum_u32 = u32::try_from(quorum).unwrap_or(u32::MAX);
    AlertConfirmation {
        peers_asked: u32::try_from(peers.len()).unwrap_or(u32::MAX),
        peers_unseen: unseen,
        peers_seen: seen,
        peers_no_reply: no_reply,
        peers_refused: refused,
        peers_incomparable: incomparable,
        peers_familiar: familiar,
        quorum: quorum_u32,
        // Two gates, and the second one is the fix.
        //
        // `quorum == 0` disables confirmation outright rather than
        // confirming everything, which is what `>=` alone would do.
        //
        // `unseen` now counts only peers that could actually compare —
        // an incomparable peer never lands in it. That is what stops a
        // cross-architecture fleet confirming every alert it raises:
        // an aarch64 peer asked about an x86-64 binary has never seen
        // it, will never have seen it, and saying so is not evidence.
        confirmed: quorum > 0 && unseen >= quorum_u32,
    }
}

/// Can this peer's "never seen it" mean anything to us?
///
/// Same-architecture is **necessary, not sufficient**: the two aarch64
/// hosts on the reference fleet still share only 5 of ~100 baseline
/// hashes, because a build is pinned by distro, version and compile
/// flags as well as target. This gate removes the answers that are
/// provably meaningless; narrowing the rest is what the descriptor
/// dimensions in DESIGN-FUZZY-CORROBORATION.md §3.1 are for.
///
/// An empty peer platform is a peer built before the field existed. It
/// is treated as incomparable rather than comparable — the safe
/// direction, and one that resolves itself as responders upgrade.
#[must_use]
pub fn comparable(asker: &str, peer: &str) -> bool {
    !asker.is_empty() && !peer.is_empty() && asker == peer
}

/// Human-readable evidence for the confirmed alert's rationale.
fn confirmation_rationale(c: &AlertConfirmation) -> String {
    let mut s = format!(
        "confirmed by the neighbourhood: {}/{} role-similar peers have never seen this binary",
        c.peers_unseen, c.peers_asked
    );
    if c.peers_seen > 0 {
        let _ = write!(s, " ({} have seen it)", c.peers_seen);
    }
    if c.peers_refused > 0 {
        let _ = write!(
            s,
            ", {} could not say (too little observed)",
            c.peers_refused
        );
    }
    if c.peers_familiar > 0 {
        let _ = write!(
            s,
            ", {} have the same program built differently",
            c.peers_familiar
        );
    }
    if c.peers_incomparable > 0 {
        let _ = write!(
            s,
            ", {} could not be compared (different platform)",
            c.peers_incomparable
        );
    }
    if c.peers_no_reply > 0 {
        let _ = write!(s, ", {} did not reply", c.peers_no_reply);
    }
    s
}

/// Why a round produced no verdict, when nothing could be compared.
///
/// Worth logging on its own: a fleet whose members cannot corroborate
/// each other is a standing gap, and the only moment anyone would
/// notice is when they expect a confirmation and none arrives. Saying
/// it every round is how that becomes visible before an incident rather
/// than during one.
fn incomparable_note(c: &AlertConfirmation, platforms: &[String]) -> String {
    let mut s = format!(
        "the neighbourhood could not check this: {}/{} peers answered but run a different \
         platform, so their \"never seen it\" is true of every binary they do not have",
        c.peers_incomparable, c.peers_asked
    );
    if !platforms.is_empty() {
        let _ = write!(s, " (asked: {})", platforms.join(", "));
    }
    s
}

#[allow(clippy::too_many_arguments)]
fn finish_round(
    trigger: WhisperQaTrigger,
    context: WhisperContext,
    pre_suspicion: f32,
    llm_submitter: &Submitter,
    llm_threshold: f32,
    events_tx: &broadcast::Sender<AgentEvent>,
    confirm: &ConfirmSink,
) {
    let mut ctx = trigger.ctx;
    inject_whisper_context(&mut ctx, &context);

    // Emit a superseding alert when the neighbourhood confirms.
    //
    // It has to be a *second* alert rather than an edit: the original is
    // appended before this round even starts, the inbox has no update
    // path, and operators drain it with a monotonic cursor — mutating an
    // already-delivered alert would be invisible to anyone who had
    // already read past it. The LLM refinement path establishes the same
    // supersede-by-episode_id pattern.
    let verdict = quorum_verdict(&context.peers, confirm.quorum);

    // A round where nobody could compare is a standing gap in the mesh,
    // not a quiet result. Logged every time rather than once, because
    // the only moment anyone would otherwise notice is when they expect
    // a confirmation and none comes — which is during an incident.
    let nothing_comparable = verdict.comparable() == 0 && verdict.peers_incomparable > 0;
    if nothing_comparable {
        let platforms: Vec<String> = context
            .peers
            .iter()
            .filter_map(|p| match &p.reply {
                PeerReply::Incomparable { platform } => Some(platform.clone()),
                _ => None,
            })
            .collect();
        warn!(
            episode = %context.episode_id,
            incomparable = verdict.peers_incomparable,
            asked = verdict.peers_asked,
            "{}",
            incomparable_note(&verdict, &platforms)
        );
    }

    // Release, or abandon, anything the response path parked on this
    // round. Both outcomes are reported: an action that was decided and
    // never carried out is exactly what an operator reads the audit
    // trail to find, so "the fleet did not agree" must never look the
    // same as "nothing was ever decided".
    if let Some(tx) = confirm.release_tx.as_ref() {
        let now = std::time::Instant::now();
        let (actions, dropped) = if verdict.confirmed {
            (confirm.pending.release(&context.episode_id, now), None)
        } else {
            (
                confirm.pending.discard(&context.episode_id),
                Some(if nothing_comparable {
                    crate::pending_actions::Dropped::NotComparable
                } else {
                    crate::pending_actions::Dropped::NotCorroborated
                }),
            )
        };
        for action in actions {
            if dropped.is_none() {
                info!(
                    action_id = action.id(),
                    episode = %context.episode_id,
                    peers_unseen = verdict.peers_unseen,
                    "neighbourhood corroborated; releasing held action"
                );
            }
            let _ = tx.try_send(crate::pending_actions::Release {
                episode_id: context.episode_id.clone(),
                action,
                dropped,
            });
        }
    }

    if verdict.confirmed && pre_suspicion >= confirm.alert_threshold {
        let alert = crate::alert_builder::AlertBuilder::new(
            confirm.originator_fp,
            &confirm.backend_label,
            leading_rule_id(&ctx.pre_verdict),
            context.episode_id.clone(),
            pre_suspicion,
            confirmation_rationale(&verdict),
        )
        .subject(
            ctx.exe_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        )
        .exe_sha256_hex(ctx.exe_sha256_hex.clone().unwrap_or_default())
        .confirmation(verdict)
        .build();
        info!(
            episode = %context.episode_id,
            unseen = verdict.peers_unseen,
            seen = verdict.peers_seen,
            quorum = verdict.quorum,
            "alert confirmed by neighbourhood quorum"
        );
        let appended = confirm.inbox.append(alert);
        if appended.stored() {
            let _ = events_tx.send(AgentEvent::AlertEmitted {
                episode_id: context.episode_id.clone(),
                suspicion: pre_suspicion,
            });
        }
    }

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
        let Some(sighting) = peer.reply.observed() else {
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

/// What the asker can say about the binary beyond its hash.
///
/// Empty fields are "not known", never "does not exist": the package
/// index loads asynchronously, and an unpackaged binary legitimately
/// has no package. A responder treats an empty field as no constraint
/// rather than as a negative claim.
#[derive(Debug, Clone, Default)]
pub struct ProgramSubject {
    pub pkg: String,
    pub exe_path: String,
}

/// First 16 hex chars of a fingerprint — short enough for log lines
/// and prompt entries, long enough to disambiguate within a fleet.
fn short_fp(fp: &Fingerprint) -> String {
    let s = fp.to_string();
    s.chars().take(16).collect()
}

/// The per-round context every `ask_one` call shares.
struct AskCtx<'a> {
    pool: &'a PeerConnections,
    kn: Arc<KnownNeighbors>,
    sealer: &'a Sealer,
    envelope_verifier: &'a Verifier<Arc<KnownNeighbors>>,
    tier1: Tier1Fingerprint,
    subject: &'a ProgramSubject,
    timeout: Duration,
}

async fn ask_one(ctx: AskCtx<'_>, peer: &PeerInfo) -> Result<bowery_proto::Answer, AskError> {
    let AskCtx {
        pool,
        kn,
        sealer,
        envelope_verifier,
        tier1,
        subject,
        timeout,
    } = ctx;
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(kn, peer.fingerprint));
    let conn = pool
        .get_or_dial(peer.fingerprint, peer.whisper_addr, dial_verifier)
        .await
        .map_err(AskError::Transport)?;
    let mut question = qa::build_question(tier1, timeout, "");
    // Say what the binary *is*, not only what it hashes to. Without
    // this a peer can only compare hashes, and across architectures
    // that comparison has no information in it.
    question.pkg = subject.pkg.clone();
    question.exe_path = subject.exe_path.clone();
    let answer = match qa::ask(
        &conn,
        sealer,
        envelope_verifier,
        peer.fingerprint,
        question,
        timeout,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            // Transport-shaped errors strongly suggest the cached
            // connection is dead. Drop it so the next round redials.
            if matches!(e, AskError::Transport(_)) {
                pool.invalidate(&peer.fingerprint);
            }
            return Err(e);
        }
    };
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

    /// A young host with plenty of binaries must still abstain.
    ///
    /// This is the production failure, reduced: two agents nineteen
    /// hours old, with 39 and 46 binaries each, honestly answered
    /// "never seen it" about `/usr/bin/pkexec`, `/usr/bin/nice` and
    /// `/usr/bin/flock` — and quorum-confirmed all three as anomalies.
    /// They were not blind, and they were not lying. They were young,
    /// and a count-only bar cannot tell the difference.
    #[test]
    fn a_young_baseline_abstains_however_many_binaries_it_holds() {
        let baseline = Baseline::open_in_memory().unwrap();
        for i in 0..200u32 {
            let mut sha = [0u8; 32];
            sha[0..4].copy_from_slice(&i.to_le_bytes());
            baseline.upsert_binary(&sha).unwrap();
        }
        // Seeded rows are milliseconds old, so this baseline is 200
        // binaries wide and no time deep — exactly the shape that
        // slipped through.
        let bar = CoverageBar {
            min_binaries: 64,
            min_age: Duration::from_hours(72),
        };
        let unrelated = Tier1Fingerprint::derive(b"never-inserted");
        assert!(
            matches!(
                local_knowledge(&baseline, unrelated, bar),
                LocalKnowledge::Insufficient { .. }
            ),
            "breadth without time is not standing to say `never seen it`"
        );

        // Same baseline, age bound lifted: now it may answer.
        let no_age_bar = CoverageBar {
            min_binaries: 64,
            min_age: Duration::ZERO,
        };
        assert!(matches!(
            local_knowledge(&baseline, unrelated, no_age_bar),
            LocalKnowledge::Observed(_)
        ));
    }

    #[test]
    fn a_hit_outranks_both_bounds() {
        // "I have this too" is honest however young you are, and it is
        // the answer that *suppresses* an alert — so refusing to give it
        // would make the guard actively harmful.
        let baseline = Baseline::open_in_memory().unwrap();
        let sha = [7u8; 32];
        baseline.upsert_binary(&sha).unwrap();
        let bar = CoverageBar {
            min_binaries: 10_000,
            min_age: Duration::from_hours(72),
        };
        match local_knowledge(&baseline, Tier1Fingerprint::derive(&sha), bar) {
            LocalKnowledge::Observed(s) => assert_eq!(s.seen_count, 1),
            other @ LocalKnowledge::Insufficient { .. } => {
                panic!("a hit must be reported, got {other:?}")
            }
        }
    }

    #[test]
    fn an_empty_baseline_is_insufficient_under_any_bar() {
        let baseline = Baseline::open_in_memory().unwrap();
        let bar = CoverageBar {
            min_binaries: 1,
            min_age: Duration::ZERO,
        };
        assert!(matches!(
            local_knowledge(&baseline, Tier1Fingerprint::derive(b"x"), bar),
            LocalKnowledge::Insufficient { binaries: 0, .. }
        ));
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
            membership_grant: None,
            log_report: None,
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
                    reply: PeerReply::Observed(LocalSighting {
                        seen_count: 12,
                        first_seen_unix_ms: 1,
                        last_seen_unix_ms: 2,
                    }),
                    note: String::new(),
                },
                PeerSighting {
                    peer: zero_sighting,
                    similarity: 0.80,
                    reply: PeerReply::Observed(LocalSighting::default()), // no observation
                    note: String::new(),
                },
                PeerSighting {
                    peer: no_response,
                    similarity: 0.70,
                    reply: PeerReply::Silent, // didn't reply
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

#[cfg(test)]
mod quorum_tests {
    use super::*;

    fn fp(b: u8) -> Fingerprint {
        Fingerprint::from_bytes([b; 32])
    }

    /// A peer that replied "never seen it" — the evidence that confirms.
    fn unseen(b: u8) -> PeerSighting {
        PeerSighting {
            peer: fp(b),
            similarity: 0.9,
            reply: PeerReply::Observed(LocalSighting::default()),
            note: String::new(),
        }
    }

    /// A peer that replied "I have it too" — argues the binary is common.
    fn seen(b: u8, count: u64) -> PeerSighting {
        PeerSighting {
            peer: fp(b),
            similarity: 0.9,
            reply: PeerReply::Observed(LocalSighting {
                seen_count: count,
                first_seen_unix_ms: 1,
                last_seen_unix_ms: 2,
            }),
            note: String::new(),
        }
    }

    /// Timed out / failed to dial.
    fn silent(b: u8) -> PeerSighting {
        PeerSighting {
            peer: fp(b),
            similarity: 0.9,
            reply: PeerReply::Silent,
            note: String::new(),
        }
    }

    #[test]
    fn confirms_when_enough_peers_have_never_seen_it() {
        let peers = vec![unseen(1), unseen(2), seen(3, 12)];
        let v = quorum_verdict(&peers, 2);
        assert!(v.confirmed, "2 unseen meets a quorum of 2");
        assert_eq!(v.peers_unseen, 2);
        assert_eq!(v.peers_seen, 1);
        assert_eq!(v.peers_no_reply, 0);
        assert_eq!(v.peers_asked, 3);
        assert_eq!(v.quorum, 2);
    }

    #[test]
    fn a_prevalent_binary_is_not_confirmed() {
        // Everyone has it: a normal fleet artifact. This is the case the
        // old `corroborating_peers` count would have called "corroborated",
        // which is exactly backwards for alert confirmation.
        let peers = vec![seen(1, 40), seen(2, 12), seen(3, 7)];
        let v = quorum_verdict(&peers, 2);
        assert!(!v.confirmed, "prevalence must not confirm an alert");
        assert_eq!(v.peers_seen, 3);
        assert_eq!(v.peers_unseen, 0);
    }

    #[test]
    fn silence_never_satisfies_a_quorum() {
        // An offline neighbourhood must not manufacture confirmations.
        let peers = vec![silent(1), silent(2), silent(3), unseen(4)];
        let v = quorum_verdict(&peers, 2);
        assert!(!v.confirmed, "non-responders are not evidence");
        assert_eq!(v.peers_no_reply, 3);
        assert_eq!(v.peers_unseen, 1);
    }

    #[test]
    fn exactly_at_threshold_confirms() {
        let peers = vec![unseen(1), unseen(2)];
        assert!(quorum_verdict(&peers, 2).confirmed);
        assert!(
            !quorum_verdict(&peers, 3).confirmed,
            "one short must not confirm"
        );
    }

    #[test]
    fn quorum_zero_disables_confirmation() {
        // `unseen >= 0` is trivially true, so a naive `>=` would confirm
        // everything — including a round that asked nobody.
        let peers = vec![unseen(1)];
        assert!(!quorum_verdict(&peers, 0).confirmed);
        assert!(!quorum_verdict(&[], 0).confirmed);
    }

    #[test]
    fn empty_round_is_not_confirmed() {
        // No pinned role-similar peers: nothing corroborated anything.
        let v = quorum_verdict(&[], 2);
        assert!(!v.confirmed);
        assert_eq!(v.peers_asked, 0);
    }

    /// A peer on another architecture answering "never seen it".
    fn incomparable(b: u8, platform: &str) -> PeerSighting {
        PeerSighting {
            peer: fp(b),
            similarity: 0.9,
            reply: PeerReply::Incomparable {
                platform: platform.to_string(),
            },
            note: String::new(),
        }
    }

    /// The failure this whole change exists for, as it occurred.
    ///
    /// otter1 (x86-64) asked its two aarch64 neighbours about
    /// `/usr/bin/dash`. Both were healthy, fully observing, and had
    /// never seen that hash — because they never could: their `dash` is
    /// a different build. The mesh reported `CONFIRMED 2/2` on the
    /// system shell, and every other alert besides.
    #[test]
    fn cross_architecture_peers_cannot_confirm_the_system_shell() {
        let peers = vec![
            incomparable(1, "aarch64/linux"),
            incomparable(2, "aarch64/linux"),
        ];
        let v = quorum_verdict(&peers, 2);
        assert!(
            !v.confirmed,
            "two peers that cannot have the binary must not confirm it"
        );
        assert_eq!(v.peers_incomparable, 2);
        assert_eq!(v.peers_unseen, 0, "an incomparable peer is not a denial");
        assert_eq!(v.comparable(), 0, "nothing could be weighed");
    }

    /// A peer that has the program at another build.
    fn familiar(b: u8, builds: u32) -> PeerSighting {
        PeerSighting {
            peer: fp(b),
            similarity: 0.9,
            reply: PeerReply::Familiar {
                pkg_builds: builds,
                by_path_only: false,
            },
            note: String::new(),
        }
    }

    /// The `/usr/bin/dash` case, answered properly rather than merely
    /// declined.
    ///
    /// Slice 1 stopped cross-architecture peers confirming it by
    /// refusing to count them. That is correct and it throws away what
    /// they know: measured on the reference fleet, those same three
    /// hosts share zero binary hashes and seven packages, `dash` among
    /// them. A peer that says "I have dash too, mine is built for
    /// aarch64" has answered the question.
    #[test]
    fn a_peer_with_the_same_package_is_not_a_denial() {
        let peers = vec![familiar(1, 1), familiar(2, 1)];
        let v = quorum_verdict(&peers, 2);
        assert!(
            !v.confirmed,
            "peers that run the same program must not confirm it as unknown"
        );
        assert_eq!(v.peers_familiar, 2);
        assert_eq!(v.peers_unseen, 0, "familiar is not a denial");
        assert_eq!(v.recognised(), 2, "the fleet recognised this program");
        assert_eq!(v.comparable(), 2, "and those answers were weighable");
    }

    /// Familiarity has to break a quorum that denials would otherwise
    /// reach — otherwise it is decorative.
    #[test]
    fn familiarity_denies_a_quorum_the_denials_would_have_met() {
        let peers = vec![unseen(1), familiar(2, 2)];
        let v = quorum_verdict(&peers, 2);
        assert!(
            !v.confirmed,
            "one denial and one recognition is not two denials"
        );
        assert_eq!(v.peers_unseen, 1);
        assert_eq!(v.peers_familiar, 1);
    }

    /// A genuinely unknown binary must still confirm. The point is to
    /// stop confirming fleet-normal software, not to stop confirming.
    #[test]
    fn an_unrecognised_binary_still_confirms() {
        let peers = vec![unseen(1), unseen(2), familiar(3, 1)];
        let v = quorum_verdict(&peers, 2);
        assert!(
            v.confirmed,
            "two peers that know nothing of it is still evidence"
        );
        assert_eq!(v.peers_unseen, 2);
        assert_eq!(v.peers_familiar, 1);
    }

    #[test]
    fn the_rationale_names_the_familiar_peers() {
        let v = quorum_verdict(&[unseen(1), unseen(2), familiar(3, 2)], 2);
        let text = confirmation_rationale(&v);
        assert!(
            text.contains("1 have the same program built differently"),
            "{text}"
        );
    }

    /// Comparable peers still confirm. The gate must remove meaningless
    /// answers, not the mechanism.
    #[test]
    fn same_platform_peers_still_confirm() {
        let peers = vec![unseen(1), unseen(2), incomparable(3, "aarch64/linux")];
        let v = quorum_verdict(&peers, 2);
        assert!(v.confirmed, "two comparable denials are still evidence");
        assert_eq!(v.peers_unseen, 2);
        assert_eq!(v.peers_incomparable, 1);
        assert_eq!(v.comparable(), 2);
    }

    /// An incomparable peer must not be able to make up the numbers.
    #[test]
    fn incomparable_peers_never_count_toward_a_quorum() {
        let peers = vec![unseen(1), incomparable(2, "aarch64/linux")];
        let v = quorum_verdict(&peers, 2);
        assert!(
            !v.confirmed,
            "one real denial plus one incomparable is one denial"
        );
        assert_eq!(v.peers_unseen, 1);
    }

    /// A peer that *has* the binary is believed regardless of platform:
    /// if the hashes match, the platforms were compatible after all, and
    /// the answer argues benign — the safe direction to accept.
    #[test]
    fn a_positive_sighting_counts_whatever_the_platform() {
        let peers = vec![seen(1, 40), seen(2, 12)];
        let v = quorum_verdict(&peers, 2);
        assert!(!v.confirmed);
        assert_eq!(v.peers_seen, 2);
    }

    /// Same architecture is necessary, not sufficient — the two aarch64
    /// hosts on the reference fleet share only 5 of ~100 hashes. This
    /// pins the gate's actual semantics so nobody later reads it as a
    /// claim that same-platform peers are directly comparable.
    #[test]
    fn comparability_is_platform_equality_and_unknown_is_not_comparable() {
        assert!(comparable("x86_64/linux", "x86_64/linux"));
        assert!(!comparable("x86_64/linux", "aarch64/linux"));
        // A peer too old to say. Treated as incomparable, because
        // assuming compatibility is what produced the bug.
        assert!(!comparable("x86_64/linux", ""));
        assert!(!comparable("", "x86_64/linux"));
        assert!(!comparable("", ""));
    }

    #[test]
    fn the_rationale_names_the_platform_gap() {
        let v = quorum_verdict(&[unseen(1), unseen(2), incomparable(3, "aarch64/linux")], 2);
        let text = confirmation_rationale(&v);
        assert!(text.contains("1 could not be compared"), "{text}");

        let nothing = quorum_verdict(
            &[
                incomparable(1, "aarch64/linux"),
                incomparable(2, "aarch64/linux"),
            ],
            2,
        );
        let gap = incomparable_note(&nothing, &["aarch64/linux".into()]);
        assert!(gap.contains("2/2"), "{gap}");
        assert!(gap.contains("aarch64/linux"), "{gap}");
        assert!(
            gap.contains("could not check"),
            "must read as a gap, not a clean result: {gap}"
        );
    }

    #[test]
    fn rationale_states_the_evidence() {
        let v = quorum_verdict(&[unseen(1), unseen(2), seen(3, 5), silent(4)], 2);
        let text = confirmation_rationale(&v);
        assert!(text.contains("2/4"), "{text}");
        assert!(text.contains("1 have seen it"), "{text}");
        assert!(text.contains("1 did not reply"), "{text}");
    }
}
