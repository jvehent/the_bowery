//! Asking the mesh to corroborate something this host saw.
//!
//! # Why this is generic
//!
//! A whole class of detections has the same shape: the host that sees
//! the event cannot tell whether it is benign, and exactly one other
//! party can. An inbound connection is the motivating case — normal
//! from here, normal from there, alarming only if the host it came
//! from has no record of making it — but the shape recurs. Did anyone
//! else get this binary pushed to them? Has any host in the fleet
//! contacted this endpoint before? Did the peer that relayed me this
//! rule actually receive it from an operator?
//!
//! Written per-detection, each of those grows its own message pair, its
//! own timeout handling, its own tally, its own idea of what silence
//! means. The security-relevant parts are the ones that rot: one of
//! them ends up without a rate limit, or counting a timeout as
//! agreement, or letting a peer answer a question it was never asked.
//!
//! So the round is written once and the detections are data:
//!
//! ```text
//!   detector ──raise(Claim)──► engine ──► audience ──► ask each peer
//!                                 │                        │
//!                                 └──── tally ◄────────────┘
//!                                        │
//!                             Rule::confirms(&tally)
//!                                        │
//!                                    Alert (superseding, quorum-backed)
//! ```
//!
//! A [`Claim`] says *what was observed* (`kind` + opaque attributes),
//! *who could know* ([`Audience`]), and *what would make it alarming*
//! ([`Rule`]). Nothing else in this module — or in the wire format, or
//! in the alert path — knows what any particular kind means. Adding a
//! detection is a [`Claim`] builder plus a [`CorroborationResponder`];
//! it touches no shared code.
//!
//! # The two invariants worth stating out loud
//!
//! **Silence is never evidence.** A peer that timed out and a peer that
//! refused both told us nothing, and neither counts toward a quorum.
//! The opposite — treating non-response as agreement — would let an
//! attacker manufacture alerts by taking peers offline, and would make
//! a partitioned mesh alert about everything.
//!
//! **A responder decides what it is willing to be asked.** This module
//! provides no default policy on purpose; see
//! [`CorroborationResponder::respond`].

pub mod file_access;
pub mod net_inbound;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bowery_crypto::Fingerprint;
use bowery_mesh::PeerInfo;
use bowery_proto::{
    AlertConfirmation, Attribute, Corroboration, CorroborationAnswer, CorroborationQuery,
};
use bowery_whisper::Sealer;
use bowery_whisper::corroborate;
use bowery_whisper::known_neighbors::KnownNeighbors;
use bowery_whisper::pool::PeerConnections;
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::{FingerprintResolver, Verifier};
use futures::future::join_all;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::agent::AgentEvent;
use crate::config::CorroborationConfig;
use crate::inbox::AlertInbox;

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// The ATT&CK-registry id for a claim kind.
///
/// Kinds are wire strings (`net.inbound_connect`) chosen for the
/// protocol; rule ids are what the coverage map and the detection
/// counters use (`corroborate.net_inbound_connect`). Written out rather
/// than derived from the kind, so renaming one fails a test instead of
/// quietly producing an id nothing else knows.
#[must_use]
pub fn rule_id_for_kind(kind: &str) -> &'static str {
    if kind == file_access::KIND {
        return "corroborate.file_access";
    }
    // `net_inbound` is also the fallback: every registered kind is
    // covered by the test below, and if one ever is not, a registered id
    // is a better answer than an unregistered or empty one.
    "corroborate.net_inbound_connect"
}

/// Something this host observed that it cannot judge alone.
///
/// Built by a detector, consumed by the engine. The engine treats
/// `kind` and `subject` as opaque — they are meaningful only to the
/// [`CorroborationResponder`] registered for the same `kind` on the
/// other side.
#[derive(Debug, Clone)]
pub struct Claim {
    /// Handler selector on both ends, e.g.
    /// [`net_inbound::KIND`]. `&'static str` because kinds are
    /// compiled-in registrations, not runtime strings.
    pub kind: &'static str,
    /// The observation, as the responder's handler expects it.
    pub subject: Vec<Attribute>,
    /// History window the responder should search, in wall-clock ms.
    /// Wide enough to absorb clock skew between the two hosts; the
    /// responder clamps it regardless of what is asked for.
    pub window_start_unix_ms: u64,
    pub window_end_unix_ms: u64,
    /// Who could possibly know.
    pub audience: Audience,
    /// What would make this alarming.
    pub rule: Rule,
    /// Collapses repeats. A host being scanned generates one claim per
    /// connection; without this it would generate one round per
    /// connection too, and turn a noisy neighbour into a mesh-wide
    /// amplifier. Scoped per `kind`.
    pub dedup_key: String,
    /// One line naming what was observed, in an operator's words. Goes
    /// into the alert rationale ahead of the tally.
    pub summary: String,
    /// Suspicion to stamp on the alert if the rule fires.
    pub suspicion: f32,
    /// An episode this round is allowed to **downgrade**.
    ///
    /// Every kind so far only ever made things worse: the round ran, the
    /// rule fired, an alert appeared. That shape cannot express the most
    /// useful answer a neighbourhood can give — *"we all do that"* —
    /// which is precisely what turns a local finding into fleet-normal
    /// behaviour.
    ///
    /// When set, and the round finds corroboration without confirming,
    /// a superseding alert is appended for this episode with
    /// [`Self::explained_suspicion`]. Superseding rather than editing
    /// because the inbox has no update path and operators pull with a
    /// monotonic cursor: mutating a delivered alert would be invisible
    /// to anyone whose cursor had already passed it.
    ///
    /// `None` for claims that stand alone, which is every counterparty
    /// claim — there is no earlier alert to revise.
    pub supersedes: Option<String>,
    /// Suspicion for the superseding alert when the fleet explains the
    /// finding. Ignored unless [`Self::supersedes`] is set.
    pub explained_suspicion: f32,
}

/// Which peers can speak to a claim.
#[derive(Debug, Clone)]
pub enum Audience {
    /// Whichever mesh peer owns this address.
    ///
    /// For claims about a counterparty: only the host at the other end
    /// of a connection can say whether it made it. Resolved against the
    /// live mesh view, never against anything the observation itself
    /// asserts. A claim whose address belongs to no pinned peer is
    /// dropped — an unmanaged host cannot answer for itself, and there
    /// is nobody else to ask.
    PeerAtAddress(IpAddr),
    /// Up to `limit` pinned peers, for claims with no particular
    /// counterparty — "has anyone else seen this?" rather than "did
    /// *you* do this?".
    Neighbourhood { limit: usize },
}

/// How a round's answers become a verdict.
///
/// Data rather than a closure so it can be unit-tested, logged, and
/// stamped onto the alert as the threshold that was in force at the
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// Peers that must answer [`Corroboration::Denied`] before this is
    /// alert-worthy. `0` disables the claim entirely.
    ///
    /// For a counterparty claim this is necessarily 1 — one host made
    /// the connection and only that host can deny it — which is why
    /// [`Self::corroboration_clears`] and the responder's own
    /// "I can't answer honestly" refusals carry the weight that a
    /// larger quorum would elsewhere.
    pub deny_quorum: usize,
    /// A single corroborating peer clears the claim regardless of how
    /// many denied it.
    ///
    /// True for every kind so far: one host owning up to the connection
    /// explains it, whatever anyone else says. Left explicit because a
    /// future kind could invert it — "someone admits to having pushed
    /// me this rule" can be the alarming answer.
    pub corroboration_clears: bool,
}

impl Rule {
    /// The common case: any peer's denial is the finding, any peer's
    /// corroboration explains it away.
    #[must_use]
    pub const fn deny_alerts() -> Self {
        Self {
            deny_quorum: 1,
            corroboration_clears: true,
        }
    }

    /// Does this tally clear the bar?
    #[must_use]
    pub fn confirms(&self, tally: &Tally) -> bool {
        if self.deny_quorum == 0 {
            return false;
        }
        if self.corroboration_clears && tally.corroborated > 0 {
            return false;
        }
        tally.denied >= self.deny_quorum
    }
}

/// What a round heard back.
///
/// Four buckets, not two. Collapsing `refused` or `no_reply` into
/// `denied` is the mistake this type exists to prevent: an unreachable
/// peer and a peer that declined both told us nothing, and only a peer
/// that actually looked and found nothing is evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub asked: usize,
    /// "Yes, that was me."
    pub corroborated: usize,
    /// "I looked; I have no record." The finding.
    pub denied: usize,
    /// "I won't say" / "I can't say honestly."
    pub refused: usize,
    /// Timed out, failed to dial, or answered unintelligibly.
    pub no_reply: usize,
}

impl Tally {
    fn record(&mut self, outcome: Corroboration) {
        match outcome {
            Corroboration::Corroborated => self.corroborated += 1,
            Corroboration::Denied => self.denied += 1,
            Corroboration::Refused => self.refused += 1,
            // An outcome this build doesn't recognise decodes to
            // `Unspecified`, which means the peer told us nothing —
            // never that it denied anything.
            Corroboration::Unspecified => self.no_reply += 1,
        }
    }

    /// Render as the operator-facing confirmation block carried on the
    /// alert.
    ///
    /// The field names read as "seen"/"unseen" because the same block
    /// serves the binary-prevalence round; the mapping is exact rather
    /// than approximate. A peer with a record of the observation is
    /// `peers_seen`, a peer without one is `peers_unseen`, and
    /// `peers_unseen` is what confirms in both rounds.
    #[must_use]
    pub fn to_confirmation(self, rule: Rule, confirmed: bool) -> AlertConfirmation {
        AlertConfirmation {
            peers_asked: u32::try_from(self.asked).unwrap_or(u32::MAX),
            peers_unseen: u32::try_from(self.denied).unwrap_or(u32::MAX),
            peers_seen: u32::try_from(self.corroborated).unwrap_or(u32::MAX),
            peers_no_reply: u32::try_from(self.no_reply).unwrap_or(u32::MAX),
            peers_refused: u32::try_from(self.refused).unwrap_or(u32::MAX),
            quorum: u32::try_from(rule.deny_quorum).unwrap_or(u32::MAX),
            confirmed,
        }
    }
}

/// A completed round, broadcast on [`AgentEvent::CorroborationRound`]
/// whether or not it alerted. Tests and dashboards read it; nothing
/// branches on it.
#[derive(Debug, Clone)]
pub struct RoundOutcome {
    pub kind: &'static str,
    pub query_id: String,
    pub dedup_key: String,
    pub tally: Tally,
    pub confirmed: bool,
    /// Evidence from the first corroborating peer, if any. For a
    /// connection this is the process attribution the observing host
    /// could never derive on its own — which is worth surfacing even
    /// though it means *no* alert.
    pub evidence: Vec<Attribute>,
}

// ---------------------------------------------------------------------------
// Claim intake
// ---------------------------------------------------------------------------

/// Where detectors hand claims to the engine.
///
/// Shed-not-block, like the event-log writer: connect events arrive far
/// faster than execs, and a detector that blocked on a full queue would
/// stall the whole pipeline behind the mesh. A dropped claim costs one
/// unasked question; a stalled pipeline costs every subsequent
/// detection.
#[derive(Clone)]
pub struct ClaimSink {
    tx: mpsc::Sender<Claim>,
    shed: Arc<AtomicU64>,
}

impl std::fmt::Debug for ClaimSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimSink")
            .field("shed", &self.shed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl ClaimSink {
    /// Offer a claim. Never blocks; returns `false` if it was shed.
    pub fn raise(&self, claim: Claim) -> bool {
        match self.tx.try_send(claim) {
            Ok(()) => true,
            Err(e) => {
                let n = self.shed.fetch_add(1, Ordering::Relaxed) + 1;
                // Every drop, not every Nth: this counter is how an
                // operator finds out the mesh is the bottleneck.
                debug!(shed_total = n, error = %e, "corroboration claim shed");
                false
            }
        }
    }

    /// Claims dropped because the queue was full.
    #[must_use]
    pub fn shed_count(&self) -> u64 {
        self.shed.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Responder side
// ---------------------------------------------------------------------------

/// Answers one `kind` of corroboration query.
///
/// # The policy contract
///
/// **An implementation MUST constrain what it is willing to be asked
/// to facts the asker already knows.** This is not advice. A handler
/// that answers any well-formed query turns the mesh into an
/// enumeration primitive against its own hosts: ask a peer about a
/// thousand addresses, and its answers map its outbound traffic. The
/// connection handler's rule is that the address named must be the
/// *asker's own*, as this host's view of the mesh reports it — so a
/// peer only ever learns about traffic it was already party to, having
/// observed the other half itself.
///
/// Refuse — do not stay silent — when a query is out of policy, when the
/// local data needed to answer honestly is missing, and above all when
/// the honest answer is "I would not have recorded that either way".
/// [`Corroboration::Denied`] is an accusation; only send it after
/// actually looking.
#[async_trait]
pub trait CorroborationResponder: Send + Sync {
    /// Kind this handler answers. Must match a [`Claim::kind`]
    /// somewhere, or nothing will ever ask.
    fn kind(&self) -> &'static str;

    /// Apply policy, consult local state, answer.
    ///
    /// Shape checks (deadline, bounds, non-empty identifiers) already
    /// ran in [`ResponderRegistry::dispatch`]; this is policy and
    /// lookup only. Build the return value with
    /// [`corroborate::answer`] or [`corroborate::refuse`] so the
    /// `query_id` and `kind` echo correctly.
    async fn respond(&self, asker: Fingerprint, query: &CorroborationQuery) -> CorroborationAnswer;
}

/// Kind → handler. Populated at startup; immutable afterwards.
#[derive(Default)]
pub struct ResponderRegistry {
    by_kind: HashMap<&'static str, Arc<dyn CorroborationResponder>>,
}

impl std::fmt::Debug for ResponderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut kinds: Vec<&str> = self.by_kind.keys().copied().collect();
        kinds.sort_unstable();
        f.debug_struct("ResponderRegistry")
            .field("kinds", &kinds)
            .finish()
    }
}

impl ResponderRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler. A second registration for the same kind
    /// replaces the first — a startup-time programming error, so it
    /// logs loudly rather than silently picking a winner.
    #[must_use]
    pub fn with(mut self, responder: Arc<dyn CorroborationResponder>) -> Self {
        let kind = responder.kind();
        if self.by_kind.insert(kind, responder).is_some() {
            warn!(
                kind,
                "duplicate corroboration responder registration; replacing"
            );
        }
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_kind.is_empty()
    }

    /// Shape-check, route, and answer.
    ///
    /// `None` means "send nothing": the query expired before it reached
    /// us, so the asker has already given up and counted us as silent.
    /// Every other rejection gets an explicit refusal, because
    /// "unreachable" and "won't answer that" should never look the same
    /// to an operator.
    pub async fn dispatch(
        &self,
        asker: Fingerprint,
        query: &CorroborationQuery,
    ) -> Option<CorroborationAnswer> {
        if let Err(e) = corroborate::check_query(query) {
            if matches!(e, corroborate::QueryRejection::Expired { .. }) {
                debug!(asker = %asker, kind = %query.kind, "dropping expired corroboration query");
                return None;
            }
            warn!(asker = %asker, kind = %query.kind, error = %e, "malformed corroboration query");
            return Some(corroborate::refuse(query, e.to_string()));
        }
        let Some(handler) = self.by_kind.get(query.kind.as_str()) else {
            // Not an error: a newer peer asking about a kind this build
            // doesn't implement is exactly what a rolling upgrade looks
            // like, and the refusal tells it so.
            debug!(asker = %asker, kind = %query.kind, "no responder for corroboration kind");
            return Some(corroborate::refuse(query, "unknown kind"));
        };
        Some(handler.respond(asker, query).await)
    }
}

// ---------------------------------------------------------------------------
// Asker side — the round engine
// ---------------------------------------------------------------------------

/// Everything a round needs that isn't the claim itself.
#[derive(Clone)]
#[allow(missing_debug_implementations)] // holds a QUIC pool and a Sealer
pub struct CorroborationContext {
    pub pool: PeerConnections,
    pub known_neighbors: Arc<KnownNeighbors>,
    pub sealer: Arc<Sealer>,
    pub peers: watch::Receiver<Vec<PeerInfo>>,
    pub inbox: Arc<AlertInbox>,
    pub originator_fp: Fingerprint,
    pub backend_label: String,
    pub config: CorroborationConfig,
    pub events_tx: broadcast::Sender<AgentEvent>,
}

/// Start the engine. Returns the sink detectors publish to, plus the
/// task handle.
pub fn spawn(
    ctx: CorroborationContext,
    mut shutdown_rx: watch::Receiver<bool>,
) -> (ClaimSink, JoinHandle<()>) {
    let (tx, mut claims) = mpsc::channel::<Claim>(ctx.config.queue_capacity.max(1));
    let sink = ClaimSink {
        tx,
        shed: Arc::new(AtomicU64::new(0)),
    };

    let task = tokio::spawn(async move {
        // Shed-not-queue, same discipline as whisper Q&A rounds: a
        // backlog would keep dialling peers long after the burst that
        // caused it is over.
        let permits = Arc::new(tokio::sync::Semaphore::new(
            ctx.config.max_concurrent_rounds.max(1),
        ));
        let seen = Arc::new(crate::seen::RecentlySeen::new(
            ctx.config.dedup_window,
            ctx.config.dedup_entries,
        ));

        let local_fp = ctx.pool.local_fingerprint();

        loop {
            tokio::select! {
                claim = claims.recv() => {
                    let Some(claim) = claim else { break };

                    // Audience first, dedup second, and the order is
                    // load-bearing in both directions.
                    //
                    // *Cost*: resolution is a scan over the mesh view —
                    // fleet-sized, no allocation — while the dedup set
                    // sweeps up to `dedup_entries` on every insert. On a
                    // host with a public port, nearly every inbound
                    // connection is from something that is not a mesh
                    // peer, so the cheap high-selectivity filter has to
                    // run first or a scan makes us walk a 4096-entry map
                    // per packet.
                    //
                    // *Meaning*: a claim nobody can answer was never
                    // asked, so it must not burn a dedup slot. Otherwise
                    // a connection arriving seconds before its source
                    // finishes enrolling would be suppressed for the
                    // whole dedup window.
                    let targets = {
                        let kn = ctx.known_neighbors.clone();
                        let is_pinned = move |fp: &Fingerprint| kn.resolve(fp).is_some();
                        let peers = ctx.peers.borrow();
                        resolve_audience(&claim.audience, &peers, local_fp, &is_pinned)
                    };
                    if targets.is_empty() {
                        debug!(
                            kind = claim.kind,
                            dedup_key = %claim.dedup_key,
                            "no pinned peer can speak to this claim; dropping"
                        );
                        continue;
                    }

                    if !seen.check_and_record(claim.kind, &claim.dedup_key) {
                        debug!(
                            kind = claim.kind,
                            dedup_key = %claim.dedup_key,
                            "corroboration claim already asked recently; skipping"
                        );
                        continue;
                    }
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        warn!(
                            kind = claim.kind,
                            max = ctx.config.max_concurrent_rounds,
                            "corroboration rounds at capacity; shedding claim"
                        );
                        continue;
                    };
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        run_round(&ctx, claim, targets).await;
                        drop(permit);
                    });
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    });

    (sink, task)
}

/// Resolve an audience against the live mesh view.
///
/// Two filters apply to every variant and neither is optional: never
/// ourselves, and only peers we have pinned. Pinning is what makes the
/// answer worth anything — an unpinned peer's reply carries no
/// verifiable identity, and we could not dial it under a pinned
/// certificate anyway.
fn resolve_audience(
    audience: &Audience,
    peers: &[PeerInfo],
    local_fp: Fingerprint,
    is_pinned: &dyn Fn(&Fingerprint) -> bool,
) -> Vec<PeerInfo> {
    let eligible = peers
        .iter()
        .filter(|p| p.fingerprint != local_fp && is_pinned(&p.fingerprint));
    match audience {
        Audience::PeerAtAddress(addr) => eligible
            .filter(|p| p.whisper_addr.ip() == *addr)
            .cloned()
            .collect(),
        Audience::Neighbourhood { limit } => eligible.take(*limit).cloned().collect(),
    }
}

/// Ask `targets` about `claim` and act on what they say.
///
/// `targets` is resolved by the caller, before the dedup check, so a
/// claim that reaches here is one somebody can actually answer.
#[allow(clippy::too_many_lines)] // one linear round; splitting hides the ordering
async fn run_round(ctx: &CorroborationContext, claim: Claim, targets: Vec<PeerInfo>) {
    let local_fp = ctx.pool.local_fingerprint();
    let query = corroborate::build_query(
        claim.kind,
        claim.subject.clone(),
        claim.window_start_unix_ms,
        claim.window_end_unix_ms,
        ctx.config.timeout,
    );
    let query_id = query.query_id.clone();
    debug!(
        kind = claim.kind,
        query_id = %query_id,
        peers = targets.len(),
        "corroboration round starting"
    );

    let verifier = Arc::new(Verifier::new(ctx.known_neighbors.clone(), local_fp));
    // Each result is tagged with the peer it came from. A round that
    // only reports counts is unreadable the moment it has more than one
    // target: "refused=1" over a three-peer mesh leaves you diffing
    // event logs to work out who, and *which* peer is silent or
    // refusing is usually the finding — a peer that refuses everything
    // is a peer whose sensor isn't recording.
    let asks = targets.into_iter().map(|peer| {
        let query = query.clone();
        let verifier = verifier.clone();
        async move {
            let fp = peer.fingerprint;
            (fp, ask_one(ctx, &verifier, &peer, query).await)
        }
    });
    let results = join_all(asks).await;

    let mut tally = Tally {
        asked: results.len(),
        ..Tally::default()
    };
    let mut evidence = Vec::new();
    for (peer, outcome) in results {
        let Some(answer) = outcome else {
            debug!(
                kind = claim.kind,
                query_id = %query_id,
                peer = %peer,
                "peer did not answer a corroboration query"
            );
            tally.no_reply += 1;
            continue;
        };

        let corroboration = answer.corroboration();
        if corroboration == Corroboration::Corroborated && evidence.is_empty() {
            evidence.clone_from(&answer.evidence);
            info!(
                kind = claim.kind,
                query_id = %query_id,
                peer = %peer,
                evidence = %render_attributes(&answer.evidence),
                "peer accounted for this observation"
            );
        }
        if corroboration == Corroboration::Refused {
            debug!(
                kind = claim.kind,
                query_id = %query_id,
                peer = %peer,
                reason = %answer.reason,
                "peer refused a corroboration query"
            );
        }
        tally.record(corroboration);
    }

    let confirmed = claim.rule.confirms(&tally);
    info!(
        kind = claim.kind,
        query_id = %query_id,
        asked = tally.asked,
        corroborated = tally.corroborated,
        denied = tally.denied,
        refused = tally.refused,
        no_reply = tally.no_reply,
        confirmed,
        "corroboration round complete"
    );

    if confirmed {
        let confirmation = tally.to_confirmation(claim.rule, true);
        let episode_id = format!("corr-{}-{}", claim.kind, query_id);
        let alert = crate::alert_builder::AlertBuilder::new(
            ctx.originator_fp,
            &ctx.backend_label,
            rule_id_for_kind(claim.kind),
            episode_id.clone(),
            claim.suspicion,
            rationale(&claim, &tally),
        )
        .confirmation(confirmation)
        .build();
        warn!(
            kind = claim.kind,
            episode = %episode_id,
            summary = %claim.summary,
            "corroboration failed — raising alert"
        );
        ctx.inbox.append(alert);
        let _ = ctx.events_tx.send(AgentEvent::AlertEmitted {
            episode_id,
            suspicion: claim.suspicion,
        });
    }
    // The neighbourhood explained it: same behaviour, other hosts.
    //
    // This is the answer that removes work rather than creating it, and
    // it only means anything when peers actually spoke. Corroboration
    // from zero peers is silence, and silence must never downgrade a
    // finding — that is the same rule that stops a blind peer confirming
    // an alert, applied in the other direction.
    if !confirmed
        && tally.corroborated > 0
        && let Some(episode_id) = claim.supersedes.clone()
    {
        let alert = crate::alert_builder::AlertBuilder::new(
            ctx.originator_fp,
            &ctx.backend_label,
            rule_id_for_kind(claim.kind),
            episode_id.clone(),
            claim.explained_suspicion,
            format!(
                "{} — but {} of {} peers asked report the same, so this is how this \
                 fleet behaves rather than something this host is doing alone",
                claim.summary, tally.corroborated, tally.asked
            ),
        )
        .confirmation(tally.to_confirmation(claim.rule, false))
        .build();
        info!(
            kind = claim.kind,
            episode = %episode_id,
            corroborated = tally.corroborated,
            "the neighbourhood explains this finding; superseding with a lower score"
        );
        ctx.inbox.append(alert);
        let _ = ctx.events_tx.send(AgentEvent::AlertEmitted {
            episode_id,
            suspicion: claim.explained_suspicion,
        });
    }

    // The corroborating peer's evidence is logged where it arrives,
    // named with the peer that supplied it — see the ask loop above.

    let _ = ctx
        .events_tx
        .send(AgentEvent::CorroborationRound(Box::new(RoundOutcome {
            kind: claim.kind,
            query_id,
            dedup_key: claim.dedup_key,
            tally,
            confirmed,
            evidence,
        })));
}

/// One peer, one question. `None` means "told us nothing" — the caller
/// must not distinguish a dial failure from a timeout, because neither
/// is evidence.
async fn ask_one(
    ctx: &CorroborationContext,
    verifier: &Verifier<Arc<KnownNeighbors>>,
    peer: &PeerInfo,
    query: CorroborationQuery,
) -> Option<CorroborationAnswer> {
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(
        ctx.known_neighbors.clone(),
        peer.fingerprint,
    ));
    let conn = match ctx
        .pool
        .get_or_dial(peer.fingerprint, peer.whisper_addr, dial_verifier)
        .await
    {
        Ok(conn) => conn,
        Err(e) => {
            debug!(peer = %peer.fingerprint, error = %e, "corroboration dial failed");
            return None;
        }
    };
    match corroborate::ask(
        &conn,
        &ctx.sealer,
        verifier,
        peer.fingerprint,
        query,
        ctx.config.timeout,
    )
    .await
    {
        Ok(answer) => Some(answer),
        Err(e) => {
            // A transport error strongly suggests the pooled connection
            // is dead; drop it so the next round redials.
            if matches!(e, corroborate::AskError::Transport(_)) {
                ctx.pool.invalidate(&peer.fingerprint);
            }
            debug!(peer = %peer.fingerprint, error = %e, "corroboration ask failed");
            None
        }
    }
}

/// Alert rationale: what was seen, then what the mesh said about it.
fn rationale(claim: &Claim, tally: &Tally) -> String {
    use std::fmt::Write as _;
    let mut s = claim.summary.clone();
    let _ = write!(
        s,
        " — {} of {} peer{} asked have no record of it",
        tally.denied,
        tally.asked,
        if tally.asked == 1 { "" } else { "s" }
    );
    if tally.refused > 0 {
        let _ = write!(s, ", {} declined to answer", tally.refused);
    }
    if tally.no_reply > 0 {
        let _ = write!(s, ", {} did not reply", tally.no_reply);
    }
    s
}

fn render_attributes(attrs: &[Attribute]) -> String {
    attrs
        .iter()
        .map(|a| format!("{}={}", a.key, a.value))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Wall-clock now in ms. Matches the encoding used on the wire.
#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Centre a search window on `at`, `half_width` either side, saturating
/// at the epoch.
#[must_use]
pub fn window_around(at: SystemTime, half_width: Duration) -> (u64, u64) {
    let at_ms = at
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or_else(now_unix_ms);
    let half = u64::try_from(half_width.as_millis()).unwrap_or(0);
    (at_ms.saturating_sub(half), at_ms.saturating_add(half))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every claim kind must map to an id the registry knows.
    ///
    /// Kinds are wire strings and rule ids are registry strings, and
    /// nothing but this connects them — a renamed kind would otherwise
    /// produce alerts attributed to a rule that does not exist.
    #[test]
    fn every_claim_kind_maps_to_a_registered_rule() {
        let known = bowery_analysis::attack::all_rule_ids();
        for kind in [net_inbound::KIND, file_access::KIND] {
            let id = rule_id_for_kind(kind);
            assert!(
                known.contains(&id),
                "{kind} maps to {id}, which is not registered"
            );
        }
        // And the two must not collapse onto one id.
        assert_ne!(
            rule_id_for_kind(net_inbound::KIND),
            rule_id_for_kind(file_access::KIND)
        );
    }

    fn tally(corroborated: usize, denied: usize, refused: usize, no_reply: usize) -> Tally {
        Tally {
            asked: corroborated + denied + refused + no_reply,
            corroborated,
            denied,
            refused,
            no_reply,
        }
    }

    #[test]
    fn a_denial_confirms() {
        assert!(Rule::deny_alerts().confirms(&tally(0, 1, 0, 0)));
    }

    #[test]
    fn corroboration_clears_even_alongside_a_denial() {
        // Somebody owned up to it. Whatever else the round heard, the
        // connection is explained.
        assert!(!Rule::deny_alerts().confirms(&tally(1, 1, 0, 0)));
    }

    #[test]
    fn a_refusal_is_not_a_denial() {
        // The single most important line in this file. "I won't answer"
        // and "I have no record" mean opposite things, and a handler
        // that cannot answer honestly refuses — so folding refusals in
        // would make every freshly-installed agent accuse its peers.
        assert!(!Rule::deny_alerts().confirms(&tally(0, 0, 3, 0)));
    }

    #[test]
    fn silence_is_not_a_denial() {
        // Otherwise taking peers offline manufactures alerts, and a
        // partitioned mesh alerts about everything it sees.
        assert!(!Rule::deny_alerts().confirms(&tally(0, 0, 0, 3)));
    }

    #[test]
    fn an_unrecognised_outcome_counts_as_no_reply() {
        let mut t = Tally::default();
        t.record(Corroboration::Unspecified);
        assert_eq!(t.no_reply, 1);
        assert_eq!(t.denied, 0);
    }

    #[test]
    fn quorum_zero_disables_the_claim() {
        let rule = Rule {
            deny_quorum: 0,
            corroboration_clears: true,
        };
        // `denied >= 0` is trivially true, so a naive `>=` would confirm
        // every round — including one that asked nobody.
        assert!(!rule.confirms(&tally(0, 5, 0, 0)));
        assert!(!rule.confirms(&Tally::default()));
    }

    #[test]
    fn a_larger_quorum_needs_more_denials() {
        let rule = Rule {
            deny_quorum: 2,
            corroboration_clears: true,
        };
        assert!(!rule.confirms(&tally(0, 1, 0, 0)));
        assert!(rule.confirms(&tally(0, 2, 0, 0)));
    }

    #[test]
    fn confirmation_maps_each_bucket_to_its_own_column() {
        let c = tally(1, 2, 3, 4).to_confirmation(Rule::deny_alerts(), true);
        assert_eq!(c.peers_seen, 1, "corroborated → seen");
        assert_eq!(c.peers_unseen, 2, "denied → unseen (what confirms)");
        assert_eq!(c.peers_refused, 3);
        assert_eq!(c.peers_no_reply, 4);
        assert_eq!(c.peers_asked, 10);
        assert_eq!(c.quorum, 1);
        assert!(c.confirmed);
    }

    // -- audience resolution --------------------------------------------

    fn peer(fp_byte: u8, addr: &str) -> PeerInfo {
        PeerInfo {
            fingerprint: Fingerprint::from_bytes([fp_byte; 32]),
            verifying_key: ed25519_dalek::VerifyingKey::from_bytes(&[
                0x3a, 0x4f, 0x77, 0x16, 0xd5, 0x3e, 0x9c, 0x6c, 0x76, 0x4b, 0x44, 0x49, 0x12, 0x91,
                0xfa, 0x9d, 0x6f, 0x1b, 0xea, 0x4d, 0x21, 0x66, 0xa2, 0xa6, 0xc5, 0xe4, 0xa1, 0xab,
                0x6b, 0x06, 0xc9, 0x07,
            ])
            .expect("valid pubkey"),
            whisper_addr: addr.parse().unwrap(),
            agent_version: "0.0.1".into(),
            role_vector: None,
            bloom_advert: None,
            membership_grant: None,
            log_report: None,
        }
    }

    fn all_pinned(_: &Fingerprint) -> bool {
        true
    }

    #[test]
    fn peer_at_address_matches_on_the_mesh_view_not_the_claim() {
        let peers = vec![peer(1, "10.0.0.1:9902"), peer(2, "10.0.0.2:9902")];
        let local = Fingerprint::from_bytes([9; 32]);
        let got = resolve_audience(
            &Audience::PeerAtAddress("10.0.0.2".parse().unwrap()),
            &peers,
            local,
            &all_pinned,
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].fingerprint, Fingerprint::from_bytes([2; 32]));
    }

    #[test]
    fn an_address_owned_by_nobody_resolves_to_nobody() {
        let peers = vec![peer(1, "10.0.0.1:9902")];
        let got = resolve_audience(
            &Audience::PeerAtAddress("192.0.2.7".parse().unwrap()),
            &peers,
            Fingerprint::from_bytes([9; 32]),
            &all_pinned,
        );
        assert!(got.is_empty(), "an unmanaged host cannot answer for itself");
    }

    #[test]
    fn we_never_ask_ourselves() {
        let local = Fingerprint::from_bytes([1; 32]);
        let peers = vec![peer(1, "10.0.0.1:9902")];
        let got = resolve_audience(
            &Audience::PeerAtAddress("10.0.0.1".parse().unwrap()),
            &peers,
            local,
            &all_pinned,
        );
        assert!(got.is_empty());
    }

    #[test]
    fn unpinned_peers_are_never_asked() {
        // An unpinned peer's answer carries no verifiable identity, and
        // we could not dial it under a pinned certificate anyway.
        let peers = vec![peer(1, "10.0.0.1:9902")];
        let got = resolve_audience(
            &Audience::PeerAtAddress("10.0.0.1".parse().unwrap()),
            &peers,
            Fingerprint::from_bytes([9; 32]),
            &|_| false,
        );
        assert!(got.is_empty());
    }

    #[test]
    fn an_unanswerable_claim_does_not_consume_its_dedup_slot() {
        // The engine resolves the audience before touching the dedup
        // set, so a claim nobody can answer leaves no trace. Two things
        // depend on it: a scan from non-peer addresses must not make us
        // sweep the dedup map per packet, and a connection that arrives
        // seconds before its source finishes enrolling must not be
        // suppressed for the whole dedup window.
        let seen = crate::seen::RecentlySeen::new(Duration::from_mins(5), 4096);
        let peers = vec![peer(1, "10.0.0.1:9902")];
        let local = Fingerprint::from_bytes([9; 32]);

        // Round one: the source isn't a mesh peer yet.
        let unanswerable = resolve_audience(
            &Audience::PeerAtAddress("10.0.0.2".parse().unwrap()),
            &peers,
            local,
            &all_pinned,
        );
        assert!(unanswerable.is_empty());
        // ...so the engine `continue`s here, and never records.

        // Round two: same claim, and now the peer is present.
        let peers = vec![peer(1, "10.0.0.1:9902"), peer(2, "10.0.0.2:9902")];
        let answerable = resolve_audience(
            &Audience::PeerAtAddress("10.0.0.2".parse().unwrap()),
            &peers,
            local,
            &all_pinned,
        );
        assert_eq!(answerable.len(), 1);
        assert!(
            seen.check_and_record("net.inbound_connect", "10.0.0.2->22"),
            "the first answerable ask must not be suppressed by an earlier unanswerable one"
        );
    }

    #[test]
    fn neighbourhood_is_capped_by_its_limit() {
        let peers: Vec<PeerInfo> = (1..=5).map(|i| peer(i, "10.0.0.1:9902")).collect();
        let got = resolve_audience(
            &Audience::Neighbourhood { limit: 3 },
            &peers,
            Fingerprint::from_bytes([9; 32]),
            &all_pinned,
        );
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn rationale_states_what_was_seen_and_what_the_mesh_said() {
        let claim = Claim {
            supersedes: None,
            explained_suspicion: 0.0,
            kind: "test.kind",
            subject: Vec::new(),
            window_start_unix_ms: 0,
            window_end_unix_ms: 1,
            audience: Audience::Neighbourhood { limit: 1 },
            rule: Rule::deny_alerts(),
            dedup_key: "k".into(),
            summary: "something happened".into(),
            suspicion: 0.8,
        };
        let text = rationale(&claim, &tally(0, 1, 1, 1));
        assert!(text.starts_with("something happened"), "{text}");
        assert!(text.contains("1 of 3 peers asked have no record"), "{text}");
        assert!(text.contains("1 declined"), "{text}");
        assert!(text.contains("1 did not reply"), "{text}");
    }

    #[test]
    fn window_around_is_symmetric_and_saturates_at_the_epoch() {
        let (start, end) = window_around(
            UNIX_EPOCH + Duration::from_secs(1_000),
            Duration::from_mins(1),
        );
        assert_eq!(start, 940_000);
        assert_eq!(end, 1_060_000);
        let (start, _) = window_around(UNIX_EPOCH, Duration::from_mins(1));
        assert_eq!(start, 0, "no underflow into a far-future window");
    }
}
