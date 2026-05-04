//! The supervised agent runtime: TOFU store + QUIC endpoint + mesh +
//! pin-task + accept-task + heartbeat-task, with watch-channel-driven
//! shutdown.

use std::sync::Arc;
use std::time::Duration;

use bowery_analysis::{Analyzer, Episode, RoleFeatures, RoleVector, Verdict};
use bowery_baseline::{Baseline, UpsertOutcome};
use bowery_crypto::{Fingerprint, Identity};
use bowery_events::source::EventSource;
use bowery_events::{Event, ProcessExec, enrich};
use bowery_llm::{
    AnalysisContext, InferenceOutcome, InferenceQueue, LlmAnalyzer, LlmVerdict, MockLlmAnalyzer,
    MockMode, QueueConfig, ShedReason, Submitter,
};
use bowery_mesh::{KEY_ROLE_VECTOR, Mesh, MeshConfig, PeerInfo};
use bowery_proto::{Body, WhisperPayload};
use bowery_whisper::fingerprint::{TIER1_LEN, Tier1Fingerprint};
use bowery_whisper::known_neighbors::{KnownNeighbors, PinOutcome};
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::{BoweryConnection, BoweryEndpoint};
use bowery_whisper::{FingerprintResolver, Sealer, Verifier};

use crate::whisper_qa::{
    WhisperContext, WhisperQaTrigger, aggregate_local_sighting, spawn_whisper_qa_task,
};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::Config;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const EVENT_CHANNEL_CAPACITY: usize = 4096;

/// Observable events emitted by a running agent.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    PeerPinned(Fingerprint),
    EnvelopeReceived {
        sender: Fingerprint,
        nonce: u64,
    },
    HeartbeatSent {
        peer: Fingerprint,
    },
    /// A binary observed via [`Event::ProcessExec`] was upserted into the
    /// baseline. `outcome` distinguishes "first time seen" from "increment".
    BinaryRecorded {
        sha: [u8; 32],
        outcome: UpsertOutcome,
    },
    /// Analyzer produced a verdict for an episode. Phase 3.
    EpisodeAnalyzed {
        verdict: Verdict,
    },
    /// Role vector recomputed and published via mesh KV. Phase 3.
    RoleVectorPublished {
        binary_count: u64,
    },
    /// LLM analyser refined the pre-filter verdict for an episode. Phase 4.
    LlmVerdict {
        episode_id: String,
        verdict: LlmVerdict,
    },
    /// LLM backend rejected or shed a request (queue full, deadline,
    /// inference error). Useful for ops to size the queue.
    LlmShed {
        episode_id: String,
        reason: LlmShedReason,
    },
    /// Phase 5: a whisper Q&A round completed for a verdict whose
    /// suspicion crossed `whisper.qa.threshold`. The bundle carries
    /// per-peer responses (or non-responses) so observers / dashboards
    /// can surface neighborhood corroboration.
    WhisperContextReady(WhisperContext),
}

/// Why an LLM request didn't produce a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmShedReason {
    QueueFull,
    Deadline,
    Failed(String),
}

impl From<ShedReason> for LlmShedReason {
    fn from(value: ShedReason) -> Self {
        match value {
            ShedReason::QueueFull => Self::QueueFull,
            ShedReason::Deadline => Self::Deadline,
        }
    }
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("config: {0}")]
    Config(String),

    #[error("known_neighbors: {0}")]
    KnownNeighbors(#[from] bowery_whisper::known_neighbors::Error),

    #[error("transport: {0}")]
    Transport(#[from] bowery_whisper::transport::Error),

    #[error("mesh: {0}")]
    Mesh(#[from] bowery_mesh::Error),

    #[error("baseline: {0}")]
    Baseline(#[from] bowery_baseline::Error),
}

/// A running Bowery agent. Drop or [`Agent::shutdown`] to stop it.
pub struct Agent {
    fingerprint: Fingerprint,
    known_neighbors: Arc<KnownNeighbors>,
    baseline: Arc<Baseline>,
    analyzer: Arc<Analyzer>,
    endpoint: BoweryEndpoint,
    mesh: Arc<Mesh>,
    shutdown_tx: watch::Sender<bool>,
    events_tx: broadcast::Sender<AgentEvent>,
    pin_task: JoinHandle<()>,
    accept_task: JoinHandle<()>,
    heartbeat_task: JoinHandle<()>,
    pipeline_task: JoinHandle<()>,
    role_publisher_task: JoinHandle<()>,
    llm_outcomes_task: JoinHandle<()>,
    whisper_qa_task: JoinHandle<()>,
    llm_queue: Option<InferenceQueue>,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("fingerprint", &self.fingerprint)
            .field("pinned", &self.known_neighbors.count())
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// Start with the default LLM backend (Phase 4 ships the mock; the
    /// real Qwen3-0.6B backend lands in Phase 4b).
    pub async fn start(
        config: Config,
        identity: Arc<Identity>,
        event_source: Box<dyn EventSource>,
    ) -> Result<Self, AgentError> {
        let llm: Arc<dyn LlmAnalyzer> = Arc::new(MockLlmAnalyzer::new(MockMode::Echo));
        Self::start_with_llm(config, identity, event_source, llm).await
    }

    /// Start with a caller-provided LLM analyzer. Tests use this to
    /// install [`MockLlmAnalyzer`] in `Quiet` / `Failing` modes.
    #[allow(clippy::too_many_lines)] // top-level wiring; sub-tasks already factored out
    pub async fn start_with_llm(
        config: Config,
        identity: Arc<Identity>,
        event_source: Box<dyn EventSource>,
        llm: Arc<dyn LlmAnalyzer>,
    ) -> Result<Self, AgentError> {
        let fingerprint = identity.fingerprint();
        info!(fingerprint = %fingerprint, "starting agent");

        let known_neighbors = Arc::new(KnownNeighbors::open(
            &config.known_neighbors.path,
            config.known_neighbors.bootstrap_window,
        )?);

        let baseline = Arc::new(open_baseline(&config.baseline.path)?);
        let analyzer = Arc::new(Analyzer::with_default_rules(baseline.clone()));

        let accept_verifier = Arc::new(PinnedCertVerifier::new(known_neighbors.clone()));
        let endpoint =
            BoweryEndpoint::bind(identity.clone(), accept_verifier, config.whisper.bind_addr)?;
        let sealer = Arc::new(Sealer::new(identity.clone()));
        let whisper_addr = endpoint
            .local_addr()
            .map_err(|e| AgentError::Config(format!("local_addr: {e}")))?;

        let mut mesh_cfg = MeshConfig::new(
            identity.clone(),
            config.mesh.listen_addr,
            whisper_addr,
            AGENT_VERSION,
        );
        if let Some(advertise) = config.mesh.advertise_addr {
            mesh_cfg.advertise_addr = advertise;
        } else {
            mesh_cfg.advertise_addr = config.mesh.listen_addr;
        }
        mesh_cfg.seed_nodes = config.mesh.seeds.clone();
        if let Some(cluster) = config.mesh.cluster_id.as_ref() {
            mesh_cfg.cluster_id = cluster.clone();
        }
        let mesh = Arc::new(Mesh::start(mesh_cfg).await?);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (events_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);

        let pin_task = spawn_pin_task(
            mesh.peers_watcher(),
            known_neighbors.clone(),
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        let accept_task = spawn_accept_task(
            endpoint.clone(),
            known_neighbors.clone(),
            sealer.clone(),
            baseline.clone(),
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        let heartbeat_task = spawn_heartbeat_task(
            endpoint.clone(),
            mesh.peers_watcher(),
            known_neighbors.clone(),
            sealer.clone(),
            config.heartbeat.interval,
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        // LLM queue + outcomes bridge
        let queue_cfg = QueueConfig {
            capacity: config.llm.queue_capacity,
            per_request_deadline: config.llm.request_deadline,
        };
        let (llm_out_tx, llm_out_rx) = mpsc::channel::<InferenceOutcome>(queue_cfg.capacity);
        let llm_queue = InferenceQueue::start(llm.clone(), &queue_cfg, llm_out_tx);
        let llm_submitter = llm_queue.submitter();
        let llm_outcomes_task =
            spawn_llm_outcomes_task(llm_out_rx, events_tx.clone(), shutdown_rx.clone());

        let (whisper_qa_tx, whisper_qa_rx) = mpsc::channel::<WhisperQaTrigger>(64);
        let whisper_qa_task = spawn_whisper_qa_task(
            whisper_qa_rx,
            endpoint.clone(),
            known_neighbors.clone(),
            sealer.clone(),
            mesh.clone(),
            baseline.clone(),
            config.whisper.qa.clone(),
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        let pipeline_task = spawn_pipeline_task(
            event_source.start(),
            baseline.clone(),
            analyzer.clone(),
            llm_submitter,
            config.llm.invocation_threshold,
            config.whisper.qa.threshold,
            whisper_qa_tx,
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        let role_publisher_task = spawn_role_publisher_task(
            mesh.clone(),
            baseline.clone(),
            config.role.publish_interval,
            events_tx.clone(),
            shutdown_rx,
        );

        info!(
            fingerprint = %fingerprint,
            mesh = %config.mesh.listen_addr,
            whisper = %whisper_addr,
            baseline = %config.baseline.path.display(),
            llm_backend = llm.name(),
            "agent ready"
        );

        Ok(Self {
            fingerprint,
            known_neighbors,
            baseline,
            analyzer,
            endpoint,
            mesh,
            shutdown_tx,
            events_tx,
            pin_task,
            accept_task,
            heartbeat_task,
            pipeline_task,
            role_publisher_task,
            llm_outcomes_task,
            whisper_qa_task,
            llm_queue: Some(llm_queue),
        })
    }

    /// Subscribe to runtime events. Useful for tests and observability.
    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.events_tx.subscribe()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn whisper_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn pinned_count(&self) -> usize {
        self.known_neighbors.count()
    }

    /// Snapshot of the baseline binary count. Useful for tests and ops.
    pub fn baseline_binary_count(&self) -> Result<u64, AgentError> {
        Ok(self.baseline.count_binaries()?)
    }

    pub fn baseline(&self) -> &Arc<Baseline> {
        &self.baseline
    }

    pub fn analyzer(&self) -> &Arc<Analyzer> {
        &self.analyzer
    }

    pub fn mesh(&self) -> &Arc<Mesh> {
        &self.mesh
    }

    pub async fn shutdown(mut self) -> Result<(), AgentError> {
        let _ = self.shutdown_tx.send(true);
        self.endpoint.close().await;
        let _ = self.pin_task.await;
        let _ = self.accept_task.await;
        let _ = self.heartbeat_task.await;
        let _ = self.pipeline_task.await;
        let _ = self.role_publisher_task.await;
        let _ = self.llm_outcomes_task.await;
        let _ = self.whisper_qa_task.await;
        if let Some(llm_queue) = self.llm_queue.take() {
            llm_queue.shutdown().await;
        }
        if let Ok(mesh) = Arc::try_unwrap(self.mesh) {
            mesh.shutdown().await?;
        }
        // Otherwise the mesh is still referenced (e.g. by an inflight task)
        // and will drop when those references do; chitchat handles its own
        // cleanup on Drop.
        Ok(())
    }
}

fn open_baseline(path: &std::path::Path) -> bowery_baseline::Result<Baseline> {
    if path.as_os_str() == ":memory:" {
        Baseline::open_in_memory()
    } else {
        Baseline::open(path)
    }
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

fn spawn_pin_task(
    mut peers_watcher: watch::Receiver<Vec<PeerInfo>>,
    kn: Arc<KnownNeighbors>,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let snapshot: Vec<PeerInfo> = peers_watcher.borrow().clone();
            for peer in snapshot {
                match kn.try_pin(&peer.verifying_key) {
                    Ok(PinOutcome::NewlyPinned) => {
                        info!(peer = %peer.fingerprint, "pinned new neighbor");
                        let _ = events_tx.send(AgentEvent::PeerPinned(peer.fingerprint));
                    }
                    Ok(PinOutcome::AlreadyPinned) => {}
                    Ok(PinOutcome::BootstrapClosed) => {
                        debug!(peer = %peer.fingerprint, "ignoring unknown peer (bootstrap closed)");
                    }
                    Err(e) => warn!(error = %e, "pin failed"),
                }
            }
            tokio::select! {
                changed = peers_watcher.changed() => {
                    if changed.is_err() { break; }
                }
                _ = shutdown_rx.changed() => break,
            }
            if *shutdown_rx.borrow() {
                break;
            }
        }
    })
}

fn spawn_accept_task(
    endpoint: BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: Arc<Sealer>,
    baseline: Arc<Baseline>,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let envelope_verifier = Arc::new(Verifier::new(kn));
        loop {
            tokio::select! {
                accept = endpoint.accept() => {
                    let Some(connection_result) = accept else { break };
                    match connection_result {
                        Ok(conn) => {
                            let verifier = envelope_verifier.clone();
                            let sealer = sealer.clone();
                            let baseline = baseline.clone();
                            let events = events_tx.clone();
                            tokio::spawn(handle_connection(conn, verifier, sealer, baseline, events));
                        }
                        Err(e) => warn!(error = %e, "accept failed"),
                    }
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

async fn handle_connection(
    conn: BoweryConnection,
    verifier: Arc<Verifier<Arc<KnownNeighbors>>>,
    sealer: Arc<Sealer>,
    baseline: Arc<Baseline>,
    events_tx: broadcast::Sender<AgentEvent>,
) {
    while let Ok(bytes) = conn.recv_envelope().await {
        match verifier.open(&bytes) {
            Ok(env) => {
                info!(sender = %env.sender, nonce = env.nonce, "received envelope");
                let _ = events_tx.send(AgentEvent::EnvelopeReceived {
                    sender: env.sender,
                    nonce: env.nonce,
                });
                if let Some(Body::Question(q)) = env.payload.body
                    && let Err(e) =
                        respond_to_question(&conn, &sealer, &baseline, q).await
                {
                    warn!(sender = %env.sender, error = %e, "whisper Q&A response failed");
                }
                // After responding, the asker will close the connection.
                // Subsequent recv_envelope will return an error and we'll
                // exit the loop.
            }
            Err(e) => warn!(error = %e, "envelope verification failed"),
        }
    }
}

async fn respond_to_question(
    conn: &BoweryConnection,
    sealer: &Sealer,
    baseline: &Arc<Baseline>,
    question: bowery_proto::Question,
) -> Result<(), bowery_whisper::transport::Error> {
    if question.tier1_fp.len() != TIER1_LEN {
        warn!(
            len = question.tier1_fp.len(),
            "received question with invalid tier1_fp length; ignoring"
        );
        return Ok(());
    }
    let mut fp_bytes = [0u8; TIER1_LEN];
    fp_bytes.copy_from_slice(&question.tier1_fp);
    let target = Tier1Fingerprint::from_bytes(fp_bytes);

    let baseline = baseline.clone();
    let sighting = match tokio::task::spawn_blocking(move || {
        aggregate_local_sighting(&baseline, target)
    })
    .await
    {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "baseline scan task panicked");
            return Ok(());
        }
    };

    let answer = bowery_proto::Answer {
        episode_id: question.episode_id,
        tier1_fp: question.tier1_fp,
        seen_count: sighting.seen_count,
        first_seen_unix_ms: sighting.first_seen_unix_ms,
        last_seen_unix_ms: sighting.last_seen_unix_ms,
        note: String::new(),
    };
    let outbound = sealer.seal(&WhisperPayload::answer(answer));
    conn.send_envelope(&outbound).await
}

fn spawn_heartbeat_task(
    endpoint: BoweryEndpoint,
    peers_watcher: watch::Receiver<Vec<PeerInfo>>,
    kn: Arc<KnownNeighbors>,
    sealer: Arc<Sealer>,
    interval: Duration,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let peers: Vec<PeerInfo> = peers_watcher.borrow().clone();
                    for peer in peers {
                        if kn.resolve(&peer.fingerprint).is_none() {
                            continue;
                        }
                        let endpoint = endpoint.clone();
                        let kn_for_dial = kn.clone();
                        let sealer = sealer.clone();
                        let events = events_tx.clone();
                        tokio::spawn(async move {
                            send_heartbeat(endpoint, kn_for_dial, sealer, peer, events).await;
                        });
                    }
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

async fn send_heartbeat(
    endpoint: BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: Arc<Sealer>,
    peer: PeerInfo,
    events_tx: broadcast::Sender<AgentEvent>,
) {
    let bytes = sealer.seal(&WhisperPayload::heartbeat(AGENT_VERSION));
    let verifier = Arc::new(PinnedCertVerifier::expecting(kn, peer.fingerprint));
    match endpoint.dial(verifier, peer.whisper_addr).await {
        Ok(conn) => match conn.send_envelope(&bytes).await {
            Ok(()) => {
                debug!(peer = %peer.fingerprint, "heartbeat sent");
                let _ = events_tx.send(AgentEvent::HeartbeatSent {
                    peer: peer.fingerprint,
                });
            }
            Err(e) => warn!(peer = %peer.fingerprint, error = %e, "heartbeat send failed"),
        },
        Err(e) => debug!(peer = %peer.fingerprint, error = %e, "heartbeat dial failed"),
    }
}

// ---------------------------------------------------------------------------
// Event pipeline
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spawn_pipeline_task(
    mut events: mpsc::Receiver<Event>,
    baseline: Arc<Baseline>,
    analyzer: Arc<Analyzer>,
    llm_submitter: Submitter,
    llm_threshold: f32,
    whisper_threshold: f32,
    whisper_qa_tx: mpsc::Sender<WhisperQaTrigger>,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = events.recv() => {
                    let Some(event) = event else { break };
                    process_event(
                        &baseline,
                        &analyzer,
                        &llm_submitter,
                        llm_threshold,
                        whisper_threshold,
                        &whisper_qa_tx,
                        &events_tx,
                        event,
                    ).await;
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn process_event(
    baseline: &Arc<Baseline>,
    analyzer: &Arc<Analyzer>,
    llm_submitter: &Submitter,
    llm_threshold: f32,
    whisper_threshold: f32,
    whisper_qa_tx: &mpsc::Sender<WhisperQaTrigger>,
    events_tx: &broadcast::Sender<AgentEvent>,
    event: Event,
) {
    // Phase 2 only persists ProcessExec; other variants are silently
    // consumed until later phases wire in network/file/exit handlers.
    if let Event::ProcessExec(exec) = event {
        process_exec(
            baseline,
            analyzer,
            llm_submitter,
            llm_threshold,
            whisper_threshold,
            whisper_qa_tx,
            events_tx,
            exec,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_exec(
    baseline: &Arc<Baseline>,
    analyzer: &Arc<Analyzer>,
    llm_submitter: &Submitter,
    llm_threshold: f32,
    whisper_threshold: f32,
    whisper_qa_tx: &mpsc::Sender<WhisperQaTrigger>,
    events_tx: &broadcast::Sender<AgentEvent>,
    exec: ProcessExec,
) {
    let Some(exe_path) = exec.exe_path.clone() else {
        debug!(
            pid = exec.pid,
            "exec event missing exe_path; skipping baseline"
        );
        return;
    };

    let sha = match tokio::task::spawn_blocking(move || enrich::sha256_file(&exe_path)).await {
        Ok(Ok(sha)) => sha,
        Ok(Err(e)) => {
            debug!(pid = exec.pid, error = %e, "exe sha256 failed");
            return;
        }
        Err(e) => {
            warn!(pid = exec.pid, error = %e, "sha256 task panicked");
            return;
        }
    };

    // Phase 3 ordering: build the episode and analyze BEFORE upserting,
    // so the baseline scorer sees the prior history (count = 0 for a
    // first-time exec, not 1).
    let episode = Episode::from_exec(exec.clone());
    let analyzer_for_call = analyzer.clone();
    let episode_for_call = episode.clone();
    let verdict = match tokio::task::spawn_blocking(move || {
        analyzer_for_call.analyze(&episode_for_call, &sha)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(pid = exec.pid, error = %e, "analyzer task panicked");
            return;
        }
    };

    let baseline_for_write = baseline.clone();
    let outcome =
        match tokio::task::spawn_blocking(move || baseline_for_write.upsert_binary(&sha)).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                warn!(pid = exec.pid, error = %e, "baseline upsert failed");
                return;
            }
            Err(e) => {
                warn!(pid = exec.pid, error = %e, "baseline task panicked");
                return;
            }
        };

    let _ = events_tx.send(AgentEvent::BinaryRecorded { sha, outcome });

    // Phase 4: gate LLM invocation on aggregated suspicion.
    if verdict.suspicion >= llm_threshold {
        let mut ctx = AnalysisContext::new(verdict.clone()).with_exe_sha256(&sha);
        if let Some(p) = exec.exe_path.as_ref() {
            ctx = ctx.with_exe_path(p.clone());
        }
        if !exec.args.is_empty() {
            ctx = ctx.with_args(exec.args.clone());
        }
        let episode_id = verdict.episode_id.clone();
        if let Err(reason) = llm_submitter.submit(ctx) {
            let _ = events_tx.send(AgentEvent::LlmShed {
                episode_id,
                reason: reason.into(),
            });
        }
    }

    // Phase 5: gate whisper Q&A on a (typically higher) suspicion
    // threshold. The Q&A task consumes the trigger asynchronously so
    // the pipeline doesn't block on neighborhood RTTs.
    if verdict.suspicion >= whisper_threshold
        && let Err(e) = whisper_qa_tx
            .send(WhisperQaTrigger {
                episode_id: verdict.episode_id.clone(),
                sha,
                suspicion: verdict.suspicion,
            })
            .await
    {
        debug!(error = %e, "whisper Q&A trigger channel closed");
    }

    let _ = events_tx.send(AgentEvent::EpisodeAnalyzed { verdict });
}

// ---------------------------------------------------------------------------
// LLM outcomes bridge
// ---------------------------------------------------------------------------

fn spawn_llm_outcomes_task(
    mut outcomes: mpsc::Receiver<InferenceOutcome>,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                outcome = outcomes.recv() => {
                    let Some(outcome) = outcome else { break };
                    handle_llm_outcome(&events_tx, outcome);
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

fn handle_llm_outcome(events_tx: &broadcast::Sender<AgentEvent>, outcome: InferenceOutcome) {
    match outcome {
        InferenceOutcome::Verdict {
            episode_id,
            verdict,
        } => {
            let _ = events_tx.send(AgentEvent::LlmVerdict {
                episode_id,
                verdict: *verdict,
            });
        }
        InferenceOutcome::Failed { episode_id, error } => {
            warn!(episode = %episode_id, error = %error, "LLM analyzer failed");
            let _ = events_tx.send(AgentEvent::LlmShed {
                episode_id,
                reason: LlmShedReason::Failed(error),
            });
        }
        InferenceOutcome::Shed { episode_id, reason } => {
            let _ = events_tx.send(AgentEvent::LlmShed {
                episode_id,
                reason: reason.into(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Role-vector publisher
// ---------------------------------------------------------------------------

fn spawn_role_publisher_task(
    mesh: Arc<Mesh>,
    baseline: Arc<Baseline>,
    interval: Duration,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    publish_role_vector(&mesh, &baseline, &events_tx).await;
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

async fn publish_role_vector(
    mesh: &Arc<Mesh>,
    baseline: &Arc<Baseline>,
    events_tx: &broadcast::Sender<AgentEvent>,
) {
    let baseline_for_call = baseline.clone();
    let features =
        match tokio::task::spawn_blocking(move || RoleFeatures::from_baseline(&baseline_for_call))
            .await
        {
            Ok(Ok(features)) => features,
            Ok(Err(e)) => {
                warn!(error = %e, "role features computation failed");
                return;
            }
            Err(e) => {
                warn!(error = %e, "role features task panicked");
                return;
            }
        };
    let vector = RoleVector::from_features(&features);
    let encoded = vector.to_base64();
    let binary_count = features.binary_count;
    if let Err(e) = mesh.set_state(KEY_ROLE_VECTOR, encoded).await {
        warn!(error = %e, "failed to publish role vector to mesh");
        return;
    }
    debug!(binary_count, "published role vector");
    let _ = events_tx.send(AgentEvent::RoleVectorPublished { binary_count });
}
