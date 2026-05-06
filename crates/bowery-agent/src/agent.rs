//! The supervised agent runtime: TOFU store + QUIC endpoint + mesh +
//! pin-task + accept-task + heartbeat-task, with watch-channel-driven
//! shutdown.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
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
use bowery_proto::{Alert, Alerts, Body, Subscribe, WhisperPayload};
use bowery_response::{
    ActionOutcome, AuditSink, JsonlFileSink, NoopEngine, NoopSink, ProcessKillEngine,
    ResponseEngine, ResponsePolicy, action, audit,
};

use crate::config::ResponseEngineKind;
use bowery_whisper::fingerprint::{TIER1_LEN, Tier1Fingerprint};
use bowery_whisper::known_neighbors::{KnownNeighbors, PinOutcome};
use bowery_whisper::pool::PeerConnections;
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::{BoweryConnection, BoweryEndpoint};
use bowery_whisper::{CompositeResolver, FingerprintResolver, Sealer, StaticResolver, Verifier};
use ed25519_dalek::VerifyingKey;

use crate::bloom_publisher;
use crate::inbox::{AlertInbox, current_unix_ms};
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
    /// Phase 6: an alert was appended to the operator inbox. Lets
    /// tests + dashboards observe inbox writes without polling.
    AlertEmitted {
        episode_id: String,
        suspicion: f32,
    },
    /// Phase 6: a subscriber drained the inbox. `delivered` is the
    /// number of alerts handed back; useful for ops to confirm the
    /// roaming-operator path works.
    AlertsDelivered {
        operator: Fingerprint,
        delivered: usize,
        cursor_unix_ms: u64,
    },
    /// Phase 5 (advert publisher): the local bloom advert was rebuilt
    /// from the baseline and pushed to mesh KV. `inserted_count` is
    /// the number of distinct binaries that contributed; useful for
    /// dashboards to confirm the publisher is making progress.
    BloomAdvertPublished {
        epoch: u64,
        bit_count: usize,
        k: u8,
        inserted_count: u64,
    },
    /// Phase 7: the response engine accepted (or suppressed) an
    /// action that the LLM verdict suggested. The variant fires
    /// regardless of whether the engine actually did anything — the
    /// outcome carries the discriminator. Operators tail this to
    /// audit autonomous enforcement.
    ActionAttempted {
        episode_id: String,
        action_id: &'static str,
        outcome: ActionOutcome,
    },
    /// Phase 6b: an operator command was received, dispatched, and a
    /// result was sealed back. `kind` is the command-body
    /// discriminator (`"sql"`, `<empty>`, etc.) for ops dashboards.
    OperatorCommandHandled {
        operator: Fingerprint,
        request_id: String,
        kind: &'static str,
    },
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
    bloom_publisher_task: JoinHandle<()>,
    llm_outcomes_task: JoinHandle<()>,
    whisper_qa_task: JoinHandle<()>,
    llm_queue: Option<InferenceQueue>,
    #[allow(dead_code)] // exposed via inbox() accessor; held alive at agent scope
    inbox: Arc<AlertInbox>,
    /// Phase-7 response engine. `Arc<dyn ResponseEngine>` so tests can
    /// substitute a recording engine without going through the
    /// agent's normal config-loading path. Held alive at agent scope.
    #[allow(dead_code)]
    response_engine: Arc<dyn ResponseEngine>,
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

        let known_neighbors = Arc::new(
            KnownNeighbors::open(
                &config.known_neighbors.path,
                config.known_neighbors.bootstrap_window,
            )?
            .with_max_pinned(config.known_neighbors.max_pinned_peers),
        );

        let operators = Arc::new(load_operators(&config.operators.pubkeys_b64)?);
        // Composite resolver: pinned peer agents AND configured
        // operators. Both can dial us — peers for heartbeats / Q&A,
        // operators for `Subscribe` against the alert inbox.
        let resolver = Arc::new(CompositeResolver::new(
            known_neighbors.clone(),
            operators.clone(),
        ));

        let baseline = Arc::new(open_baseline(&config.baseline.path)?);
        let analyzer = Arc::new(Analyzer::with_default_rules(baseline.clone()));
        let inbox = Arc::new(AlertInbox::new(
            config.inbox.capacity,
            config.inbox.retention,
        ));

        // Phase 7: load the response policy + instantiate an engine.
        // Today the only engine variant is NoopEngine (observe-only);
        // turning on enforcement is a future commit's job, not a
        // config knob. The startup log line makes the engine name
        // explicit so operators can audit which hosts are observe-only
        // vs. live.
        let response_policy = match config.response.policy_path.as_deref() {
            Some(path) => ResponsePolicy::load(path).map_err(|e| {
                AgentError::Config(format!(
                    "loading response policy from {}: {e}",
                    path.display()
                ))
            })?,
            None => ResponsePolicy::default(),
        };
        for typo in response_policy.warnings() {
            warn!(
                action_id = %typo,
                "[response] allowed_actions entry doesn't match any known action id; ignored"
            );
        }
        let response_engine: Arc<dyn ResponseEngine> = match config.response.engine {
            ResponseEngineKind::Noop => Arc::new(NoopEngine::new(response_policy)),
            ResponseEngineKind::ProcessKill => Arc::new(ProcessKillEngine::new(response_policy)),
            ResponseEngineKind::BpfLsm => {
                // Find the BPF object via the same search path as the
                // event source — env var, /usr/local/lib/bowery/, the
                // in-tree dev build dir. Operators turning on
                // `engine = bpf-lsm` are explicit about wanting it,
                // so a missing BPF object or insufficient
                // capabilities is a startup error rather than a
                // silent fall-back to noop.
                let obj_path = bowery_ebpf_loader::BpfEventSource::from_default_locations()
                    .map_err(|e| {
                        AgentError::Config(format!(
                            "[response] engine = bpf-lsm but the BPF object isn't loadable: {e}"
                        ))
                    })?
                    .obj_path()
                    .to_path_buf();
                let blocker = bowery_ebpf_loader::BpfBlocker::load(&obj_path).map_err(|e| {
                    AgentError::Config(format!(
                        "loading BPF blocker from {}: {e}",
                        obj_path.display()
                    ))
                })?;
                Arc::new(crate::response_bpf::BpfLsmEngine::new(
                    response_policy,
                    blocker,
                ))
            }
        };
        info!(
            engine = response_engine.name(),
            "response engine initialised"
        );
        info!(
            deny_list = ?response_engine.policy().effective_block_exec_deny_list(),
            "block_exec deny-list (defaults + operator additions)"
        );

        // Phase-7 slice 4: signed audit log. Off by default — operators
        // who turn it on get one fsynced JSON line per action attempt,
        // signed with the agent's identity key.
        let audit_sink: Arc<dyn AuditSink> = match config.response.audit_log_path.as_ref() {
            Some(path) => match JsonlFileSink::open(path).await {
                Ok(sink) => {
                    info!(path = %path.display(), "audit log opened");
                    Arc::new(sink)
                }
                Err(e) => {
                    return Err(AgentError::Config(format!(
                        "opening audit log {}: {e}",
                        path.display()
                    )));
                }
            },
            None => Arc::new(NoopSink),
        };

        let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
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

        let relay_ctx = Arc::new(RelayContext {
            endpoint: endpoint.clone(),
            known_neighbors: known_neighbors.clone(),
            peers_watcher: mesh.peers_watcher(),
        });
        // Bonus tables (Phase-9 slice 8) — Bowery-internal state
        // exposed as SQL views. Each table holds an Arc to its
        // data source and re-reads on every query.
        //
        // Phase-9 final-4 + final-5: substitute the agent's
        // configured ProcessesTable (with optional cmdline) for
        // the default-default-cmdline-off instance, and apply the
        // configured concurrency cap.
        let sql_engine = bowery_sql::Sql::new()
            .with_concurrency_cap(config.sql.max_concurrent_queries)
            .override_default_table("processes")
            .with_extra_table(Arc::new(bowery_tables::processes::ProcessesTable::new(
                config.sql.expose_cmdline,
            )))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryPeersTable::new(
                known_neighbors.clone(),
            )))
            .with_extra_table(Arc::new(
                crate::sql_tables::BoweryBaselineBinariesTable::new(baseline.clone()),
            ))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryAlertsTable::new(
                inbox.clone(),
            )))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryAuditTable::new(
                config.response.audit_log_path.clone(),
            )));
        let op_router = Arc::new(OperatorCommandRouter {
            sql: Some(Arc::new(sql_engine)),
            relay: Some(relay_ctx),
            fanout_rate_limit: Arc::new(FanoutRateLimit::new()),
            max_timeout: config.sql.max_timeout,
        });

        // Persistent outbound-connection pool — Phase-10 slices 1+2.
        // Heartbeat (and, in later slices, Q&A and operator fanout)
        // borrow connections from here instead of dialing every time.
        // The inbound handler runs `handle_connection` on every fresh
        // outbound connection so peers can initiate streams *back*
        // through the same QUIC socket without us needing them to
        // dial our listener.
        let peer_connections = {
            let envelope_verifier = Arc::new(Verifier::new(resolver.clone(), sealer.fingerprint()));
            let operators_for_handler = operators.clone();
            let sealer_for_handler = sealer.clone();
            let baseline_for_handler = baseline.clone();
            let inbox_for_handler = inbox.clone();
            let op_router_for_handler = op_router.clone();
            let events_for_handler = events_tx.clone();
            let handler: bowery_whisper::pool::InboundHandler = Arc::new(move |peer_fp, conn| {
                let verifier = envelope_verifier.clone();
                let operators = operators_for_handler.clone();
                let sealer = sealer_for_handler.clone();
                let baseline = baseline_for_handler.clone();
                let inbox = inbox_for_handler.clone();
                let op_router = op_router_for_handler.clone();
                let events = events_for_handler.clone();
                debug!(
                    peer = %peer_fp,
                    conn_id = conn.stable_id(),
                    "spawning inbound handler on outbound-pooled connection"
                );
                tokio::spawn(handle_connection(
                    conn, verifier, operators, sealer, baseline, inbox, op_router, events,
                ));
            });
            PeerConnections::with_handler(endpoint.clone(), handler)
        };

        let accept_task = spawn_accept_task(
            endpoint.clone(),
            resolver.clone(),
            operators.clone(),
            sealer.clone(),
            baseline.clone(),
            inbox.clone(),
            op_router,
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        let heartbeat_task = spawn_heartbeat_task(
            peer_connections.clone(),
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
        let llm_outcomes_task = spawn_llm_outcomes_task(
            llm_out_rx,
            inbox.clone(),
            fingerprint,
            config.alerts.threshold,
            llm.name().to_string(),
            response_engine.clone(),
            audit_sink.clone(),
            identity.clone(),
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        let (whisper_qa_tx, whisper_qa_rx) = mpsc::channel::<WhisperQaTrigger>(64);
        let whisper_qa_task = spawn_whisper_qa_task(
            whisper_qa_rx,
            endpoint.clone(),
            known_neighbors.clone(),
            sealer.clone(),
            mesh.clone(),
            baseline.clone(),
            config.whisper.qa.clone(),
            llm_submitter.clone(),
            config.llm.invocation_threshold,
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
            inbox.clone(),
            fingerprint,
            config.alerts.threshold,
            llm.name().to_string(),
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        let role_publisher_task = spawn_role_publisher_task(
            mesh.clone(),
            baseline.clone(),
            config.role.publish_interval,
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        let bloom_publisher_task = bloom_publisher::spawn_bloom_publisher_task(
            mesh.clone(),
            baseline.clone(),
            config.bloom.clone(),
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
            inbox,
            shutdown_tx,
            events_tx,
            pin_task,
            accept_task,
            heartbeat_task,
            pipeline_task,
            role_publisher_task,
            bloom_publisher_task,
            llm_outcomes_task,
            whisper_qa_task,
            llm_queue: Some(llm_queue),
            response_engine,
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

    pub fn inbox(&self) -> &Arc<AlertInbox> {
        &self.inbox
    }

    /// Pin store accessor — used by integration tests to seed peers
    /// without going through the chitchat-bootstrap path.
    pub fn known_neighbors(&self) -> &Arc<KnownNeighbors> {
        &self.known_neighbors
    }

    pub async fn shutdown(mut self) -> Result<(), AgentError> {
        let _ = self.shutdown_tx.send(true);
        self.endpoint.close().await;
        let _ = self.pin_task.await;
        let _ = self.accept_task.await;
        let _ = self.heartbeat_task.await;
        let _ = self.pipeline_task.await;
        let _ = self.role_publisher_task.await;
        let _ = self.bloom_publisher_task.await;
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

/// Build a [`StaticResolver`] from a list of base64-encoded operator
/// verifying keys. Empty list ⇒ empty resolver (operators are
/// optional; an agent with no configured operators simply ignores any
/// `Subscribe` request).
fn load_operators(pubkeys_b64: &[String]) -> Result<StaticResolver, AgentError> {
    let mut resolver = StaticResolver::new();
    for s in pubkeys_b64 {
        let bytes = BASE64
            .decode(s.as_bytes())
            .map_err(|e| AgentError::Config(format!("operator key `{s}` not base64: {e}")))?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            AgentError::Config(format!(
                "operator key `{s}` has {} bytes; expected 32",
                bytes.len()
            ))
        })?;
        let vk = VerifyingKey::from_bytes(&arr).map_err(|e| {
            AgentError::Config(format!(
                "operator key `{s}` is not a valid Ed25519 key: {e}"
            ))
        })?;
        resolver.insert(vk);
    }
    Ok(resolver)
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
                    Ok(PinOutcome::AtCapacity) => {
                        warn!(
                            peer = %peer.fingerprint,
                            "pin store at capacity; ignoring new neighbor (possible mesh flood)"
                        );
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

type ResolverArc = Arc<CompositeResolver<Arc<KnownNeighbors>, Arc<StaticResolver>>>;

/// Bundle of operator-command handler dependencies. `None` for any
/// field means the corresponding command is rejected with
/// `policy_denied` instead of being dispatched.
#[derive(Clone, Default)]
pub(crate) struct OperatorCommandRouter {
    /// Phase-9 native SQL engine. Always populated — `bowery-sql`
    /// has no privileged surface and no external dependencies, so
    /// there's nothing to gate. `Arc` makes the engine
    /// cheap-to-clone across handler spawns even though `Sql`
    /// itself is `Clone`; it preserves a single canonical
    /// configuration owned by the agent.
    pub sql: Option<Arc<bowery_sql::Sql>>,
    /// Phase-9 slice 7: relay context. Populated when the agent
    /// has a mesh peer set and can act as a fan-out relay for
    /// operator-issued `SqlQuery { fanout: true }`. `None` falls
    /// back to local-only execution (the operator's `fanout` flag
    /// is silently ignored — the result still streams correctly,
    /// just without per-peer rows).
    pub relay: Option<Arc<RelayContext>>,
    /// Phase-9 final-2: per-operator-fingerprint rate limiter for
    /// fan-out queries. Enforces F-4 from the security audit.
    /// Operator-direct queries aren't throttled — the blast radius
    /// is one host and `max_timeout` already caps per-query work.
    pub fanout_rate_limit: Arc<FanoutRateLimit>,
    /// Hard ceiling on per-query wall-clock timeout.
    pub max_timeout: Duration,
}

/// Token-bucket rate limiter keyed on operator fingerprint. Each
/// fan-out query consumes one token; tokens refill at
/// `REFILL_PER_SEC`. A first-time operator gets `BURST` tokens
/// immediately. Defends against a compromised operator key
/// driving the relay into sustained mesh-amplified work.
///
/// Sized for the realistic operator workflow: one fan-out every
/// 5 seconds for interactive triage, bursts up to 6 queries.
#[derive(Debug, Default)]
pub(crate) struct FanoutRateLimit {
    inner: std::sync::Mutex<std::collections::HashMap<Fingerprint, FanoutBucket>>,
}

#[derive(Debug)]
struct FanoutBucket {
    tokens: f64,
    last_refill: std::time::Instant,
}

impl FanoutRateLimit {
    const REFILL_PER_SEC: f64 = 0.2; // 1 token / 5 s
    const BURST: f64 = 6.0;

    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Try to consume one token for `operator`. Returns `true` if
    /// a token was available; `false` if the operator should be
    /// deferred.
    pub(crate) fn try_acquire(&self, operator: &Fingerprint) -> bool {
        let now = std::time::Instant::now();
        let mut map = self.inner.lock().expect("fanout rate-limit mutex poisoned");
        let bucket = map.entry(*operator).or_insert(FanoutBucket {
            tokens: Self::BURST,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * Self::REFILL_PER_SEC).min(Self::BURST);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Phase-9 slice 7: handles needed to dial pinned peers from
/// inside an operator-command handler.
///
/// Held inside an `Arc` so cloning the router across spawned
/// tasks doesn't deep-copy the endpoint. The fields are exactly
/// what `send_heartbeat` already needs — the relay path reuses
/// the same dial primitives.
pub(crate) struct RelayContext {
    pub endpoint: BoweryEndpoint,
    pub known_neighbors: Arc<KnownNeighbors>,
    pub peers_watcher: watch::Receiver<Vec<PeerInfo>>,
}

impl std::fmt::Debug for RelayContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayContext").finish_non_exhaustive()
    }
}

#[allow(clippy::too_many_arguments)] // wiring kept explicit at the call site
fn spawn_accept_task(
    endpoint: BoweryEndpoint,
    resolver: ResolverArc,
    operators: Arc<StaticResolver>,
    sealer: Arc<Sealer>,
    baseline: Arc<Baseline>,
    inbox: Arc<AlertInbox>,
    op_router: Arc<OperatorCommandRouter>,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let self_fp = sealer.fingerprint();
        let envelope_verifier = Arc::new(Verifier::new(resolver, self_fp));
        loop {
            tokio::select! {
                accept = endpoint.accept() => {
                    let Some(connection_result) = accept else { break };
                    match connection_result {
                        Ok(conn) => {
                            let verifier = envelope_verifier.clone();
                            let operators = operators.clone();
                            let sealer = sealer.clone();
                            let baseline = baseline.clone();
                            let inbox = inbox.clone();
                            let op_router = op_router.clone();
                            let events = events_tx.clone();
                            tokio::spawn(handle_connection(
                                conn, verifier, operators, sealer, baseline, inbox, op_router, events,
                            ));
                        }
                        Err(e) => warn!(error = %e, "accept failed"),
                    }
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    conn: BoweryConnection,
    verifier: Arc<Verifier<ResolverArc>>,
    operators: Arc<StaticResolver>,
    sealer: Arc<Sealer>,
    baseline: Arc<Baseline>,
    inbox: Arc<AlertInbox>,
    op_router: Arc<OperatorCommandRouter>,
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
                match env.payload.body {
                    Some(Body::Question(q)) => {
                        if let Err(e) =
                            respond_to_question(&conn, &sealer, &baseline, env.sender, q).await
                        {
                            warn!(sender = %env.sender, error = %e, "whisper Q&A response failed");
                        }
                    }
                    Some(Body::Subscribe(s)) => {
                        // Only configured operators can drain the
                        // inbox. The envelope verifier already checked
                        // the signature against the *composite*
                        // resolver, but that includes peer agents — we
                        // need the stricter "is this an operator?"
                        // check before handing back alerts.
                        if operators.resolve(&env.sender).is_none() {
                            warn!(
                                sender = %env.sender,
                                "rejecting Subscribe from non-operator sender"
                            );
                            continue;
                        }
                        if let Err(e) =
                            respond_to_subscribe(&conn, &sealer, &inbox, env.sender, s, &events_tx)
                                .await
                        {
                            warn!(sender = %env.sender, error = %e, "Subscribe response failed");
                        }
                    }
                    Some(Body::OperatorCommand(c)) => {
                        // Two acceptable callers (Phase-9 final-1):
                        //   1. The envelope sender is a configured
                        //      operator (direct-dial path).
                        //   2. The envelope sender is a pinned peer
                        //      AND `forwarded_from_operator` carries
                        //      a delegation we can verify against
                        //      `[operators]` further inside
                        //      `respond_to_operator_command`. F-2
                        //      closure — peers no longer need the
                        //      relay listed in `[operators]`.
                        let is_direct_operator = operators.resolve(&env.sender).is_some();
                        let is_relay_forward = !c.forwarded_from_operator.is_empty();
                        if !is_direct_operator && !is_relay_forward {
                            warn!(
                                sender = %env.sender,
                                "rejecting OperatorCommand from non-operator sender"
                            );
                            continue;
                        }
                        if let Err(e) = respond_to_operator_command(
                            &conn,
                            sealer.clone(),
                            env.sender,
                            c,
                            &op_router,
                            &operators,
                            &events_tx,
                        )
                        .await
                        {
                            warn!(sender = %env.sender, error = %e, "OperatorCommand response failed");
                        }
                    }
                    _ => {
                        // Heartbeat / other bodies: nothing to do beyond
                        // emitting EnvelopeReceived above.
                    }
                }
                // After responding (or no-op), the asker closes the
                // connection. Subsequent recv_envelope returns an
                // error and we exit the loop.
            }
            Err(e) => warn!(error = %e, "envelope verification failed"),
        }
    }
}

async fn respond_to_question(
    conn: &BoweryConnection,
    sealer: &Sealer,
    baseline: &Arc<Baseline>,
    asker: Fingerprint,
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
    let outbound = sealer.seal_for(&asker, &WhisperPayload::answer(answer));
    conn.send_envelope(&outbound).await
}

async fn respond_to_subscribe(
    conn: &BoweryConnection,
    sealer: &Sealer,
    inbox: &Arc<AlertInbox>,
    operator: Fingerprint,
    sub: Subscribe,
    events_tx: &broadcast::Sender<AgentEvent>,
) -> Result<(), bowery_whisper::transport::Error> {
    let max = usize::try_from(sub.max_items).unwrap_or(usize::MAX);
    let inbox = inbox.clone();
    let (items, cursor) =
        tokio::task::spawn_blocking(move || inbox.read_since(sub.since_unix_ms, max))
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "inbox read task panicked");
                (Vec::new(), sub.since_unix_ms)
            });

    let delivered = items.len();
    let response = Alerts {
        items,
        cursor_unix_ms: cursor,
    };
    let outbound = sealer.seal_for(&operator, &WhisperPayload::alerts(response));
    conn.send_envelope(&outbound).await?;

    let _ = events_tx.send(AgentEvent::AlertsDelivered {
        operator,
        delivered,
        cursor_unix_ms: cursor,
    });
    Ok(())
}

/// Phase-6b operator-command dispatch.
///
/// The envelope-level operator gate has already passed by the time
/// we get here (`handle_connection` rejects non-operators upstream).
/// This function:
///
/// 1. Decodes the typed command body. An empty `command` field
///    surfaces as `unsupported_command` so the operator's CLI sees
///    the wire-level mismatch rather than a silent timeout.
/// 2. Dispatches to the per-command handler (`Sql` against the
///    native engine; future commands add new arms).
/// 3. Builds an [`OperatorResult`] echoing the `request_id`, seals
///    it back to the operator, and emits an event.
///
/// New commands are added by extending the match — never by
/// smuggling free-form strings, so each command's surface stays
/// visible at code-review time.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // wiring kept explicit
async fn respond_to_operator_command(
    conn: &BoweryConnection,
    sealer: Arc<Sealer>,
    sender: Fingerprint,
    cmd: bowery_proto::OperatorCommand,
    op_router: &OperatorCommandRouter,
    operators: &Arc<StaticResolver>,
    events_tx: &broadcast::Sender<AgentEvent>,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::OperatorCommandBody;

    let request_id = cmd.request_id.clone();
    let command_kind = match cmd.command.as_ref() {
        Some(OperatorCommandBody::Sql(_)) => "sql",
        None => "<empty>",
    };

    // Phase-9 final-1: resolve the *effective* operator. Two cases:
    //
    // 1. Direct operator dial: envelope sender is in [operators];
    //    forwarded_from_operator may be set or empty (the operator
    //    pre-signs an authorisation when it wants the relay to fan
    //    out). The effective operator is the envelope sender; the
    //    authorisation field is parsed only to validate it.
    //
    // 2. Relay-forwarded: envelope sender is a pinned peer (NOT in
    //    [operators]) and forwarded_from_operator MUST be set. We
    //    verify the operator's signature, recompute the
    //    command_digest, and use the operator_fp from the
    //    authorisation as the effective operator. Sealed responses
    //    flow back to that operator, not to the relay.
    let is_direct_operator = operators.resolve(&sender).is_some();
    let operator = match resolve_effective_operator(&cmd, &request_id, operators, sender) {
        Ok(fp) => fp,
        Err(reason) => {
            warn!(
                sender = %sender,
                request_id = %request_id,
                reason,
                "rejecting OperatorCommand: forwarded_from_operator failed verification"
            );
            return send_sql_error(
                conn,
                &sealer,
                &sender,
                &request_id,
                "forwarding_invalid",
                reason,
            )
            .await;
        }
    };

    // Cycle prevention: only the originally-dialled relay (which
    // received the command directly from a configured operator)
    // may fan out. A relay-forwarded command (i.e. one whose
    // envelope sender is NOT in [operators]) requesting further
    // fanout is rejected — that's a malicious relay trying to
    // multi-hop amplify.
    if !is_direct_operator
        && let Some(OperatorCommandBody::Sql(q)) = &cmd.command
        && q.fanout
    {
        warn!(
            sender = %sender,
            request_id = %request_id,
            "rejecting forwarded SqlQuery with fanout=true (cycle prevention)"
        );
        return send_sql_error(
            conn,
            &sealer,
            &sender,
            &request_id,
            "policy_denied",
            "forwarded SqlQuery may not request fanout (one-hop cap)",
        )
        .await;
    }
    // Clamp the operator's requested timeout to our configured cap.
    // The operator can ask for less; they can't ask for more.
    let requested = Duration::from_millis(u64::from(cmd.timeout_ms));
    let effective_timeout = requested
        .min(op_router.max_timeout)
        .max(Duration::from_millis(100));
    info!(
        operator = %operator,
        request_id = %request_id,
        kind = command_kind,
        requested_ms = cmd.timeout_ms,
        effective_ms = u64::try_from(effective_timeout.as_millis()).unwrap_or(u64::MAX),
        "operator command received"
    );

    // SQL is special-cased: it streams multiple chunked envelopes
    // back over the same connection. Other variants build a single
    // OperatorResultBody and fall through to the unified send below.
    if let Some(OperatorCommandBody::Sql(q)) = &cmd.command {
        let sql_engine = op_router.sql.clone();
        // SECURITY-AUDIT-PHASE9 F-4: per-operator-fp rate limit
        // on fan-out queries. Only applied to the entry-point
        // relay (is_direct_operator), not to forwarded peers
        // (their fanout=true is rejected upstream by cycle
        // prevention; their fanout=false bypasses the limiter).
        if q.fanout && is_direct_operator && !op_router.fanout_rate_limit.try_acquire(&operator) {
            warn!(
                operator = %operator,
                request_id = %request_id,
                "rate-limiting fan-out: operator bucket empty"
            );
            return send_sql_error(
                conn,
                &sealer,
                &operator,
                &request_id,
                "rate_limited",
                "fan-out bucket empty for this operator; back off and retry",
            )
            .await;
        }
        let relay = if q.fanout {
            op_router.relay.clone()
        } else {
            None
        };
        let outcome = stream_sql_response(
            conn,
            &sealer,
            operator,
            &request_id,
            sql_engine.as_ref(),
            &q.sql,
            q.fanout,
            &q.peers,
            &cmd.forwarded_from_operator,
            relay.as_ref(),
            effective_timeout,
        )
        .await;
        let _ = events_tx.send(AgentEvent::OperatorCommandHandled {
            operator,
            request_id,
            kind: command_kind,
        });
        return outcome;
    }

    // The `Sql` body is the only command kind; everything is
    // returned above. An empty `command` falls through here.
    send_sql_error(
        conn,
        &sealer,
        &operator,
        &request_id,
        "unsupported_command",
        "OperatorCommand.command is empty",
    )
    .await?;
    let _ = events_tx.send(AgentEvent::OperatorCommandHandled {
        operator,
        request_id,
        kind: command_kind,
    });
    Ok(())
}

/// Soft cap on rows per `SqlChunk` envelope. Trades off
/// per-envelope encoded size (proto + ed25519 sig + QUIC framing
/// overhead) against the operator's "first row" latency. 256 rows
/// of typical /proc-shaped columns sit well under the
/// `MAX_FRAME_BYTES` envelope cap with headroom for wide rows.
const SQL_CHUNK_ROW_LIMIT: usize = 256;

/// Drive the streaming SQL response. On success, emits one or
/// more `OperatorResult { SqlChunk }` envelopes (each with `end =
/// true` per agent contributing rows); on failure, emits a single
/// `OperatorResult { Error }` and stops. Each envelope is sealed
/// independently for the operator and rides its own QUIC stream.
///
/// In fan-out mode (`fanout = true` and `relay = Some`), the
/// relay also dispatches the query to its pinned peers in
/// parallel and multiplexes their chunks back to the operator,
/// rewriting each chunk's `agent_fp` to the peer's fingerprint so
/// the operator can attribute rows. Cycle prevention: the relay
/// always sends `fanout = false` to peers.
#[allow(clippy::too_many_arguments)] // wiring kept explicit
async fn stream_sql_response(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    sql_engine: Option<&Arc<bowery_sql::Sql>>,
    sql: &str,
    fanout: bool,
    peer_filter: &[Vec<u8>],
    forwarded_authorization: &[u8],
    relay: Option<&Arc<RelayContext>>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::SqlChunk;

    let Some(engine) = sql_engine else {
        return send_sql_error(
            conn,
            sealer,
            &operator,
            request_id,
            "policy_denied",
            "SQL engine not configured on this agent",
        )
        .await;
    };

    let self_fp = sealer.fingerprint();

    // -- Phase 1: stream the relay's own rows. --
    let rows = match engine.query(sql, timeout).await {
        Ok(rows) => rows,
        Err(e) => {
            let kind = match &e {
                bowery_sql::SqlError::Timeout(_) => "timeout",
                bowery_sql::SqlError::RowCapExceeded { .. } => "row_cap_exceeded",
                bowery_sql::SqlError::Sqlite(_) => "sql_error",
                _ => "handler_error",
            };
            return send_sql_error(conn, sealer, &operator, request_id, kind, &e.to_string()).await;
        }
    };

    let columns: Vec<String> = rows
        .first()
        .map(|r| r.columns.iter().map(|(name, _)| name.clone()).collect())
        .unwrap_or_default();

    // Always populate `agent_fp = self_fp`. With Phase-9 final-1
    // e2e signing, peer chunks are sealed for the operator
    // directly, so the operator can also recover attribution
    // from `envelope.sender` and is encouraged to cross-check.
    // We still set the chunk-level field so:
    //   - the operator-side decoder doesn't have to plumb
    //     envelope.sender into the chunk struct, and
    //   - tests + CLI can render attribution without a
    //     verifier-roundtrip.
    let agent_fp_bytes = self_fp.as_bytes().to_vec();

    if rows.is_empty() {
        let chunk = SqlChunk {
            columns,
            rows: Vec::new(),
            end: true,
            agent_fp: agent_fp_bytes.clone(),
        };
        send_chunk(conn, sealer, &operator, request_id, chunk).await?;
    } else {
        let mut sent = 0usize;
        while sent < rows.len() {
            let take = SQL_CHUNK_ROW_LIMIT.min(rows.len() - sent);
            let batch = &rows[sent..sent + take];
            let proto_rows: Vec<bowery_proto::SqlRow> = batch.iter().map(encode_row).collect();
            let chunk_columns = if sent == 0 {
                columns.clone()
            } else {
                Vec::new()
            };
            let end = sent + take == rows.len();
            let chunk = SqlChunk {
                columns: chunk_columns,
                rows: proto_rows,
                end,
                agent_fp: agent_fp_bytes.clone(),
            };
            send_chunk(conn, sealer, &operator, request_id, chunk).await?;
            sent += take;
        }
    }

    // -- Phase 2: fan-out to peers (if requested + relay-capable). --
    //
    // No relay context (mesh disabled / no peers) silently collapses
    // to local-only — the operator still got the local rows; just no
    // extra peer streams. The operator can distinguish via the
    // per-chunk agent_fp set.
    if fanout && let Some(relay) = relay {
        relay_to_peers(
            conn,
            sealer,
            operator,
            request_id,
            sql,
            peer_filter,
            forwarded_authorization,
            relay,
            timeout,
        )
        .await?;
    }
    Ok(())
}

/// Helper to seal + send one `SqlChunk` envelope.
async fn send_chunk(
    conn: &BoweryConnection,
    sealer: &Sealer,
    operator: &Fingerprint,
    request_id: &str,
    chunk: bowery_proto::SqlChunk,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::{OperatorResult, OperatorResultBody};
    let response = OperatorResult {
        request_id: request_id.to_string(),
        result: Some(OperatorResultBody::SqlChunk(chunk)),
    };
    let outbound = sealer.seal_for(operator, &WhisperPayload::operator_result(response));
    conn.send_envelope(&outbound).await
}

/// Helper to seal + send a stream-terminating `OperatorError`
/// envelope. The decoder treats any `Error` body as the end of
/// the stream regardless of how many `SqlChunk`s preceded it.
async fn send_sql_error(
    conn: &BoweryConnection,
    sealer: &Sealer,
    operator: &Fingerprint,
    request_id: &str,
    kind: &str,
    message: &str,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::{OperatorError, OperatorResult, OperatorResultBody};
    let response = OperatorResult {
        request_id: request_id.to_string(),
        result: Some(OperatorResultBody::Error(OperatorError {
            kind: kind.to_string(),
            message: message.to_string(),
        })),
    };
    let outbound = sealer.seal_for(operator, &WhisperPayload::operator_result(response));
    conn.send_envelope(&outbound).await
}

/// Phase-9 slice 7: dispatch the query to every selected pinned
/// peer in parallel, multiplexing their chunks back to the
/// operator. Each peer's chunks have their `agent_fp` rewritten
/// to the peer's fingerprint before forwarding so the operator
/// can attribute rows.
///
/// Per-peer failures (dial failed, peer error, peer timeout) are
/// surfaced as a synthetic terminal chunk for that peer with no
/// rows — the operator still sees the EOF and knows that peer
/// didn't contribute. We don't propagate per-peer errors as a
/// stream-wide failure; the relay best-efforts every peer
/// independently.
#[allow(clippy::too_many_arguments)]
async fn relay_to_peers(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    sql: &str,
    peer_filter: &[Vec<u8>],
    forwarded_authorization: &[u8],
    relay: &Arc<RelayContext>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::{OperatorError, SqlChunk};

    // Snapshot the current peer set; turn the filter (if any) into
    // a HashSet of fingerprints for O(1) membership checks.
    let peers: Vec<PeerInfo> = relay.peers_watcher.borrow().clone();
    let peers: Vec<PeerInfo> = if peer_filter.is_empty() {
        peers
            .into_iter()
            .filter(|p| relay.known_neighbors.resolve(&p.fingerprint).is_some())
            .filter(|p| p.fingerprint != sealer.fingerprint())
            .collect()
    } else {
        let mut wanted: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::with_capacity(peer_filter.len());
        for fp in peer_filter {
            if let Ok(arr) = <[u8; 32]>::try_from(fp.as_slice()) {
                wanted.insert(arr);
            }
        }
        peers
            .into_iter()
            .filter(|p| wanted.contains(p.fingerprint.as_bytes()))
            .filter(|p| relay.known_neighbors.resolve(&p.fingerprint).is_some())
            .filter(|p| p.fingerprint != sealer.fingerprint())
            .collect()
    };

    if peers.is_empty() {
        return Ok(());
    }

    // Spawn one task per peer onto a JoinSet so we can abort the
    // whole batch if the operator disconnects (SECURITY-AUDIT-PHASE9
    // F-16). The channel now carries opaque envelope **bytes** —
    // peers seal `SqlChunk` directly for the operator (Phase-9
    // final-1 / F-1), so the relay forwards them verbatim.
    let (bytes_tx, mut bytes_rx) =
        mpsc::channel::<(Fingerprint, Result<Vec<u8>, OperatorError>)>(64);
    let per_peer_timeout = timeout;
    let mut join_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    for peer in peers {
        let bytes_tx = bytes_tx.clone();
        let endpoint = relay.endpoint.clone();
        let kn = relay.known_neighbors.clone();
        let sealer_clone = sealer.clone();
        let sql = sql.to_string();
        let request_id = request_id.to_string();
        let auth = forwarded_authorization.to_vec();
        join_set.spawn(async move {
            run_peer_query(
                endpoint,
                kn,
                &sealer_clone,
                peer,
                auth,
                &sql,
                &request_id,
                per_peer_timeout,
                bytes_tx,
            )
            .await;
        });
    }
    drop(bytes_tx); // close the channel so bytes_rx ends when all peers finish

    // Drain peer envelope bytes; forward verbatim to operator. On
    // per-peer error, synthesise a relay-signed terminal chunk so
    // the operator still sees the EOF. If the operator-side send
    // fails (operator dropped), abort every peer task.
    let drain_outcome: Result<(), bowery_whisper::transport::Error> = async {
        while let Some((peer_fp, outcome)) = bytes_rx.recv().await {
            if let Ok(bytes) = outcome {
                // Peer sealed this for the operator's fp; the
                // operator's verifier will check it. We just
                // ship the bytes through.
                conn.send_envelope(&bytes).await?;
            } else {
                // Synthesise a relay-signed terminal chunk for
                // the failed peer. agent_fp is informational;
                // the operator can detect "this came from the
                // relay, not the peer" because the envelope is
                // signed by the relay rather than the peer.
                let chunk = SqlChunk {
                    columns: Vec::new(),
                    rows: Vec::new(),
                    end: true,
                    agent_fp: peer_fp.as_bytes().to_vec(),
                };
                send_chunk(conn, sealer, &operator, request_id, chunk).await?;
            }
        }
        Ok(())
    }
    .await;

    join_set.abort_all();
    while join_set.join_next().await.is_some() {}
    drain_outcome
}

/// One peer's leg of the fan-out. Dials the peer, sends an
/// `OperatorCommand { forwarded_from_operator, … }`, reads
/// **opaque** envelope bytes back, and forwards them through
/// `chunk_tx`. Each envelope is sealed by the peer for the
/// *original operator's* fingerprint, so the relay cannot
/// verify the signature — only operator-side verification can.
/// The relay still peeks into the inner `WhisperPayload`
/// (plaintext per Phase-1a wire format) to detect end-of-stream
/// per peer.
///
/// On dial / send failure, an `OperatorError` is enqueued so the
/// multiplexer can emit a synthetic EOF chunk to the operator
/// (sealed by the relay — operators see a labelled "this peer
/// failed" rather than silence).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_peer_query(
    endpoint: BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: &Arc<Sealer>,
    peer: PeerInfo,
    forwarded_authorization: Vec<u8>,
    sql: &str,
    request_id: &str,
    timeout: Duration,
    bytes_tx: mpsc::Sender<(Fingerprint, Result<Vec<u8>, bowery_proto::OperatorError>)>,
) {
    use bowery_proto::{
        Body, OperatorCommand, OperatorCommandBody, OperatorError, OperatorResultBody, SqlQuery,
        WhisperEnvelope,
    };
    use prost::Message as _;

    let peer_fp = peer.fingerprint;
    let cmd = OperatorCommand {
        request_id: request_id.to_string(),
        timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        forwarded_from_operator: forwarded_authorization,
        command: Some(OperatorCommandBody::Sql(SqlQuery {
            sql: sql.to_string(),
            fanout: false, // cycle prevention
            peers: Vec::new(),
        })),
    };
    let outbound = sealer.seal_for(&peer_fp, &WhisperPayload::operator_command(cmd));

    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(kn, peer_fp));
    let conn = match endpoint.dial(dial_verifier, peer.whisper_addr).await {
        Ok(c) => c,
        Err(e) => {
            warn!(peer = %peer_fp, error = %e, "fanout dial failed");
            let _ = bytes_tx
                .send((
                    peer_fp,
                    Err(OperatorError {
                        kind: "dial_failed".into(),
                        message: e.to_string(),
                    }),
                ))
                .await;
            return;
        }
    };
    if let Err(e) = conn.send_envelope(&outbound).await {
        warn!(peer = %peer_fp, error = %e, "fanout send failed");
        let _ = bytes_tx
            .send((
                peer_fp,
                Err(OperatorError {
                    kind: "send_failed".into(),
                    message: e.to_string(),
                }),
            ))
            .await;
        return;
    }

    let exchange = async {
        loop {
            let bytes = conn
                .recv_envelope()
                .await
                .map_err(|e| format!("recv: {e}"))?;
            // Peek at the envelope just enough to (a) verify the
            // sender claim and (b) detect end-of-stream. The
            // signature is *not* verified here — it's sealed for
            // the original operator, not the relay. Operator-side
            // verification is the authoritative integrity check.
            let env = WhisperEnvelope::decode(bytes.as_slice())
                .map_err(|e| format!("envelope decode: {e}"))?;
            if env.sender_fingerprint.as_slice() != peer_fp.as_bytes().as_slice() {
                return Err(format!(
                    "envelope sender mismatch: peer {peer_fp} responded with sender_fingerprint {:x?}",
                    env.sender_fingerprint
                ));
            }
            let payload = WhisperPayload::decode(env.payload.as_slice())
                .map_err(|e| format!("payload decode: {e}"))?;
            let is_end_of_stream = matches!(
                &payload.body,
                Some(Body::OperatorResult(r))
                    if matches!(
                        &r.result,
                        Some(OperatorResultBody::SqlChunk(c)) if c.end
                    ) || matches!(&r.result, Some(OperatorResultBody::Error(_)))
            );
            if bytes_tx.send((peer_fp, Ok(bytes))).await.is_err() {
                return Ok(());
            }
            if is_end_of_stream {
                return Ok(());
            }
        }
    };
    let outcome: Result<Result<(), String>, tokio::time::error::Elapsed> =
        tokio::time::timeout(timeout + Duration::from_secs(2), exchange).await;
    if let Err(_) | Ok(Err(_)) = outcome {
        let (kind, message) = match outcome {
            Err(_) => ("timeout", format!("peer {peer_fp} timed out")),
            Ok(Err(e)) => ("peer_error", e),
            _ => unreachable!(),
        };
        let _ = bytes_tx
            .send((
                peer_fp,
                Err(OperatorError {
                    kind: kind.into(),
                    message,
                }),
            ))
            .await;
    }
}

/// Phase-9 final-1: resolve the effective operator for an
/// `OperatorCommand`. Returns either the envelope sender (for
/// direct operator dials) or the operator embedded in a verified
/// `forwarded_from_operator` authorisation. Errors back-propagate
/// as `&'static str` reasons so the caller can surface them in a
/// structured `OperatorError`.
fn resolve_effective_operator(
    cmd: &bowery_proto::OperatorCommand,
    request_id: &str,
    operators: &Arc<StaticResolver>,
    sender: Fingerprint,
) -> Result<Fingerprint, &'static str> {
    use prost::Message as _;

    if cmd.forwarded_from_operator.is_empty() {
        return Ok(sender);
    }
    let auth = bowery_proto::OperatorAuthorization::decode(cmd.forwarded_from_operator.as_slice())
        .map_err(|_| "forwarded_from_operator decode failed")?;
    if auth.operator_fp.len() != 32 {
        return Err("forwarded_from_operator: bad operator_fp length");
    }
    if auth.command_digest.len() != 32 {
        return Err("forwarded_from_operator: bad command_digest length");
    }
    if auth.signature.len() != 64 {
        return Err("forwarded_from_operator: bad signature length");
    }
    if auth.request_id != request_id {
        return Err("forwarded_from_operator: request_id mismatch");
    }
    let mut operator_fp_arr = [0u8; 32];
    operator_fp_arr.copy_from_slice(&auth.operator_fp);
    let operator_fp = Fingerprint::from_bytes(operator_fp_arr);

    // Operator must be in [operators] to authorise a query.
    let Some(vk) = operators.resolve(&operator_fp) else {
        return Err("forwarded_from_operator: operator not in [operators]");
    };

    // Bind authorisation to the actual command we're about to run:
    // peer recomputes SHA-256 of the encoded OperatorCommandBody and
    // compares against the digest signed by the operator. A relay
    // can't substitute a different SQL string under an authorisation
    // issued for some other query.
    let body = cmd
        .command
        .as_ref()
        .ok_or("forwarded_from_operator: empty command")?;
    let actual_digest = command_body_digest(body);
    if actual_digest.as_slice() != auth.command_digest.as_slice() {
        return Err("forwarded_from_operator: command_digest mismatch");
    }

    // ts_unix_ms skew check: same window envelopes use (5 minutes).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let skew = now.abs_diff(auth.ts_unix_ms);
    if skew > 5 * 60 * 1000 {
        return Err("forwarded_from_operator: ts_unix_ms outside skew window");
    }

    let mut digest_arr = [0u8; 32];
    digest_arr.copy_from_slice(&auth.command_digest);
    let signing_input = bowery_proto::OperatorAuthorization::signing_input(
        &operator_fp_arr,
        auth.ts_unix_ms,
        &auth.request_id,
        &digest_arr,
    );
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&auth.signature);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    if vk.verify_strict(&signing_input, &sig).is_err() {
        return Err("forwarded_from_operator: signature verification failed");
    }
    Ok(operator_fp)
}

/// SHA-256 of a *normalised* `OperatorCommandBody`. Delegates
/// to [`bowery_whisper::forwarding::command_body_digest`] so
/// peer + operator + relay all agree on the same hash; see that
/// function's doc-comment for the normalisation rules.
fn command_body_digest(body: &bowery_proto::OperatorCommandBody) -> [u8; 32] {
    bowery_whisper::forwarding::command_body_digest(body)
}

/// Phase-9 final-3: hard cap on the bytes any single cell may
/// occupy on the wire. SECURITY-AUDIT-PHASE9 F-6: previously a
/// query like `SELECT randomblob(80000)` would build a row
/// larger than `MAX_FRAME_BYTES` (64 KiB), and the unstructured
/// `FrameTooLarge` would tear down the QUIC stream with no
/// signal to the operator. We now truncate large cells at the
/// agent and substitute a `Text` placeholder so the operator
/// gets an unambiguous "<truncated N bytes>" marker on each
/// affected cell.
///
/// 16 KiB is well above any sensible row width (typical procfs
/// columns are <1 KiB) but well below the per-frame cap, leaving
/// room for the rest of the chunk's structure + a healthy batch
/// of rows.
const MAX_CELL_BYTES: usize = 16 * 1024;

fn encode_row(row: &bowery_sql::Row) -> bowery_proto::SqlRow {
    let values = row
        .columns
        .iter()
        .map(|(_, v)| {
            let kind = match v {
                bowery_sql::Value::Null => None,
                bowery_sql::Value::Integer(i) => Some(bowery_proto::SqlValueKind::Integer(*i)),
                bowery_sql::Value::Real(f) => Some(bowery_proto::SqlValueKind::Real(*f)),
                bowery_sql::Value::Text(s) => {
                    if s.len() > MAX_CELL_BYTES {
                        Some(bowery_proto::SqlValueKind::Text(format!(
                            "<truncated {} bytes>",
                            s.len()
                        )))
                    } else {
                        Some(bowery_proto::SqlValueKind::Text(s.clone()))
                    }
                }
                bowery_sql::Value::Blob(b) => {
                    if b.len() > MAX_CELL_BYTES {
                        Some(bowery_proto::SqlValueKind::Text(format!(
                            "<truncated {} bytes>",
                            b.len()
                        )))
                    } else {
                        Some(bowery_proto::SqlValueKind::Blob(b.clone()))
                    }
                }
            };
            bowery_proto::SqlValue { value: kind }
        })
        .collect();
    bowery_proto::SqlRow { values }
}

fn spawn_heartbeat_task(
    pool: PeerConnections,
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
                        let pool = pool.clone();
                        let kn_for_dial = kn.clone();
                        let sealer = sealer.clone();
                        let events = events_tx.clone();
                        tokio::spawn(async move {
                            send_heartbeat(pool, kn_for_dial, sealer, peer, events).await;
                        });
                    }
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

async fn send_heartbeat(
    pool: PeerConnections,
    kn: Arc<KnownNeighbors>,
    sealer: Arc<Sealer>,
    peer: PeerInfo,
    events_tx: broadcast::Sender<AgentEvent>,
) {
    let bytes = sealer.seal_for(&peer.fingerprint, &WhisperPayload::heartbeat(AGENT_VERSION));
    let verifier = Arc::new(PinnedCertVerifier::expecting(kn, peer.fingerprint));
    let conn = match pool
        .get_or_dial(peer.fingerprint, peer.whisper_addr, verifier)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            debug!(peer = %peer.fingerprint, error = %e, "heartbeat dial failed");
            return;
        }
    };
    match conn.send_envelope(&bytes).await {
        Ok(()) => {
            debug!(peer = %peer.fingerprint, "heartbeat sent");
            let _ = events_tx.send(AgentEvent::HeartbeatSent {
                peer: peer.fingerprint,
            });
        }
        Err(e) => {
            warn!(peer = %peer.fingerprint, error = %e, "heartbeat send failed");
            // The cached connection is dead; drop it so the next
            // heartbeat redials instead of looping over a corpse.
            pool.invalidate(&peer.fingerprint);
        }
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
    inbox: Arc<AlertInbox>,
    originator_fp: Fingerprint,
    alert_threshold: f32,
    backend_label: String,
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
                        &inbox,
                        originator_fp,
                        alert_threshold,
                        &backend_label,
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
    inbox: &Arc<AlertInbox>,
    originator_fp: Fingerprint,
    alert_threshold: f32,
    backend_label: &str,
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
            inbox,
            originator_fp,
            alert_threshold,
            backend_label,
            events_tx,
            exec,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn process_exec(
    baseline: &Arc<Baseline>,
    analyzer: &Arc<Analyzer>,
    llm_submitter: &Submitter,
    llm_threshold: f32,
    whisper_threshold: f32,
    whisper_qa_tx: &mpsc::Sender<WhisperQaTrigger>,
    inbox: &Arc<AlertInbox>,
    originator_fp: Fingerprint,
    alert_threshold: f32,
    backend_label: &str,
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

    // Build the LLM context once. Both paths (direct LLM submission
    // below, and the whisper-mediated submission performed by
    // whisper_qa_task) consume the same shape; whisper_qa_task
    // additionally injects neighborhood sightings into `ctx.extra`
    // before submitting.
    let mut ctx = AnalysisContext::new(verdict.clone())
        .with_exe_sha256(&sha)
        .with_exe_pid(exec.pid)
        .with_exe_comm(exec.comm.clone());
    if let Some(p) = exec.exe_path.as_ref() {
        ctx = ctx.with_exe_path(p.clone());
    }
    if !exec.args.is_empty() {
        ctx = ctx.with_args(exec.args.clone());
    }

    // Phase 4 + 5 routing: when the whisper threshold is met, defer
    // the LLM submission to whisper_qa_task so the LLM sees peer
    // sightings. Otherwise (LLM threshold met but whisper threshold
    // not), submit directly with no neighborhood context.
    let going_through_whisper = verdict.suspicion >= whisper_threshold;
    if !going_through_whisper && verdict.suspicion >= llm_threshold {
        let episode_id = verdict.episode_id.clone();
        if let Err(reason) = llm_submitter.submit(ctx.clone()) {
            let _ = events_tx.send(AgentEvent::LlmShed {
                episode_id,
                reason: reason.into(),
            });
        }
    }

    if going_through_whisper
        && let Err(e) = whisper_qa_tx
            .send(WhisperQaTrigger {
                episode_id: verdict.episode_id.clone(),
                sha,
                ctx: ctx.clone(),
            })
            .await
    {
        debug!(error = %e, "whisper Q&A trigger channel closed");
    }

    // Phase 6: append an Alert to the operator inbox if the verdict
    // crosses the alert threshold. We use the *pre-verdict's*
    // suspicion + rule rationale here; a later phase can re-emit a
    // refined alert when the LLM's verdict comes back.
    if verdict.suspicion >= alert_threshold {
        let rationale = first_rule_message(&verdict)
            .unwrap_or_else(|| "pre-filter score above threshold".to_string());
        let alert = Alert {
            originator_fp: originator_fp.as_bytes().to_vec(),
            episode_id: verdict.episode_id.clone(),
            exe_sha256_hex: sha_to_hex(&sha),
            exe_path: exec
                .exe_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            suspicion: verdict.suspicion,
            rationale,
            suggested_actions: Vec::new(), // populated by the LLM enrichment, later phase
            ts_unix_ms: current_unix_ms(),
            backend: backend_label.to_string(),
        };
        let episode_id = alert.episode_id.clone();
        let suspicion = alert.suspicion;
        inbox.append(alert);
        let _ = events_tx.send(AgentEvent::AlertEmitted {
            episode_id,
            suspicion,
        });
    }

    let _ = events_tx.send(AgentEvent::EpisodeAnalyzed { verdict });
}

fn first_rule_message(verdict: &Verdict) -> Option<String> {
    verdict
        .rule_hits
        .first()
        .map(|h| format!("{}: {}", h.rule_id, h.reason))
}

fn sha_to_hex(sha: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in sha {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// LLM outcomes bridge
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spawn_llm_outcomes_task(
    mut outcomes: mpsc::Receiver<InferenceOutcome>,
    inbox: Arc<AlertInbox>,
    originator_fp: Fingerprint,
    alert_threshold: f32,
    backend_label: String,
    response_engine: Arc<dyn ResponseEngine>,
    audit_sink: Arc<dyn AuditSink>,
    identity: Arc<Identity>,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                outcome = outcomes.recv() => {
                    let Some(outcome) = outcome else { break };
                    handle_llm_outcome(
                        &events_tx,
                        &inbox,
                        originator_fp,
                        alert_threshold,
                        &backend_label,
                        &response_engine,
                        &audit_sink,
                        &identity,
                        outcome,
                    );
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_llm_outcome(
    events_tx: &broadcast::Sender<AgentEvent>,
    inbox: &Arc<AlertInbox>,
    originator_fp: Fingerprint,
    alert_threshold: f32,
    backend_label: &str,
    response_engine: &Arc<dyn ResponseEngine>,
    audit_sink: &Arc<dyn AuditSink>,
    identity: &Arc<Identity>,
    outcome: InferenceOutcome,
) {
    match outcome {
        InferenceOutcome::Verdict {
            episode_id,
            ctx,
            verdict,
        } => {
            // Re-emit a refined Alert with the LLM's rationale +
            // suggested_actions. This *complements* the pre-verdict
            // alert that process_exec already pushed: operators see two
            // entries for the same episode_id, the second of which has
            // the model's explanation. They can dedup on episode_id at
            // display time if they want a single record per episode.
            //
            // The LLM may have lowered the suspicion below the alert
            // threshold (e.g. "this is a known build artifact, not
            // malicious"). In that case we don't append.
            if verdict.suspicion >= alert_threshold {
                let alert = Alert {
                    originator_fp: originator_fp.as_bytes().to_vec(),
                    episode_id: episode_id.clone(),
                    exe_sha256_hex: ctx.exe_sha256_hex.clone().unwrap_or_default(),
                    exe_path: ctx
                        .exe_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    suspicion: verdict.suspicion,
                    rationale: verdict.rationale.clone(),
                    suggested_actions: verdict.suggested_actions.clone(),
                    ts_unix_ms: current_unix_ms(),
                    backend: backend_label.to_string(),
                };
                inbox.append(alert);
                let _ = events_tx.send(AgentEvent::AlertEmitted {
                    episode_id: episode_id.clone(),
                    suspicion: verdict.suspicion,
                });
            }
            // Phase 7: route every suggested action through the
            // response engine. The engine is policy-gated (defaults
            // deny-all), so on a freshly-installed agent this only
            // generates AlertEmitted-style observability and never
            // touches the host. Operators turn enforcement on by
            // editing the policy file, not by recompiling.
            for action_id in &verdict.suggested_actions {
                let Some(action) =
                    action::from_id(action_id, &episode_id, ctx.exe_pid, ctx.exe_comm.as_deref())
                else {
                    debug!(action_id, episode = %episode_id, "unknown action id; skipping");
                    continue;
                };
                let engine = response_engine.clone();
                let audit_sink = audit_sink.clone();
                let identity = identity.clone();
                let events_tx_inner = events_tx.clone();
                let episode = episode_id.clone();
                let id = action.id();
                let engine_name = engine.name();
                tokio::spawn(async move {
                    let outcome_to_audit = match engine.execute(&action).await {
                        Ok(outcome) => {
                            let _ = events_tx_inner.send(AgentEvent::ActionAttempted {
                                episode_id: episode.clone(),
                                action_id: id,
                                outcome: outcome.clone(),
                            });
                            outcome
                        }
                        Err(e) => {
                            warn!(
                                action_id = id,
                                episode = %episode,
                                error = %e,
                                "response engine returned an error"
                            );
                            let outcome = ActionOutcome::suppressed(format!("error: {e}"));
                            let _ = events_tx_inner.send(AgentEvent::ActionAttempted {
                                episode_id: episode.clone(),
                                action_id: id,
                                outcome: outcome.clone(),
                            });
                            outcome
                        }
                    };
                    audit::record(
                        &audit_sink,
                        &identity,
                        engine_name,
                        &episode,
                        action,
                        outcome_to_audit,
                    )
                    .await;
                });
            }

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
