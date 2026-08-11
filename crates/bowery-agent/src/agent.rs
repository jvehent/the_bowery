//! The supervised agent runtime: TOFU store + QUIC endpoint + mesh +
//! pin-task + accept-task + heartbeat-task, with watch-channel-driven
//! shutdown.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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
use crate::eventlog_writer::EventLogHandle;
use bowery_whisper::fingerprint::{TIER1_LEN, Tier1Fingerprint};
use bowery_whisper::known_neighbors::{KnownNeighbors, PinOutcome};
use bowery_whisper::mesh_trust::RevocationStore;
use bowery_whisper::pool::PeerConnections;
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::{BoweryConnection, BoweryEndpoint};
use bowery_whisper::{CompositeResolver, FingerprintResolver, Sealer, StaticResolver, Verifier};
use ed25519_dalek::VerifyingKey;

use crate::bloom_publisher;
use crate::inbox::{AlertInbox, current_unix_ms};
use crate::monitor::MonitorRules;
use crate::whisper_qa::{
    WhisperContext, WhisperQaTrigger, aggregate_local_sighting, spawn_whisper_qa_task,
};
use crate::yara_store::{YaraSeen, YaraStore};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::Config;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const EVENT_CHANNEL_CAPACITY: usize = 4096;
/// Buffer for operator file-watch events. Smaller than the kernel event
/// channel: inotify fires on a handful of explicitly-watched paths, not
/// every exec on the host.
const FILE_EVENT_CHANNEL_CAPACITY: usize = 256;

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
    /// `None` when the event log is disabled or failed to open.
    eventlog_tasks: Option<(JoinHandle<()>, JoinHandle<()>)>,
    revocations: Arc<RevocationStore>,
    /// `None` when no file rules are configured (or inotify is unavailable).
    file_monitor_task: Option<JoinHandle<()>>,
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

        let operators = Arc::new(load_operators(&config.operators.pubkeys_b64)?);

        let cluster_id_for_trust = config
            .mesh
            .cluster_id
            .clone()
            .unwrap_or_else(|| bowery_mesh::DEFAULT_CLUSTER_ID.to_string());
        // Revocations load before KnownNeighbors so the pin store can
        // consult them on every pin attempt — no code path should be
        // able to admit a revoked identity by forgetting to check. They
        // are re-verified against the operator keys on every load, so
        // the file itself carries no authority.
        let revocations = {
            let ops = operators.clone();
            let resolve = move |fp: &Fingerprint| ops.resolve(fp);
            Arc::new(RevocationStore::load_signed(
                &config.known_neighbors.revocations_path,
                &cluster_id_for_trust,
                &resolve,
            )?)
        };
        if !revocations.is_empty() {
            info!(count = revocations.len(), "loaded revocation list");
        }

        let known_neighbors = Arc::new(
            KnownNeighbors::open(
                &config.known_neighbors.path,
                config.known_neighbors.bootstrap_window,
            )?
            .with_max_pinned(config.known_neighbors.max_pinned_peers)
            .with_revocations(revocations.clone()),
        );

        // Composite resolver: pinned peer agents AND configured
        // operators. Both can dial us — peers for heartbeats / Q&A,
        // operators for `Subscribe` against the alert inbox.
        let resolver = Arc::new(CompositeResolver::new(
            known_neighbors.clone(),
            operators.clone(),
        ));

        let baseline = Arc::new(open_baseline(&config.baseline.path)?);

        // Operator-configurable monitoring: validated once here, then shared
        // with the analyzer (process rules), the inotify file monitor (file
        // rules), and the `bowery_monitor_rules` SQL table.
        let monitor_rules =
            Arc::new(MonitorRules::from_config(&config.monitor).map_err(AgentError::Config)?);
        if !monitor_rules.is_empty() {
            info!(
                file_rules = monitor_rules.file_rules().len(),
                process_rules = monitor_rules.process_rules().len(),
                "operator monitoring rules loaded"
            );
        }

        // Built-in detections plus the operator's process rules. Operator ids
        // are leaked once (rules live for the process lifetime) because
        // `RuleHit::rule_id` is `&'static str`.
        let mut rules = bowery_analysis::rule::default_rules();
        for spec in monitor_rules.process_rules() {
            let id: &'static str = Box::leak(spec.id.clone().into_boxed_str());
            rules.push(Box::new(bowery_analysis::OperatorProcessRule::new(
                id,
                spec.exe_prefix.clone(),
                spec.comm.clone(),
                spec.arg_substr.clone(),
                spec.severity,
            )));
        }
        let analyzer = Arc::new(Analyzer::new(
            rules,
            bowery_analysis::BinaryScorer::new(baseline.clone()),
        ));

        // Operator-distributed YARA rules survive restarts, so a rule that
        // reached this agent through the mesh keeps working after a reboot
        // without the operator re-pushing it.
        let yara_store = Arc::new(
            YaraStore::open(
                &config.yara.path,
                config.yara.max_rules,
                config.yara.max_rule_bytes,
            )
            .map_err(|e| AgentError::Config(format!("opening yara store: {e}")))?,
        );
        if !yara_store.is_empty() {
            info!(rules = yara_store.len(), "yara rules loaded from store");
        }
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
        // The whisper address gossiped to peers (their fan-out dial target).
        // When the socket binds a wildcard like 0.0.0.0:9902 — which we want
        // for boot robustness, since binding a specific tailnet IP fails if
        // the agent starts before Tailscale assigns it — `local_addr()`
        // returns that unroutable 0.0.0.0. `whisper.advertise_addr` lets a
        // node bind the wildcard yet advertise its routable 100.x:9902 so
        // peers can actually dial it for relay fan-out.
        let whisper_addr = match config.whisper.advertise_addr {
            Some(addr) => addr,
            None => endpoint
                .local_addr()
                .map_err(|e| AgentError::Config(format!("local_addr: {e}")))?,
        };

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

        // Publish our own grant so peers running `enrollment = "grant"`
        // can pin us. Set once rather than on a timer: chitchat KV is
        // replicated state, not a heartbeat, and a grant doesn't change.
        if let Some(path) = &config.known_neighbors.grant_path {
            match load_grant_b64(path) {
                Ok(encoded) => {
                    if let Err(e) = mesh
                        .set_state(bowery_mesh::KEY_MEMBERSHIP_GRANT, encoded)
                        .await
                    {
                        warn!(error = %e, "failed to publish membership grant");
                    } else {
                        info!(path = %path.display(), "published membership grant");
                    }
                }
                // Non-fatal: an agent with an unreadable grant still runs
                // and still detects. It just won't be pinned by peers
                // enforcing `grant`, which `bowery peers check` surfaces.
                Err(e) => warn!(
                    error = %e,
                    path = %path.display(),
                    "could not load membership grant; peers enforcing enrollment=grant will not pin this agent"
                ),
            }
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (events_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);

        let enrollment = Arc::new(EnrollmentContext {
            policy: config.known_neighbors.enrollment,
            cluster_id: config
                .mesh
                .cluster_id
                .clone()
                .unwrap_or_else(|| bowery_mesh::DEFAULT_CLUSTER_ID.to_string()),
            operators: operators.clone(),
            revocations: revocations.clone(),
        });
        // Evict anything revoked while this agent was down: a revocation
        // that only applied to peers we meet *after* a restart would let
        // containment lapse across a reboot.
        for fp in known_neighbors.fingerprints() {
            if revocations.is_revoked(&fp) && known_neighbors.unpin(&fp).unwrap_or(false) {
                warn!(peer = %fp, "evicted revoked peer at startup");
            }
        }

        let pin_task = spawn_pin_task(
            mesh.peers_watcher(),
            known_neighbors.clone(),
            enrollment,
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
        // Append-only local history. A failure to open it is logged and
        // degrades to "not recording" rather than refusing to start: an
        // agent that still detects and alerts is worth far more than one
        // that refuses to boot because a disk is full.
        let (eventlog, eventlog_tasks) = if config.eventlog.enabled {
            match open_event_log(&config.eventlog) {
                Ok(log) => {
                    let log = Arc::new(log);
                    let (handle, writer, maintenance) = crate::eventlog_writer::spawn(
                        log.clone(),
                        config.eventlog.queue_capacity,
                        bowery_eventlog::Retention {
                            max_age_secs: config.eventlog.retention.as_secs(),
                            max_rows: config.eventlog.max_rows,
                        },
                        config.eventlog.maintenance_interval,
                        shutdown_rx.clone(),
                    );
                    info!(path = %log.path().display(), "event log recording");
                    (Some((handle, log)), Some((writer, maintenance)))
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %config.eventlog.path.display(),
                        "event log unavailable; continuing without local history"
                    );
                    (None, None)
                }
            }
        } else {
            (None, None)
        };
        let eventlog_handle = eventlog.as_ref().map(|(h, _)| h.clone());
        let eventlog_store = eventlog.map(|(_, log)| log);

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
                crate::sql_tables::BoweryMeshPeersTable::new(
                    mesh.peers_watcher(),
                    known_neighbors.clone(),
                )
                .with_enrollment(crate::sql_tables::GrantCheck {
                    cluster_id: config
                        .mesh
                        .cluster_id
                        .clone()
                        .unwrap_or_else(|| bowery_mesh::DEFAULT_CLUSTER_ID.to_string()),
                    operators: operators.clone(),
                }),
            ))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryRevocationsTable::new(
                revocations.clone(),
            )))
            .with_extra_table(Arc::new(
                crate::sql_tables::BoweryBaselineBinariesTable::new(baseline.clone()),
            ))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryAlertsTable::new(
                inbox.clone(),
            )))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryAuditTable::new(
                config.response.audit_log_path.clone(),
            )))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryMonitorRulesTable::new(
                monitor_rules.clone(),
            )))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryYaraRulesTable::new(
                yara_store.clone(),
            )))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryEventsTable::new(
                eventlog_store.clone(),
            )))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryEventLogStatusTable::new(
                eventlog_store.clone(),
                eventlog_handle
                    .as_ref()
                    .map(EventLogHandle::dropped_counter),
            )));
        let op_router = Arc::new(OperatorCommandRouter {
            sql: Some(Arc::new(sql_engine)),
            relay: Some(relay_ctx),
            fanout_rate_limit: Arc::new(RateLimit::fanout()),
            max_timeout: config.sql.max_timeout,
            revocation: Some(Arc::new(RevocationContext {
                store: revocations.clone(),
                known_neighbors: known_neighbors.clone(),
                cluster_id: cluster_id_for_trust.clone(),
                operators: operators.clone(),
            })),
            yara: Some(Arc::new(YaraContext {
                store: yara_store.clone(),
                // Remembering a push for 30 minutes is far longer than any
                // flood takes to settle, so a rule can't lap the mesh.
                seen: Arc::new(YaraSeen::new(Duration::from_mins(30), 4096)),
                inbox: inbox.clone(),
                scan_permits: Arc::new(tokio::sync::Semaphore::new(
                    config.yara.max_concurrent_scans.max(1),
                )),
                config: config.yara.clone(),
                originator_fp: fingerprint,
            })),
        });

        // One bucket-set per agent, shared by both inbound paths (the
        // listener and streams opened back through pooled outbound
        // connections) — otherwise a peer gets a fresh budget simply by
        // choosing the other route in.
        let qa_rate_limit = Arc::new(RateLimit::whisper_qa());

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
            let qa_limit_for_handler = qa_rate_limit.clone();
            let handler: bowery_whisper::pool::InboundHandler = Arc::new(move |peer_fp, conn| {
                let verifier = envelope_verifier.clone();
                let operators = operators_for_handler.clone();
                let sealer = sealer_for_handler.clone();
                let baseline = baseline_for_handler.clone();
                let inbox = inbox_for_handler.clone();
                let op_router = op_router_for_handler.clone();
                let events = events_for_handler.clone();
                let qa_rate_limit = qa_limit_for_handler.clone();
                debug!(
                    peer = %peer_fp,
                    conn_id = conn.stable_id(),
                    "spawning inbound handler on outbound-pooled connection"
                );
                tokio::spawn(handle_connection(
                    conn,
                    verifier,
                    operators,
                    sealer,
                    baseline,
                    inbox,
                    op_router,
                    events,
                    qa_rate_limit,
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
            qa_rate_limit.clone(),
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
            peer_connections.clone(),
            known_neighbors.clone(),
            sealer.clone(),
            mesh.clone(),
            baseline.clone(),
            config.whisper.qa.clone(),
            llm_submitter.clone(),
            config.llm.invocation_threshold,
            events_tx.clone(),
            crate::whisper_qa::ConfirmSink {
                inbox: inbox.clone(),
                originator_fp: fingerprint,
                alert_threshold: config.alerts.threshold,
                backend_label: llm.name().to_string(),
                quorum: config.whisper.qa.quorum,
            },
            shutdown_rx.clone(),
        );

        // Operator file watches (inotify). `None` when there are no file
        // rules or inotify is unavailable — the channel then closes and the
        // pipeline just serves kernel events.
        let (file_events_tx, file_events_rx) = mpsc::channel::<Event>(FILE_EVENT_CHANNEL_CAPACITY);
        let file_monitor_task = crate::monitor::spawn_file_monitor_task(
            &monitor_rules,
            file_events_tx,
            shutdown_rx.clone(),
        );

        let pipeline_task = spawn_pipeline_task(
            event_source.start(),
            file_events_rx,
            baseline.clone(),
            analyzer.clone(),
            monitor_rules.clone(),
            llm_submitter,
            config.llm.invocation_threshold,
            config.whisper.qa.threshold,
            whisper_qa_tx,
            inbox.clone(),
            fingerprint,
            config.alerts.threshold,
            llm.name().to_string(),
            events_tx.clone(),
            eventlog_handle.clone(),
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
            eventlog_tasks,
            revocations,
            file_monitor_task,
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
    /// The verified revocation set, for tests and diagnostics.
    pub fn revocations(&self) -> &Arc<RevocationStore> {
        &self.revocations
    }

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
        // The writer exits when the pipeline drops the last handle, so
        // it must be joined after the pipeline, not alongside it.
        if let Some((writer, maintenance)) = self.eventlog_tasks.take() {
            let _ = writer.await;
            let _ = maintenance.await;
        }
        if let Some(task) = self.file_monitor_task.take() {
            let _ = task.await;
        }
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

/// Everything the pin task needs to decide whether a gossiping peer is
/// allowed to become a trusted neighbour.
pub(crate) struct EnrollmentContext {
    pub policy: crate::config::EnrollmentPolicy,
    pub cluster_id: String,
    /// Operator keys this agent trusts — the same set that authorises
    /// commands. A grant is only as good as the key that signed it.
    pub operators: Arc<StaticResolver>,
    pub revocations: Arc<RevocationStore>,
}

/// How a peer qualified for a pin. The distinction matters because only
/// a verified grant justifies bypassing the bootstrap window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// A valid operator-signed grant. Admission is proven, so the
    /// bootstrap window — which exists to bound *unproven* TOFU
    /// admission — does not apply.
    Granted,
    /// No grant, but policy is `tofu`, so the bootstrap window is the
    /// admission control and must still gate the pin.
    Tofu,
    Refused,
}

impl EnrollmentContext {
    /// Decide whether, and on what basis, a gossiping peer may be pinned.
    ///
    /// A grant is verified whenever one is present, regardless of policy:
    /// it is operator-signed evidence and is no less valid because this
    /// agent happens to be running in `tofu` mode. That also smooths
    /// migration — agents not yet flipped still honour grants, so a newly
    /// provisioned host joins even after their bootstrap windows closed.
    fn admits(&self, peer: &PeerInfo) -> Admission {
        let tofu = self.policy == crate::config::EnrollmentPolicy::Tofu;
        let Some(grant) = decode_grant(peer.membership_grant.as_deref()) else {
            if !tofu {
                debug!(
                    peer = %peer.fingerprint,
                    "refusing pin: enrollment=grant but peer published no usable grant"
                );
            }
            return if tofu {
                Admission::Tofu
            } else {
                Admission::Refused
            };
        };
        let operators = self.operators.clone();
        let resolve = move |fp: &Fingerprint| operators.resolve(fp);
        match bowery_whisper::mesh_trust::verify_grant(
            &grant,
            &peer.fingerprint,
            &self.cluster_id,
            &resolve,
            SystemTime::now(),
        ) {
            Ok(()) => Admission::Granted,
            Err(e) => {
                warn!(peer = %peer.fingerprint, error = %e, "membership grant rejected");
                // A bad grant under tofu is not itself disqualifying —
                // tofu admits ungranted peers anyway, and treating a
                // malformed grant as worse than none would let any peer
                // lock itself out by publishing garbage.
                if tofu {
                    Admission::Tofu
                } else {
                    Admission::Refused
                }
            }
        }
    }
}

/// Decode a base64 gossip-KV grant. Any malformation is simply "no
/// grant" — a peer cannot gain anything by publishing garbage.
fn decode_grant(encoded: Option<&str>) -> Option<bowery_proto::MembershipGrant> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded?.as_bytes())
        .ok()?;
    <bowery_proto::MembershipGrant as prost::Message>::decode(raw.as_slice()).ok()
}

fn spawn_pin_task(
    mut peers_watcher: watch::Receiver<Vec<PeerInfo>>,
    kn: Arc<KnownNeighbors>,
    enrollment: Arc<EnrollmentContext>,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let snapshot: Vec<PeerInfo> = peers_watcher.borrow().clone();
            for peer in snapshot {
                // A peer revoked while already pinned must lose the pin,
                // not merely fail to gain one — otherwise containment
                // only applies to hosts we hadn't met yet.
                if enrollment.revocations.is_revoked(&peer.fingerprint) {
                    match kn.unpin(&peer.fingerprint) {
                        Ok(true) => warn!(
                            peer = %peer.fingerprint,
                            "evicted revoked peer from the pin set"
                        ),
                        Ok(false) => {}
                        Err(e) => warn!(error = %e, "failed to evict revoked peer"),
                    }
                    continue;
                }
                let outcome = match enrollment.admits(&peer) {
                    Admission::Refused => continue,
                    Admission::Granted => kn.pin_authorized(&peer.verifying_key),
                    Admission::Tofu => kn.try_pin(&peer.verifying_key),
                };
                match outcome {
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
                    Ok(PinOutcome::Revoked) => {
                        warn!(peer = %peer.fingerprint, "refusing pin: identity is revoked");
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
    pub fanout_rate_limit: Arc<RateLimit>,
    /// Hard ceiling on per-query wall-clock timeout.
    pub max_timeout: Duration,
    /// Operator-distributed YARA rules: the persistent store, the
    /// propagation seen-set (loop prevention), the alert inbox to raise
    /// matches into, and the caps that bound scan work. `None` rejects
    /// `YaraPush` with `policy_denied`, per this struct's convention.
    pub yara: Option<Arc<YaraContext>>,
    /// Revocation store + pin store, for `RevokePush`. `None` rejects
    /// the command with `policy_denied`.
    pub revocation: Option<Arc<RevocationContext>>,
}

/// Hop budget ceiling for revocation propagation. Small on purpose: a
/// mesh deep enough to need more hops than this has bigger problems, and
/// the store-based termination already stops echoes.
const MAX_REVOKE_TTL: u32 = 8;

/// Everything the YARA push handler needs, grouped so the router stays
/// readable.
pub(crate) struct YaraContext {
    pub store: Arc<YaraStore>,
    pub seen: Arc<YaraSeen>,
    pub inbox: Arc<AlertInbox>,
    /// Bounds concurrent scans: a fleet-wide push otherwise pins every
    /// core on every agent at once.
    pub scan_permits: Arc<tokio::sync::Semaphore>,
    pub config: crate::config::YaraConfig,
    /// This agent's own fingerprint, stamped on emitted alerts.
    pub originator_fp: Fingerprint,
}

/// Token-bucket rate limiter keyed on peer fingerprint. Each request
/// consumes one token; tokens refill at `refill_per_sec` and a
/// first-time key starts with a full `burst`.
///
/// Keyed on an *authenticated* fingerprint in both of its uses, so the
/// map is bounded by the number of enrolled operators / pinned peers
/// rather than by anything an unauthenticated attacker controls.
#[derive(Debug)]
pub(crate) struct RateLimit {
    inner: std::sync::Mutex<std::collections::HashMap<Fingerprint, Bucket>>,
    refill_per_sec: f64,
    burst: f64,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: std::time::Instant,
}

impl Default for RateLimit {
    /// The struct is reachable through `OperatorCommandRouter`'s derived
    /// `Default`, where the field is the fan-out limiter.
    fn default() -> Self {
        Self::fanout()
    }
}

impl RateLimit {
    fn new(refill_per_sec: f64, burst: f64) -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
            refill_per_sec,
            burst,
        }
    }

    /// Defends against a compromised operator key driving the relay into
    /// sustained mesh-amplified work. Sized for the realistic operator
    /// workflow: one fan-out every 5 seconds for interactive triage,
    /// bursts up to 6 queries.
    pub(crate) fn fanout() -> Self {
        Self::new(0.2, 6.0)
    }

    /// Bounds inbound whisper questions from a single peer. Each one
    /// costs an O(baseline) scan, so an otherwise-legitimate pinned peer
    /// that has been compromised could pin a core just by asking. A
    /// burst of 10 covers a genuine exec storm on the asking host;
    /// 1/sec sustained is far above any honest steady-state rate.
    pub(crate) fn whisper_qa() -> Self {
        Self::new(1.0, 10.0)
    }

    /// Try to consume one token for `key`. Returns `true` if a token was
    /// available; `false` if the caller should be shed.
    pub(crate) fn try_acquire(&self, key: &Fingerprint) -> bool {
        let now = std::time::Instant::now();
        let mut map = self.inner.lock().expect("rate-limit mutex poisoned");
        let bucket = map.entry(*key).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.burst);
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
    qa_rate_limit: Arc<RateLimit>,
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
                            let qa_rate_limit = qa_rate_limit.clone();
                            tokio::spawn(handle_connection(
                                conn, verifier, operators, sealer, baseline, inbox, op_router,
                                events, qa_rate_limit,
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

/// Spawn the per-connection accept loops. Run two parallel readers:
///
/// - **Uni stream loop.** Heartbeats, `Subscribe`, and `OperatorCommand`
///   land here. Responses go back via fresh outbound uni streams.
/// - **Bi stream loop (slice 3).** Whisper `Question` lands here.
///   The reply rides the same bidi stream so it doesn't race the
///   uni-loop's `accept_uni` for delivery.
///
/// Splitting the two readers means a pooled connection can receive
/// peer-initiated whispers without the dialler's bi-loop racing its
/// own `ask()` for the response — they use disjoint Quinn streams.
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
    qa_rate_limit: Arc<RateLimit>,
) {
    let uni = tokio::spawn(handle_uni_stream_loop(
        conn.clone(),
        verifier.clone(),
        operators.clone(),
        sealer.clone(),
        inbox,
        op_router,
        events_tx.clone(),
    ));
    let bi = tokio::spawn(handle_bi_stream_loop(
        conn,
        verifier,
        sealer,
        baseline,
        events_tx,
        qa_rate_limit,
    ));
    let _ = tokio::join!(uni, bi);
}

#[allow(clippy::too_many_arguments)]
async fn handle_uni_stream_loop(
    conn: BoweryConnection,
    verifier: Arc<Verifier<ResolverArc>>,
    operators: Arc<StaticResolver>,
    sealer: Arc<Sealer>,
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
                    Some(Body::Question(_)) => {
                        // Slice 3: questions ride bidi streams now. A
                        // Question on a uni stream is a stale-protocol
                        // peer or an oversight; log and ignore.
                        warn!(
                            sender = %env.sender,
                            "received whisper Question on uni stream; ignoring (Q&A is bidi)"
                        );
                    }
                    Some(Body::Subscribe(s)) => {
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
            }
            Err(e) => warn!(error = %e, "envelope verification failed"),
        }
    }
}

async fn handle_bi_stream_loop(
    conn: BoweryConnection,
    verifier: Arc<Verifier<ResolverArc>>,
    sealer: Arc<Sealer>,
    baseline: Arc<Baseline>,
    events_tx: broadcast::Sender<AgentEvent>,
    qa_rate_limit: Arc<RateLimit>,
) {
    loop {
        let Ok((bytes, reply)) = conn.accept_request().await else {
            break;
        };
        let env = match verifier.open(&bytes) {
            Ok(env) => env,
            Err(e) => {
                warn!(error = %e, "bidi envelope verification failed");
                continue;
            }
        };
        info!(sender = %env.sender, nonce = env.nonce, "received bi envelope");
        let _ = events_tx.send(AgentEvent::EnvelopeReceived {
            sender: env.sender,
            nonce: env.nonce,
        });
        match env.payload.body {
            Some(Body::Question(q)) => {
                // Check the budget before the O(baseline) scan, not after.
                if !qa_rate_limit.try_acquire(&env.sender) {
                    warn!(sender = %env.sender, "whisper Q&A rate limit exceeded; shedding");
                    continue;
                }
                if let Err(e) = respond_to_question(reply, &sealer, &baseline, env.sender, q).await
                {
                    warn!(sender = %env.sender, error = %e, "whisper Q&A response failed");
                }
            }
            other => {
                warn!(
                    sender = %env.sender,
                    body = ?other.as_ref().map(body_kind_name),
                    "unexpected body on bi stream; ignoring"
                );
            }
        }
    }
}

fn body_kind_name(body: &Body) -> &'static str {
    match body {
        Body::Question(_) => "Question",
        Body::Answer(_) => "Answer",
        Body::Alert(_) => "Alert",
        Body::OperatorCommand(_) => "OperatorCommand",
        Body::OperatorResult(_) => "OperatorResult",
        Body::Heartbeat(_) => "Heartbeat",
        Body::NeighborOp(_) => "NeighborOp",
        Body::Subscribe(_) => "Subscribe",
        Body::Alerts(_) => "Alerts",
    }
}

async fn respond_to_question(
    reply: bowery_whisper::transport::Reply,
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
        // Drop `reply` without sending — Quinn resets the stream and
        // the asker observes a transport error / timeout.
        return Ok(());
    }
    // `ttl_ms` is an absolute deadline (see `qa::ttl_deadline_ms`). An
    // expired question is work whose answer nobody is still waiting for
    // — the other responder path (`qa.rs`) already drops these, and not
    // doing so here left a free way to buy baseline scans with stale
    // replayed-shaped traffic.
    let now_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX);
    if now_ms > question.ttl_ms {
        debug!(
            sender = %asker,
            now_ms,
            ttl_ms = question.ttl_ms,
            "dropping expired whisper question"
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
    reply.send(&outbound).await
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

    // Chunk the response so no single envelope exceeds the transport frame
    // cap. A full inbox serialized as one `Alerts` envelope overflows the
    // cap and is rejected by `send_envelope`, which would silently deliver
    // ZERO alerts — an EDR blind spot precisely when a host is noisy. Each
    // batch is its own envelope; the last is flagged `end = true` and
    // carries the authoritative cursor. The operator reassembles until it
    // sees `end`.
    let batches = chunk_alerts(items, ALERTS_CHUNK_BUDGET_BYTES);
    let last = batches.len() - 1; // chunk_alerts always returns ≥ 1 batch
    for (i, batch) in batches.into_iter().enumerate() {
        let end = i == last;
        // Only the terminal chunk carries the authoritative cursor.
        let cursor_for = if end { cursor } else { 0 };
        send_alerts_chunk(conn, sealer, &operator, batch, cursor_for, end).await?;
    }

    let _ = events_tx.send(AgentEvent::AlertsDelivered {
        operator,
        delivered,
        cursor_unix_ms: cursor,
    });
    Ok(())
}

/// Budget for one `Alerts` envelope's items, well under `MAX_FRAME_BYTES`
/// (64 KiB) so the sealed envelope (signature + header + wrapper) still
/// fits the transport frame cap.
const ALERTS_CHUNK_BUDGET_BYTES: usize = 48 * 1024;

/// Split alerts into batches that each encode to under `budget` bytes.
/// Order is preserved and no item is dropped; a single oversized alert
/// still goes out alone (best effort) so the stream always progresses.
/// Always returns at least one batch (possibly empty) so the caller emits
/// a terminal `end` chunk even for an empty inbox.
fn chunk_alerts(items: Vec<Alert>, budget: usize) -> Vec<Vec<Alert>> {
    use prost::Message as _;
    let mut batches: Vec<Vec<Alert>> = Vec::new();
    let mut batch: Vec<Alert> = Vec::new();
    let mut batch_bytes = 0usize;
    for item in items {
        let item_bytes = item.encoded_len();
        if !batch.is_empty() && batch_bytes + item_bytes > budget {
            batches.push(std::mem::take(&mut batch));
            batch_bytes = 0;
        }
        batch_bytes += item_bytes;
        batch.push(item);
    }
    batches.push(batch);
    batches
}

/// Seal and send one `Alerts` chunk to the operator. `end` marks the final
/// chunk of a (possibly multi-envelope) response; only the final chunk's
/// `cursor_unix_ms` is authoritative on the operator side.
async fn send_alerts_chunk(
    conn: &BoweryConnection,
    sealer: &Sealer,
    operator: &Fingerprint,
    items: Vec<Alert>,
    cursor_unix_ms: u64,
    end: bool,
) -> Result<(), bowery_whisper::transport::Error> {
    let response = Alerts {
        items,
        cursor_unix_ms,
        end,
    };
    let outbound = sealer.seal_for(operator, &WhisperPayload::alerts(response));
    conn.send_envelope(&outbound).await
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
        Some(OperatorCommandBody::YaraPush(_)) => "yara_push",
        Some(OperatorCommandBody::RevokePush(_)) => "revoke_push",
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

    // Revocation delivery + propagation. Placed before the other
    // bodies because it is the only command whose payload authorises
    // itself: the revocation carries an operator signature over its own
    // fields, so a relaying peer can drop it but cannot forge one.
    if let Some(OperatorCommandBody::RevokePush(p)) = &cmd.command {
        let Some(rev_ctx) = op_router.revocation.clone() else {
            return send_sql_error(
                conn,
                &sealer,
                &operator,
                &request_id,
                "policy_denied",
                "revocation handling is not enabled on this agent",
            )
            .await;
        };
        if p.fanout && is_direct_operator && !op_router.fanout_rate_limit.try_acquire(&operator) {
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
        // Clamp the hop budget so one push can't be handed an unbounded
        // one, same as YARA.
        let capped = bowery_proto::RevokePush {
            ttl: p.ttl.min(MAX_REVOKE_TTL),
            ..p.clone()
        };
        let outcome = handle_revoke_push(
            conn,
            &sealer,
            operator,
            &request_id,
            &capped,
            &cmd.forwarded_from_operator,
            &rev_ctx,
            op_router.relay.as_ref(),
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

    // YARA rule distribution. Like SQL it streams its own responses;
    // unlike SQL it may propagate multiple hops (bounded by ttl + the
    // seen-set) because a detection rule is meant to reach the fleet.
    if let Some(OperatorCommandBody::YaraPush(p)) = &cmd.command {
        let Some(yara_ctx) = op_router.yara.clone() else {
            return send_sql_error(
                conn,
                &sealer,
                &operator,
                &request_id,
                "policy_denied",
                "yara rule distribution is not enabled on this agent",
            )
            .await;
        };
        // Rate-limit the entry-point push the same way as fan-out SQL:
        // one operator shouldn't be able to flood the mesh with pushes.
        if p.fanout && is_direct_operator && !op_router.fanout_rate_limit.try_acquire(&operator) {
            warn!(
                operator = %operator,
                request_id = %request_id,
                "rate-limiting yara push: operator bucket empty"
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
        // Clamp the operator's requested TTL to this agent's cap, so a
        // single push can't be given an unbounded hop budget.
        let capped = bowery_proto::YaraPush {
            ttl: p.ttl.min(yara_ctx.config.max_ttl),
            ..p.clone()
        };
        let outcome = handle_yara_push(
            conn,
            &sealer,
            operator,
            &request_id,
            &capped,
            &cmd.forwarded_from_operator,
            &yara_ctx,
            op_router.relay.as_ref(),
            effective_timeout,
            events_tx,
        )
        .await;
        let _ = events_tx.send(AgentEvent::OperatorCommandHandled {
            operator,
            request_id,
            kind: command_kind,
        });
        return outcome;
    }

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

    // -- Phase 3: fan-out completion terminator. --
    //
    // In fan-out mode the operator can't know how many peers will reply,
    // so it reads until it sees this explicit end marker: a chunk with an
    // empty `agent_fp` and `end = true`. No real chunk ever has an empty
    // agent_fp — the relay stamps its own 32-byte fingerprint and every
    // peer stamps its own — so the sentinel is unambiguous. We send it
    // whenever fan-out was requested (even with zero peers, or with the
    // relay disabled), which is what makes an empty-peer fan-out return
    // immediately instead of hanging until the operator's exchange
    // timeout. Single-agent mode never sends it (the operator stops on
    // the first `end && !fanout`).
    if fanout {
        let terminator = SqlChunk {
            columns: Vec::new(),
            rows: Vec::new(),
            end: true,
            agent_fp: Vec::new(),
        };
        send_chunk(conn, sealer, &operator, request_id, terminator).await?;
    }
    Ok(())
}

/// Handle an operator `YaraPush`: store the rule, scan the requested
/// targets, alert on matches, report back, and (when asked) propagate the
/// push onward through the mesh.
///
/// Ordering matters. The seen-set is consulted **first** so a push that
/// has already been handled is dropped whole — no re-store, no re-scan,
/// and crucially no re-forward. That's what terminates propagation in a
/// cyclic pinned-peer graph; the `ttl` hop counter is the independent
/// structural backstop.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_yara_push(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    push: &bowery_proto::YaraPush,
    forwarded_authorization: &[u8],
    yara: &Arc<YaraContext>,
    relay: Option<&Arc<RelayContext>>,
    timeout: Duration,
    events_tx: &broadcast::Sender<AgentEvent>,
) -> Result<(), bowery_whisper::transport::Error> {
    let self_fp = sealer.fingerprint();
    let operator_hex = operator.to_string();

    // --- Loop prevention. Must come before any work or forwarding. ---
    if !yara.seen.check_and_record(&operator_hex, request_id) {
        debug!(
            operator = %operator,
            request_id,
            rule = %push.rule_id,
            "dropping already-seen yara push (propagation loop cut)"
        );
        // Still terminate the operator's stream cleanly.
        return send_yara_report(
            conn,
            sealer,
            &operator,
            request_id,
            bowery_proto::YaraReport {
                agent_fp: self_fp.as_bytes().to_vec(),
                rule_id: push.rule_id.clone(),
                matches: Vec::new(),
                scanned: 0,
                errors: vec!["already handled (duplicate push)".to_string()],
                end: true,
            },
        )
        .await;
    }

    // --- Store. Idempotent + content-verified. ---
    let mut errors: Vec<String> = Vec::new();
    if push.rules.len() > yara.config.max_rule_bytes {
        return send_sql_error(
            conn,
            sealer,
            &operator,
            request_id,
            "rule_too_large",
            &format!(
                "rule is {} bytes; this agent's cap is {}",
                push.rules.len(),
                yara.config.max_rule_bytes
            ),
        )
        .await;
    }
    match yara.store.store(
        &push.rule_id,
        &push.rules,
        &operator_hex,
        request_id,
        current_unix_ms() / 1000,
    ) {
        Ok(true) => info!(rule = %push.rule_id, operator = %operator, "yara rule stored"),
        Ok(false) => debug!(rule = %push.rule_id, "yara rule already stored"),
        Err(e) => {
            return send_sql_error(
                conn,
                sealer,
                &operator,
                request_id,
                "rule_rejected",
                &e.to_string(),
            )
            .await;
        }
    }

    // --- Scan. CPU-heavy: bounded by a semaphore, run off the async
    // runtime, and capped by config. ---
    let mut matches: Vec<bowery_proto::YaraMatch> = Vec::new();
    let mut scanned: u32 = 0;
    if push.targets.is_empty() {
        debug!(rule = %push.rule_id, "no scan targets; stored only");
    } else {
        let permit = yara.scan_permits.clone().acquire_owned().await;
        if permit.is_err() {
            errors.push("scan semaphore closed".to_string());
        } else {
            let source = String::from_utf8_lossy(&push.rules).into_owned();
            let targets: Vec<PathBuf> = push.targets.iter().map(PathBuf::from).collect();
            let limits = bowery_yara::ScanLimits {
                max_file_bytes: yara.config.max_file_bytes,
                max_files: yara.config.max_files_per_scan,
                max_depth: yara.config.max_depth,
            };
            let secs = i32::try_from(timeout.as_secs()).unwrap_or(i32::MAX).max(1);
            let scan = tokio::task::spawn_blocking(move || {
                let rules = bowery_yara::Rules::compile(&source)?;
                let mut agg = bowery_yara::ScanOutcome::default();
                for t in targets {
                    let out = rules.scan_path(&t, limits, secs);
                    agg.matches.extend(out.matches);
                    agg.scanned += out.scanned;
                    agg.errors.extend(out.errors);
                }
                Ok::<_, bowery_yara::YaraError>(agg)
            })
            .await;
            match scan {
                Ok(Ok(out)) => {
                    scanned = out.scanned;
                    errors.extend(out.errors);
                    for m in out.matches {
                        matches.push(bowery_proto::YaraMatch {
                            rule_name: m.rule_name,
                            path: m.path.display().to_string(),
                            tags: m.tags,
                        });
                    }
                }
                // A rule that won't compile, or an engine-less build, is
                // reported rather than failing the whole push — the rule
                // is still stored and propagated.
                Ok(Err(e)) => errors.push(e.to_string()),
                Err(e) => errors.push(format!("scan task failed: {e}")),
            }
        }
    }

    // --- Alert on every match, so a hit reaches the operator's inbox
    // even if they aren't watching this command's response. ---
    for m in &matches {
        let alert = Alert {
            originator_fp: yara.originator_fp.as_bytes().to_vec(),
            episode_id: format!("yara-{}-{}", push.rule_id, current_unix_ms()),
            exe_sha256_hex: String::new(),
            exe_path: m.path.clone(),
            suspicion: 1.0,
            rationale: format!("yara rule `{}` matched {}", m.rule_name, m.path),
            suggested_actions: Vec::new(),
            ts_unix_ms: current_unix_ms(),
            backend: "yara".to_string(),
            // A YARA hit is a direct content match; there is nothing for
            // the neighbourhood to corroborate.
            confirmation: None,
        };
        let episode_id = alert.episode_id.clone();
        warn!(rule = %m.rule_name, path = %m.path, "YARA MATCH");
        yara.inbox.append(alert);
        let _ = events_tx.send(AgentEvent::AlertEmitted {
            episode_id,
            suspicion: 1.0,
        });
    }

    // --- Report this agent's own result. ---
    send_yara_report(
        conn,
        sealer,
        &operator,
        request_id,
        bowery_proto::YaraReport {
            agent_fp: self_fp.as_bytes().to_vec(),
            rule_id: push.rule_id.clone(),
            matches,
            scanned,
            errors,
            end: true,
        },
    )
    .await?;

    // --- Propagate. Unlike SQL fan-out (one hop), a rule is meant to
    // reach the whole mesh, so forwarding is bounded by ttl rather than
    // by "have I been forwarded already". ---
    if push.fanout
        && push.ttl > 0
        && let Some(relay) = relay
    {
        relay_yara_push(
            conn,
            sealer,
            operator,
            request_id,
            push,
            forwarded_authorization,
            relay,
            timeout,
        )
        .await?;
    }

    // Fan-out completion terminator (empty agent_fp), mirroring the SQL
    // path so the operator's read loop ends promptly rather than waiting
    // out its timeout.
    if push.fanout {
        send_yara_report(
            conn,
            sealer,
            &operator,
            request_id,
            bowery_proto::YaraReport {
                agent_fp: Vec::new(),
                rule_id: push.rule_id.clone(),
                matches: Vec::new(),
                scanned: 0,
                errors: Vec::new(),
                end: true,
            },
        )
        .await?;
    }
    Ok(())
}

/// Forward a YARA push to every pinned peer, decrementing `ttl`, and pipe
/// each peer's sealed reports back to the operator verbatim.
///
/// Peers seal their reports for the *operator*, not for us, so a relaying
/// agent can drop a report but cannot forge or read one.
#[allow(clippy::too_many_arguments)]
async fn relay_yara_push(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    push: &bowery_proto::YaraPush,
    forwarded_authorization: &[u8],
    relay: &Arc<RelayContext>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    let peers: Vec<PeerInfo> = relay
        .peers_watcher
        .borrow()
        .clone()
        .into_iter()
        .filter(|p| relay.known_neighbors.resolve(&p.fingerprint).is_some())
        .filter(|p| p.fingerprint != sealer.fingerprint())
        .collect();
    if peers.is_empty() {
        return Ok(());
    }

    let (bytes_tx, mut bytes_rx) = mpsc::channel::<Vec<u8>>(64);
    let mut join_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    // Each hop sees one less TTL; the push that reaches ttl == 0 stops.
    let onward = bowery_proto::YaraPush {
        rule_id: push.rule_id.clone(),
        rules: push.rules.clone(),
        targets: push.targets.clone(),
        fanout: true,
        ttl: push.ttl.saturating_sub(1),
    };

    for peer in peers {
        let bytes_tx = bytes_tx.clone();
        let endpoint = relay.endpoint.clone();
        let kn = relay.known_neighbors.clone();
        let sealer_clone = sealer.clone();
        let request_id = request_id.to_string();
        let auth = forwarded_authorization.to_vec();
        let onward = onward.clone();
        join_set.spawn(async move {
            run_peer_yara_push(
                endpoint,
                kn,
                &sealer_clone,
                peer,
                auth,
                onward,
                &request_id,
                timeout,
                bytes_tx,
            )
            .await;
        });
    }
    drop(bytes_tx);

    let drain: Result<(), bowery_whisper::transport::Error> = async {
        while let Some(bytes) = bytes_rx.recv().await {
            conn.send_envelope(&bytes).await?;
        }
        Ok(())
    }
    .await;

    join_set.abort_all();
    while join_set.join_next().await.is_some() {}
    let _ = operator; // attribution is carried by each peer's own sealing
    drain
}

/// Push a rule to one peer and stream its sealed reports back.
#[allow(clippy::too_many_arguments)]
async fn run_peer_yara_push(
    endpoint: BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: &Arc<Sealer>,
    peer: PeerInfo,
    forwarded_authorization: Vec<u8>,
    push: bowery_proto::YaraPush,
    request_id: &str,
    timeout: Duration,
    bytes_tx: mpsc::Sender<Vec<u8>>,
) {
    use bowery_proto::{OperatorCommand, OperatorCommandBody, WhisperEnvelope};
    use prost::Message as _;

    let peer_fp = peer.fingerprint;
    let cmd = OperatorCommand {
        request_id: request_id.to_string(),
        timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        forwarded_from_operator: forwarded_authorization,
        command: Some(OperatorCommandBody::YaraPush(push)),
    };
    let outbound = sealer.seal_for(&peer_fp, &WhisperPayload::operator_command(cmd));

    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(kn, peer_fp));
    let Ok(conn) = endpoint.dial(dial_verifier, peer.whisper_addr).await else {
        warn!(peer = %peer_fp, "yara propagation dial failed");
        return;
    };
    if conn.send_envelope(&outbound).await.is_err() {
        warn!(peer = %peer_fp, "yara propagation send failed");
        return;
    }

    // Relay whatever the peer sends back, until it closes or we time out.
    // Reports are sealed for the operator, so we only peek at the sender
    // claim for sanity — verification is the operator's job.
    let pump = async {
        loop {
            let Ok(bytes) = conn.recv_envelope().await else {
                return;
            };
            let Ok(env) = WhisperEnvelope::decode(bytes.as_slice()) else {
                return;
            };
            if env.sender_fingerprint.as_slice() != peer_fp.as_bytes().as_slice() {
                warn!(peer = %peer_fp, "yara propagation sender mismatch");
                return;
            }
            if bytes_tx.send(bytes).await.is_err() {
                return;
            }
        }
    };
    let _ = tokio::time::timeout(timeout, pump).await;
}

/// Helper to seal + send one `YaraReport` envelope.
async fn send_yara_report(
    conn: &BoweryConnection,
    sealer: &Sealer,
    operator: &Fingerprint,
    request_id: &str,
    report: bowery_proto::YaraReport,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::{OperatorResult, OperatorResultBody};
    let response = OperatorResult {
        request_id: request_id.to_string(),
        result: Some(OperatorResultBody::YaraReport(report)),
    };
    let outbound = sealer.seal_for(operator, &WhisperPayload::operator_result(response));
    conn.send_envelope(&outbound).await
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
    mut file_events: mpsc::Receiver<Event>,
    baseline: Arc<Baseline>,
    analyzer: Arc<Analyzer>,
    monitor_rules: Arc<MonitorRules>,
    llm_submitter: Submitter,
    llm_threshold: f32,
    whisper_threshold: f32,
    whisper_qa_tx: mpsc::Sender<WhisperQaTrigger>,
    inbox: Arc<AlertInbox>,
    originator_fp: Fingerprint,
    alert_threshold: f32,
    backend_label: String,
    events_tx: broadcast::Sender<AgentEvent>,
    eventlog: Option<EventLogHandle>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Each source can end independently, and a closed channel returns
        // `None` on every poll — which would spin the select. Track both and
        // disable the drained branch; exit only when BOTH are done. Notably
        // a dead kernel event source (e.g. the BPF source exiting) must not
        // take operator file monitoring down with it, and vice versa.
        let mut events_open = true;
        let mut file_events_open = true;
        loop {
            if !events_open && !file_events_open {
                break;
            }
            tokio::select! {
                event = events.recv(), if events_open => {
                    let Some(event) = event else { events_open = false; continue };
                    process_event(
                        &baseline,
                        &analyzer,
                        &monitor_rules,
                        &llm_submitter,
                        llm_threshold,
                        whisper_threshold,
                        &whisper_qa_tx,
                        &inbox,
                        originator_fp,
                        alert_threshold,
                        &backend_label,
                        &events_tx,
                        eventlog.as_ref(),
                        event,
                    ).await;
                }
                // Operator-configured file watches (inotify) fan in here.
                file_event = file_events.recv(), if file_events_open => {
                    match file_event {
                        Some(event) => {
                            process_event(
                                &baseline,
                                &analyzer,
                                &monitor_rules,
                                &llm_submitter,
                                llm_threshold,
                                whisper_threshold,
                                &whisper_qa_tx,
                                &inbox,
                                originator_fp,
                                alert_threshold,
                                &backend_label,
                                &events_tx,
                                eventlog.as_ref(),
                                event,
                            ).await;
                        }
                        None => file_events_open = false,
                    }
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
    monitor_rules: &Arc<MonitorRules>,
    llm_submitter: &Submitter,
    llm_threshold: f32,
    whisper_threshold: f32,
    whisper_qa_tx: &mpsc::Sender<WhisperQaTrigger>,
    inbox: &Arc<AlertInbox>,
    originator_fp: Fingerprint,
    alert_threshold: f32,
    backend_label: &str,
    events_tx: &broadcast::Sender<AgentEvent>,
    eventlog: Option<&EventLogHandle>,
    event: Event,
) {
    // Record first, analyse second. Every event goes to the log
    // regardless of whether anything downstream scores it — the whole
    // value of a history is that it contains the things nobody thought
    // were interesting at the time. This is also the only consumer of
    // ProcessExit / NetworkConnect / FileOpen, which the analyzer
    // pipeline still has no scoring path for.
    if let Some(log) = eventlog {
        log.record(event.clone());
    }

    // ProcessExec drives the full analyzer pipeline; FileChange is the
    // operator-configured file-integrity signal. The rest are recorded
    // above and carry no scoring path yet.
    match event {
        Event::ProcessExec(exec) => {
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
        Event::FileChange(change) => {
            process_file_change(
                monitor_rules,
                inbox,
                originator_fp,
                backend_label,
                events_tx,
                change,
            )
            .await;
        }
        // Recorded above; no analyzer path yet. Network connections in
        // particular are now queryable history even though nothing scores
        // them — which is what makes retrospective hunting possible
        // before the detection content exists.
        Event::ProcessExit(_) | Event::FileOpen(_) | Event::NetworkConnect(_) => {}
    }
}

/// Emit an alert for a change to an operator-watched file.
///
/// Unlike exec events there's no scoring step: the operator explicitly asked
/// to be told about this file, so a matching change always alerts. The rule's
/// severity becomes the alert's suspicion so existing consumers (inbox
/// ordering, the console, `bowery_alerts`) rank it sensibly.
///
/// The file is hashed after the change so the operator sees what it became;
/// a deleted (or unreadable) file yields an empty hash rather than dropping
/// the alert — "it's gone" is exactly what you want to hear about.
async fn process_file_change(
    monitor_rules: &Arc<MonitorRules>,
    inbox: &Arc<AlertInbox>,
    originator_fp: Fingerprint,
    backend_label: &str,
    events_tx: &broadcast::Sender<AgentEvent>,
    change: bowery_events::FileChange,
) {
    // The watcher only emits changes that already matched a rule, but
    // re-resolve here so the alert can name it (and so a future producer
    // can't inject unmatched paths).
    let Some(rule) = monitor_rules
        .file_rules()
        .iter()
        .find(|r| r.path == change.path && r.ops.contains(&change.op))
    else {
        return;
    };

    let path_for_hash = change.path.clone();
    let sha_hex =
        match tokio::task::spawn_blocking(move || enrich::sha256_file(&path_for_hash)).await {
            Ok(Ok(sha)) => sha_to_hex(&sha),
            // Deleted/unreadable file: still alert, just without a hash.
            Ok(Err(_)) | Err(_) => String::new(),
        };

    let op = crate::monitor::file_op_label(change.op);
    let suspicion = crate::monitor::severity_weight(rule.severity);
    let alert = Alert {
        originator_fp: originator_fp.as_bytes().to_vec(),
        episode_id: format!("file-{}-{}", rule.id, current_unix_ms()),
        exe_sha256_hex: sha_hex,
        exe_path: change.path.display().to_string(),
        suspicion,
        rationale: format!(
            "file rule `{}`: {} was {}",
            rule.id,
            change.path.display(),
            op
        ),
        suggested_actions: Vec::new(),
        ts_unix_ms: current_unix_ms(),
        backend: backend_label.to_string(),
        // File watches don't whisper: a deleted file has no hash to ask
        // the neighbourhood about, and the operator asked to be told
        // regardless of what peers think.
        confirmation: None,
    };
    let episode_id = alert.episode_id.clone();
    info!(rule = %rule.id, path = %change.path.display(), op, "file monitor alert");
    inbox.append(alert);
    let _ = events_tx.send(AgentEvent::AlertEmitted {
        episode_id,
        suspicion,
    });
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
            // First alert for this episode. A whisper round may follow and
            // append a confirmed, superseding alert.
            confirmation: None,
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
                    // The LLM refinement path doesn't carry the whisper
                    // round's outcome; confirmation arrives on its own
                    // superseding alert from `finish_round`.
                    confirmation: None,
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
                            // A genuine enforcement FAILURE (e.g. kill(2)
                            // EPERM — the agent lacks CAP_KILL). Record it as
                            // `Failed`, NOT `Suppressed`: containment did not
                            // happen, and the operator must see that in the
                            // audit trail (`bowery_audit` outcome_kind =
                            // "failed") rather than mistaking it for a
                            // deliberate policy suppression.
                            error!(
                                action_id = id,
                                episode = %episode,
                                error = %e,
                                "response engine FAILED to enforce action"
                            );
                            let outcome = ActionOutcome::failed(e.to_string());
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

/// Open the configured event log, honouring the `:memory:` sentinel the
/// baseline path uses so tests and ephemeral agents behave the same way
/// across both stores.
fn open_event_log(
    cfg: &crate::config::EventLogConfig,
) -> Result<bowery_eventlog::EventLog, bowery_eventlog::Error> {
    if cfg.path.as_os_str() == ":memory:" {
        bowery_eventlog::EventLog::open_in_memory()
    } else {
        bowery_eventlog::EventLog::open(&cfg.path)
    }
}

/// Read a membership grant from disk and return it base64-encoded for
/// the gossip KV.
///
/// The grant is validated as decodable here so a corrupt file is caught
/// at startup with a clear message, rather than silently gossiping
/// garbage that every peer rejects.
fn load_grant_b64(path: &std::path::Path) -> Result<String, AgentError> {
    use base64::Engine as _;
    let raw = std::fs::read(path).map_err(|e| {
        AgentError::Config(format!("reading membership grant {}: {e}", path.display()))
    })?;
    // Accept either raw protobuf or a base64 text file, since the CLI
    // writes base64 and operators may paste either.
    let bytes = match base64::engine::general_purpose::STANDARD.decode(raw.trim_ascii()) {
        Ok(decoded)
            if <bowery_proto::MembershipGrant as prost::Message>::decode(decoded.as_slice())
                .is_ok() =>
        {
            decoded
        }
        _ => raw.clone(),
    };
    <bowery_proto::MembershipGrant as prost::Message>::decode(bytes.as_slice()).map_err(|e| {
        AgentError::Config(format!(
            "membership grant {} is not a valid MembershipGrant: {e}",
            path.display()
        ))
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
}

// ---------------------------------------------------------------------------
// Revocation propagation
// ---------------------------------------------------------------------------

/// Everything the `RevokePush` handler needs.
pub(crate) struct RevocationContext {
    pub store: Arc<RevocationStore>,
    pub known_neighbors: Arc<KnownNeighbors>,
    pub cluster_id: String,
    pub operators: Arc<StaticResolver>,
}

/// Apply an operator-signed revocation and, when asked, spread it.
///
/// The security argument here is different from every other command, and
/// simpler: the payload is **self-authenticating**. A `Revocation`
/// carries its own operator signature over its own fields, so this agent
/// verifies it directly rather than trusting whoever relayed it. A
/// compromised peer can therefore *drop* a revocation in transit — it
/// cannot forge one, and cannot use the relay path to eject healthy
/// agents. Dropping is the residual risk, which is why
/// `bowery_revocations` is queryable fleet-wide: convergence is checked,
/// not assumed.
///
/// Propagation terminates on the store rather than on a separate
/// seen-set: revocations are permanent, so a re-received one is not new
/// and is not forwarded. `ttl` remains as an independent structural
/// bound.
#[allow(clippy::too_many_arguments)]
async fn handle_revoke_push(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    push: &bowery_proto::RevokePush,
    forwarded_authorization: &[u8],
    ctx: &Arc<RevocationContext>,
    relay: Option<&Arc<RelayContext>>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    let self_fp = sealer.fingerprint();
    let mut report = bowery_proto::RevokeReport {
        agent_fp: self_fp.as_bytes().to_vec(),
        end: true,
        ..Default::default()
    };

    let decoded = <bowery_proto::Revocation as prost::Message>::decode(push.revocation.as_slice());
    let mut is_new = false;
    match decoded {
        Err(e) => report.error = format!("undecodable revocation: {e}"),
        Ok(revocation) => {
            let ops = ctx.operators.clone();
            let resolve = move |fp: &Fingerprint| ops.resolve(fp);
            match bowery_whisper::mesh_trust::verify_revocation(
                &revocation,
                &ctx.cluster_id,
                &resolve,
            ) {
                Err(e) => {
                    warn!(sender = %operator, error = %e, "rejecting unverifiable revocation");
                    report.error = e.to_string();
                }
                Ok(target) => match ctx.store.insert(target, &revocation) {
                    Err(e) => report.error = format!("persisting revocation: {e}"),
                    Ok(new) => {
                        is_new = new;
                        report.accepted = true;
                        report.already_known = !new;
                        // Evict immediately rather than waiting for the
                        // next gossip tick: the window between "we know
                        // this peer is compromised" and "we stop
                        // trusting it" should be as close to zero as the
                        // code can make it.
                        report.evicted = ctx.known_neighbors.unpin(&target).unwrap_or(false);
                        if new {
                            warn!(
                                target = %target,
                                reason = %revocation.reason,
                                evicted = report.evicted,
                                "revocation applied"
                            );
                        }
                    }
                },
            }
        }
    }

    send_revoke_report(conn, sealer, &operator, request_id, report).await?;

    // Forward only what we hadn't already seen — that is what makes a
    // flood converge instead of echoing around the mesh forever.
    if push.fanout
        && push.ttl > 0
        && is_new
        && let Some(relay) = relay
    {
        relay_revoke_push(
            conn,
            sealer,
            request_id,
            push,
            forwarded_authorization,
            relay,
            timeout,
        )
        .await?;
    }

    if push.fanout {
        send_revoke_report(
            conn,
            sealer,
            &operator,
            request_id,
            bowery_proto::RevokeReport {
                agent_fp: Vec::new(),
                end: true,
                ..Default::default()
            },
        )
        .await?;
    }
    Ok(())
}

async fn send_revoke_report(
    conn: &BoweryConnection,
    sealer: &Sealer,
    operator: &Fingerprint,
    request_id: &str,
    report: bowery_proto::RevokeReport,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::{OperatorResult, OperatorResultBody};
    let response = OperatorResult {
        request_id: request_id.to_string(),
        result: Some(OperatorResultBody::RevokeReport(report)),
    };
    let outbound = sealer.seal_for(operator, &WhisperPayload::operator_result(response));
    conn.send_envelope(&outbound).await
}

/// Forward a revocation to every pinned peer with `ttl` decremented,
/// piping their sealed reports back to the operator verbatim.
async fn relay_revoke_push(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    request_id: &str,
    push: &bowery_proto::RevokePush,
    forwarded_authorization: &[u8],
    relay: &Arc<RelayContext>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    let peers: Vec<PeerInfo> = relay
        .peers_watcher
        .borrow()
        .clone()
        .into_iter()
        .filter(|p| relay.known_neighbors.resolve(&p.fingerprint).is_some())
        .filter(|p| p.fingerprint != sealer.fingerprint())
        .collect();
    if peers.is_empty() {
        return Ok(());
    }

    let (bytes_tx, mut bytes_rx) = mpsc::channel::<Vec<u8>>(64);
    let mut join_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let onward = bowery_proto::RevokePush {
        revocation: push.revocation.clone(),
        fanout: true,
        ttl: push.ttl.saturating_sub(1),
    };

    for peer in peers {
        let bytes_tx = bytes_tx.clone();
        let endpoint = relay.endpoint.clone();
        let kn = relay.known_neighbors.clone();
        let sealer_clone = sealer.clone();
        let request_id = request_id.to_string();
        let auth = forwarded_authorization.to_vec();
        let onward = onward.clone();
        join_set.spawn(async move {
            run_peer_revoke_push(
                endpoint,
                kn,
                &sealer_clone,
                peer,
                auth,
                onward,
                &request_id,
                timeout,
                bytes_tx,
            )
            .await;
        });
    }
    drop(bytes_tx);

    let drain: Result<(), bowery_whisper::transport::Error> = async {
        while let Some(bytes) = bytes_rx.recv().await {
            conn.send_envelope(&bytes).await?;
        }
        Ok(())
    }
    .await;

    join_set.abort_all();
    while join_set.join_next().await.is_some() {}
    drain
}

#[allow(clippy::too_many_arguments)]
async fn run_peer_revoke_push(
    endpoint: BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: &Arc<Sealer>,
    peer: PeerInfo,
    forwarded_authorization: Vec<u8>,
    push: bowery_proto::RevokePush,
    request_id: &str,
    timeout: Duration,
    bytes_tx: mpsc::Sender<Vec<u8>>,
) {
    use bowery_proto::{OperatorCommand, OperatorCommandBody, WhisperEnvelope};
    use prost::Message as _;

    let peer_fp = peer.fingerprint;
    let cmd = OperatorCommand {
        request_id: request_id.to_string(),
        timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        forwarded_from_operator: forwarded_authorization,
        command: Some(OperatorCommandBody::RevokePush(push)),
    };
    let outbound = sealer.seal_for(&peer_fp, &WhisperPayload::operator_command(cmd));

    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(kn, peer_fp));
    let Ok(conn) = endpoint.dial(dial_verifier, peer.whisper_addr).await else {
        warn!(peer = %peer_fp, "revocation propagation dial failed");
        return;
    };
    if conn.send_envelope(&outbound).await.is_err() {
        warn!(peer = %peer_fp, "revocation propagation send failed");
        return;
    }

    let pump = async {
        loop {
            let Ok(bytes) = conn.recv_envelope().await else {
                return;
            };
            let Ok(env) = WhisperEnvelope::decode(bytes.as_slice()) else {
                return;
            };
            if env.sender_fingerprint.as_slice() != peer_fp.as_bytes().as_slice() {
                warn!(peer = %peer_fp, "revocation propagation sender mismatch");
                return;
            }
            if bytes_tx.send(bytes).await.is_err() {
                return;
            }
        }
    };
    let _ = tokio::time::timeout(timeout, pump).await;
}

#[cfg(test)]
mod alert_chunk_tests {
    use super::*;

    fn sample_alert(i: u64, rationale_len: usize) -> Alert {
        Alert {
            originator_fp: vec![0u8; 32],
            episode_id: format!("ep-{i}"),
            exe_sha256_hex: "ab".repeat(32),
            exe_path: "/usr/bin/example".to_string(),
            suspicion: 0.9,
            rationale: "x".repeat(rationale_len),
            suggested_actions: vec![],
            ts_unix_ms: i,
            backend: "test".to_string(),
            confirmation: None,
        }
    }

    #[test]
    fn chunk_alerts_preserves_all_items_in_order_and_bounds_batches() {
        let items: Vec<Alert> = (0..50).map(|i| sample_alert(i, 500)).collect();
        let budget = 4 * 1024;
        let batches = chunk_alerts(items.clone(), budget);

        // Splitting actually happened (50 * ~550B >> 4 KiB).
        assert!(
            batches.len() > 1,
            "expected multiple batches, got {}",
            batches.len()
        );

        // No item dropped; order preserved — the whole point (the bug this
        // fixes silently delivered ZERO alerts).
        let flat: Vec<Alert> = batches.iter().flatten().cloned().collect();
        assert_eq!(flat, items);

        // Every batch fits the budget, except a lone oversized item.
        for b in &batches {
            let bytes: usize = b.iter().map(prost::Message::encoded_len).sum();
            assert!(
                b.len() == 1 || bytes <= budget,
                "batch of {} = {bytes}B exceeds budget {budget}",
                b.len()
            );
        }
    }

    #[test]
    fn chunk_alerts_empty_yields_one_terminal_batch() {
        // An empty inbox still yields one (empty) batch → one `end` chunk,
        // so the operator's read loop always terminates.
        assert_eq!(chunk_alerts(Vec::new(), ALERTS_CHUNK_BUDGET_BYTES).len(), 1);
    }
}
