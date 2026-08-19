//! The supervised agent runtime: TOFU store + QUIC endpoint + mesh +
//! pin-task + accept-task + heartbeat-task, with watch-channel-driven
//! shutdown.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_analysis::{Analyzer, RoleFeatures, RoleVector, Verdict};
use bowery_baseline::{Baseline, UpsertOutcome};
use bowery_crypto::{Fingerprint, Identity};
use bowery_events::source::EventSource;
use bowery_events::{Event, enrich};
use bowery_llm::{
    InferenceOutcome, InferenceQueue, LlmAnalyzer, LlmVerdict, MockLlmAnalyzer, MockMode,
    QueueConfig, ShedReason,
};
use bowery_mesh::{KEY_ROLE_VECTOR, Mesh, MeshConfig, PeerInfo};
use bowery_proto::{Alert, Alerts, Subscribe, WhisperPayload};
use bowery_response::{
    ActionOutcome, AuditSink, JsonlFileSink, NoopEngine, NoopSink, ProcessKillEngine,
    ResponseEngine, ResponsePolicy, action, audit,
};

use crate::config::ResponseEngineKind;
use crate::eventlog_writer::EventLogHandle;
use bowery_whisper::known_neighbors::{KnownNeighbors, PinOutcome};
use bowery_whisper::mesh_trust::RevocationStore;
use bowery_whisper::pool::PeerConnections;
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::{BoweryConnection, BoweryEndpoint};
use bowery_whisper::{CompositeResolver, FingerprintResolver, Sealer, StaticResolver, Verifier};
use ed25519_dalek::VerifyingKey;

use crate::bloom_publisher;
use crate::inbox::AlertInbox;
use crate::monitor::MonitorRules;
use crate::seen::RecentlySeen;
use crate::whisper_qa::{WhisperContext, WhisperQaTrigger, spawn_whisper_qa_task};
use crate::yara_store::YaraStore;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::Config;

/// Version plus the commit it was built from, e.g. `0.2.0+2bff539`.
///
/// The commit is the load-bearing half. A crate version alone cannot
/// distinguish two builds of the same release, which is exactly the
/// question asked when checking whether a rollout landed. A `-dirty`
/// suffix means the tree had uncommitted changes, so the named commit
/// does not describe what is running.
///
/// Gossiped to peers and surfaced as `bowery_mesh_peers.agent_version`,
/// which turns "is the fleet on the same build" into one query.
pub const AGENT_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BOWERY_GIT_COMMIT"));
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
    /// A cross-host corroboration round finished, whether or not it
    /// alerted. Carries the per-outcome tally and, when a peer owned up
    /// to the observation, the evidence it returned — attribution the
    /// observing host could not have derived on its own.
    ///
    /// Boxed because it is much larger than the other variants, and
    /// every subscriber pays the size of the widest one.
    CorroborationRound(Box<crate::corroboration::RoundOutcome>),
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
    /// `None` when cross-host corroboration is disabled.
    corroboration_task: Option<JoinHandle<()>>,
    revocations: Arc<RevocationStore>,
    silences: Arc<crate::silence_store::SilenceStore>,
    /// `None` when no file rules are configured (or inotify is unavailable).
    file_monitor_task: Option<JoinHandle<()>>,
    detection_stats: Arc<crate::detection_stats::DetectionStats>,
    detection_flush_task: JoinHandle<()>,
    probe_watchdog_task: JoinHandle<()>,
    peer_watchdog_task: Option<JoinHandle<()>>,
    action_release_task: JoinHandle<()>,
    role_publisher_task: JoinHandle<()>,
    log_witness_task: JoinHandle<()>,
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

        // Taken before `start` consumes the source, and before the SQL
        // surface is assembled so `bowery_probe_status` can read it.
        // `None` means the agent has no health-reporting sensor — not
        // missing information, but the finding itself: it is not
        // watching.
        let probe_health = event_source.health();
        if probe_health.is_none() {
            warn!(
                "no health-reporting event source; this agent observes no kernel events \
                 and will alert about its own blindness"
            );
        }

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
        // Operator judgements about which findings are benign. Loaded
        // and re-verified the same way revocations are — the file
        // carries no authority of its own, only the signatures in it do.
        let silences = {
            let ops = operators.clone();
            let resolve = move |fp: &Fingerprint| ops.resolve(fp);
            Arc::new(crate::silence_store::SilenceStore::load(
                &config.alerts.silences_path,
                &cluster_id_for_trust,
                &resolve,
                crate::inbox::current_unix_ms(),
            ))
        };
        if !silences.is_empty() {
            info!(
                count = silences.len(),
                "loaded operator alert silences; matching alerts will be damped or withheld"
            );
        }

        let inbox = Arc::new(
            AlertInbox::new(config.inbox.capacity, config.inbox.retention)
                .with_silences(silences.clone(), config.alerts.threshold),
        );

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
        // `mode` gates whether the host may be touched at all; `engine`
        // only says how. Off is the default and short-circuits before
        // any engine is constructed — a host that is not meant to act
        // should not be loading a BPF blocker or asking for CAP_KILL to
        // do nothing with them.
        let build_engine = |policy: ResponsePolicy| -> Result<Box<dyn ResponseEngine>, AgentError> {
            Ok(match config.response.engine {
                ResponseEngineKind::Noop => Box::new(NoopEngine::new(policy)),
                ResponseEngineKind::ProcessKill => Box::new(ProcessKillEngine::new(policy)),
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
                    Box::new(crate::response_bpf::BpfLsmEngine::new(policy, blocker))
                }
            })
        };
        let response_engine: Arc<dyn ResponseEngine> = match config.response.mode {
            // Nothing is decided and nothing is done. Reported as a
            // policy suppression, which is what it is.
            crate::config::ResponseMode::Off => Arc::new(NoopEngine::new(response_policy)),
            crate::config::ResponseMode::DryRun => Arc::from(bowery_response::DryRunEngine::new(
                build_engine(response_policy)?,
            )),
            crate::config::ResponseMode::Enforce => Arc::from(build_engine(response_policy)?),
        };
        info!(
            engine = response_engine.name(),
            mode = ?config.response.mode,
            "response engine initialised"
        );
        if config.response.mode == crate::config::ResponseMode::Enforce {
            // Loud on purpose. This is the line an operator greps for
            // after something on this host died unexpectedly.
            warn!(
                engine = response_engine.name(),
                "response enforcement is ARMED — this agent may kill or block on this host"
            );
        }
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
        // Handlers for corroboration queries peers send us, one per
        // kind. Registering a new kind of suspicion is a line here plus
        // its handler — no change to the wire format, the dispatcher,
        // the rate limiter, or the alert path.
        //
        // The connection handler needs our own outbound history, so it
        // is only registered when the event log is on: with no history
        // we cannot distinguish "I did not make that connection" from
        // "I would not have recorded it either way", and answering
        // anyway would manufacture evidence. An unregistered kind is
        // refused, which is exactly the right answer.
        let mut responders = crate::corroboration::ResponderRegistry::new();
        if let Some(log) = eventlog_store.as_ref() {
            responders = responders.with(Arc::new(
                crate::corroboration::net_inbound::InboundConnectResponder::new(
                    log.clone(),
                    mesh.peers_watcher(),
                ),
            ));
            // Same reasoning, same dependency: "no binary reads that
            // file here" is only evidence from a host whose history
            // covers the window.
            responders = responders.with(Arc::new(
                crate::corroboration::file_access::FileAccessResponder::new(log.clone()),
            ));
        }
        let responders = Arc::new(responders);
        debug!(?responders, "corroboration responders registered");

        // Seeded with every rule the agent knows, so a detection that
        // has never fired is a visible zero rather than a missing row.
        let detection_stats = Arc::new(crate::detection_stats::DetectionStats::new());
        // Fold the counters into the baseline on a slow cadence and at
        // shutdown. Not per fire: a rule can fire thousands of times a
        // day and a write per fire would put SQLite on the alert path
        // for no benefit. Losing the last interval on a hard kill is the
        // right trade for keeping detection off the disk.
        let detection_flush_task = {
            let stats = detection_stats.clone();
            let baseline = baseline.clone();
            let mut shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                // `interval_at`, not `interval`: the latter's first tick
                // completes immediately, which wrote a full table of
                // zeros to SQLite at every agent start for no reason.
                let period = Duration::from_mins(5);
                let mut tick =
                    tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    let stopping = tokio::select! {
                        _ = tick.tick() => false,
                        _ = shutdown.changed() => true,
                    };
                    let counts = stats.drain();
                    let refs: Vec<(&str, u64, Option<u64>)> = counts
                        .iter()
                        .map(|(id, n, last)| (*id, *n, *last))
                        .collect();
                    if let Err(e) = baseline.add_detection_counts(&refs) {
                        warn!(error = %e, "persisting detection counts failed");
                    }
                    if stopping {
                        break;
                    }
                }
            })
        };

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
            .with_extra_table(Arc::new(
                crate::sql_tables::BoweryNetDestinationsTable::new(baseline.clone()),
            ))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryRevocationsTable::new(
                revocations.clone(),
            )))
            .with_extra_table(Arc::new(
                crate::sql_tables::BoweryBaselineBinariesTable::new(baseline.clone()),
            ))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryDetectionsTable::new(
                detection_stats.clone(),
                baseline.clone(),
            )))
            .with_extra_table(Arc::new(crate::sql_tables::BoweryAlertsTable::new(
                inbox.clone(),
            )))
            .with_extra_table(Arc::new(crate::sql_tables::BowerySilencesTable::new(Some(
                silences.clone(),
            ))))
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
            .with_extra_table(Arc::new(crate::sql_tables::BoweryProbeStatusTable::new(
                probe_health.clone(),
            )))
            .with_extra_table(Arc::new({
                let status = crate::sql_tables::BoweryEventLogStatusTable::new(
                    eventlog_store.clone(),
                    eventlog_handle
                        .as_ref()
                        .map(EventLogHandle::dropped_counter),
                );
                // Without the write-failure side, this view can report
                // `recording=1, dropped=0` while every write is failing.
                match eventlog_handle.as_ref() {
                    Some(h) => status.with_health(h.health()),
                    None => status,
                }
            }));
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
            silence: Some(Arc::new(SilenceContext {
                store: silences.clone(),
                operators: operators.clone(),
            })),
            yara: Some(Arc::new(YaraContext {
                store: yara_store.clone(),
                // Remembering a push for 30 minutes is far longer than any
                // flood takes to settle, so a rule can't lap the mesh.
                seen: Arc::new(RecentlySeen::new(Duration::from_mins(30), 4096)),
                inbox: inbox.clone(),
                scan_permits: Arc::new(tokio::sync::Semaphore::new(
                    config.yara.max_concurrent_scans.max(1),
                )),
                config: config.yara.clone(),
                originator_fp: fingerprint,
            })),
        });

        // The bar a peer's "never seen it" must clear before we send
        // one. Built once so both inbound paths use identical policy.
        let coverage_bar = crate::whisper_qa::CoverageBar {
            min_binaries: config.whisper.qa.min_baseline_binaries,
            min_age: config.whisper.qa.min_baseline_age,
        };

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
        // Assembled once: the accept loop and the pooled-connection
        // handler serve the same requests from the same state, and used
        // to restate it as twelve and eleven positional arguments.
        let server_ctx = crate::operator::ServerContext {
            operators: operators.clone(),
            sealer: sealer.clone(),
            baseline: baseline.clone(),
            inbox: inbox.clone(),
            op_router: op_router.clone(),
            events_tx: events_tx.clone(),
            qa_rate_limit: qa_rate_limit.clone(),
            responders: responders.clone(),
            coverage_bar,
        };

        let peer_connections = {
            let envelope_verifier = Arc::new(Verifier::new(resolver.clone(), sealer.fingerprint()));
            let ctx_for_handler = server_ctx.clone();
            let sealer_for_handler = sealer.clone();
            let inbox_for_handler = inbox.clone();
            let events_for_handler = events_tx.clone();
            let responders_for_handler = responders.clone();
            let handler: bowery_whisper::pool::InboundHandler = Arc::new(move |peer_fp, conn| {
                let verifier = envelope_verifier.clone();
                let _sealer = sealer_for_handler.clone();
                let _inbox = inbox_for_handler.clone();
                let _events = events_for_handler.clone();
                let _responders = responders_for_handler.clone();
                debug!(
                    peer = %peer_fp,
                    conn_id = conn.stable_id(),
                    "spawning inbound handler on outbound-pooled connection"
                );
                tokio::spawn(crate::operator::handle_connection(
                    conn,
                    verifier,
                    ctx_for_handler.clone(),
                ));
            });
            PeerConnections::with_handler(endpoint.clone(), handler)
        };

        let accept_task = crate::operator::spawn_accept_task(
            endpoint.clone(),
            resolver.clone(),
            server_ctx.clone(),
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
        // Shared with the whisper round: parked here when an action
        // needs the fleet's agreement, released there when it arrives.
        let pending_actions = Arc::new(crate::pending_actions::PendingActions::new(
            crate::pending_actions::DEFAULT_TTL,
        ));
        // Bounded: a released action is rare (it needs a confirmed
        // round), and a full channel must shed rather than block the
        // whisper task.
        let (release_tx, release_rx) = mpsc::channel::<crate::pending_actions::Release>(256);
        let action_release_task = spawn_action_release_task(
            release_rx,
            pending_actions.clone(),
            response_engine.clone(),
            audit_sink.clone(),
            identity.clone(),
            events_tx.clone(),
            shutdown_rx.clone(),
        );
        let llm_outcomes_task = spawn_llm_outcomes_task(
            llm_out_rx,
            inbox.clone(),
            fingerprint,
            config.alerts.threshold,
            llm.name().to_string(),
            response_engine.clone(),
            audit_sink.clone(),
            identity.clone(),
            pending_actions.clone(),
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
                pending: pending_actions.clone(),
                release_tx: Some(release_tx.clone()),
                inbox: inbox.clone(),
                originator_fp: fingerprint,
                alert_threshold: config.alerts.threshold,
                backend_label: llm.name().to_string(),
                quorum: config.whisper.qa.quorum,
            },
            shutdown_rx.clone(),
        );

        // Package provenance, loaded in the background and never
        // awaited. Reading dpkg's metadata took five seconds on a runner
        // with 53,000 packaged executables, and awaiting it here delayed
        // every task created afterwards — including the file monitor,
        // which meant five seconds of a "ready" agent not watching the
        // files it was configured to watch. An optimisation must not
        // gate the sensors. Until the index arrives, provenance answers
        // Unknown, which damps nothing.
        let packages = Arc::new(bowery_analysis::provenance::ProvenanceCache::empty());
        {
            let packages = packages.clone();
            tokio::task::spawn_blocking(move || {
                let index = bowery_analysis::provenance::PackageIndex::load_system();
                if index.is_available() {
                    info!(executables = index.len(), "package provenance index loaded");
                } else {
                    warn!(
                        "no package database found; executions cannot be damped by \
                         provenance and rare binaries will score as never-seen"
                    );
                }
                packages.install(index);
            });
        }

        // Cross-host corroboration. Detectors raise claims; the engine
        // picks an audience, asks, tallies, and alerts. Kind-agnostic:
        // it is started once and every present and future detection
        // shares it.
        let (claims, corroboration_task) = if config.whisper.corroboration.enabled {
            let (sink, task) = crate::corroboration::spawn(
                crate::corroboration::CorroborationContext {
                    pool: peer_connections.clone(),
                    known_neighbors: known_neighbors.clone(),
                    sealer: sealer.clone(),
                    peers: mesh.peers_watcher(),
                    inbox: inbox.clone(),
                    originator_fp: fingerprint,
                    backend_label: llm.name().to_string(),
                    config: config.whisper.corroboration.clone(),
                    events_tx: events_tx.clone(),
                },
                shutdown_rx.clone(),
            );
            (Some(sink), Some(task))
        } else {
            info!("cross-host corroboration disabled by config");
            (None, None)
        };

        // Operator file watches (inotify). `None` when there are no file
        // rules or inotify is unavailable — the channel then closes and the
        // pipeline just serves kernel events.
        let (file_events_tx, file_events_rx) = mpsc::channel::<Event>(FILE_EVENT_CHANNEL_CAPACITY);
        let file_monitor_task = crate::monitor::spawn_file_monitor_task(
            &monitor_rules,
            file_events_tx,
            shutdown_rx.clone(),
        );

        // One struct rather than 27 positional arguments. Adding a
        // detection used to mean editing four parameter lists and six
        // call sites in the right order, and three bugs in one session
        // came from exactly that.
        let pipeline_ctx = crate::pipeline::PipelineContext {
            // Half an hour: long enough that describing a hash is
            // once-per-hash in practice, short enough that a descriptor
            // written before the package index finished loading gets
            // filled in the same session rather than at next restart.
            // Capped well above the few thousand distinct binaries a
            // host runs, so it bounds a pathological case only.
            described: Arc::new(crate::seen::RecentlySeen::new(
                Duration::from_mins(30),
                8192,
            )),
            baseline: baseline.clone(),
            analyzer: analyzer.clone(),
            packages,
            eventlog: eventlog_handle.clone(),
            eventlog_store: eventlog_store.clone(),
            inbox: inbox.clone(),
            monitor_rules: monitor_rules.clone(),
            originator_fp: fingerprint,
            backend_label: llm.name().to_string(),
            alert_threshold: config.alerts.threshold,
            events_tx: events_tx.clone(),
            llm_submitter,
            llm_threshold: config.llm.invocation_threshold,
            whisper_threshold: config.whisper.qa.threshold,
            whisper_qa_tx,
            claims,
            corroboration: config.whisper.corroboration.clone(),
            detection: config.detection.clone(),
            detections: detection_stats.clone(),
            discovery: Arc::new(bowery_analysis::DiscoveryTracker::new(
                config.detection.discovery_window,
                config.detection.discovery_threshold,
            )),
            suppressor: Arc::new(bowery_analysis::AlertSuppressor::new(
                config.detection.repeat_window,
            )),
            suppress_window: config.detection.repeat_window,
            procs: Arc::new(crate::proc_table::ProcTable::default()),
            beacons: config.detection.beacons.then(|| {
                Arc::new(bowery_analysis::BeaconTracker::new(
                    // Long enough to hold several intervals of a slow
                    // beacon without keeping a day of timestamps.
                    Duration::from_hours(12),
                    bowery_analysis::beacon::DEFAULT_MIN_SAMPLES,
                    bowery_analysis::beacon::DEFAULT_MAX_JITTER,
                ))
            }),
            mass_writes: config.detection.mass_writes.then(|| {
                Arc::new(bowery_analysis::MassWriteTracker::new(
                    config.detection.mass_write_window,
                    config.detection.mass_write_min_files,
                    config.detection.mass_write_min_dirs,
                ))
            }),
        };
        let pipeline_task = crate::pipeline::spawn(
            pipeline_ctx,
            event_source.start(),
            file_events_rx,
            shutdown_rx.clone(),
        );

        // A neighbour that stops talking is a finding here, because it
        // cannot be one there. Started after the pipeline so this
        // agent's own startup is already past.
        let peer_watchdog_task = config.detection.peer_liveness.then(|| {
            crate::peer_watchdog::spawn(
                mesh.peers_watcher(),
                inbox.clone(),
                fingerprint,
                llm.name().to_string(),
                config.detection.peer_grace,
                events_tx.clone(),
                shutdown_rx.clone(),
            )
        });

        // Blindness reaches an operator the same way any finding does.
        // Started after the pipeline so a source that fails immediately
        // has already recorded why.
        let probe_watchdog_task = crate::probe_watchdog::spawn(
            probe_health.clone(),
            inbox.clone(),
            fingerprint,
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

        // Peers remember how much history this host had, and this host
        // remembers theirs. Shares the role publisher's cadence: it is
        // the same kind of slow, self-describing gossip.
        let log_witness_task = spawn_log_witness_task(
            mesh.clone(),
            identity.clone(),
            eventlog_store.clone(),
            detection_stats.clone(),
            inbox.clone(),
            identity.fingerprint(),
            llm.name().to_string(),
            events_tx.clone(),
            config.role.publish_interval,
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
            corroboration_task,
            revocations,
            silences,
            file_monitor_task,
            detection_stats,
            detection_flush_task,
            probe_watchdog_task,
            peer_watchdog_task,
            action_release_task,
            role_publisher_task,
            log_witness_task,
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

    /// Per-rule fire counters, also exposed as `bowery_detections`.
    ///
    /// Public so an integration test can assert a rule that fired was
    /// actually *counted* — the wiring, not just the counter. Six
    /// separate things went wrong today by being correct in isolation
    /// and connected to nothing.
    pub fn detection_stats(&self) -> &Arc<crate::detection_stats::DetectionStats> {
        &self.detection_stats
    }

    /// Pin store accessor — used by integration tests to seed peers
    /// without going through the chitchat-bootstrap path.
    /// The verified revocation set, for tests and diagnostics.
    pub fn revocations(&self) -> &Arc<RevocationStore> {
        &self.revocations
    }

    /// Operator judgements this agent is honouring.
    pub fn silences(&self) -> &Arc<crate::silence_store::SilenceStore> {
        &self.silences
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
        // After the pipeline: it holds the claim sink, and the engine
        // exits when the last sender drops.
        if let Some(task) = self.corroboration_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.file_monitor_task.take() {
            let _ = task.await;
        }
        let _ = self.detection_flush_task.await;
        let _ = self.probe_watchdog_task.await;
        let _ = self.action_release_task.await;
        if let Some(t) = self.peer_watchdog_task {
            let _ = t.await;
        }
        let _ = self.role_publisher_task.await;
        let _ = self.log_witness_task.await;
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

pub(crate) type ResolverArc = Arc<CompositeResolver<Arc<KnownNeighbors>, Arc<StaticResolver>>>;

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
    /// Operator judgements about which findings are benign. `None` on an
    /// agent that cannot accept them at all.
    pub silence: Option<Arc<SilenceContext>>,
}

/// Hop budget ceiling for revocation propagation. Small on purpose: a
/// mesh deep enough to need more hops than this has bigger problems, and
/// the store-based termination already stops echoes.
pub(crate) const MAX_REVOKE_TTL: u32 = 8;

/// Everything the YARA push handler needs, grouped so the router stays
/// readable.
pub(crate) struct YaraContext {
    pub store: Arc<YaraStore>,
    pub seen: Arc<RecentlySeen>,
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

pub(crate) async fn respond_to_subscribe(
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

/// Soft cap on rows per `SqlChunk` envelope. Trades off
/// per-envelope encoded size (proto + ed25519 sig + QUIC framing
/// overhead) against the operator's "first row" latency. 256 rows
/// of typical /proc-shaped columns sit well under the
/// `MAX_FRAME_BYTES` envelope cap with headroom for wide rows.
pub(crate) const SQL_CHUNK_ROW_LIMIT: usize = 256;

/// Push a rule to one peer and stream its sealed reports back.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_peer_yara_push(
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
pub(crate) async fn send_yara_report(
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
pub(crate) async fn send_chunk(
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
pub(crate) async fn send_sql_error(
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

/// SHA-256 of a *normalised* `OperatorCommandBody`. Delegates
/// to [`bowery_whisper::forwarding::command_body_digest`] so
/// peer + operator + relay all agree on the same hash; see that
/// function's doc-comment for the normalisation rules.
pub(crate) fn command_body_digest(body: &bowery_proto::OperatorCommandBody) -> [u8; 32] {
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

pub(crate) fn encode_row(row: &bowery_sql::Row) -> bowery_proto::SqlRow {
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

/// Is this pid a packaged, unmodified setuid-root privilege helper?
///
/// Answers "did this root process come through the sanctioned path",
/// which is a question about the **parent**: `sudo` execs the command
/// *as root* while the forked `sudo` that waits for it keeps the
/// invoking user's real uid. Checking the executed binary instead made
/// every `sudo <command>` a 0.9 finding — 78 in one day on a live host.
///
/// `false` whenever the parent cannot be resolved, which fails towards
/// alerting: an exemption has to be demonstrated.
/// Why the sanctioned-path exemption did or did not apply.
///
/// Reported rather than reduced to a bool because the answer decides
/// whether an alert an operator is reading is a finding or an artefact,
/// and the two are indistinguishable without it. On a live fleet this
/// rule fired 206 times in a fortnight, every sampled instance an
/// ordinary `sudo`-driven deploy — and nothing recorded *which* check had
/// declined, so the cause could only be guessed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HelperCheck {
    /// The parent is a packaged, unmodified setuid helper. Exempt.
    Helper,
    /// `/proc/<ppid>/exe` could not be read — almost always because the
    /// parent exited between the exec and this lookup. A short-lived
    /// `sudo` running a fast command is exactly that shape.
    ParentGone,
    /// The parent is not setuid, so it did not grant the privilege.
    NotSetuid { exe: String },
    /// Setuid, but no package vouches for it unmodified.
    NotPackaged {
        exe: String,
        provenance: bowery_analysis::provenance::Provenance,
    },
}

impl HelperCheck {
    pub(crate) fn is_helper(&self) -> bool {
        matches!(self, Self::Helper)
    }

    /// One clause for the alert rationale, so a reader can tell an
    /// escalation from a lost race.
    pub(crate) fn why(&self) -> String {
        match self {
            Self::Helper => String::new(),
            Self::ParentGone => " The parent had already exited when this was checked, so \
                 whether it was a sanctioned helper could not be established — a short-lived \
                 `sudo` running a fast command looks exactly like this."
                .to_string(),
            Self::NotSetuid { exe } => {
                format!(" The parent ({exe}) is not setuid, so it did not grant this privilege.")
            }
            Self::NotPackaged { exe, provenance } => format!(
                " The parent ({exe}) is setuid but its provenance is {provenance:?}, so no \
                 package vouches for it."
            ),
        }
    }
}

pub(crate) async fn parent_privilege_helper(
    ppid: u32,
    packages: &Arc<bowery_analysis::provenance::ProvenanceCache>,
) -> HelperCheck {
    let Some(exe) = bowery_events::enrich::pid_exe_path(ppid) else {
        return HelperCheck::ParentGone;
    };
    let Some((setuid, _)) = bowery_analysis::provenance::setid_bits(&exe) else {
        return HelperCheck::ParentGone;
    };
    if !setuid {
        return HelperCheck::NotSetuid {
            exe: exe.display().to_string(),
        };
    }
    let packages = packages.clone();
    tokio::task::spawn_blocking(move || {
        let shown = exe.display().to_string();
        let Ok(sha) = enrich::sha256_file(&exe) else {
            return HelperCheck::ParentGone;
        };
        let provenance = packages.classify(&exe, &sha);
        if bowery_analysis::provenance::is_privilege_helper(true, provenance) {
            HelperCheck::Helper
        } else {
            HelperCheck::NotPackaged {
                exe: shown,
                provenance,
            }
        }
    })
    .await
    .unwrap_or(HelperCheck::ParentGone)
}

/// The finding that best explains the verdict's score.
///
/// The most severe hit, not the first one evaluated. An episode routinely
/// collects several — a binary under `/tmp` that a web server also
/// started trips both the writable-path rule and the lineage rule — and
/// the rationale should lead with the one that drove the number an
/// operator is looking at. Ties keep evaluation order, so the output is
/// stable.
/// The rule that best explains the verdict, as an id.
///
/// Pairs with [`leading_rule_message`] and picks the same hit, so an
/// alert's `rule_id` and its rationale never name different detections.
///
/// An exec that cleared the threshold without any rule firing did so on
/// baseline rarity, which is a score rather than a rule table entry;
/// `baseline.rarity` is its registered id, so the alert is attributable
/// rather than blank.
pub(crate) fn leading_rule_id(verdict: &Verdict) -> String {
    verdict
        .rule_hits
        .iter()
        .reduce(|best, h| {
            if h.severity.weight() > best.severity.weight() {
                h
            } else {
                best
            }
        })
        .map_or_else(|| "baseline.rarity".to_string(), |h| h.rule_id.to_string())
}

pub(crate) fn leading_rule_message(verdict: &Verdict) -> Option<String> {
    verdict
        .rule_hits
        .iter()
        .reduce(|best, h| {
            if h.severity.weight() > best.severity.weight() {
                h
            } else {
                best
            }
        })
        .map(|h| format!("{}: {}", h.rule_id, h.reason))
}

pub(crate) fn sha_to_hex(sha: &[u8; 32]) -> String {
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

/// Carries out (or records the abandonment of) actions that were held
/// waiting on the fleet.
///
/// Separate from the whisper task on purpose: `finish_round` must not
/// block on a kill or a BPF map write, and the audit trail is written by
/// the same path that writes every other entry.
///
/// The sweeper is the other half. An episode whose suspicion never
/// reached the whisper threshold fires no round at all, so nothing will
/// ever release it — without a sweep those actions would sit in the
/// store until the process exited, and the fact that they were decided
/// and dropped would never reach the audit log.
#[allow(clippy::too_many_arguments)]
fn spawn_action_release_task(
    mut releases: mpsc::Receiver<crate::pending_actions::Release>,
    pending: Arc<crate::pending_actions::PendingActions>,
    response_engine: Arc<dyn ResponseEngine>,
    audit_sink: Arc<dyn AuditSink>,
    identity: Arc<Identity>,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut sweep = tokio::time::interval(Duration::from_secs(30));
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let release = tokio::select! {
                r = releases.recv() => match r {
                    Some(r) => Some(r),
                    None => break,
                },
                _ = sweep.tick() => None,
                _ = shutdown_rx.changed() => break,
            };
            if *shutdown_rx.borrow() {
                break;
            }
            let mut batch: Vec<crate::pending_actions::Release> = Vec::new();
            match release {
                Some(r) => batch.push(r),
                None => {
                    for (episode_id, actions) in pending.take_expired(std::time::Instant::now()) {
                        for action in actions {
                            batch.push(crate::pending_actions::Release {
                                episode_id: episode_id.clone(),
                                action,
                                dropped: Some(crate::pending_actions::Dropped::Expired),
                            });
                        }
                    }
                }
            }
            for r in batch {
                let id = r.action.id();
                let outcome = match r.dropped {
                    Some(why) => {
                        // Recorded as a suppression, which is exactly
                        // what it is: a gate said no. The reason names
                        // the gate so this is never confused with a
                        // policy denial or a failed kill.
                        warn!(
                            action_id = id,
                            episode = %r.episode_id,
                            reason = why.reason(),
                            "held action abandoned"
                        );
                        ActionOutcome::suppressed(why.reason())
                    }
                    None => match response_engine.execute(&r.action).await {
                        Ok(o) => o,
                        Err(e) => {
                            error!(
                                action_id = id,
                                episode = %r.episode_id,
                                error = %e,
                                "response engine FAILED to enforce a corroborated action"
                            );
                            ActionOutcome::failed(e.to_string())
                        }
                    },
                };
                let _ = events_tx.send(AgentEvent::ActionAttempted {
                    episode_id: r.episode_id.clone(),
                    action_id: id,
                    outcome: outcome.clone(),
                });
                audit::record(
                    &audit_sink,
                    &identity,
                    response_engine.name(),
                    &r.episode_id,
                    r.action,
                    outcome,
                )
                .await;
            }
        }
        info!("action release task stopped");
    })
}

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
    pending_actions: Arc<crate::pending_actions::PendingActions>,
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
                        &pending_actions,
                        outcome,
                    );
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

#[allow(clippy::too_many_lines)] // one linear outcome path
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
    pending_actions: &Arc<crate::pending_actions::PendingActions>,
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
                let alert = crate::alert_builder::AlertBuilder::new(
                    originator_fp,
                    backend_label,
                    leading_rule_id(&ctx.pre_verdict),
                    episode_id.clone(),
                    verdict.suspicion,
                    verdict.rationale.clone(),
                )
                .subject(
                    ctx.exe_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                )
                .exe_sha256_hex(ctx.exe_sha256_hex.clone().unwrap_or_default())
                .context(
                    ctx.extra
                        .iter()
                        .map(|(k, v)| bowery_proto::Attribute::new(k, v))
                        .collect(),
                )
                .suggested_actions(verdict.suggested_actions.clone())
                .build();
                let appended = inbox.append(alert);
                if appended.stored() {
                    let _ = events_tx.send(AgentEvent::AlertEmitted {
                        episode_id: episode_id.clone(),
                        suspicion: verdict.suspicion,
                    });
                }
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
                // Hard actions can be made to wait for the fleet.
                //
                // Parked rather than gated inside the engine, because
                // the two facts arrive at different times: the action is
                // decided here, with the whisper round only just fired
                // and the alert still carrying no confirmation. An
                // engine asked "is this corroborated?" now would always
                // answer no and deny everything forever.
                //
                // `finish_round` releases it if the neighbourhood
                // confirms, and drops it — with a recorded reason — if
                // it does not. Nothing is ever silently forgotten.
                if response_engine.policy().needs_corroboration(action.id()) {
                    info!(
                        action_id = action.id(),
                        episode = %episode_id,
                        "action held pending neighbourhood corroboration"
                    );
                    pending_actions.park(&episode_id, vec![action], std::time::Instant::now());
                    continue;
                }
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

/// Publish how much event-log history this host holds, and check what
/// neighbours say about theirs.
///
/// Both halves in one task because they share a cadence and neither is
/// worth its own. The publishing half is what lets a *peer* notice this
/// host being cleared; the witnessing half is what lets this host notice
/// a peer being cleared. Neither can do anything about its own log — an
/// attacker who deletes it also deletes the evidence that it was ever
/// bigger, which is exactly why the number has to live somewhere else.
#[allow(clippy::too_many_arguments)] // wiring kept explicit at the call site
fn spawn_log_witness_task(
    mesh: Arc<Mesh>,
    identity: Arc<Identity>,
    event_log: Option<Arc<bowery_eventlog::EventLog>>,
    detections: Arc<crate::detection_stats::DetectionStats>,
    inbox: Arc<AlertInbox>,
    originator_fp: Fingerprint,
    backend_label: String,
    events_tx: broadcast::Sender<AgentEvent>,
    interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut witness = bowery_analysis::log_witness::LogWitness::new();
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    publish_log_report(&mesh, &identity, event_log.as_ref()).await;
                    witness_peer_logs(
                        &mesh,
                        &mut witness,
                        &detections,
                        &inbox,
                        originator_fp,
                        &backend_label,
                        &events_tx,
                    );
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

/// Sign this host's event-log height and gossip it.
async fn publish_log_report(
    mesh: &Arc<Mesh>,
    identity: &Arc<Identity>,
    event_log: Option<&Arc<bowery_eventlog::EventLog>>,
) {
    // A host with no event log has no history to lose, and publishing a
    // zero would make every restart of a logless agent look like a
    // rollback to anyone watching.
    let Some(log) = event_log else { return };
    // `stats` queries SQLite, so it runs off the reactor like every
    // other read of that store.
    let log_for_call = log.clone();
    let highest = match tokio::task::spawn_blocking(move || log_for_call.stats()).await {
        Ok(Ok(stats)) => stats.highest_seq,
        Ok(Err(e)) => {
            warn!(error = %e, "could not read the event log height to publish");
            return;
        }
        Err(e) => {
            warn!(error = %e, "event log height task panicked");
            return;
        }
    };
    let now = crate::inbox::current_unix_ms();
    let fp = identity.fingerprint();
    let signature = identity.sign(&bowery_proto::LogReport::signing_input_for(
        fp.as_bytes(),
        highest,
        now,
    ));
    let report = bowery_proto::LogReport {
        host_fp: fp.as_bytes().to_vec(),
        highest_seq: highest,
        reported_unix_ms: now,
        signature: signature.to_bytes().to_vec(),
    };
    let encoded = {
        use base64::Engine as _;
        use prost::Message as _;
        base64::engine::general_purpose::STANDARD.encode(report.encode_to_vec())
    };
    if let Err(e) = mesh.set_state(bowery_mesh::KEY_LOG_REPORT, encoded).await {
        warn!(error = %e, "failed to publish the log report");
        return;
    }
    debug!(highest_seq = highest, "published event-log height");
}

/// Verify each peer's report and alert if one lost history.
#[allow(clippy::too_many_arguments)] // wiring kept explicit
fn witness_peer_logs(
    mesh: &Arc<Mesh>,
    witness: &mut bowery_analysis::log_witness::LogWitness,
    detections: &Arc<crate::detection_stats::DetectionStats>,
    inbox: &Arc<AlertInbox>,
    originator_fp: Fingerprint,
    backend_label: &str,
    events_tx: &broadcast::Sender<AgentEvent>,
) {
    use bowery_analysis::log_witness::{LogReport as Witnessed, RULE_ID};
    for peer in mesh.peers() {
        let Some(encoded) = peer.log_report.as_ref() else {
            continue;
        };
        let Some(report) = decode_log_report(encoded) else {
            continue;
        };
        // The report must be *about* the peer publishing it, and signed
        // by them. Gossip is unauthenticated, so without both checks a
        // peer could accuse any host of rolling back.
        if report.host_fp.as_slice() != peer.fingerprint.as_bytes() {
            warn!(peer = %peer.fingerprint, "log report names a different host; ignored");
            continue;
        }
        let Some(input) = report.signing_input() else {
            continue;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = report.signature.as_slice().try_into() else {
            continue;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        if bowery_crypto::Identity::verify(&peer.verifying_key, &input, &signature).is_err() {
            warn!(peer = %peer.fingerprint, "log report signature did not verify; ignored");
            continue;
        }

        let fp_hex = peer.fingerprint.to_hex();
        let Some(finding) = witness.observe(
            &fp_hex,
            Witnessed {
                highest_seq: report.highest_seq,
                reported_unix_ms: report.reported_unix_ms,
            },
        ) else {
            continue;
        };

        let why = bowery_analysis::log_witness::rationale(&finding);
        detections.record(RULE_ID);
        warn!(
            rule = RULE_ID,
            peer = %peer.fingerprint,
            witnessed = finding.witnessed_seq,
            reported = finding.reported_seq,
            "a peer's event log went backwards"
        );
        let episode_id = format!("peer-{RULE_ID}-{}", crate::inbox::current_unix_ms());
        let appended = inbox.append(
            crate::alert_builder::AlertBuilder::new(
                originator_fp,
                backend_label,
                RULE_ID,
                episode_id.clone(),
                0.9,
                why,
            )
            .context(vec![
                bowery_proto::Attribute::new("peer", fp_hex),
                bowery_proto::Attribute::new("witnessed_seq", finding.witnessed_seq.to_string()),
                bowery_proto::Attribute::new("reported_seq", finding.reported_seq.to_string()),
                bowery_proto::Attribute::new("events_lost", finding.lost.to_string()),
            ])
            .build(),
        );
        if appended.stored() {
            let _ = events_tx.send(AgentEvent::AlertEmitted {
                episode_id,
                suspicion: 0.9,
            });
        }
    }
}

fn decode_log_report(encoded: &str) -> Option<bowery_proto::LogReport> {
    use base64::Engine as _;
    use prost::Message as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .ok()?;
    bowery_proto::LogReport::decode(bytes.as_slice()).ok()
}

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

pub(crate) async fn send_revoke_report(
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

// ---------------------------------------------------------------------------
// Silence propagation
// ---------------------------------------------------------------------------

/// Everything the `SilencePush` handler needs.
pub(crate) struct SilenceContext {
    /// Holds the cluster id and checks it on accept, so this struct
    /// deliberately does not carry a second copy for the two to disagree
    /// about.
    pub store: Arc<crate::silence_store::SilenceStore>,
    pub operators: Arc<StaticResolver>,
}

pub(crate) async fn send_silence_report(
    conn: &BoweryConnection,
    sealer: &Sealer,
    operator: &Fingerprint,
    request_id: &str,
    report: bowery_proto::SilenceReport,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::{OperatorResult, OperatorResultBody};
    let response = OperatorResult {
        request_id: request_id.to_string(),
        result: Some(OperatorResultBody::SilenceReport(report)),
    };
    let outbound = sealer.seal_for(operator, &WhisperPayload::operator_result(response));
    conn.send_envelope(&outbound).await
}

#[cfg(test)]
mod helper_check_tests {
    use super::HelperCheck;
    use bowery_analysis::provenance::Provenance;

    #[test]
    fn only_a_packaged_setuid_parent_is_a_helper() {
        assert!(HelperCheck::Helper.is_helper());
        assert!(!HelperCheck::ParentGone.is_helper());
        assert!(
            !HelperCheck::NotSetuid {
                exe: "/usr/bin/bash".into()
            }
            .is_helper()
        );
        assert!(
            !HelperCheck::NotPackaged {
                exe: "/tmp/sudo".into(),
                provenance: Provenance::Unpackaged,
            }
            .is_helper()
        );
    }

    /// The exemption declining is the whole reason an alert exists, so
    /// each reason has to reach the operator in words. A rule that fired
    /// 206 times in a fortnight said only "privilege transition to root"
    /// for every one of them.
    #[test]
    fn every_declining_reason_explains_itself() {
        assert!(
            HelperCheck::Helper.why().is_empty(),
            "an exemption says nothing"
        );
        for reason in [
            HelperCheck::ParentGone,
            HelperCheck::NotSetuid {
                exe: "/usr/bin/bash".into(),
            },
            HelperCheck::NotPackaged {
                exe: "/tmp/sudo".into(),
                provenance: Provenance::Unpackaged,
            },
        ] {
            let why = reason.why();
            assert!(why.len() > 30, "{reason:?} explains too little: {why:?}");
        }
        // And the two that name a binary must name it.
        assert!(
            HelperCheck::NotSetuid {
                exe: "/usr/bin/bash".into()
            }
            .why()
            .contains("/usr/bin/bash")
        );
    }

    /// A parent that exited is the case most easily mistaken for an
    /// escalation, so it must say so plainly.
    #[test]
    fn a_vanished_parent_says_the_check_could_not_be_made() {
        let why = HelperCheck::ParentGone.why();
        assert!(why.contains("already exited"), "{why}");
        assert!(
            why.contains("sudo"),
            "the likely benign cause is named: {why}"
        );
    }
}

#[cfg(test)]
mod alert_chunk_tests {
    use super::*;

    fn sample_alert(i: u64, rationale_len: usize) -> Alert {
        Alert {
            originator_fp: vec![0u8; 32],
            rule_id: "cred.read_netrc".into(),
            episode_id: format!("ep-{i}"),
            exe_sha256_hex: "ab".repeat(32),
            exe_path: "/usr/bin/example".to_string(),
            suspicion: 0.9,
            rationale: "x".repeat(rationale_len),
            suggested_actions: vec![],
            ts_unix_ms: i,
            backend: "test".to_string(),
            confirmation: None,
            context: Vec::new(),
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
