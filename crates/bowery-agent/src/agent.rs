//! The supervised agent runtime: TOFU store + QUIC endpoint + mesh +
//! pin-task + accept-task + heartbeat-task, with watch-channel-driven
//! shutdown.

use std::sync::Arc;
use std::time::Duration;

use bowery_crypto::{Fingerprint, Identity};
use bowery_mesh::{Mesh, MeshConfig, PeerInfo};
use bowery_proto::WhisperPayload;
use bowery_whisper::known_neighbors::{KnownNeighbors, PinOutcome};
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::{BoweryConnection, BoweryEndpoint};
use bowery_whisper::{FingerprintResolver, Sealer, Verifier};
use thiserror::Error;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::Config;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const EVENT_CHANNEL_CAPACITY: usize = 4096;

/// Observable events emitted by a running agent.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    PeerPinned(Fingerprint),
    EnvelopeReceived { sender: Fingerprint, nonce: u64 },
    HeartbeatSent { peer: Fingerprint },
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
}

/// A running Bowery agent. Drop or [`Agent::shutdown`] to stop it.
pub struct Agent {
    fingerprint: Fingerprint,
    known_neighbors: Arc<KnownNeighbors>,
    endpoint: BoweryEndpoint,
    mesh: Option<Mesh>,
    shutdown_tx: watch::Sender<bool>,
    events_tx: broadcast::Sender<AgentEvent>,
    pin_task: JoinHandle<()>,
    accept_task: JoinHandle<()>,
    heartbeat_task: JoinHandle<()>,
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
    pub async fn start(config: Config, identity: Arc<Identity>) -> Result<Self, AgentError> {
        let fingerprint = identity.fingerprint();
        info!(fingerprint = %fingerprint, "starting agent");

        let known_neighbors = Arc::new(KnownNeighbors::open(
            &config.known_neighbors.path,
            config.known_neighbors.bootstrap_window,
        )?);

        let accept_verifier = Arc::new(PinnedCertVerifier::new(known_neighbors.clone()));
        let endpoint =
            BoweryEndpoint::bind(identity.clone(), accept_verifier, config.whisper.bind_addr)?;
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
        let mesh = Mesh::start(mesh_cfg).await?;

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
            events_tx.clone(),
            shutdown_rx.clone(),
        );

        let heartbeat_task = spawn_heartbeat_task(
            endpoint.clone(),
            mesh.peers_watcher(),
            known_neighbors.clone(),
            identity,
            config.heartbeat.interval,
            events_tx.clone(),
            shutdown_rx,
        );

        info!(
            fingerprint = %fingerprint,
            mesh = %config.mesh.listen_addr,
            whisper = %whisper_addr,
            "agent ready"
        );

        Ok(Self {
            fingerprint,
            known_neighbors,
            endpoint,
            mesh: Some(mesh),
            shutdown_tx,
            events_tx,
            pin_task,
            accept_task,
            heartbeat_task,
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

    pub async fn shutdown(mut self) -> Result<(), AgentError> {
        let _ = self.shutdown_tx.send(true);
        self.endpoint.close().await;
        let _ = self.pin_task.await;
        let _ = self.accept_task.await;
        let _ = self.heartbeat_task.await;
        if let Some(mesh) = self.mesh.take() {
            mesh.shutdown().await?;
        }
        Ok(())
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
                            let events = events_tx.clone();
                            tokio::spawn(handle_connection(conn, verifier, events));
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
            }
            Err(e) => warn!(error = %e, "envelope verification failed"),
        }
    }
}

fn spawn_heartbeat_task(
    endpoint: BoweryEndpoint,
    peers_watcher: watch::Receiver<Vec<PeerInfo>>,
    kn: Arc<KnownNeighbors>,
    identity: Arc<Identity>,
    interval: Duration,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let sealer = Arc::new(Sealer::new(identity));
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
