//! SWIM-style gossip layer for The Bowery agents.
//!
//! Wraps `chitchat` to provide membership and a small key/value cluster
//! state. Each node publishes:
//! - `version`: agent semver string
//! - `whisper_addr`: the QUIC endpoint to dial for whisper RPC
//! - `verifying_key`: raw 32-byte Ed25519 pubkey, base64-encoded
//!
//! Subscribers receive a typed [`PeerInfo`] for every live peer, with
//! cross-checked fingerprint↔pubkey integrity.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_crypto::{Fingerprint, Identity};
use chitchat::transport::UdpTransport;
use chitchat::{
    ChitchatConfig, ChitchatHandle, ChitchatId, FailureDetectorConfig, NodeState, spawn_chitchat,
};
use ed25519_dalek::VerifyingKey;
use thiserror::Error;
use tokio::sync::watch;
use tracing::warn;

const KEY_VERSION: &str = "version";
const KEY_WHISPER_ADDR: &str = "whisper_addr";
const KEY_VERIFYING_KEY: &str = "verifying_key";
/// Key under which each node publishes its base64-encoded role vector.
pub const KEY_ROLE_VECTOR: &str = "role_vec";
/// Key under which each node publishes its base64-encoded
/// `bowery_proto::BloomAdvert` (Phase 5: tier-1 fingerprint
/// summary). Receivers compare epochs per peer and keep only the
/// highest one they've seen.
pub const KEY_BLOOM_ADVERT: &str = "bloom_advert";
pub const DEFAULT_CLUSTER_ID: &str = "bowery";

#[derive(Debug, Error)]
pub enum Error {
    #[error("mesh start failed: {0}")]
    Start(String),

    #[error("mesh shutdown failed: {0}")]
    Shutdown(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A single live peer as seen by the local mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub fingerprint: Fingerprint,
    pub verifying_key: VerifyingKey,
    pub whisper_addr: SocketAddr,
    pub agent_version: String,
    /// Base64-encoded role vector published by the peer, if any. Decode
    /// with `bowery_analysis::RoleVector::from_base64`.
    pub role_vector: Option<String>,
    /// Base64-encoded `bowery_proto::BloomAdvert` published by the peer,
    /// if any. Decode by base64'ing then `prost::Message::decode`'ing
    /// into `bowery_proto::BloomAdvert`. Phase 5.
    pub bloom_advert: Option<String>,
}

#[derive(Debug)]
pub struct MeshConfig {
    pub identity: Arc<Identity>,
    /// UDP socket the chitchat server listens on.
    pub listen_addr: SocketAddr,
    /// Address other peers should use to reach us via gossip. Usually equals
    /// `listen_addr` for loopback / single-NIC hosts.
    pub advertise_addr: SocketAddr,
    /// Chitchat seed strings (`host:port`).
    pub seed_nodes: Vec<String>,
    /// Address peers should dial for whisper RPC (QUIC).
    pub whisper_addr: SocketAddr,
    pub agent_version: String,
    pub cluster_id: String,
    pub gossip_interval: Duration,
}

impl MeshConfig {
    pub fn new(
        identity: Arc<Identity>,
        listen_addr: SocketAddr,
        whisper_addr: SocketAddr,
        agent_version: impl Into<String>,
    ) -> Self {
        Self {
            identity,
            listen_addr,
            advertise_addr: listen_addr,
            seed_nodes: Vec::new(),
            whisper_addr,
            agent_version: agent_version.into(),
            cluster_id: DEFAULT_CLUSTER_ID.to_string(),
            gossip_interval: Duration::from_millis(500),
        }
    }
}

pub struct Mesh {
    handle: Option<ChitchatHandle>,
    fingerprint: Fingerprint,
    peers_rx: watch::Receiver<Vec<PeerInfo>>,
    refresh_task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Mesh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mesh")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl Mesh {
    pub async fn start(config: MeshConfig) -> Result<Self> {
        let fingerprint = config.identity.fingerprint();
        let node_id = fingerprint.to_hex();
        let chitchat_id = ChitchatId::new(node_id, generation_id_now(), config.advertise_addr);

        let initial_kvs = vec![
            (KEY_VERSION.to_string(), config.agent_version.clone()),
            (
                KEY_WHISPER_ADDR.to_string(),
                config.whisper_addr.to_string(),
            ),
            (
                KEY_VERIFYING_KEY.to_string(),
                BASE64.encode(config.identity.verifying_key().as_bytes()),
            ),
        ];

        let chitchat_config = ChitchatConfig {
            chitchat_id,
            cluster_id: config.cluster_id,
            gossip_interval: config.gossip_interval,
            listen_addr: config.listen_addr,
            seed_nodes: config.seed_nodes,
            failure_detector_config: FailureDetectorConfig::default(),
            marked_for_deletion_grace_period: Duration::from_mins(1),
            catchup_callback: None,
            extra_liveness_predicate: None,
        };

        let handle = spawn_chitchat(chitchat_config, initial_kvs, &UdpTransport)
            .await
            .map_err(|e| Error::Start(e.to_string()))?;

        let live_nodes_rx = handle
            .with_chitchat(|chitchat| chitchat.live_nodes_watcher())
            .await;

        let (peers_tx, peers_rx) = watch::channel(Vec::<PeerInfo>::new());
        let self_fp = fingerprint;

        let refresh_task = tokio::spawn(async move {
            let mut rx = live_nodes_rx;
            loop {
                let peers = build_peer_infos(&rx.borrow(), &self_fp);
                if peers_tx.send(peers).is_err() {
                    break;
                }
                if rx.changed().await.is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            handle: Some(handle),
            fingerprint,
            peers_rx,
            refresh_task,
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        self.peers_rx.borrow().clone()
    }

    pub fn peers_watcher(&self) -> watch::Receiver<Vec<PeerInfo>> {
        self.peers_rx.clone()
    }

    /// Update a key in this node's KV state. Other nodes pick up the new
    /// value via gossip on the next round.
    pub async fn set_state(&self, key: impl Into<String>, value: impl Into<String>) -> Result<()> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| Error::Shutdown("mesh already shut down".into()))?;
        let key = key.into();
        let value = value.into();
        handle
            .with_chitchat(|chitchat| {
                chitchat.self_node_state().set(key.clone(), value.clone());
            })
            .await;
        Ok(())
    }

    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(handle) = self.handle.take() {
            handle
                .shutdown()
                .await
                .map_err(|e| Error::Shutdown(e.to_string()))?;
        }
        self.refresh_task.abort();
        Ok(())
    }
}

fn build_peer_infos(
    nodes: &BTreeMap<ChitchatId, NodeState>,
    self_fp: &Fingerprint,
) -> Vec<PeerInfo> {
    nodes
        .iter()
        .filter_map(|(chitchat_id, state)| {
            let fp = Fingerprint::from_hex(&chitchat_id.node_id).ok()?;
            if &fp == self_fp {
                return None;
            }
            let agent_version = state.get(KEY_VERSION)?.to_string();
            let whisper_addr = state.get(KEY_WHISPER_ADDR)?.parse().ok()?;
            let vk_b64 = state.get(KEY_VERIFYING_KEY)?;
            let bytes = BASE64.decode(vk_b64.as_bytes()).ok()?;
            let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
            let vk = VerifyingKey::from_bytes(&arr).ok()?;
            // Cross-check: the published vk must hash to the claimed fingerprint.
            let derived_fp = Fingerprint::from_verifying_key(&vk);
            if derived_fp != fp {
                warn!(claimed = %fp, derived = %derived_fp, "peer fingerprint/key mismatch");
                return None;
            }
            let role_vector = state.get(KEY_ROLE_VECTOR).map(str::to_string);
            let bloom_advert = state.get(KEY_BLOOM_ADVERT).map(str::to_string);
            Some(PeerInfo {
                fingerprint: fp,
                verifying_key: vk,
                whisper_addr,
                agent_version,
                role_vector,
                bloom_advert,
            })
        })
        .collect()
}

fn generation_id_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn loopback_ephemeral() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    /// Pick an ephemeral UDP port on loopback for chitchat. We ask the OS
    /// then close the socket — small race window where another process
    /// could grab the port, but acceptable for tests.
    fn ephemeral_udp_port() -> SocketAddr {
        let socket = std::net::UdpSocket::bind(loopback_ephemeral()).unwrap();
        socket.local_addr().unwrap()
    }

    #[tokio::test]
    async fn two_nodes_discover_each_other() {
        let id_a = Arc::new(Identity::generate());
        let id_b = Arc::new(Identity::generate());

        let mesh_addr_a = ephemeral_udp_port();
        let mesh_addr_b = ephemeral_udp_port();
        let whisper_addr_a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let whisper_addr_b: SocketAddr = "127.0.0.1:2".parse().unwrap();

        let mut cfg_a = MeshConfig::new(id_a.clone(), mesh_addr_a, whisper_addr_a, "0.0.1");
        cfg_a.cluster_id = "bowery-test".to_string();
        cfg_a.seed_nodes = vec![mesh_addr_b.to_string()];

        let mut cfg_b = MeshConfig::new(id_b.clone(), mesh_addr_b, whisper_addr_b, "0.0.1");
        cfg_b.cluster_id = "bowery-test".to_string();
        cfg_b.seed_nodes = vec![mesh_addr_a.to_string()];

        let mesh_a = Mesh::start(cfg_a).await.expect("start a");
        let mesh_b = Mesh::start(cfg_b).await.expect("start b");

        // Wait for both sides to see one peer.
        let observed_a = wait_for_peer(&mesh_a, id_b.fingerprint())
            .await
            .expect("a sees b");
        let observed_b = wait_for_peer(&mesh_b, id_a.fingerprint())
            .await
            .expect("b sees a");

        assert_eq!(observed_a.whisper_addr, whisper_addr_b);
        assert_eq!(observed_a.agent_version, "0.0.1");
        assert_eq!(observed_a.verifying_key, id_b.verifying_key());

        assert_eq!(observed_b.whisper_addr, whisper_addr_a);
        assert_eq!(observed_b.verifying_key, id_a.verifying_key());

        mesh_a.shutdown().await.expect("shutdown a");
        mesh_b.shutdown().await.expect("shutdown b");
    }

    async fn wait_for_peer(mesh: &Mesh, expected: Fingerprint) -> Option<PeerInfo> {
        let mut watcher = mesh.peers_watcher();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            for peer in watcher.borrow().iter() {
                if peer.fingerprint == expected {
                    return Some(peer.clone());
                }
            }
            let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
            if timeout.is_zero() {
                return None;
            }
            if tokio::time::timeout(timeout, watcher.changed())
                .await
                .is_err()
            {
                return None;
            }
        }
    }
}
