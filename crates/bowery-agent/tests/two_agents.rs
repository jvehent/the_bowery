//! End-to-end integration: two in-process agents discover each other via
//! gossip, mutually pin, and exchange heartbeats.
//!
//! This is the Phase 1 integration test for The Bowery's mesh stack: it
//! exercises chitchat, the TOFU pinning store, the QUIC transport, the
//! envelope crypto, and the agent's task supervision in one go.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bowery_agent::config::{
    BaselineConfig, Config, HeartbeatConfig, IdentityConfig, KnownNeighborsConfig, MeshConfig,
    WhisperConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::NoopEventSource;
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// Reserve an ephemeral UDP port on loopback by briefly binding it. Returns
/// the address; the OS will likely re-issue this same port immediately
/// after we drop the socket. There's a small race window, but it's
/// acceptable for tests.
fn reserve_udp_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(loopback_ephemeral()).expect("bind");
    socket.local_addr().expect("local_addr")
}

fn build_config(dir: &Path, mesh_addr: SocketAddr, seeds: Vec<String>) -> Config {
    Config {
        identity: IdentityConfig {
            path: dir.join("identity.key"),
        },
        known_neighbors: KnownNeighborsConfig {
            path: dir.join("known_neighbors.json"),
            bootstrap_window: Duration::from_hours(1),
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr,
            advertise_addr: Some(mesh_addr),
            seeds,
            cluster_id: Some("bowery-test".to_string()),
        },
        whisper: WhisperConfig {
            bind_addr: loopback_ephemeral(),
        },
        heartbeat: HeartbeatConfig {
            interval: Duration::from_millis(200),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_agents_discover_pin_and_heartbeat() {
    let dir_alpha = TempDir::new().unwrap();
    let dir_beta = TempDir::new().unwrap();

    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();

    let id_alpha = Arc::new(Identity::generate());
    let id_beta = Arc::new(Identity::generate());

    let cfg_alpha = build_config(
        dir_alpha.path(),
        mesh_addr_alpha,
        vec![mesh_addr_beta.to_string()],
    );
    let cfg_beta = build_config(
        dir_beta.path(),
        mesh_addr_beta,
        vec![mesh_addr_alpha.to_string()],
    );

    let agent_alpha = Agent::start(cfg_alpha, id_alpha.clone(), Box::new(NoopEventSource))
        .await
        .expect("start alpha");
    let agent_beta = Agent::start(cfg_beta, id_beta.clone(), Box::new(NoopEventSource))
        .await
        .expect("start beta");

    let alpha_fp = agent_alpha.fingerprint();
    let beta_fp = agent_beta.fingerprint();
    assert_ne!(alpha_fp, beta_fp, "fingerprints must differ");

    let timeout = Duration::from_secs(15);

    // Subscribe to events on both sides before any of the four conditions
    // can fire, then wait for all four concurrently. Subscribing per goal
    // ensures we don't miss an event because another receiver is being
    // drained.
    let pinned_alpha_rx = agent_alpha.subscribe();
    let pinned_beta_rx = agent_beta.subscribe();
    let recv_alpha_rx = agent_alpha.subscribe();
    let recv_beta_rx = agent_beta.subscribe();

    let goals = async {
        tokio::join!(
            wait_for_event(pinned_alpha_rx, move |e| match e {
                AgentEvent::PeerPinned(fp) if *fp == beta_fp => Some(()),
                _ => None,
            }),
            wait_for_event(pinned_beta_rx, move |e| match e {
                AgentEvent::PeerPinned(fp) if *fp == alpha_fp => Some(()),
                _ => None,
            }),
            wait_for_event(recv_alpha_rx, move |e| match e {
                AgentEvent::EnvelopeReceived { sender, .. } if *sender == beta_fp => Some(()),
                _ => None,
            }),
            wait_for_event(recv_beta_rx, move |e| match e {
                AgentEvent::EnvelopeReceived { sender, .. } if *sender == alpha_fp => Some(()),
                _ => None,
            }),
        )
    };

    tokio::time::timeout(timeout, goals)
        .await
        .expect("agents did not reach mutual pinning + heartbeat exchange in time");

    assert_eq!(agent_alpha.pinned_count(), 1);
    assert_eq!(agent_beta.pinned_count(), 1);

    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}

async fn wait_for_event<F, T>(
    mut rx: tokio::sync::broadcast::Receiver<AgentEvent>,
    mut matcher: F,
) -> T
where
    F: FnMut(&AgentEvent) -> Option<T>,
{
    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Some(value) = matcher(&event) {
                    return value;
                }
            }
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => panic!("event channel closed"),
        }
    }
}
