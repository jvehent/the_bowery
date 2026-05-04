//! Phase-5 bloom publisher integration: starts a single agent with a
//! short publish interval, asserts that `BloomAdvertPublished` fires
//! and that the published advert (now visible via the agent's own
//! `mesh().peers()` once we'd have a peer, but here we settle for the
//! event itself) reflects the baseline's contents.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, HeartbeatConfig, IdentityConfig,
    InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig, OperatorsConfig, ResponseConfig,
    RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::NoopEventSource;
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn reserve_udp_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(loopback_ephemeral()).expect("bind");
    socket.local_addr().expect("local_addr")
}

fn build_config(dir: &Path, mesh_addr: SocketAddr, publish_interval: Duration) -> Config {
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
            seeds: vec![],
            cluster_id: Some("bowery-test-bloom".to_string()),
        },
        whisper: WhisperConfig {
            qa: WhisperQaConfig::default(),
            bind_addr: loopback_ephemeral(),
        },
        heartbeat: HeartbeatConfig {
            interval: Duration::from_secs(5),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
        role: RoleConfig {
            publish_interval: Duration::from_secs(5),
        },
        llm: LlmConfig::default(),
        operators: OperatorsConfig::default(),
        inbox: InboxConfig::default(),
        alerts: AlertsConfig::default(),
        bloom: BloomConfig {
            publish_interval,
            ..BloomConfig::default()
        },
        response: ResponseConfig::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publisher_fires_bloomadvertpublished_with_baseline_inserts() {
    let workdir = TempDir::new().unwrap();
    let identity = Arc::new(Identity::generate());

    // Short publish interval — the first tick fires immediately on
    // startup, so we don't wait long.
    let cfg = build_config(workdir.path(), reserve_udp_port(), Duration::from_secs(1));
    let agent = Agent::start(cfg, identity, Box::new(NoopEventSource))
        .await
        .expect("start agent");

    // Pre-seed the baseline before subscribing — but the publisher's
    // first tick fires asynchronously, so we'll see the second tick
    // (1s later) reflect the inserts. To make the test fast, we
    // subscribe and assert on whichever tick has the inserts.
    agent
        .baseline()
        .upsert_binary(&[1u8; 32])
        .expect("upsert 1");
    agent
        .baseline()
        .upsert_binary(&[2u8; 32])
        .expect("upsert 2");
    agent
        .baseline()
        .upsert_binary(&[3u8; 32])
        .expect("upsert 3");

    let mut events = agent.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut last_publish: Option<(u64, usize, u8, u64)> = None;
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        if timeout.is_zero() {
            break;
        }
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::BloomAdvertPublished {
                epoch,
                bit_count,
                k,
                inserted_count,
            })) => {
                last_publish = Some((epoch, bit_count, k, inserted_count));
                if inserted_count >= 3 {
                    break; // we've seen the post-seed publish
                }
            }
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed"),
            Err(_) => break,
        }
    }

    let (epoch, bit_count, k, inserted) = last_publish.expect("at least one publish");
    assert!(epoch > 0, "epoch should be initialised from wall clock");
    assert_eq!(bit_count, BloomConfig::default().bit_count);
    assert_eq!(k, BloomConfig::default().k);
    assert!(
        inserted >= 3,
        "expected publisher to see at least the 3 pre-seeded binaries, got {inserted}"
    );

    agent.shutdown().await.expect("shutdown");
}
