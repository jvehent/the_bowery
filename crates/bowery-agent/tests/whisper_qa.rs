//! Phase 5 integration: a high-suspicion exec on alpha triggers a
//! whisper Q&A round; beta — pre-seeded with the same sha256 in its
//! baseline — replies; alpha emits `WhisperContextReady` carrying
//! beta's sighting.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_agent::config::{
    BaselineConfig, Config, HeartbeatConfig, IdentityConfig, KnownNeighborsConfig, LlmConfig,
    MeshConfig, RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::{MockEventSource, NoopEventSource};
use bowery_events::{Event, ProcessExec};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

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
            cluster_id: Some("bowery-test-whisper-qa".to_string()),
        },
        whisper: WhisperConfig {
            qa: WhisperQaConfig {
                threshold: 0.5, // first-time exec scores 1.0; well above
                fanout: 4,
                timeout: Duration::from_secs(3),
                min_similarity: -1.0, // accept anything; tiny test fleet
            },
            bind_addr: loopback_ephemeral(),
        },
        heartbeat: HeartbeatConfig {
            interval: Duration::from_millis(200),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
        role: RoleConfig {
            // Faster than the default so the test doesn't stall waiting
            // for beta's role vector to land in alpha's mesh KV.
            publish_interval: Duration::from_millis(200),
        },
        llm: LlmConfig::default(),
    }
}

fn make_exec(pid: u32, exe_path: std::path::PathBuf) -> Event {
    Event::ProcessExec(ProcessExec {
        pid,
        ppid: 1,
        uid: 0,
        comm: "test".into(),
        exe_path: Some(exe_path),
        args: vec!["whisper-test".into()],
        ts: SystemTime::now(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_suspicion_exec_triggers_whisper_round_and_aggregates_beta_sighting() {
    let workdir_alpha = TempDir::new().unwrap();
    let workdir_beta = TempDir::new().unwrap();

    // alpha's exec target; beta will be pre-seeded with the matching sha.
    let payload_path = workdir_alpha.path().join("payload");
    let payload_bytes = b"phase-5-whisper-test-binary";
    std::fs::write(&payload_path, payload_bytes).unwrap();
    let payload_sha: [u8; 32] = Sha256::digest(payload_bytes).into();

    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();

    let id_alpha = Arc::new(Identity::generate());
    let id_beta = Arc::new(Identity::generate());

    let cfg_alpha = build_config(
        workdir_alpha.path(),
        mesh_addr_alpha,
        vec![mesh_addr_beta.to_string()],
    );
    let cfg_beta = build_config(
        workdir_beta.path(),
        mesh_addr_beta,
        vec![mesh_addr_alpha.to_string()],
    );

    // Alpha: send the exec event after a delay long enough for mesh
    // discovery, mutual pinning, and a role-vector exchange. The Q&A
    // task then has actual peers to query.
    let alpha_source = Box::new(
        MockEventSource::new(vec![make_exec(1234, payload_path)])
            .with_delay(Duration::from_secs(2)),
    );

    let agent_alpha = Agent::start(cfg_alpha, id_alpha.clone(), alpha_source)
        .await
        .expect("start alpha");
    let agent_beta = Agent::start(cfg_beta, id_beta.clone(), Box::new(NoopEventSource))
        .await
        .expect("start beta");

    let alpha_fp = agent_alpha.fingerprint();
    let beta_fp = agent_beta.fingerprint();
    assert_ne!(alpha_fp, beta_fp);

    // Pre-seed beta's baseline with the payload sha. The whisper
    // responder scans the baseline by tier-1 fingerprint and replies
    // with the aggregated seen_count.
    agent_beta
        .baseline()
        .upsert_binary(&payload_sha)
        .expect("upsert beta");
    agent_beta
        .baseline()
        .upsert_binary(&payload_sha)
        .expect("upsert beta again"); // seen_count = 2

    // Wait until alpha sees a WhisperContextReady whose tier1 matches
    // our payload's tier1. Timeout generously; the round has to wait
    // for mesh+pin+role-publish before it can fire.
    let mut events = agent_alpha.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let context = loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for WhisperContextReady");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::WhisperContextReady(ctx))) => break ctx,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed early"),
            Err(tokio::time::error::Elapsed { .. }) => {
                panic!("timed out waiting for WhisperContextReady")
            }
        }
    };

    assert_eq!(
        context.peers.len(),
        1,
        "expected exactly beta in the round, got {:?}",
        context.peers.iter().map(|p| p.peer).collect::<Vec<_>>()
    );
    let beta_sighting = &context.peers[0];
    assert_eq!(beta_sighting.peer, beta_fp);
    assert!(
        beta_sighting.sighting.is_some(),
        "beta should have replied (no transport error / timeout)"
    );
    let s = beta_sighting.sighting.unwrap();
    assert_eq!(s.seen_count, 2, "beta upserted twice");
    assert_eq!(context.corroborating_peers, 1);
    assert_eq!(context.total_seen_count, 2);

    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}
