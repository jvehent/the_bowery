//! Phase 2 integration: drive the agent's event pipeline with a
//! `MockEventSource` and verify that enrichment + baseline upsert work
//! end-to-end.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, HeartbeatConfig, IdentityConfig,
    InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig, OperatorsConfig, ResponseConfig,
    RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_baseline::UpsertOutcome;
use bowery_crypto::Identity;
use bowery_events::source::MockEventSource;
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

fn build_config(dir: &Path, mesh_addr: SocketAddr) -> Config {
    Config {
        identity: IdentityConfig {
            path: dir.join("identity.key"),
        },
        known_neighbors: KnownNeighborsConfig {
            path: dir.join("known_neighbors.json"),
            bootstrap_window: Duration::from_hours(1),
            max_pinned_peers: 1024,
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr,
            advertise_addr: Some(mesh_addr),
            seeds: Vec::new(),
            cluster_id: Some("bowery-test".to_string()),
        },
        whisper: WhisperConfig {
            qa: WhisperQaConfig::default(),
            bind_addr: loopback_ephemeral(),
        },
        heartbeat: HeartbeatConfig {
            interval: Duration::from_mins(1),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
        role: RoleConfig {
            publish_interval: Duration::from_mins(1),
        },
        llm: LlmConfig::default(),
        operators: OperatorsConfig::default(),
        inbox: InboxConfig::default(),
        alerts: AlertsConfig::default(),
        bloom: BloomConfig::default(),
        response: ResponseConfig::default(),
        sysquery: bowery_agent::config::SysqueryConfig::default(),
    }
}

fn make_exec(pid: u32, exe_path: std::path::PathBuf) -> Event {
    Event::ProcessExec(ProcessExec {
        pid,
        ppid: 1,
        uid: 0,
        comm: "test".into(),
        exe_path: Some(exe_path),
        args: vec!["test".into()],
        ts: SystemTime::now(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_records_binary_from_exec_event() {
    let workdir = TempDir::new().unwrap();

    // Synthesise a "binary" with known contents so we can predict the SHA.
    let bin_path = workdir.path().join("test.bin");
    std::fs::write(&bin_path, b"the bowery is watching").unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"the bowery is watching");
    let expected_sha: [u8; 32] = hasher.finalize().into();

    let source = Box::new(MockEventSource::new(vec![
        make_exec(1234, bin_path.clone()),
        make_exec(1235, bin_path.clone()),
    ]));

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port());

    let agent = Agent::start(cfg, identity, source).await.expect("start");

    let mut events = agent.subscribe();

    // First event: Inserted.
    let outcome_1 = wait_for_binary(&mut events, expected_sha).await;
    assert!(matches!(outcome_1, UpsertOutcome::Inserted));

    // Second event for the same binary: Updated.
    let outcome_2 = wait_for_binary(&mut events, expected_sha).await;
    assert_eq!(outcome_2, UpsertOutcome::Updated { seen_count: 2 });

    // Baseline should reflect exactly one distinct binary, seen twice.
    assert_eq!(agent.baseline_binary_count().expect("count"), 1);
    let record = agent
        .baseline()
        .get_binary(&expected_sha)
        .expect("query")
        .expect("present");
    assert_eq!(record.seen_count, 2);

    agent.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_skips_exec_with_missing_path() {
    let workdir = TempDir::new().unwrap();
    let nonexistent = workdir.path().join("does-not-exist");

    let source = Box::new(MockEventSource::new(vec![make_exec(99, nonexistent)]));

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port());
    let agent = Agent::start(cfg, identity, source).await.expect("start");

    // Give the pipeline a chance to attempt and fail.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(agent.baseline_binary_count().unwrap(), 0);

    agent.shutdown().await.expect("shutdown");
}

async fn wait_for_binary(
    rx: &mut tokio::sync::broadcast::Receiver<AgentEvent>,
    expected_sha: [u8; 32],
) -> UpsertOutcome {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        let event = tokio::time::timeout(timeout, rx.recv())
            .await
            .expect("timed out waiting for BinaryRecorded");
        match event {
            Ok(AgentEvent::BinaryRecorded { sha, outcome }) if sha == expected_sha => {
                return outcome;
            }
            Ok(_) | Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => panic!("event channel closed"),
        }
    }
}
