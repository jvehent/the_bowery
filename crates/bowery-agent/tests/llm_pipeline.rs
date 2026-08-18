//! Phase 4 integration: `ProcessExec` events flow through the analyzer
//! and, when suspicion crosses the threshold, get routed to the LLM
//! queue. We assert the resulting `LlmVerdict` event lands and
//! references the original episode.

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
use bowery_crypto::Identity;
use bowery_events::source::MockEventSource;
use bowery_events::{Event, ProcessExec};
use bowery_llm::{LlmAnalyzer, MockLlmAnalyzer, MockMode};
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn reserve_udp_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(loopback_ephemeral()).expect("bind");
    socket.local_addr().expect("local_addr")
}

fn build_config(dir: &Path, mesh_addr: SocketAddr, llm_threshold: f32) -> Config {
    Config {
        identity: IdentityConfig {
            path: dir.join("identity.key"),
        },
        known_neighbors: KnownNeighborsConfig {
            path: dir.join("known_neighbors.json"),
            bootstrap_window: Duration::from_hours(1),
            max_pinned_peers: 1024,
            // Phase-3 defaults: unchanged TOFU behaviour.
            enrollment: bowery_agent::config::EnrollmentPolicy::Tofu,
            grant_path: None,
            revocations_path: dir.join("revocations.json"),
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr,
            advertise_addr: Some(mesh_addr),
            seeds: Vec::new(),
            cluster_id: Some("bowery-test".to_string()),
        },
        whisper: WhisperConfig {
            advertise_addr: None,
            qa: WhisperQaConfig::default(),
            bind_addr: loopback_ephemeral(),
            // Left at the production default so every existing
            // two-agent fixture also exercises the corroboration
            // engine's startup and shutdown paths.
            corroboration: bowery_agent::config::CorroborationConfig::default(),
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
        llm: LlmConfig {
            invocation_threshold: llm_threshold,
            queue_capacity: 16,
            request_deadline: Duration::from_secs(2),
            llama_cpp: None,
        },
        operators: OperatorsConfig::default(),
        inbox: InboxConfig::default(),
        alerts: AlertsConfig::default(),
        bloom: BloomConfig::default(),
        response: ResponseConfig::default(),
        sql: bowery_agent::config::SqlConfig::default(),
        monitor: bowery_agent::config::MonitorConfig::default(),
        yara: bowery_agent::config::YaraConfig::default(),
        // Disabled: these fixtures predate the event log and don't
        // need a writer task (the default path isn't writable in CI).
        detection: bowery_agent::config::DetectionConfig::default(),
        eventlog: bowery_agent::config::EventLogConfig {
            enabled: false,
            ..Default::default()
        },
    }
}

fn make_exec(pid: u32, args: Vec<&str>, exe_path: std::path::PathBuf) -> Event {
    Event::ProcessExec(ProcessExec {
        pid,
        ppid: 1,
        parent_comm: String::new(),
        uid: 0,
        comm: "test".into(),
        exe_path: Some(exe_path),
        args: args.into_iter().map(String::from).collect(),
        ts: SystemTime::now(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_suspicion_exec_routes_to_llm_and_emits_verdict() {
    let workdir = TempDir::new().unwrap();
    assert!(
        workdir.path().starts_with("/tmp/"),
        "this test relies on TMPDIR=/tmp"
    );
    let suspicious_bin = workdir.path().join("payload");
    std::fs::write(&suspicious_bin, b"suspicious").unwrap();

    // Gated so the pipeline cannot outrun `subscribe()`; see `EventGate`.
    let (source, gate) = MockEventSource::new(vec![make_exec(
        4242,
        vec!["payload", "--exfil"],
        suspicious_bin,
    )])
    .gated();

    let identity = Arc::new(Identity::generate());
    // Threshold 0.5 — the writable-path rule (medium severity, weight 0.6)
    // alone clears it.
    let cfg = build_config(workdir.path(), reserve_udp_port(), 0.5);
    let llm: Arc<dyn LlmAnalyzer> = Arc::new(MockLlmAnalyzer::new(MockMode::Echo));

    let agent = Agent::start_with_llm(cfg, identity, Box::new(source), llm)
        .await
        .expect("start");

    let mut events = agent.subscribe();
    gate.open();

    // Wait for the EpisodeAnalyzed first to capture the episode_id, then
    // for the LlmVerdict that should reference it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut episode_id: Option<String> = None;
    let mut verdict: Option<bowery_llm::LlmVerdict> = None;
    let mut verdict_ep: Option<String> = None;
    while episode_id.is_none() || verdict.is_none() {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for events");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::EpisodeAnalyzed { verdict: v })) => {
                episode_id = Some(v.episode_id.clone());
            }
            Ok(Ok(AgentEvent::LlmVerdict {
                episode_id: ep,
                verdict: v,
            })) => {
                verdict_ep = Some(ep);
                verdict = Some(v);
            }
            Ok(Ok(AgentEvent::LlmShed { reason, .. })) => {
                panic!("LLM shed unexpectedly: {reason:?}");
            }
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed"),
            Err(tokio::time::error::Elapsed { .. }) => panic!("recv timed out"),
        }
    }

    let ep = episode_id.expect("episode_id");
    let v = verdict.expect("verdict");
    assert_eq!(verdict_ep.unwrap(), ep, "LlmVerdict episode_id mismatch");
    assert_eq!(v.backend, "mock/echo");
    // MockMode::Echo returns suspicion >= 0.6 for our suspicious exec.
    assert!(v.suspicion >= 0.6, "echoed suspicion {}", v.suspicion);
    // Whatever reaches the pipeline must be an action the response
    // engine can perform. It used to be "alert", which the engine does
    // not implement, so every verdict's suggestion was discarded as an
    // unknown id and the enforcement path was never entered at all.
    for a in &v.suggested_actions {
        assert!(
            bowery_response::Action::known_ids().contains(&a.as_str()),
            "verdict proposed `{a}`, which the engine cannot perform"
        );
    }

    agent.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn low_suspicion_exec_skips_llm() {
    // Use a small system binary outside /tmp so neither the writable-path
    // rule nor the SHA-256 hashing path becomes the test's bottleneck.
    let normal_bin = ["/bin/true", "/usr/bin/true", "/bin/false"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
        .expect("no /bin/true on this host; can't run the low-suspicion test");
    assert!(!normal_bin.starts_with("/tmp/"));

    let workdir = TempDir::new().unwrap();
    let identity = Arc::new(Identity::generate());

    // Threshold above 1.0 — even a never-seen binary (score = 1.0) won't
    // cross it, so the LLM must stay silent.
    let cfg = build_config(workdir.path(), reserve_udp_port(), 1.5);

    let llm: Arc<dyn LlmAnalyzer> = Arc::new(MockLlmAnalyzer::new(MockMode::Echo));
    // Gated so the pipeline cannot outrun `subscribe()`; see `EventGate`.
    let (source, gate) =
        MockEventSource::new(vec![make_exec(99, vec!["test"], normal_bin)]).gated();
    let agent = Agent::start_with_llm(cfg, identity, Box::new(source), llm)
        .await
        .expect("start");

    let mut events = agent.subscribe();
    gate.open();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut saw_episode = false;
    let mut saw_llm_verdict = false;
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        if timeout.is_zero() {
            break;
        }
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::EpisodeAnalyzed { .. })) => saw_episode = true,
            Ok(Ok(AgentEvent::LlmVerdict { .. })) => saw_llm_verdict = true,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            // Either the channel closed or the recv timed out — both are
            // signals to stop polling.
            _ => break,
        }
    }
    assert!(saw_episode, "expected EpisodeAnalyzed");
    assert!(
        !saw_llm_verdict,
        "LLM should not have been invoked below the threshold"
    );

    agent.shutdown().await.expect("shutdown");
}
