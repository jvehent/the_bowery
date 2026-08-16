//! Integration: an operator-configured file watch produces an alert when
//! the watched file changes, end-to-end through a real agent (inotify →
//! pipeline → alert inbox).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, FileRule, HeartbeatConfig, IdentityConfig,
    InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig, MonitorConfig, OperatorsConfig,
    ProcessRule, ResponseConfig, RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_analysis::RuleSeverity;
use bowery_crypto::Identity;
use bowery_events::source::MockEventSource;
use bowery_events::{Event, FileOpen};
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn reserve_udp_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(loopback_ephemeral()).expect("bind");
    socket.local_addr().expect("local_addr")
}

fn build_config(dir: &Path, mesh_addr: SocketAddr, monitor: MonitorConfig) -> Config {
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
            cluster_id: Some("bowery-test-file-monitor".to_string()),
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
        llm: LlmConfig::default(),
        operators: OperatorsConfig::default(),
        inbox: InboxConfig::default(),
        alerts: AlertsConfig::default(),
        bloom: BloomConfig::default(),
        response: ResponseConfig::default(),
        sql: bowery_agent::config::SqlConfig::default(),
        monitor,
        yara: bowery_agent::config::YaraConfig::default(),
        // Disabled: these fixtures predate the event log and don't
        // need a writer task (the default path isn't writable in CI).
        eventlog: bowery_agent::config::EventLogConfig {
            enabled: false,
            ..Default::default()
        },
    }
}

/// Wait for an `AlertEmitted` event, or panic on timeout.
async fn wait_for_alert(
    events: &mut tokio::sync::broadcast::Receiver<AgentEvent>,
) -> (String, f32) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for AlertEmitted");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::AlertEmitted {
                episode_id,
                suspicion,
            })) => return (episode_id, suspicion),
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("agent event channel closed"),
            Err(tokio::time::error::Elapsed { .. }) => {
                panic!("timed out waiting for AlertEmitted")
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watched_file_change_emits_alert() {
    let workdir = TempDir::new().unwrap();
    let watched = workdir.path().join("sensitive.conf");
    std::fs::write(&watched, b"original").unwrap();

    let monitor = MonitorConfig {
        file_rules: vec![FileRule {
            id: Some("sensitive".to_string()),
            path: watched.clone(),
            // Default ops (modify/attrib/delete/move) — set explicitly so the
            // test doesn't silently depend on the default set.
            ops: vec![bowery_events::FileOp::Modify],
            severity: RuleSeverity::High,
        }],
        process_rules: Vec::new(),
    };

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port(), monitor);
    // No kernel events in this test — the file monitor is the only producer.
    let source = Box::new(MockEventSource::new(Vec::new()));
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    let mut events = agent.subscribe();

    // Give the inotify watch a moment to be registered before mutating.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // IN_CLOSE_WRITE fires when the writer closes the fd.
    std::fs::write(&watched, b"tampered").unwrap();

    let (episode_id, suspicion) = wait_for_alert(&mut events).await;
    assert!(
        episode_id.starts_with("file-sensitive-"),
        "episode id should name the rule, got {episode_id}"
    );
    // High severity → 0.9 suspicion (mirrors the analyzer's severity weights).
    assert!(
        (suspicion - 0.9).abs() < f32::EPSILON,
        "expected high-severity suspicion 0.9, got {suspicion}"
    );

    agent.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unwatched_file_change_emits_no_alert() {
    let workdir = TempDir::new().unwrap();
    let watched = workdir.path().join("watched.conf");
    let other = workdir.path().join("other.conf");
    std::fs::write(&watched, b"a").unwrap();
    std::fs::write(&other, b"b").unwrap();

    let monitor = MonitorConfig {
        file_rules: vec![FileRule {
            id: None,
            path: watched.clone(),
            ops: vec![bowery_events::FileOp::Modify],
            severity: RuleSeverity::High,
        }],
        process_rules: Vec::new(),
    };

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port(), monitor);
    let source = Box::new(MockEventSource::new(Vec::new()));
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    let mut events = agent.subscribe();

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Touch a DIFFERENT file in the same watched directory: the directory
    // watch sees it, but the basename doesn't match the rule, so no alert.
    std::fs::write(&other, b"changed").unwrap();

    // Timing out is the expected outcome; any non-alert agent event is fine.
    // `sensor-*` episodes are the probe watchdog reporting on the event
    // source, not the file monitor — this test is about the file rule.
    if let Ok(Ok(AgentEvent::AlertEmitted { episode_id, .. })) =
        tokio::time::timeout(Duration::from_secs(2), events.recv()).await
        && !episode_id.starts_with("sensor-")
    {
        panic!("unwatched file must not alert, got {episode_id}");
    }

    agent.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_rejects_process_rule_with_no_matcher() {
    // A rule with no matchers would fire on every exec — the agent must
    // refuse to start rather than silently alert on everything.
    let workdir = TempDir::new().unwrap();
    let monitor = MonitorConfig {
        file_rules: Vec::new(),
        process_rules: vec![ProcessRule {
            id: Some("catch-all".to_string()),
            exe_prefix: None,
            comm: None,
            arg_substr: None,
            severity: RuleSeverity::High,
        }],
    };
    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port(), monitor);
    let source = Box::new(MockEventSource::new(Vec::new()));
    let err = Agent::start(cfg, identity, source)
        .await
        .expect_err("agent must reject an all-empty process rule");
    assert!(
        format!("{err}").contains("no matcher"),
        "unexpected error: {err}"
    );
}

/// A write to a built-in watch path alerts, with the process named.
///
/// Distinct from the operator-configured file rules above: nobody has to
/// know in advance that `/etc/ld.so.preload` matters. The path here is a
/// temp-dir stand-in, so the assertion is on the *rule firing*, which is
/// unit-tested against the real paths in `bowery_analysis::file_watch`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_to_a_persistence_path_alerts_and_names_the_process() {
    let workdir = TempDir::new().unwrap();
    let cfg = build_config(workdir.path(), reserve_udp_port(), MonitorConfig::default());

    // Feed the event the kernel sensor would produce.
    let source = Box::new(MockEventSource::new(vec![Event::FileOpen(FileOpen {
        pid: 4242,
        comm: "curl".into(),
        path: "/root/.ssh/authorized_keys".into(),
        flags: 0o1101,
        truncated: false,
        ts: SystemTime::now(),
    })]));

    let identity = Arc::new(Identity::generate());
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    let mut events = agent.subscribe();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let episode = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !left.is_zero(),
            "timed out waiting for the file-watch alert"
        );
        if let Ok(Ok(AgentEvent::AlertEmitted { episode_id, .. })) =
            tokio::time::timeout(left, events.recv()).await
            && episode_id.starts_with("file-persist.authorized_keys-")
        {
            break episode_id;
        }
    };

    let (alerts, _) = agent.inbox().read_since(0, 100);
    let alert = alerts
        .iter()
        .find(|a| a.episode_id == episode)
        .expect("alert in the inbox");
    assert!(alert.rationale.contains("/root/.ssh/authorized_keys"));
    // The process is the lead an operator follows next.
    assert!(alert.rationale.contains("curl"), "{}", alert.rationale);
    assert!(alert.rationale.contains("pid 4242"), "{}", alert.rationale);
    // And it explains why the path matters at all.
    assert!(
        alert.rationale.contains("passwordless login"),
        "{}",
        alert.rationale
    );
    assert!(alert.suspicion > 0.9);

    agent.shutdown().await.expect("shutdown");
}
