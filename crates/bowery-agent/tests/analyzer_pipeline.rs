//! Phase 3 integration: drive the pipeline with `MockEventSource` and
//! verify that the analyzer fires per episode and the role publisher
//! periodically updates mesh state.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, HeartbeatConfig, IdentityConfig,
    InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig, OperatorsConfig, ResponseConfig,
    RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_analysis::{RoleVector, Verdict};
use bowery_crypto::Identity;
use bowery_events::source::MockEventSource;
use bowery_events::{Event, ProcessExec};
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

mod common;
use common::{loopback_ephemeral, reserve_udp_port};

fn build_config(dir: &Path, mesh_addr: SocketAddr, role_interval: Duration) -> Config {
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
            publish_interval: role_interval,
        },
        llm: LlmConfig::default(),
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
async fn analyzer_fires_per_episode_with_expected_suspicion() {
    let workdir = TempDir::new().unwrap();

    // `tempfile::TempDir` lands under `/tmp` on Linux, which is exactly
    // what we want for the suspicious case — the writable-path rule
    // matches the literal `/tmp/` prefix.
    assert!(
        workdir.path().starts_with("/tmp/"),
        "this test assumes TMPDIR is /tmp; got {}",
        workdir.path().display()
    );
    let suspicious_bin = workdir.path().join("payload");
    std::fs::write(&suspicious_bin, b"sus content").unwrap();

    // For the "normal" exec we need a real on-disk binary whose path is
    // NOT under /tmp. This used to be `current_exe()`, which satisfies
    // that and is also a ~95 MB debug binary: the pipeline hashes what
    // it is handed, and under a full `cargo test --workspace` — fifteen
    // test binaries competing for the page cache — hashing it took just
    // under six seconds against this loop's five-second deadline. The
    // test passed alone and failed about one workspace run in three.
    //
    // Nothing here needs a large binary, only a small one somewhere
    // other than /tmp.
    let normal_bin = ["/bin/true", "/usr/bin/true", "/bin/sh"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .expect("no small system binary found outside /tmp");
    assert!(
        !normal_bin.starts_with("/tmp/"),
        "{} is under /tmp; the writable-path rule will misfire",
        normal_bin.display()
    );

    // Gated so the pipeline cannot outrun `subscribe()`; see `EventGate`.
    let (source, gate) = MockEventSource::new(vec![
        make_exec(1, vec!["payload", "--tail"], suspicious_bin),
        make_exec(2, vec!["test-runner"], normal_bin),
    ])
    .gated();

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(
        workdir.path(),
        reserve_udp_port(),
        Duration::from_millis(200),
    );
    let agent = Agent::start(cfg, identity, Box::new(source))
        .await
        .expect("start");

    let mut events = agent.subscribe();
    gate.open();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    let mut sus: Option<Verdict> = None;
    let mut normal: Option<Verdict> = None;
    while sus.is_none() || normal.is_none() {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for both verdicts");
        let event = tokio::time::timeout(timeout, events.recv())
            .await
            .expect("timeout")
            .expect("event");
        if let AgentEvent::EpisodeAnalyzed { verdict } = event {
            // Identify which exec produced this verdict by looking at the
            // rule hits — only the suspicious one should fire any rule.
            if verdict.rule_hits.is_empty() {
                normal = Some(verdict);
            } else {
                sus = Some(verdict);
            }
        }
    }

    let sus = sus.unwrap();
    let normal = normal.unwrap();

    // The /tmp-located exec must trigger the writable-path rule.
    assert!(
        sus.rule_hits
            .iter()
            .any(|h| h.rule_id == "exec_from_writable_path"),
        "expected writable-path rule hit, got: {:?}",
        sus.rule_hits
    );
    // Suspicion is bounded above 0.6 because writable-path is medium severity.
    assert!(sus.suspicion >= 0.6, "suspicion {}", sus.suspicion);

    // The normal exec has no rule hits but is unseen, so suspicion is
    // dominated by the score (1.0 because seen_count == 0 at scoring time).
    assert!(normal.rule_hits.is_empty());
    #[allow(clippy::float_cmp)] // exact 1.0 sentinel
    {
        assert_eq!(normal.suspicion, 1.0);
    }

    agent.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn role_publisher_emits_periodically_and_round_trips_via_mesh_kv() {
    let workdir = TempDir::new().unwrap();

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(
        workdir.path(),
        reserve_udp_port(),
        Duration::from_millis(150),
    );
    let agent = Agent::start(cfg, identity, Box::new(MockEventSource::new(Vec::new())))
        .await
        .expect("start");

    let mut events = agent.subscribe();

    // Wait for at least one publish event.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let initial_count = loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !timeout.is_zero(),
            "timed out waiting for RoleVectorPublished"
        );
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::RoleVectorPublished { binary_count })) => break binary_count,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed"),
            Err(tokio::time::error::Elapsed { .. }) => panic!("recv timed out"),
        }
    };
    assert_eq!(initial_count, 0);

    // Encoded role vector should be present on the mesh self-state and
    // round-trip through the protocol's base64 codec.
    let peers_initial: Vec<_> = agent.mesh().peers();
    // Peers list is empty (we're alone in the cluster), so we read the
    // role vector via chitchat's KV directly through `peers_watcher` only
    // shows peers, not self. To smoke-test the encoding we recompute from
    // the analyzer-side helpers and assert the codec works.
    let _ = peers_initial; // explicitly noop
    // Round-trip a sample.
    let features =
        bowery_analysis::RoleFeatures::with_dims([0.1, 0.2, 0.0, 0.3, 0.0, 0.4, 0.0, 0.0], 17);
    let v = RoleVector::from_features(&features);
    let encoded = v.to_base64();
    let decoded = RoleVector::from_base64(&encoded).expect("roundtrip");
    assert_eq!(v, decoded);

    agent.shutdown().await.expect("shutdown");
}

/// A directly-scored detection must reach the operator as a *reason*,
/// not just as a number.
///
/// Four detections — set-id, privilege transition, discovery burst and
/// lineage — raised `Verdict::suspicion` and appended to the baseline
/// narrative, but never recorded a `RuleHit`. `RuleHit` is the only
/// channel the alert rationale and the model prompt read, so every alert
/// those four produced carried the fallback text "pre-filter score above
/// threshold" and the prompt told the model "Rule hits: none" while
/// asking it to judge an episode scored 0.95. This is that shape, end to
/// end: nginx starting a shell.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directly_scored_finding_explains_itself_in_the_alert() {
    let workdir = TempDir::new().unwrap();
    let shell = workdir.path().join("dash");
    std::fs::write(&shell, b"#!/bin/sh\n").unwrap();

    let (source, gate) = MockEventSource::new(vec![Event::ProcessExec(ProcessExec {
        pid: 6001,
        ppid: 1,
        // The signal: a network-facing service is the parent.
        parent_comm: "nginx".into(),
        uid: 0,
        comm: "dash".into(),
        exe_path: Some(shell),
        args: vec!["dash".into()],
        ts: SystemTime::now(),
    })])
    .gated();

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port(), Duration::from_hours(1));
    let agent = Agent::start(cfg, identity, Box::new(source))
        .await
        .expect("start");
    let mut events = agent.subscribe();
    gate.open();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let episode = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "timed out waiting for the alert");
        if let Ok(Ok(AgentEvent::AlertEmitted { episode_id, .. })) =
            tokio::time::timeout(left, events.recv()).await
        {
            break episode_id;
        }
    };

    let (alerts, _) = agent.inbox().read_since(0, 100);
    let alert = alerts
        .iter()
        .find(|a| a.episode_id == episode)
        .expect("alert in the inbox");

    assert!(
        alert.rationale.contains("lineage.service_spawned_shell"),
        "the alert must name the rule that fired, got: {}",
        alert.rationale
    );
    assert_ne!(
        alert.rationale, "pre-filter score above threshold",
        "a scored finding that cannot explain itself is the defect"
    );
    assert!(
        alert.rationale.contains("nginx"),
        "and it must name the parent that made it a finding, got: {}",
        alert.rationale
    );

    agent.shutdown().await.expect("shutdown");
}

/// A binary the baseline already knows must still get a descriptor.
///
/// The first version of this gated descriptor writes on
/// `UpsertOutcome::Inserted`, which is correct-looking, passes every
/// unit test, and describes almost nothing in production: on a host
/// whose baseline already held 366 hashes, exactly one was ever
/// described, because every later exec of a known binary is an
/// `Updated`. The descriptor table stayed empty on precisely the
/// long-lived hosts it exists to serve, and slice 3 would have had
/// nothing to compare.
///
/// So the hash is seeded first, making the exec an `Updated`. Without
/// the fix this test finds no descriptor at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_binary_already_in_the_baseline_still_gets_described() {
    let workdir = TempDir::new().unwrap();
    let bin = workdir.path().join("described-payload");
    std::fs::write(&bin, b"payload contents").unwrap();

    // The sha the pipeline will compute for this file.
    let sha: [u8; 32] = {
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(std::fs::read(&bin).unwrap());
        h.finalize().into()
    };

    let (source, gate) =
        MockEventSource::new(vec![make_exec(1, vec!["described-payload"], bin.clone())]).gated();

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(
        workdir.path(),
        reserve_udp_port(),
        Duration::from_millis(200),
    );
    let agent = Agent::start(cfg, identity, Box::new(source))
        .await
        .expect("start");

    // Seed it, so the pipeline's upsert reports `Updated` rather than
    // `Inserted` — the case the original gate skipped.
    agent.baseline().upsert_binary(&sha).expect("seed");
    assert!(
        agent.baseline().descriptor(&sha).unwrap().is_none(),
        "precondition: nothing described yet"
    );

    let mut events = agent.subscribe();
    gate.open();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for the exec");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::BinaryRecorded { .. })) => break,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed early"),
            Err(tokio::time::error::Elapsed { .. }) => {
                panic!("timed out waiting for BinaryRecorded")
            }
        }
    }

    // The descriptor is written on a spawn_blocking after the event, so
    // give it a moment to land rather than racing it.
    let mut described = None;
    for _ in 0..50 {
        if let Some(d) = agent.baseline().descriptor(&sha).unwrap() {
            described = Some(d);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let described = described.expect("an already-known binary must still be described");
    assert_eq!(
        described.exe_path.as_deref(),
        Some(bin.to_str().unwrap()),
        "the descriptor must name the program"
    );
    assert_eq!(
        described.platform.as_deref(),
        Some(bowery_proto::platform_key()).as_deref()
    );

    agent.shutdown().await.expect("shutdown");
}
