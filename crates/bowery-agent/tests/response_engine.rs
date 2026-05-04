//! Phase-7 response engine integration: a high-suspicion exec
//! produces an LLM verdict whose `suggested_actions` list contains
//! `kill_process`. The agent routes that through the response engine
//! (default deny-all `NoopEngine` on a fresh agent) and emits
//! `ActionAttempted` with the resulting outcome.
//!
//! Two shapes covered:
//! - default policy → `Suppressed { reason: "policy denied" }`
//! - permissive policy with `allowed_actions = ["kill_process"]` →
//!   `Suppressed { reason: "observe-only engine" }` (`NoopEngine`
//!   never executes; the real-kill executor lands in a follow-up)

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, HeartbeatConfig, IdentityConfig, InboxConfig,
    KnownNeighborsConfig, LlmConfig, MeshConfig, OperatorsConfig, ResponseConfig,
    ResponseEngineKind, RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::MockEventSource;
use bowery_events::{Event, ProcessExec};
use bowery_llm::{AnalysisContext, LlmAnalyzer, LlmError, LlmVerdict};
use bowery_response::ActionOutcome;
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn reserve_udp_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(loopback_ephemeral()).expect("bind");
    socket.local_addr().expect("local_addr")
}

/// Test-only analyzer that always suggests `kill_process` so we can
/// drive the response engine deterministically.
struct AlwaysKillAnalyzer;

#[async_trait::async_trait]
impl LlmAnalyzer for AlwaysKillAnalyzer {
    async fn analyze(&self, ctx: &AnalysisContext) -> Result<LlmVerdict, LlmError> {
        Ok(LlmVerdict {
            suspicion: ctx.pre_verdict.suspicion,
            rationale: "test analyzer: always suggests kill_process".into(),
            suggested_actions: vec!["kill_process".into()],
            whisper_query: String::new(),
            backend: "test/always-kill".into(),
        })
    }

    fn name(&self) -> &'static str {
        "test/always-kill"
    }
}

fn build_config(dir: &Path, mesh_addr: SocketAddr, response: ResponseConfig) -> Config {
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
            cluster_id: Some("bowery-test-response".to_string()),
        },
        whisper: WhisperConfig {
            qa: WhisperQaConfig {
                // Force whisper-Q&A to NOT trigger so the LLM
                // submission goes via the direct path (faster + no
                // peer dependency in the test).
                threshold: 2.0,
                fanout: 1,
                timeout: Duration::from_secs(1),
                min_similarity: 0.0,
            },
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
        llm: LlmConfig {
            invocation_threshold: 0.4,
            queue_capacity: 4,
            request_deadline: Duration::from_secs(2),
            llama_cpp: None,
        },
        operators: OperatorsConfig::default(),
        inbox: InboxConfig::default(),
        alerts: AlertsConfig {
            threshold: 0.4,
        },
        bloom: BloomConfig::default(),
        response,
    }
}

fn make_exec(pid: u32, exe_path: std::path::PathBuf) -> Event {
    Event::ProcessExec(ProcessExec {
        pid,
        ppid: 1,
        uid: 0,
        comm: "test".into(),
        exe_path: Some(exe_path),
        args: vec!["payload".into()],
        ts: SystemTime::now(),
    })
}

async fn run_scenario(response: ResponseConfig) -> Vec<(String, &'static str, ActionOutcome)> {
    let workdir = TempDir::new().unwrap();
    let payload_path = workdir.path().join("payload");
    std::fs::write(&payload_path, b"phase-7-response-test").unwrap();

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port(), response);
    let source = Box::new(
        MockEventSource::new(vec![make_exec(31337, payload_path)])
            .with_delay(Duration::from_millis(200)),
    );
    let llm: Arc<dyn LlmAnalyzer> = Arc::new(AlwaysKillAnalyzer);

    let agent = Agent::start_with_llm(cfg, identity, source, llm)
        .await
        .expect("start");

    let mut events = agent.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut attempted: Vec<(String, &'static str, ActionOutcome)> = Vec::new();
    let mut llm_done = false;
    while attempted.is_empty() || !llm_done {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !timeout.is_zero(),
            "timed out; attempted={attempted:?} llm_done={llm_done}"
        );
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::ActionAttempted {
                episode_id,
                action_id,
                outcome,
            })) => attempted.push((episode_id, action_id, outcome)),
            Ok(Ok(AgentEvent::LlmVerdict { .. })) => llm_done = true,
            Ok(Ok(AgentEvent::LlmShed { reason, .. })) => {
                panic!("LLM shed: {reason:?}")
            }
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed"),
            Err(_) => break,
        }
    }

    agent.shutdown().await.expect("shutdown");
    attempted
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_policy_suppresses_all_actions() {
    let attempted = run_scenario(ResponseConfig::default()).await;
    assert_eq!(
        attempted.len(),
        1,
        "expected exactly one ActionAttempted, got {attempted:?}"
    );
    let (_episode, action_id, outcome) = &attempted[0];
    assert_eq!(*action_id, "kill_process");
    match outcome {
        ActionOutcome::Suppressed { reason } => {
            assert_eq!(reason, "policy denied");
        }
        other => panic!("expected Suppressed/policy-denied, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_kill_engine_actually_kills_a_real_child() {
    // End-to-end: a high-suspicion exec event for a *real* spawned
    // child process. The agent's ProcessKillEngine — gated on a
    // permissive policy — actually delivers SIGKILL.
    let workdir = TempDir::new().unwrap();
    let payload_path = workdir.path().join("payload");
    std::fs::write(&payload_path, b"phase-7-real-kill-test").unwrap();

    let policy_path = workdir.path().join("policy.toml");
    std::fs::write(&policy_path, r#"allowed_actions = ["kill_process"]"#).unwrap();

    // Spawn a long-running child; we'll feed its pid to the agent's
    // ProcessExec event so the engine has a real target.
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let target_pid = child.id();

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(
        workdir.path(),
        reserve_udp_port(),
        ResponseConfig {
            policy_path: Some(policy_path),
            engine: ResponseEngineKind::ProcessKill,
        },
    );
    let source = Box::new(
        MockEventSource::new(vec![make_exec(target_pid, payload_path)])
            .with_delay(Duration::from_millis(200)),
    );
    let llm: Arc<dyn LlmAnalyzer> = Arc::new(AlwaysKillAnalyzer);

    let agent = Agent::start_with_llm(cfg, identity, source, llm)
        .await
        .expect("start agent");

    // Wait for ActionAttempted with Executed outcome.
    let mut events = agent.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let outcome = loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for ActionAttempted");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::ActionAttempted {
                action_id: "kill_process",
                outcome,
                ..
            })) => break outcome,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed"),
            Err(tokio::time::error::Elapsed { .. }) => panic!("ActionAttempted timeout"),
        }
    };

    match outcome {
        ActionOutcome::Executed { at_unix_ms } => assert!(at_unix_ms > 0),
        other => {
            // Reap the child even on test failure to avoid leaking
            // zombie processes in CI.
            let _ = child.kill();
            let _ = child.wait();
            panic!("expected Executed, got {other:?}");
        }
    }

    // The child should now be reapable — SIGKILL doesn't yield a
    // success() exit status.
    let status = child.wait().expect("wait child");
    assert!(
        !status.success(),
        "child should have been killed; got {status:?}"
    );

    agent.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permissive_policy_routes_through_observe_only_engine() {
    let workdir = TempDir::new().unwrap();
    let policy_path = workdir.path().join("policy.toml");
    std::fs::write(&policy_path, r#"allowed_actions = ["kill_process"]"#).unwrap();

    let response = ResponseConfig {
        policy_path: Some(policy_path),
        engine: ResponseEngineKind::Noop,
    };
    let attempted = run_scenario(response).await;
    assert_eq!(attempted.len(), 1);
    let (_episode, action_id, outcome) = &attempted[0];
    assert_eq!(*action_id, "kill_process");
    match outcome {
        ActionOutcome::Suppressed { reason } => {
            // NoopEngine reports "observe-only engine" once policy
            // permits — the eventual real-kill engine will return
            // Executed { at_unix_ms } here.
            assert_eq!(reason, "observe-only engine");
        }
        other => panic!("expected Suppressed/observe-only, got {other:?}"),
    }
}
