//! Phase 6a integration: an agent emits an Alert when a high-suspicion
//! exec lands; an operator dials in with their key and `Subscribe`s;
//! the operator receives the alert.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_agent::config::{
    AlertsConfig, BaselineConfig, Config, HeartbeatConfig, IdentityConfig, InboxConfig, LlmConfig,
    MeshConfig, OperatorsConfig, RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::MockEventSource;
use bowery_events::{Event, ProcessExec};
use bowery_proto::{Body, Subscribe, WhisperPayload};
use bowery_whisper::known_neighbors::KnownNeighbors;
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::BoweryEndpoint;
use bowery_whisper::{Sealer, StaticResolver, Verifier};
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn reserve_udp_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(loopback_ephemeral()).expect("bind");
    socket.local_addr().expect("local_addr")
}

fn build_agent_config(
    dir: &Path,
    mesh_addr: SocketAddr,
    operator_pubkey_b64: String,
) -> Config {
    Config {
        identity: IdentityConfig {
            path: dir.join("identity.key"),
        },
        known_neighbors: bowery_agent::config::KnownNeighborsConfig {
            path: dir.join("known_neighbors.json"),
            bootstrap_window: Duration::from_hours(1),
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr,
            advertise_addr: Some(mesh_addr),
            seeds: vec![],
            cluster_id: Some("bowery-test-inbox".to_string()),
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
        operators: OperatorsConfig {
            pubkeys_b64: vec![operator_pubkey_b64],
        },
        inbox: InboxConfig::default(),
        alerts: AlertsConfig {
            // First-time exec scores 1.0 — well above 0.5.
            threshold: 0.5,
        },
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_suspicion_exec_appears_in_operator_inbox_via_subscribe() {
    let workdir = TempDir::new().unwrap();
    let payload_path = workdir.path().join("payload");
    std::fs::write(&payload_path, b"phase-6a-alerts-test").unwrap();

    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());

    let agent_id = Arc::new(Identity::generate());
    let agent_fp = agent_id.fingerprint();
    let agent_vk = agent_id.verifying_key();

    let cfg = build_agent_config(workdir.path(), reserve_udp_port(), operator_pubkey_b64);
    let source = Box::new(MockEventSource::new(vec![make_exec(4242, payload_path)]));

    let agent = Agent::start(cfg, agent_id, source).await.expect("start agent");
    let agent_whisper_addr = agent.whisper_addr().expect("whisper_addr");

    // Wait for the agent to emit the AlertEmitted event before
    // Subscribing — the inbox would be empty otherwise.
    let mut events = agent.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut emitted_episode: Option<String> = None;
    while emitted_episode.is_none() {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for AlertEmitted");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::AlertEmitted {
                episode_id,
                suspicion,
            })) => {
                assert!(suspicion >= 0.5);
                emitted_episode = Some(episode_id);
            }
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed"),
            Err(tokio::time::error::Elapsed { .. }) => panic!("AlertEmitted timeout"),
        }
    }
    let expected_episode = emitted_episode.unwrap();

    // Operator side: dial agent with operator key, send Subscribe.
    let mut resolver = StaticResolver::new();
    resolver.insert(agent_vk);
    let resolver = Arc::new(resolver);

    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let operator_endpoint = BoweryEndpoint::bind(
        operator_id.clone(),
        accept_verifier,
        loopback_ephemeral(),
    )
    .expect("bind operator endpoint");

    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), agent_fp));
    let conn = operator_endpoint
        .dial(dial_verifier, agent_whisper_addr)
        .await
        .expect("operator dial");

    let sealer = Sealer::new(operator_id.clone());
    let envelope_verifier = Verifier::new(resolver.clone());

    let outbound = sealer.seal(&WhisperPayload::subscribe(Subscribe {
        since_unix_ms: 0,
        max_items: 0,
    }));
    conn.send_envelope(&outbound).await.expect("send subscribe");
    let bytes = conn.recv_envelope().await.expect("recv alerts");
    let opened = envelope_verifier.open(&bytes).expect("verify alerts");
    let alerts = match opened.payload.body {
        Some(Body::Alerts(a)) => a,
        other => panic!("unexpected body: {other:?}"),
    };

    assert!(!alerts.items.is_empty(), "operator should have received at least one alert");
    let alert = alerts
        .items
        .iter()
        .find(|a| a.episode_id == expected_episode)
        .expect("alert with our episode_id should be in the inbox");

    assert_eq!(alert.originator_fp, agent_fp.as_bytes().to_vec());
    assert!(alert.suspicion >= 0.5);
    assert!(alert.exe_path.contains("payload"));
    assert!(!alert.exe_sha256_hex.is_empty());
    assert!(alerts.cursor_unix_ms > alert.ts_unix_ms);

    // Cursor advance: a second Subscribe with the new cursor should
    // return zero items (the alert is now "before" the cursor).
    let dial_verifier_2 = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), agent_fp));
    let conn2 = operator_endpoint
        .dial(dial_verifier_2, agent_whisper_addr)
        .await
        .expect("re-dial");
    let outbound2 = sealer.seal(&WhisperPayload::subscribe(Subscribe {
        since_unix_ms: alerts.cursor_unix_ms,
        max_items: 0,
    }));
    conn2.send_envelope(&outbound2).await.expect("send subscribe 2");
    let bytes2 = conn2.recv_envelope().await.expect("recv alerts 2");
    let opened2 = envelope_verifier.open(&bytes2).expect("verify alerts 2");
    let alerts2 = match opened2.payload.body {
        Some(Body::Alerts(a)) => a,
        other => panic!("unexpected body 2: {other:?}"),
    };
    assert!(alerts2.items.is_empty(), "second subscribe should be empty");

    operator_endpoint.close().await;
    agent.shutdown().await.expect("shutdown agent");

    // Suppress warning about unused KnownNeighbors import in test scope.
    let _ = std::any::type_name::<KnownNeighbors>();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthorized_operator_subscribe_is_rejected() {
    let workdir = TempDir::new().unwrap();
    let payload_path = workdir.path().join("payload");
    std::fs::write(&payload_path, b"phase-6a-rejected-test").unwrap();

    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());

    // Agent only trusts `operator_id`; we'll subscribe with a *different*
    // identity that should be rejected even though the TLS layer would
    // succeed via the agent's bootstrap window.
    let stranger_id = Arc::new(Identity::generate());

    let agent_id = Arc::new(Identity::generate());
    let agent_fp = agent_id.fingerprint();
    let agent_vk = agent_id.verifying_key();

    let cfg = build_agent_config(workdir.path(), reserve_udp_port(), operator_pubkey_b64);
    let source = Box::new(MockEventSource::new(vec![make_exec(7, payload_path)]));

    let agent = Agent::start(cfg, agent_id, source).await.expect("start agent");
    let agent_whisper_addr = agent.whisper_addr().expect("whisper_addr");

    let mut resolver = StaticResolver::new();
    resolver.insert(agent_vk);
    resolver.insert(stranger_id.verifying_key());
    let resolver = Arc::new(resolver);

    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let stranger_endpoint = BoweryEndpoint::bind(
        stranger_id.clone(),
        accept_verifier,
        loopback_ephemeral(),
    )
    .expect("bind stranger endpoint");

    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), agent_fp));
    // The TLS handshake should fail because the agent doesn't have
    // the stranger pinned (operators-only resolver). If somehow the
    // dial succeeds, the agent's Subscribe handler still drops the
    // request and we'd get no Alerts response — either way, the
    // stranger learns nothing.
    let dial_result = stranger_endpoint
        .dial(dial_verifier, agent_whisper_addr)
        .await;
    if let Ok(conn) = dial_result {
        let sealer = Sealer::new(stranger_id.clone());
        let outbound = sealer.seal(&WhisperPayload::subscribe(Subscribe {
            since_unix_ms: 0,
            max_items: 0,
        }));
        // Send may succeed (one-way uni stream); recv must error.
        let _ = conn.send_envelope(&outbound).await;
        let recv_result = tokio::time::timeout(
            Duration::from_millis(500),
            conn.recv_envelope(),
        )
        .await;
        assert!(
            !matches!(recv_result, Ok(Ok(_))),
            "stranger must not receive Alerts; got {recv_result:?}"
        );
    }

    stranger_endpoint.close().await;
    agent.shutdown().await.expect("shutdown agent");
}
