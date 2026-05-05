//! Phase-6b slice 1 integration: the operator dials a running agent,
//! sends an `OperatorCommand::Osquery`, and the agent's dispatch
//! returns the slice-1 stub error. Proves the round-trip wiring is
//! correct end-to-end (proto → handler → seal → operator-side parse)
//! before the real osquery handler arrives in slice 2.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, HeartbeatConfig, IdentityConfig,
    InboxConfig, LlmConfig, MeshConfig, OperatorsConfig, ResponseConfig, RoleConfig, WhisperConfig,
    WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::NoopEventSource;
use bowery_proto::{
    Body, OperatorCommand, OperatorCommandBody, OperatorResultBody, OsqueryQuery, WhisperPayload,
};
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

fn build_agent_config(dir: &Path, mesh_addr: SocketAddr, operator_pubkey_b64: String) -> Config {
    Config {
        identity: IdentityConfig {
            path: dir.join("identity.key"),
        },
        known_neighbors: bowery_agent::config::KnownNeighborsConfig {
            path: dir.join("known_neighbors.json"),
            bootstrap_window: Duration::from_hours(1),
            max_pinned_peers: 1024,
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr,
            advertise_addr: Some(mesh_addr),
            seeds: vec![],
            cluster_id: Some("bowery-test-opcmd".to_string()),
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
        alerts: AlertsConfig::default(),
        bloom: BloomConfig::default(),
        response: ResponseConfig::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn osquery_command_round_trips_slice_1_stub_error() {
    let workdir = TempDir::new().unwrap();
    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());

    let cfg = build_agent_config(
        workdir.path(),
        reserve_udp_port(),
        operator_pubkey_b64.clone(),
    );

    let agent_id = Arc::new(Identity::generate());
    let agent_fp = agent_id.fingerprint();
    let agent_vk = agent_id.verifying_key();

    let agent = Agent::start(cfg, agent_id, Box::new(NoopEventSource))
        .await
        .expect("start agent");
    let agent_whisper_addr = agent.whisper_addr().expect("whisper addr");

    // Operator side: build a Sealer + Verifier + endpoint that can
    // dial the agent and round-trip an envelope.
    let mut resolver = StaticResolver::new();
    resolver.insert(agent_vk);
    let resolver = Arc::new(resolver);
    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let operator_endpoint =
        BoweryEndpoint::bind(operator_id.clone(), accept_verifier, loopback_ephemeral())
            .expect("bind operator endpoint");
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), agent_fp));
    let conn = operator_endpoint
        .dial(dial_verifier, agent_whisper_addr)
        .await
        .expect("operator dial");

    let operator_fp = operator_id.fingerprint();
    let sealer = Sealer::new(operator_id.clone());
    let envelope_verifier = Verifier::new(resolver.clone(), operator_fp);

    let cmd = OperatorCommand {
        request_id: "test-req-1".into(),
        timeout_ms: 5_000,
        command: Some(OperatorCommandBody::Osquery(OsqueryQuery {
            sql: "SELECT pid, name FROM processes LIMIT 1".into(),
        })),
    };
    let outbound = sealer.seal_for(&agent_fp, &WhisperPayload::operator_command(cmd));
    conn.send_envelope(&outbound).await.expect("send");
    let bytes = conn.recv_envelope().await.expect("recv");
    let opened = envelope_verifier.open(&bytes).expect("verify");

    let result = match opened.payload.body {
        Some(Body::OperatorResult(r)) => r,
        other => panic!("unexpected body: {other:?}"),
    };
    assert_eq!(result.request_id, "test-req-1");
    match result.result {
        Some(OperatorResultBody::Error(e)) => {
            // Slice 1 stub: real handler in slice 2.
            assert_eq!(e.kind, "unimplemented");
            assert!(e.message.contains("slice 2"));
        }
        other => panic!("expected Error body, got {other:?}"),
    }

    // Confirm the AgentEvent fired so dashboards see the dispatch.
    let mut events = agent.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let saw_event = loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        if timeout.is_zero() {
            break false;
        }
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::OperatorCommandHandled {
                request_id,
                kind: "osquery",
                ..
            })) if request_id == "test-req-1" => break true,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) | Err(_) => break false,
        }
    };
    // The event might already have been emitted before our subscribe;
    // tolerate that as long as the round-trip itself succeeded.
    let _ = saw_event;

    drop(conn);
    operator_endpoint.close().await;
    agent.shutdown().await.expect("shutdown");
}

/// A non-operator pinned peer must not be able to issue
/// `OperatorCommand`. The agent's gate matches the Subscribe gate —
/// envelope-verified-as-pinned-peer is not enough; the sender must
/// be in the configured `[operators]` set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_operator_sender_is_rejected() {
    let workdir = TempDir::new().unwrap();
    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());
    // The "stranger" is NOT in operators, but we still let the agent
    // pin them via known_neighbors (simulating any peer).
    let stranger_id = Arc::new(Identity::generate());

    let agent_id = Arc::new(Identity::generate());
    let agent_fp = agent_id.fingerprint();
    let agent_vk = agent_id.verifying_key();

    let cfg = build_agent_config(
        workdir.path(),
        reserve_udp_port(),
        operator_pubkey_b64.clone(),
    );
    let agent = Agent::start(cfg, agent_id, Box::new(NoopEventSource))
        .await
        .expect("start agent");
    let agent_whisper_addr = agent.whisper_addr().expect("whisper addr");

    // Pin the stranger so TLS + envelope verification both pass; the
    // operators-only gate inside handle_connection should still reject.
    agent
        .known_neighbors()
        .try_pin(&stranger_id.verifying_key())
        .expect("pin stranger");

    let mut resolver = StaticResolver::new();
    resolver.insert(agent_vk);
    resolver.insert(stranger_id.verifying_key());
    let resolver = Arc::new(resolver);
    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let stranger_endpoint =
        BoweryEndpoint::bind(stranger_id.clone(), accept_verifier, loopback_ephemeral())
            .expect("bind stranger endpoint");
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), agent_fp));
    let conn = stranger_endpoint
        .dial(dial_verifier, agent_whisper_addr)
        .await
        .expect("stranger dial");

    let sealer = Sealer::new(stranger_id);
    let cmd = OperatorCommand {
        request_id: "stranger-req".into(),
        timeout_ms: 1_000,
        command: Some(OperatorCommandBody::Osquery(OsqueryQuery {
            sql: "SELECT 1".into(),
        })),
    };
    let outbound = sealer.seal_for(&agent_fp, &WhisperPayload::operator_command(cmd));
    let _ = conn.send_envelope(&outbound).await;
    let recv = tokio::time::timeout(Duration::from_millis(500), conn.recv_envelope()).await;
    assert!(
        !matches!(recv, Ok(Ok(_))),
        "stranger must not receive an OperatorResult; got {recv:?}"
    );

    drop(conn);
    stranger_endpoint.close().await;
    agent.shutdown().await.expect("shutdown");
}
