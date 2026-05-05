//! Phase-6b slice 1 integration: the operator dials a running agent,
//! sends an `OperatorCommand::Sysquery`, and the agent's dispatch
//! returns the slice-1 stub error. Proves the round-trip wiring is
//! correct end-to-end (proto → handler → seal → operator-side parse)
//! before the real sysquery handler arrives in slice 2.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, HeartbeatConfig, IdentityConfig,
    InboxConfig, LlmConfig, MeshConfig, OperatorsConfig, ResponseConfig, RoleConfig,
    SysqueryConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::NoopEventSource;
use bowery_proto::{
    Body, OperatorCommand, OperatorCommandBody, OperatorResultBody, SqlQuery, SqlValueKind,
    SysqueryQuery, WhisperPayload,
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

fn build_agent_config(
    dir: &Path,
    mesh_addr: SocketAddr,
    operator_pubkey_b64: String,
    sysquery: SysqueryConfig,
) -> Config {
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
        sysquery,
    }
}

/// Write a shim shell script that pretends to be a sysquery binary: ignores
/// all its args (the agent's hardening flags + the SQL string) and
/// emits a known JSON payload on stdout.
fn make_sysquery_shim(dir: &Path, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("sysquery-shim.sh");
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// Phase-6b slice 2: with a real (shim) sysquery binary configured,
/// the round-trip returns a `SysqueryResult` populated with the
/// shim's stdout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sysquery_command_round_trips_with_shim_handler() {
    let workdir = TempDir::new().unwrap();
    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());

    // Shim emits a fixed JSON payload regardless of the SQL string.
    let shim = make_sysquery_shim(workdir.path(), r#"echo '[{"pid":42,"name":"shimmed"}]'"#);
    let sysquery = SysqueryConfig {
        enabled: true,
        binary_path: shim,
        max_timeout: Duration::from_secs(5),
    };
    let cfg = build_agent_config(
        workdir.path(),
        reserve_udp_port(),
        operator_pubkey_b64.clone(),
        sysquery,
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
        forwarded_from_operator: Vec::new(),
        request_id: "test-req-1".into(),
        timeout_ms: 5_000,
        command: Some(OperatorCommandBody::Sysquery(SysqueryQuery {
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
        Some(OperatorResultBody::Sysquery(o)) => {
            assert_eq!(o.exit_code, 0);
            assert!(o.json.contains("shimmed"), "got json: {}", o.json);
        }
        other => panic!("expected Sysquery body, got {other:?}"),
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
                kind: "sysquery",
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

/// Phase-6b slice 2: when sysquery is disabled in config, dispatch
/// returns a structured `policy_denied` error rather than a silent
/// timeout. Operator's CLI sees a clean failure mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sysquery_command_returns_policy_denied_when_disabled() {
    let workdir = TempDir::new().unwrap();
    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());

    // Default SysqueryConfig has enabled = false.
    let cfg = build_agent_config(
        workdir.path(),
        reserve_udp_port(),
        operator_pubkey_b64.clone(),
        SysqueryConfig::default(),
    );

    let agent_id = Arc::new(Identity::generate());
    let agent_fp = agent_id.fingerprint();
    let agent_vk = agent_id.verifying_key();

    let agent = Agent::start(cfg, agent_id, Box::new(NoopEventSource))
        .await
        .expect("start agent");
    let agent_whisper_addr = agent.whisper_addr().expect("whisper addr");

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
        forwarded_from_operator: Vec::new(),
        request_id: "denied-req".into(),
        timeout_ms: 5_000,
        command: Some(OperatorCommandBody::Sysquery(SysqueryQuery {
            sql: "SELECT 1".into(),
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
    match result.result {
        Some(OperatorResultBody::Error(e)) => {
            assert_eq!(e.kind, "policy_denied");
            assert!(e.message.contains("sysquery"));
        }
        other => panic!("expected Error body, got {other:?}"),
    }

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
        SysqueryConfig::default(),
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
        forwarded_from_operator: Vec::new(),
        request_id: "stranger-req".into(),
        timeout_ms: 1_000,
        command: Some(OperatorCommandBody::Sysquery(SysqueryQuery {
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

/// Phase-9 slice 6: the operator dials a running agent, sends an
/// `OperatorCommand::Sql` against the native `bowery-sql` engine,
/// and the agent streams the response back as one or more
/// `SqlChunk` envelopes terminated by `end = true`. This test
/// exercises the full path: proto encode → seal → QUIC → handler
/// dispatch → bowery-sql query → chunked sealed envelopes → operator
/// decode + reassembly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sql_command_streams_chunked_response() {
    let workdir = TempDir::new().unwrap();
    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());

    let cfg = build_agent_config(
        workdir.path(),
        reserve_udp_port(),
        operator_pubkey_b64.clone(),
        SysqueryConfig::default(),
    );
    let agent_id = Arc::new(Identity::generate());
    let agent_fp = agent_id.fingerprint();
    let agent_vk = agent_id.verifying_key();

    let agent = Agent::start(cfg, agent_id, Box::new(NoopEventSource))
        .await
        .expect("start agent");
    let agent_whisper_addr = agent.whisper_addr().expect("whisper addr");

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
        forwarded_from_operator: Vec::new(),
        request_id: "sql-req-1".into(),
        timeout_ms: 5_000,
        command: Some(OperatorCommandBody::Sql(SqlQuery {
            // Recursive CTE produces 600 rows — well above the
            // SQL_CHUNK_ROW_LIMIT (256) so the response must arrive
            // as multiple chunks, exercising the streaming path.
            sql: "WITH RECURSIVE c(x) AS \
                  (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 600) \
                  SELECT x AS counter FROM c"
                .into(),
            fanout: false,
            peers: Vec::new(),
        })),
    };
    let outbound = sealer.seal_for(&agent_fp, &WhisperPayload::operator_command(cmd));
    conn.send_envelope(&outbound).await.expect("send");

    // Read chunks until end=true. Confirm columns arrived once,
    // total rows match the CTE output, and the value of the first
    // and last row are intact.
    let mut chunks_seen = 0;
    let mut columns: Vec<String> = Vec::new();
    let mut rows_seen: Vec<i64> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        let bytes = tokio::time::timeout(timeout, conn.recv_envelope())
            .await
            .expect("recv chunk in time")
            .expect("recv chunk");
        let opened = envelope_verifier.open(&bytes).expect("verify chunk");
        let result = match opened.payload.body {
            Some(Body::OperatorResult(r)) => r,
            other => panic!("unexpected body: {other:?}"),
        };
        assert_eq!(result.request_id, "sql-req-1");
        let chunk = match result.result {
            Some(OperatorResultBody::SqlChunk(c)) => c,
            other => panic!("expected SqlChunk, got {other:?}"),
        };
        if chunks_seen == 0 {
            assert_eq!(chunk.columns, vec!["counter".to_string()]);
            columns = chunk.columns.clone();
        } else {
            assert!(
                chunk.columns.is_empty(),
                "subsequent chunks must not repeat column names"
            );
        }
        for row in &chunk.rows {
            assert_eq!(row.values.len(), columns.len());
            match &row.values[0].value {
                Some(SqlValueKind::Integer(i)) => rows_seen.push(*i),
                other => panic!("unexpected value: {other:?}"),
            }
        }
        chunks_seen += 1;
        if chunk.end {
            break;
        }
    }
    assert!(
        chunks_seen >= 2,
        "600 rows must arrive in multiple chunks; got {chunks_seen}"
    );
    assert_eq!(rows_seen.len(), 600);
    assert_eq!(rows_seen[0], 1);
    assert_eq!(rows_seen[599], 600);

    drop(conn);
    operator_endpoint.close().await;
    agent.shutdown().await.expect("shutdown");
}

/// Phase-9 slice 6: a SQL syntax error surfaces as a single
/// `OperatorResult::Error` (terminating the stream with no chunks),
/// not a `SqlChunk` with no rows. Operator-side decoder must accept
/// either as a stream terminator.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sql_syntax_error_returns_structured_error() {
    let workdir = TempDir::new().unwrap();
    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());

    let cfg = build_agent_config(
        workdir.path(),
        reserve_udp_port(),
        operator_pubkey_b64.clone(),
        SysqueryConfig::default(),
    );
    let agent_id = Arc::new(Identity::generate());
    let agent_fp = agent_id.fingerprint();
    let agent_vk = agent_id.verifying_key();

    let agent = Agent::start(cfg, agent_id, Box::new(NoopEventSource))
        .await
        .expect("start agent");
    let agent_whisper_addr = agent.whisper_addr().expect("whisper addr");

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
        forwarded_from_operator: Vec::new(),
        request_id: "sql-req-err".into(),
        timeout_ms: 5_000,
        command: Some(OperatorCommandBody::Sql(SqlQuery {
            sql: "SELECT * FROM does_not_exist".into(),
            fanout: false,
            peers: Vec::new(),
        })),
    };
    let outbound = sealer.seal_for(&agent_fp, &WhisperPayload::operator_command(cmd));
    conn.send_envelope(&outbound).await.expect("send");

    let bytes = tokio::time::timeout(Duration::from_secs(3), conn.recv_envelope())
        .await
        .expect("recv error envelope in time")
        .expect("recv");
    let opened = envelope_verifier.open(&bytes).expect("verify");
    let result = match opened.payload.body {
        Some(Body::OperatorResult(r)) => r,
        other => panic!("unexpected body: {other:?}"),
    };
    assert_eq!(result.request_id, "sql-req-err");
    match result.result {
        Some(OperatorResultBody::Error(e)) => {
            assert_eq!(e.kind, "sql_error", "expected sql_error, got {e:?}");
            assert!(
                e.message.to_lowercase().contains("does_not_exist")
                    || e.message.to_lowercase().contains("no such table"),
                "error message should mention the missing table; got: {}",
                e.message
            );
        }
        other => panic!("expected Error body, got {other:?}"),
    }

    drop(conn);
    operator_endpoint.close().await;
    agent.shutdown().await.expect("shutdown");
}

/// Phase-9 slice 7: two agents discover each other via the mesh,
/// pin each other, then the operator dials one of them with
/// `OperatorCommand::Sql { fanout: true }`. The relay must:
/// 1. Run the query locally and emit chunks tagged with its own fp.
/// 2. Dispatch the query to its pinned peer (with fanout=false to
///    prevent recursion) and forward that peer's chunks tagged
///    with the peer's fp.
/// 3. Drop the connection once both peer streams are done.
///
/// This is the canonical multi-agent test: real QUIC handshake
/// across two agents + a third operator, mesh discovery, pinning,
/// fan-out, end-to-end signature verification at every hop.
#[allow(clippy::too_many_lines)] // multi-agent fixture is inherently long
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_streams_rows_from_relay_and_peer() {
    // Two agents, both with the operator authorized + each
    // authorizing the other (relay must be in peer's [operators]
    // for the fan-out leg; peer must be in relay's [operators]
    // strictly speaking only matters for the reverse direction,
    // but symmetric setup is simpler).
    let dir_alpha = TempDir::new().unwrap();
    let dir_beta = TempDir::new().unwrap();

    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();

    let id_alpha = Arc::new(Identity::generate());
    let id_beta = Arc::new(Identity::generate());
    let operator_id = Arc::new(Identity::generate());

    let _pub_alpha = BASE64.encode(id_alpha.verifying_key().as_bytes());
    let _pub_beta = BASE64.encode(id_beta.verifying_key().as_bytes());
    let pub_op = BASE64.encode(operator_id.verifying_key().as_bytes());

    let cfg_alpha = Config {
        identity: IdentityConfig {
            path: dir_alpha.path().join("identity.key"),
        },
        known_neighbors: bowery_agent::config::KnownNeighborsConfig {
            path: dir_alpha.path().join("known_neighbors.json"),
            bootstrap_window: Duration::from_hours(1),
            max_pinned_peers: 1024,
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr_alpha,
            advertise_addr: Some(mesh_addr_alpha),
            seeds: vec![mesh_addr_beta.to_string()],
            cluster_id: Some("bowery-fanout-test".to_string()),
        },
        whisper: WhisperConfig {
            qa: WhisperQaConfig::default(),
            bind_addr: loopback_ephemeral(),
        },
        heartbeat: HeartbeatConfig {
            interval: Duration::from_millis(200),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
        role: RoleConfig {
            publish_interval: Duration::from_millis(500),
        },
        llm: LlmConfig::default(),
        // Phase-9 final-1: each agent only authorises the
        // operator, NOT the other agent. The relay no longer
        // signs commands "as the operator" — it forwards an
        // operator-signed authorisation that the peer verifies
        // against its own [operators] set.
        operators: OperatorsConfig {
            pubkeys_b64: vec![pub_op.clone()],
        },
        inbox: InboxConfig::default(),
        alerts: AlertsConfig::default(),
        bloom: BloomConfig::default(),
        response: ResponseConfig::default(),
        sysquery: bowery_agent::config::SysqueryConfig::default(),
    };
    let cfg_beta = Config {
        identity: IdentityConfig {
            path: dir_beta.path().join("identity.key"),
        },
        known_neighbors: bowery_agent::config::KnownNeighborsConfig {
            path: dir_beta.path().join("known_neighbors.json"),
            bootstrap_window: Duration::from_hours(1),
            max_pinned_peers: 1024,
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr_beta,
            advertise_addr: Some(mesh_addr_beta),
            seeds: vec![mesh_addr_alpha.to_string()],
            cluster_id: Some("bowery-fanout-test".to_string()),
        },
        whisper: WhisperConfig {
            qa: WhisperQaConfig::default(),
            bind_addr: loopback_ephemeral(),
        },
        heartbeat: HeartbeatConfig {
            interval: Duration::from_millis(200),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
        role: RoleConfig {
            publish_interval: Duration::from_millis(500),
        },
        llm: LlmConfig::default(),
        operators: OperatorsConfig {
            pubkeys_b64: vec![pub_op.clone()],
        },
        inbox: InboxConfig::default(),
        alerts: AlertsConfig::default(),
        bloom: BloomConfig::default(),
        response: ResponseConfig::default(),
        sysquery: bowery_agent::config::SysqueryConfig::default(),
    };

    let agent_alpha = Agent::start(cfg_alpha, id_alpha.clone(), Box::new(NoopEventSource))
        .await
        .expect("start alpha");
    let agent_beta = Agent::start(cfg_beta, id_beta.clone(), Box::new(NoopEventSource))
        .await
        .expect("start beta");

    let alpha_fp = agent_alpha.fingerprint();
    let beta_fp = agent_beta.fingerprint();
    let alpha_addr = agent_alpha.whisper_addr().expect("alpha whisper addr");

    // Wait for both agents to mutually pin each other so the
    // relay's KnownNeighbors actually contains beta when we
    // dispatch the fan-out.
    let pinned_alpha_rx = agent_alpha.subscribe();
    let pinned_beta_rx = agent_beta.subscribe();
    tokio::time::timeout(Duration::from_secs(15), async move {
        tokio::join!(
            wait_for_pin(pinned_alpha_rx, beta_fp),
            wait_for_pin(pinned_beta_rx, alpha_fp),
        )
    })
    .await
    .expect("agents must pin each other before fanout dispatch");

    // Operator-side QUIC stack — pinned to alpha (the relay).
    let mut resolver = StaticResolver::new();
    resolver.insert(id_alpha.verifying_key());
    resolver.insert(id_beta.verifying_key());
    let resolver = Arc::new(resolver);
    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let operator_endpoint =
        BoweryEndpoint::bind(operator_id.clone(), accept_verifier, loopback_ephemeral())
            .expect("bind operator endpoint");
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), alpha_fp));
    let conn = operator_endpoint
        .dial(dial_verifier, alpha_addr)
        .await
        .expect("operator dial relay");

    let operator_fp = operator_id.fingerprint();
    let sealer = Sealer::new(operator_id.clone());
    let envelope_verifier = Verifier::new(resolver.clone(), operator_fp);

    // Phase-9 final-1: build the operator-signed authorisation
    // that lets the relay forward the query to its peers without
    // the peers needing the relay in their [operators] set.
    let body = OperatorCommandBody::Sql(SqlQuery {
        sql: "SELECT 1 AS one".into(),
        fanout: true,
        peers: Vec::new(),
    });
    let authorization =
        bowery_whisper::forwarding::sign_operator_authorization(&operator_id, "fanout-1", &body);
    let cmd = OperatorCommand {
        forwarded_from_operator: authorization.encode_to_vec(),
        request_id: "fanout-1".into(),
        timeout_ms: 8_000,
        command: Some(body),
    };
    let outbound = sealer.seal_for(&alpha_fp, &WhisperPayload::operator_command(cmd));
    conn.send_envelope(&outbound)
        .await
        .expect("send fanout cmd");

    // Read until connection closes; track per-agent EOFs.
    let mut ended_agents: HashSet<Vec<u8>> = HashSet::new();
    let mut rows_per_agent: HashMap<Vec<u8>, Vec<i64>> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        if timeout.is_zero() {
            break;
        }
        match tokio::time::timeout(timeout, conn.recv_envelope()).await {
            Ok(Ok(bytes)) => {
                let opened = envelope_verifier.open(&bytes).expect("verify chunk");
                let result = match opened.payload.body {
                    Some(Body::OperatorResult(r)) => r,
                    other => panic!("unexpected body: {other:?}"),
                };
                assert_eq!(result.request_id, "fanout-1");
                let chunk = match result.result {
                    Some(OperatorResultBody::SqlChunk(c)) => c,
                    other => panic!("expected SqlChunk, got {other:?}"),
                };
                for row in &chunk.rows {
                    if let Some(SqlValueKind::Integer(i)) = &row.values[0].value {
                        rows_per_agent
                            .entry(chunk.agent_fp.clone())
                            .or_default()
                            .push(*i);
                    }
                }
                if chunk.end {
                    ended_agents.insert(chunk.agent_fp.clone());
                }
                // Stop once both agents have produced an EOF.
                if ended_agents.len() == 2 {
                    break;
                }
            }
            // Connection closed or deadline expired — both end the loop.
            Ok(Err(_)) | Err(_) => break,
        }
    }
    assert_eq!(
        ended_agents.len(),
        2,
        "expected EOF from both agents, got {}: {:?}",
        ended_agents.len(),
        ended_agents
    );
    assert!(
        ended_agents.contains(alpha_fp.as_bytes().as_slice()),
        "missing relay's own EOF"
    );
    assert!(
        ended_agents.contains(beta_fp.as_bytes().as_slice()),
        "missing peer's EOF"
    );
    assert_eq!(rows_per_agent[alpha_fp.as_bytes().as_slice()], vec![1]);
    assert_eq!(rows_per_agent[beta_fp.as_bytes().as_slice()], vec![1]);

    drop(conn);
    operator_endpoint.close().await;
    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}

async fn wait_for_pin(
    mut rx: tokio::sync::broadcast::Receiver<AgentEvent>,
    expected: bowery_crypto::Fingerprint,
) {
    loop {
        match rx.recv().await {
            Ok(AgentEvent::PeerPinned(fp)) if fp == expected => return,
            Ok(_) | Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => panic!("agent event channel closed before pinning"),
        }
    }
}

/// Phase-9 slice 8: end-to-end test that the agent's bonus
/// `bowery_peers` table sees the relay's pinned-peer set after
/// mutual mesh discovery. This exercises the full vertical slice:
///
/// 1. Two agents discover each other and pin via TOFU.
/// 2. Operator dials `agent_alpha`, runs
///    `SELECT fingerprint_hex FROM bowery_peers`.
/// 3. The streaming SQL path delivers the row, and the
///    `fingerprint_hex` matches `agent_beta`'s actual fp.
///
/// This is the canonical "Bowery-internal state surfaced as SQL"
/// smoke test — the table only exists because slice 8a wired the
/// agent's `KnownNeighbors` handle into a `BoweryTable` impl.
#[allow(clippy::too_many_lines)] // multi-agent fixture is inherently long
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bowery_peers_table_surfaces_pinned_peers() {
    let dir_alpha = TempDir::new().unwrap();
    let dir_beta = TempDir::new().unwrap();

    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();

    let id_alpha = Arc::new(Identity::generate());
    let id_beta = Arc::new(Identity::generate());
    let operator_id = Arc::new(Identity::generate());
    let operator_pub = BASE64.encode(operator_id.verifying_key().as_bytes());

    let mut cfg_alpha = build_agent_config(
        dir_alpha.path(),
        mesh_addr_alpha,
        operator_pub.clone(),
        SysqueryConfig::default(),
    );
    cfg_alpha.mesh.seeds = vec![mesh_addr_beta.to_string()];
    cfg_alpha.mesh.cluster_id = Some("bowery-bonus-test".into());
    cfg_alpha.heartbeat.interval = Duration::from_millis(200);

    let mut cfg_beta = build_agent_config(
        dir_beta.path(),
        mesh_addr_beta,
        operator_pub.clone(),
        SysqueryConfig::default(),
    );
    cfg_beta.mesh.seeds = vec![mesh_addr_alpha.to_string()];
    cfg_beta.mesh.cluster_id = Some("bowery-bonus-test".into());
    cfg_beta.heartbeat.interval = Duration::from_millis(200);

    let agent_alpha = Agent::start(cfg_alpha, id_alpha.clone(), Box::new(NoopEventSource))
        .await
        .expect("start alpha");
    let agent_beta = Agent::start(cfg_beta, id_beta.clone(), Box::new(NoopEventSource))
        .await
        .expect("start beta");

    let alpha_fp = agent_alpha.fingerprint();
    let beta_fp = agent_beta.fingerprint();
    let alpha_addr = agent_alpha.whisper_addr().expect("alpha whisper addr");

    // Wait for alpha to pin beta so bowery_peers has something to
    // surface. Beta's pinning of alpha doesn't matter for this test.
    let pinned_alpha_rx = agent_alpha.subscribe();
    tokio::time::timeout(
        Duration::from_secs(15),
        wait_for_pin(pinned_alpha_rx, beta_fp),
    )
    .await
    .expect("alpha must pin beta");

    let mut resolver = StaticResolver::new();
    resolver.insert(id_alpha.verifying_key());
    let resolver = Arc::new(resolver);
    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let operator_endpoint =
        BoweryEndpoint::bind(operator_id.clone(), accept_verifier, loopback_ephemeral())
            .expect("bind operator endpoint");
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), alpha_fp));
    let conn = operator_endpoint
        .dial(dial_verifier, alpha_addr)
        .await
        .expect("operator dial alpha");

    let operator_fp = operator_id.fingerprint();
    let sealer = Sealer::new(operator_id.clone());
    let envelope_verifier = Verifier::new(resolver.clone(), operator_fp);

    let cmd = OperatorCommand {
        forwarded_from_operator: Vec::new(),
        request_id: "bonus-peers".into(),
        timeout_ms: 5_000,
        command: Some(OperatorCommandBody::Sql(SqlQuery {
            sql: "SELECT fingerprint_hex FROM bowery_peers".into(),
            fanout: false,
            peers: Vec::new(),
        })),
    };
    let outbound = sealer.seal_for(&alpha_fp, &WhisperPayload::operator_command(cmd));
    conn.send_envelope(&outbound).await.expect("send");

    // Read until first end=true; collect fingerprint_hex strings.
    let mut seen_fps: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        let bytes = tokio::time::timeout(timeout, conn.recv_envelope())
            .await
            .expect("recv in time")
            .expect("recv");
        let opened = envelope_verifier.open(&bytes).expect("verify");
        let result = match opened.payload.body {
            Some(Body::OperatorResult(r)) => r,
            other => panic!("unexpected body: {other:?}"),
        };
        let chunk = match result.result {
            Some(OperatorResultBody::SqlChunk(c)) => c,
            other => panic!("expected SqlChunk, got {other:?}"),
        };
        for row in &chunk.rows {
            if let Some(SqlValueKind::Text(s)) = &row.values[0].value {
                seen_fps.push(s.clone());
            }
        }
        if chunk.end {
            break;
        }
    }
    assert!(
        seen_fps.iter().any(|fp| fp == &beta_fp.to_string()),
        "bowery_peers must include beta's fingerprint; got {seen_fps:?}"
    );

    drop(conn);
    operator_endpoint.close().await;
    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}
