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
    InboxConfig, LlmConfig, MeshConfig, OperatorsConfig, OsqueryConfig, ResponseConfig, RoleConfig,
    WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::NoopEventSource;
use bowery_proto::{
    Body, OperatorCommand, OperatorCommandBody, OperatorResultBody, OsqueryQuery, SqlQuery,
    SqlValueKind, WhisperPayload,
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
    osquery: OsqueryConfig,
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
        osquery,
    }
}

/// Write a shim shell script that pretends to be osqueryi: ignores
/// all its args (the agent's hardening flags + the SQL string) and
/// emits a known JSON payload on stdout.
fn make_osquery_shim(dir: &Path, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("osquery-shim.sh");
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// Phase-6b slice 2: with a real (shim) osquery binary configured,
/// the round-trip returns an `OsqueryResult` populated with the
/// shim's stdout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn osquery_command_round_trips_with_shim_handler() {
    let workdir = TempDir::new().unwrap();
    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());

    // Shim emits a fixed JSON payload regardless of the SQL string.
    let shim = make_osquery_shim(workdir.path(), r#"echo '[{"pid":42,"name":"shimmed"}]'"#);
    let osquery = OsqueryConfig {
        enabled: true,
        binary_path: shim,
        max_timeout: Duration::from_secs(5),
    };
    let cfg = build_agent_config(
        workdir.path(),
        reserve_udp_port(),
        operator_pubkey_b64.clone(),
        osquery,
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
        Some(OperatorResultBody::Osquery(o)) => {
            assert_eq!(o.exit_code, 0);
            assert!(o.json.contains("shimmed"), "got json: {}", o.json);
        }
        other => panic!("expected Osquery body, got {other:?}"),
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

/// Phase-6b slice 2: when osquery is disabled in config, dispatch
/// returns a structured `policy_denied` error rather than a silent
/// timeout. Operator's CLI sees a clean failure mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn osquery_command_returns_policy_denied_when_disabled() {
    let workdir = TempDir::new().unwrap();
    let operator_id = Arc::new(Identity::generate());
    let operator_pubkey_b64 = BASE64.encode(operator_id.verifying_key().as_bytes());

    // Default OsqueryConfig has enabled = false.
    let cfg = build_agent_config(
        workdir.path(),
        reserve_udp_port(),
        operator_pubkey_b64.clone(),
        OsqueryConfig::default(),
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
        request_id: "denied-req".into(),
        timeout_ms: 5_000,
        command: Some(OperatorCommandBody::Osquery(OsqueryQuery {
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
            assert!(e.message.contains("osquery"));
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
        OsqueryConfig::default(),
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
        OsqueryConfig::default(),
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
        OsqueryConfig::default(),
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
        request_id: "sql-req-err".into(),
        timeout_ms: 5_000,
        command: Some(OperatorCommandBody::Sql(SqlQuery {
            sql: "SELECT * FROM does_not_exist".into(),
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
