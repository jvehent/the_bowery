//! Integration: a YARA push propagates across the mesh and the
//! propagation terminates in a cyclic peer graph.
//!
//! Two agents pin each other (a 2-cycle — the smallest graph that would
//! loop forever without the seen-set). The operator pushes one rule to
//! alpha with `fanout` and a hop budget; alpha stores it and forwards to
//! beta; beta stores it and — because alpha has already handled that
//! `(operator_fp, request_id)` — alpha drops the push coming back
//! instead of bouncing it again.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, HeartbeatConfig, IdentityConfig,
    InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig, MonitorConfig, OperatorsConfig,
    ResponseConfig, RoleConfig, WhisperConfig, WhisperQaConfig, YaraConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::NoopEventSource;
use bowery_proto::{
    Body, OperatorCommand, OperatorCommandBody, OperatorResultBody, WhisperPayload, YaraPush,
};
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::BoweryEndpoint;
use bowery_whisper::{Sealer, StaticResolver, Verifier};
use prost::Message as _;
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

mod common;
use common::{loopback_ephemeral, reserve_udp_port};

#[allow(clippy::too_many_arguments)]
fn build_config(
    dir: &std::path::Path,
    mesh_addr: SocketAddr,
    seed: SocketAddr,
    operator_pubkey_b64: String,
) -> Config {
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
            seeds: vec![seed.to_string()],
            cluster_id: Some("bowery-test-yara".to_string()),
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
            pubkeys_b64: vec![operator_pubkey_b64],
        },
        inbox: InboxConfig::default(),
        alerts: AlertsConfig::default(),
        bloom: BloomConfig::default(),
        response: ResponseConfig::default(),
        sql: bowery_agent::config::SqlConfig::default(),
        monitor: MonitorConfig::default(),
        detection: bowery_agent::config::DetectionConfig::default(),
        eventlog: bowery_agent::config::EventLogConfig {
            enabled: false,
            ..Default::default()
        },
        yara: YaraConfig {
            path: dir.join("yara"),
            ..YaraConfig::default()
        },
    }
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

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn yara_push_propagates_to_peer_and_terminates() {
    let dir_alpha = TempDir::new().unwrap();
    let dir_beta = TempDir::new().unwrap();
    let mesh_alpha = reserve_udp_port();
    let mesh_beta = reserve_udp_port();

    let id_alpha = Arc::new(Identity::generate());
    let id_beta = Arc::new(Identity::generate());
    let operator_id = Arc::new(Identity::generate());
    let pub_op = BASE64.encode(operator_id.verifying_key().as_bytes());

    let agent_alpha = Agent::start(
        build_config(dir_alpha.path(), mesh_alpha, mesh_beta, pub_op.clone()),
        id_alpha.clone(),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start alpha");
    let agent_beta = Agent::start(
        build_config(dir_beta.path(), mesh_beta, mesh_alpha, pub_op),
        id_beta.clone(),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start beta");

    let alpha_fp = agent_alpha.fingerprint();
    let beta_fp = agent_beta.fingerprint();
    let alpha_addr = agent_alpha.whisper_addr().expect("alpha whisper addr");

    // Mutual pinning makes this a 2-cycle: without loop prevention the
    // push would bounce alpha→beta→alpha→… indefinitely.
    let pin_a = agent_alpha.subscribe();
    let pin_b = agent_beta.subscribe();
    tokio::time::timeout(Duration::from_secs(15), async move {
        tokio::join!(wait_for_pin(pin_a, beta_fp), wait_for_pin(pin_b, alpha_fp))
    })
    .await
    .expect("agents must pin each other before propagation");

    // Operator side.
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
        .expect("operator dial alpha");
    let sealer = Sealer::new(operator_id.clone());
    let envelope_verifier = Verifier::new(resolver.clone(), operator_id.fingerprint());

    let rule_src = b"rule bowery_test { strings: $a = \"NEEDLE\" condition: $a }".to_vec();
    let rule_id = {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;
        Sha256::digest(&rule_src)
            .iter()
            .fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    };

    let body = OperatorCommandBody::YaraPush(YaraPush {
        rule_id: rule_id.clone(),
        rules: rule_src,
        targets: Vec::new(), // store + propagate only; no scan needed here
        fanout: true,
        ttl: 3,
    });
    let auth =
        bowery_whisper::forwarding::sign_operator_authorization(&operator_id, "yara-1", &body);
    let cmd = OperatorCommand {
        forwarded_from_operator: auth.encode_to_vec(),
        request_id: "yara-1".into(),
        timeout_ms: 8_000,
        command: Some(body),
    };
    conn.send_envelope(&sealer.seal_for(&alpha_fp, &WhisperPayload::operator_command(cmd)))
        .await
        .expect("send yara push");

    // Collect reports until the relay's terminator (empty agent_fp).
    let mut reporters: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, conn.recv_envelope()).await {
            Ok(Ok(bytes)) => {
                let opened = envelope_verifier.open(&bytes).expect("verify report");
                let sender = opened.sender;
                let Some(Body::OperatorResult(r)) = opened.payload.body else {
                    panic!("unexpected body");
                };
                match r.result {
                    Some(OperatorResultBody::YaraReport(rep)) => {
                        if rep.end && rep.agent_fp.is_empty() && sender == alpha_fp {
                            break; // relay's completion terminator
                        }
                        reporters.insert(sender.as_bytes().to_vec());
                    }
                    Some(OperatorResultBody::Error(e)) => {
                        panic!("agent error: {} ({})", e.message, e.kind)
                    }
                    other => panic!("unexpected result body: {other:?}"),
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }

    // Both agents should have reported: alpha directly, beta via
    // propagation (its report is sealed for the operator and relayed).
    assert!(
        reporters.contains(alpha_fp.as_bytes().as_slice()),
        "relay alpha must report"
    );
    assert!(
        reporters.contains(beta_fp.as_bytes().as_slice()),
        "peer beta must report (rule did not propagate)"
    );

    // The rule landed in BOTH stores — the actual goal of distribution.
    for (name, dir) in [("alpha", &dir_alpha), ("beta", &dir_beta)] {
        let path = dir.path().join("yara").join(format!("{rule_id}.yar"));
        assert!(
            path.exists(),
            "{name} should have persisted the rule at {}",
            path.display()
        );
    }

    // Loop prevention: the push bounced back to alpha (beta forwards to
    // its pinned peers too) must have been dropped, so alpha holds
    // exactly one copy and the exchange terminated instead of running
    // until the deadline.
    let index = std::fs::read_to_string(dir_alpha.path().join("yara").join("index.json"))
        .expect("alpha index");
    assert_eq!(
        index.matches(&rule_id).count(),
        1,
        "alpha must store the rule exactly once"
    );

    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}

/// With the engine compiled in, a pushed rule actually scans the given
/// target and a match becomes an operator alert.
#[cfg(feature = "yara")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn yara_push_scans_target_and_alerts_on_match() {
    let dir = TempDir::new().unwrap();
    let mesh = reserve_udp_port();

    // The file the rule should match.
    let scan_dir = dir.path().join("scanme");
    std::fs::create_dir_all(&scan_dir).unwrap();
    std::fs::write(scan_dir.join("evil.bin"), b"prefix NEEDLE suffix").unwrap();
    std::fs::write(scan_dir.join("clean.bin"), b"nothing interesting").unwrap();

    let id = Arc::new(Identity::generate());
    let operator_id = Arc::new(Identity::generate());
    let pub_op = BASE64.encode(operator_id.verifying_key().as_bytes());

    // Seed points at itself: a single standalone agent, no peers.
    let agent = Agent::start(
        build_config(dir.path(), mesh, mesh, pub_op),
        id.clone(),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start agent");
    let agent_fp = agent.fingerprint();
    let addr = agent.whisper_addr().expect("whisper addr");
    let mut events = agent.subscribe();

    let mut resolver = StaticResolver::new();
    resolver.insert(id.verifying_key());
    let resolver = Arc::new(resolver);
    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let operator_endpoint =
        BoweryEndpoint::bind(operator_id.clone(), accept_verifier, loopback_ephemeral())
            .expect("bind operator endpoint");
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), agent_fp));
    let conn = operator_endpoint
        .dial(dial_verifier, addr)
        .await
        .expect("dial agent");
    let sealer = Sealer::new(operator_id.clone());

    let rule_src = b"rule needle_finder { strings: $a = \"NEEDLE\" condition: $a }".to_vec();
    let rule_id = {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;
        Sha256::digest(&rule_src)
            .iter()
            .fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    };
    let body = OperatorCommandBody::YaraPush(YaraPush {
        rule_id,
        rules: rule_src,
        targets: vec![scan_dir.display().to_string()],
        fanout: false,
        ttl: 0,
    });
    let auth =
        bowery_whisper::forwarding::sign_operator_authorization(&operator_id, "yara-scan", &body);
    let cmd = OperatorCommand {
        forwarded_from_operator: auth.encode_to_vec(),
        request_id: "yara-scan".into(),
        timeout_ms: 20_000,
        command: Some(body),
    };
    conn.send_envelope(&sealer.seal_for(&agent_fp, &WhisperPayload::operator_command(cmd)))
        .await
        .expect("send push");

    // The scan must surface an alert for the matching file.
    let alert = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            match events.recv().await {
                Ok(AgentEvent::AlertEmitted { episode_id, .. }) => return episode_id,
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => panic!("event channel closed"),
            }
        }
    })
    .await
    .expect("a YARA match must raise an alert");
    assert!(
        alert.starts_with("yara-"),
        "alert should be attributed to the yara rule, got {alert}"
    );

    agent.shutdown().await.expect("shutdown");
}
