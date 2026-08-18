//! End-to-end integration: two in-process agents discover each other via
//! gossip, mutually pin, and exchange heartbeats.
//!
//! This is the Phase 1 integration test for The Bowery's mesh stack: it
//! exercises chitchat, the TOFU pinning store, the QUIC transport, the
//! envelope crypto, and the agent's task supervision in one go.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, HeartbeatConfig, IdentityConfig,
    InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig, OperatorsConfig, ResponseConfig,
    RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::NoopEventSource;
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

mod common;
use common::{loopback_ephemeral, reserve_udp_port};

fn build_config(dir: &Path, mesh_addr: SocketAddr, seeds: Vec<String>) -> Config {
    build_config_with_log(dir, mesh_addr, seeds, false)
}

/// `with_log` gives the agent a real on-disk event log, which the
/// log-witness path needs: an agent with no log publishes no height, so
/// there is nothing for a peer to remember.
fn build_config_with_log(
    dir: &Path,
    mesh_addr: SocketAddr,
    seeds: Vec<String>,
    with_log: bool,
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
            seeds,
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
            interval: Duration::from_millis(200),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
        role: RoleConfig {
            publish_interval: Duration::from_millis(500),
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
            enabled: with_log,
            path: dir.join("events.db"),
            ..Default::default()
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_agents_discover_pin_and_heartbeat() {
    let dir_alpha = TempDir::new().unwrap();
    let dir_beta = TempDir::new().unwrap();

    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();

    let id_alpha = Arc::new(Identity::generate());
    let id_beta = Arc::new(Identity::generate());

    let cfg_alpha = build_config(
        dir_alpha.path(),
        mesh_addr_alpha,
        vec![mesh_addr_beta.to_string()],
    );
    let cfg_beta = build_config(
        dir_beta.path(),
        mesh_addr_beta,
        vec![mesh_addr_alpha.to_string()],
    );

    let agent_alpha = Agent::start(cfg_alpha, id_alpha.clone(), Box::new(NoopEventSource))
        .await
        .expect("start alpha");
    let agent_beta = Agent::start(cfg_beta, id_beta.clone(), Box::new(NoopEventSource))
        .await
        .expect("start beta");

    let alpha_fp = agent_alpha.fingerprint();
    let beta_fp = agent_beta.fingerprint();
    assert_ne!(alpha_fp, beta_fp, "fingerprints must differ");

    let timeout = Duration::from_secs(15);

    // Subscribe to events on both sides before any of the four conditions
    // can fire, then wait for all four concurrently. Subscribing per goal
    // ensures we don't miss an event because another receiver is being
    // drained.
    let pinned_alpha_rx = agent_alpha.subscribe();
    let pinned_beta_rx = agent_beta.subscribe();
    let recv_alpha_rx = agent_alpha.subscribe();
    let recv_beta_rx = agent_beta.subscribe();

    let goals = async {
        tokio::join!(
            wait_for_event(pinned_alpha_rx, move |e| match e {
                AgentEvent::PeerPinned(fp) if *fp == beta_fp => Some(()),
                _ => None,
            }),
            wait_for_event(pinned_beta_rx, move |e| match e {
                AgentEvent::PeerPinned(fp) if *fp == alpha_fp => Some(()),
                _ => None,
            }),
            wait_for_event(recv_alpha_rx, move |e| match e {
                AgentEvent::EnvelopeReceived { sender, .. } if *sender == beta_fp => Some(()),
                _ => None,
            }),
            wait_for_event(recv_beta_rx, move |e| match e {
                AgentEvent::EnvelopeReceived { sender, .. } if *sender == alpha_fp => Some(()),
                _ => None,
            }),
        )
    };

    tokio::time::timeout(timeout, goals)
        .await
        .expect("agents did not reach mutual pinning + heartbeat exchange in time");

    assert_eq!(agent_alpha.pinned_count(), 1);
    assert_eq!(agent_beta.pinned_count(), 1);

    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}

async fn wait_for_event<F, T>(
    mut rx: tokio::sync::broadcast::Receiver<AgentEvent>,
    mut matcher: F,
) -> T
where
    F: FnMut(&AgentEvent) -> Option<T>,
{
    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Some(value) = matcher(&event) {
                    return value;
                }
            }
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => panic!("event channel closed"),
        }
    }
}

/// A peer notices another peer's event log losing history.
///
/// The point of the whole mechanism: root on a host can delete that
/// host's log, and nothing local survives to say it existed — a verifier
/// only sees what remains. A neighbour that already wrote the number
/// down is not so easily edited.
///
/// The wipe is staged the way it really happens: the agent is stopped,
/// its database file is removed, and it comes back with the same
/// identity. Deleting *rows* would not do — `highest_seq` is read from
/// `sqlite_sequence`, which `DELETE` does not reset, which is exactly
/// why retention pruning can never look like an attack.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_notices_an_event_log_that_went_backwards() {
    use bowery_events::{Event, ProcessExit};
    use std::time::SystemTime;

    let dir_alpha = TempDir::new().unwrap();
    let dir_beta = TempDir::new().unwrap();
    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();
    let id_alpha = Arc::new(Identity::generate());
    let id_beta = Arc::new(Identity::generate());
    let beta_db = dir_beta.path().join("events.db");

    let events = |n: u32| -> Vec<Event> {
        (0..n)
            .map(|i| {
                Event::ProcessExit(ProcessExit {
                    pid: 9000 + i,
                    exit_code: 0,
                    ts: SystemTime::now(),
                })
            })
            .collect()
    };

    let agent_alpha = Agent::start(
        build_config_with_log(dir_alpha.path(), mesh_addr_alpha, Vec::new(), true),
        id_alpha,
        Box::new(NoopEventSource),
    )
    .await
    .expect("start alpha");

    let beta_cfg = || {
        build_config_with_log(
            dir_beta.path(),
            mesh_addr_beta,
            vec![mesh_addr_alpha.to_string()],
            true,
        )
    };
    let agent_beta = Agent::start(
        beta_cfg(),
        id_beta.clone(),
        Box::new(bowery_events::source::MockEventSource::new(events(40))),
    )
    .await
    .expect("start beta");

    let beta_fp = agent_beta.fingerprint();

    // Wait until alpha has witnessed beta at a nonzero height. Until
    // then there is nothing to roll back *from*, and asserting earlier
    // would test something else.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "alpha never witnessed beta's log height"
        );
        if agent_alpha
            .mesh()
            .peers()
            .into_iter()
            .any(|p| p.fingerprint == beta_fp && p.log_report.is_some())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Subscribe before the wipe so the alert cannot be missed.
    let alerts = agent_alpha.subscribe();

    // The wipe, as an attacker with root performs it.
    agent_beta.shutdown().await.expect("stop beta");
    std::fs::remove_file(&beta_db).expect("remove beta's event log");
    let agent_beta = Agent::start(
        beta_cfg(),
        id_beta,
        Box::new(bowery_events::source::MockEventSource::new(events(2))),
    )
    .await
    .expect("restart beta");

    let episode = tokio::time::timeout(
        Duration::from_secs(30),
        wait_for_event(alerts, |e| match e {
            AgentEvent::AlertEmitted { episode_id, .. }
                if episode_id.contains("event_log_rollback") =>
            {
                Some(episode_id.clone())
            }
            _ => None,
        }),
    )
    .await
    .expect("alpha did not report beta's log rolling back");

    let (found, _) = agent_alpha.inbox().read_since(0, 100);
    let alert = found
        .iter()
        .find(|a| a.episode_id == episode)
        .expect("the alert is in the inbox");
    assert!(alert.rationale.contains("event log"), "{}", alert.rationale);
    assert!(
        alert.context.iter().any(|a| a.key == "events_lost"),
        "an operator needs to know how much went missing"
    );

    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}
