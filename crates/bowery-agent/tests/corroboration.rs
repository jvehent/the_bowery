//! Cross-host corroboration, end to end over two real agents.
//!
//! Alpha observes an inbound connection from beta and asks beta about
//! it. The three scenarios here are the three answers beta can give, and
//! the difference between them is the whole feature:
//!
//! - beta has no record of it → **alert** (the finding),
//! - beta owns up to it → no alert, plus process attribution alpha
//!   could not have derived on its own,
//! - beta's history doesn't reach back that far → **refusal**, and
//!   still no alert.
//!
//! The third is the one that decides whether an operator trusts the
//! other two. A freshly-installed agent knows nothing about last week;
//! if that read as a denial, every peer that ever talked to it would be
//! accused, and the real finding would be buried under the noise.
//!
//! Nothing in this file is specific to connections beyond the events it
//! feeds in and the `kind` it asserts on — the round, the tally, the
//! quorum rule, and the alert are all kind-agnostic machinery.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, CorroborationConfig, EventLogConfig,
    HeartbeatConfig, IdentityConfig, InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig,
    OperatorsConfig, ResponseConfig, RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::corroboration::net_inbound;
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::{MockEventSource, NoopEventSource};
use bowery_events::{Event, NetDirection, NetFamily, NetworkConnect, ProcessExec};
use bowery_proto::attribute;
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

mod common;
use common::{loopback_ephemeral, reserve_udp_port};

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
/// The port alpha "listens" on in these scenarios.
const TARGET_PORT: u16 = 22;

fn build_config(dir: &Path, mesh_addr: SocketAddr, seeds: Vec<String>, cluster: &str) -> Config {
    Config {
        identity: IdentityConfig {
            path: dir.join("identity.key"),
        },
        known_neighbors: KnownNeighborsConfig {
            path: dir.join("known_neighbors.json"),
            bootstrap_window: Duration::from_hours(1),
            max_pinned_peers: 1024,
            enrollment: bowery_agent::config::EnrollmentPolicy::Tofu,
            grant_path: None,
            revocations_path: dir.join("revocations.json"),
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr,
            advertise_addr: Some(mesh_addr),
            seeds,
            cluster_id: Some(cluster.to_string()),
        },
        whisper: WhisperConfig {
            advertise_addr: None,
            bind_addr: loopback_ephemeral(),
            qa: WhisperQaConfig {
                // Irrelevant here, but a high threshold keeps the binary
                // round from firing and cluttering the event stream.
                threshold: 2.0,
                ..WhisperQaConfig::default()
            },
            corroboration: CorroborationConfig {
                enabled: true,
                timeout: Duration::from_secs(3),
                ..CorroborationConfig::default()
            },
        },
        heartbeat: HeartbeatConfig {
            interval: Duration::from_millis(200),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
        role: RoleConfig {
            publish_interval: Duration::from_millis(200),
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
        // The whole feature is answered out of this log, so unlike the
        // other fixtures it has to be on.
        detection: bowery_agent::config::DetectionConfig::default(),
        eventlog: EventLogConfig {
            enabled: true,
            path: dir.join("events.db"),
            ..Default::default()
        },
    }
}

/// An event old enough to prove the recorder was alive before any
/// window under test.
///
/// Beta needs this or it will (correctly) refuse everything: a log whose
/// oldest row is from thirty seconds ago cannot honestly say what did or
/// did not happen five minutes ago.
fn ancient_exec() -> Event {
    Event::ProcessExec(ProcessExec {
        pid: 1,
        ppid: 0,
        parent_comm: String::new(),
        uid: 0,
        comm: "init".into(),
        exe_path: Some("/sbin/init".into()),
        args: vec![],
        ts: SystemTime::now() - Duration::from_hours(1),
    })
}

/// What alpha sees: beta connected to us.
fn inbound_from_beta() -> Event {
    Event::NetworkConnect(NetworkConnect {
        // Inbound events carry no attribution — that is the entire
        // reason alpha has to ask.
        pid: 0,
        comm: String::new(),
        family: NetFamily::V4,
        daddr: IpAddr::V4(LOOPBACK),
        local_addr: IpAddr::V4(LOOPBACK),
        dport: 51075,
        local_port: TARGET_PORT,
        direction: NetDirection::Inbound,
        ts: SystemTime::now(),
    })
}

/// What beta would have recorded if it really made that connection.
fn outbound_to_alpha() -> Event {
    Event::NetworkConnect(NetworkConnect {
        pid: 4242,
        comm: "ssh".into(),
        family: NetFamily::V4,
        daddr: IpAddr::V4(LOOPBACK),
        local_addr: IpAddr::V4(LOOPBACK),
        dport: TARGET_PORT,
        // Zero for outbound: the kernel hasn't assigned a source port at
        // `TCP_CLOSE -> TCP_SYN_SENT`.
        local_port: 0,
        direction: NetDirection::Outbound,
        ts: SystemTime::now(),
    })
}

struct Pair {
    alpha: Agent,
    beta: Agent,
    _dirs: (TempDir, TempDir),
}

/// Start alpha (which observes the inbound connection after a delay long
/// enough for mesh discovery and mutual pinning) and beta (seeded with
/// `beta_events`).
async fn start_pair(cluster: &str, beta_events: Vec<Event>) -> Pair {
    let dir_alpha = TempDir::new().unwrap();
    let dir_beta = TempDir::new().unwrap();
    let mesh_alpha = reserve_udp_port();
    let mesh_beta = reserve_udp_port();

    let cfg_alpha = build_config(
        dir_alpha.path(),
        mesh_alpha,
        vec![mesh_beta.to_string()],
        cluster,
    );
    let cfg_beta = build_config(
        dir_beta.path(),
        mesh_beta,
        vec![mesh_alpha.to_string()],
        cluster,
    );

    // Alpha's observation lands after the mesh has converged, so the
    // claim has a pinned peer to resolve to.
    let alpha_source = Box::new(
        MockEventSource::new(vec![inbound_from_beta()]).with_delay(Duration::from_secs(3)),
    );
    let beta_source: Box<dyn bowery_events::source::EventSource> = if beta_events.is_empty() {
        Box::new(NoopEventSource)
    } else {
        Box::new(MockEventSource::new(beta_events))
    };

    let alpha = Agent::start(cfg_alpha, Arc::new(Identity::generate()), alpha_source)
        .await
        .expect("start alpha");
    let beta = Agent::start(cfg_beta, Arc::new(Identity::generate()), beta_source)
        .await
        .expect("start beta");

    Pair {
        alpha,
        beta,
        _dirs: (dir_alpha, dir_beta),
    }
}

/// Wait for alpha's corroboration round to finish and return its outcome.
async fn await_round(
    events: &mut tokio::sync::broadcast::Receiver<AgentEvent>,
) -> bowery_agent::corroboration::RoundOutcome {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for a round");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::CorroborationRound(outcome))) => return *outcome,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed early"),
            Err(tokio::time::error::Elapsed { .. }) => panic!("timed out waiting for a round"),
        }
    }
}

/// A peer that has history, but no record of the connection, is the
/// finding: its agent is blind or tampered with, or the source address
/// was spoofed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_denied_inbound_connection_raises_a_confirmed_alert() {
    let pair = start_pair("bowery-test-corr-deny", vec![ancient_exec()]).await;
    let mut events = pair.alpha.subscribe();

    let outcome = await_round(&mut events).await;
    assert_eq!(outcome.kind, net_inbound::KIND);
    assert_eq!(outcome.tally.asked, 1, "beta is the only peer at that IP");
    assert_eq!(outcome.tally.denied, 1, "beta has no record of connecting");
    assert_eq!(outcome.tally.corroborated, 0);
    assert!(outcome.confirmed, "a denial is the finding");

    let (alerts, _) = pair.alpha.inbox().read_since(0, 100);
    let alert = alerts
        .iter()
        .find(|a| a.episode_id.contains(net_inbound::KIND))
        .expect("a corroboration alert reached the inbox");
    let c = alert.confirmation.expect("confirmation block");
    assert!(c.confirmed);
    assert_eq!(c.peers_unseen, 1, "the denial is what confirms");
    assert_eq!(c.peers_seen, 0);
    assert_eq!(c.peers_refused, 0);
    assert_eq!(c.peers_no_reply, 0);
    // The rationale has to name the connection, not just the counts —
    // an operator reading this at 3am needs to know what to look at.
    assert!(
        alert.rationale.contains("inbound connection from"),
        "{}",
        alert.rationale
    );
    assert!(
        alert.rationale.contains("no record of it"),
        "{}",
        alert.rationale
    );

    pair.alpha.shutdown().await.expect("shutdown alpha");
    pair.beta.shutdown().await.expect("shutdown beta");
}

/// A peer that owns up to the connection explains it — and hands back
/// the process attribution the accepting host can never see.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corroborated_connection_raises_no_alert_and_returns_attribution() {
    let pair = start_pair(
        "bowery-test-corr-ok",
        vec![ancient_exec(), outbound_to_alpha()],
    )
    .await;
    let mut events = pair.alpha.subscribe();

    let outcome = await_round(&mut events).await;
    assert_eq!(outcome.tally.corroborated, 1);
    assert_eq!(outcome.tally.denied, 0);
    assert!(!outcome.confirmed, "somebody owned up to it");

    // This is the payoff: alpha's own sensor recorded pid 0 and an empty
    // comm for the inbound half, because the kernel's accept-side
    // transition runs in softirq context. Only beta could supply this.
    assert_eq!(
        attribute(&outcome.evidence, net_inbound::ATTR_COMM),
        Some("ssh")
    );
    assert_eq!(
        attribute(&outcome.evidence, net_inbound::ATTR_PID),
        Some("4242")
    );

    let (alerts, _) = pair.alpha.inbox().read_since(0, 100);
    assert!(
        !alerts
            .iter()
            .any(|a| a.episode_id.contains(net_inbound::KIND)),
        "an explained connection must not alert"
    );

    pair.alpha.shutdown().await.expect("shutdown alpha");
    pair.beta.shutdown().await.expect("shutdown beta");
}

/// A peer whose history doesn't reach back far enough refuses, and a
/// refusal never confirms.
///
/// This is the difference between an alert worth waking up for and one
/// an operator learns to ignore. Beta here is what every agent is on its
/// first day: running, reachable, answering — and unable to say anything
/// truthful about a window it wasn't recording for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_without_history_refuses_rather_than_denying() {
    // No `ancient_exec`: beta's log holds nothing older than its own
    // startup, so it cannot speak to a window that opens five minutes
    // before alpha's observation.
    let pair = start_pair("bowery-test-corr-nohist", vec![]).await;
    let mut events = pair.alpha.subscribe();

    let outcome = await_round(&mut events).await;
    assert_eq!(outcome.tally.refused, 1);
    assert_eq!(
        outcome.tally.denied, 0,
        "\"I wasn't recording then\" is not \"it didn't happen\""
    );
    assert!(!outcome.confirmed);

    let (alerts, _) = pair.alpha.inbox().read_since(0, 100);
    assert!(
        !alerts
            .iter()
            .any(|a| a.episode_id.contains(net_inbound::KIND)),
        "a refusal must never raise an alert"
    );

    pair.alpha.shutdown().await.expect("shutdown alpha");
    pair.beta.shutdown().await.expect("shutdown beta");
}
