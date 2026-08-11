//! Phase-3 mesh trust, end to end over a real two-agent mesh.
//!
//! The unit tests prove `verify_grant` rejects the right things. This
//! proves the wiring around it: that a grant minted by the operator CLI
//! reaches a peer through gossip KV, is verified there, and actually
//! decides whether a pin happens — and that without one, under
//! `enrollment = "grant"`, no pin happens at all.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_agent::Agent;
use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, EnrollmentPolicy, EventLogConfig,
    HeartbeatConfig, IdentityConfig, InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig,
    OperatorsConfig, ResponseConfig, RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_crypto::Identity;
use bowery_events::source::NoopEventSource;
use tempfile::TempDir;

const CLUSTER: &str = "bowery-test-enrollment";

fn reserve_udp_port() -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.local_addr().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn build_config(
    dir: &Path,
    mesh_addr: SocketAddr,
    seeds: Vec<String>,
    operator_pubkey_b64: String,
    enrollment: EnrollmentPolicy,
    grant_path: Option<PathBuf>,
) -> Config {
    Config {
        identity: IdentityConfig {
            path: dir.join("identity.key"),
        },
        known_neighbors: KnownNeighborsConfig {
            path: dir.join("known_neighbors.json"),
            bootstrap_window: Duration::from_hours(1),
            max_pinned_peers: 64,
            enrollment,
            grant_path,
            revocations_path: dir.join("revocations.json"),
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr,
            advertise_addr: Some(mesh_addr),
            seeds,
            cluster_id: Some(CLUSTER.to_string()),
        },
        whisper: WhisperConfig {
            advertise_addr: None,
            qa: WhisperQaConfig::default(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
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
        monitor: bowery_agent::config::MonitorConfig::default(),
        yara: bowery_agent::config::YaraConfig::default(),
        eventlog: EventLogConfig {
            enabled: false,
            ..Default::default()
        },
    }
}

/// Wait until `agent` has pinned `expected` peers, or return false.
async fn wait_for_pins(agent: &Agent, expected: usize, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if agent.known_neighbors().count() >= expected {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Under `enrollment = "grant"`, a peer holding a valid operator-signed
/// grant is pinned — and one without a grant is not, even though it is
/// gossiping happily and the bootstrap window is wide open.
///
/// That second half is the whole point: under TOFU it *would* have been
/// pinned, because reaching the gossip port was the entire admission
/// check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grant_policy_admits_the_granted_peer_and_refuses_the_ungranted_one() {
    let operator = Identity::generate();
    let operator_pubkey_b64 = BASE64.encode(operator.verifying_key().to_bytes());

    let dir_hub = TempDir::new().unwrap();
    let dir_granted = TempDir::new().unwrap();
    let dir_ungranted = TempDir::new().unwrap();

    // Identities are generated up front so the operator can mint a grant
    // for `granted` before that agent starts — mirroring real
    // provisioning, where the grant is issued against a known key.
    let granted_id = Arc::new(Identity::generate());
    let ungranted_id = Arc::new(Identity::generate());

    let operator_key_path = dir_hub.path().join("operator.key");
    operator.save(&operator_key_path).unwrap();
    let grant_path = dir_granted.path().join("grant.b64");
    bowery_cli::mesh_trust::mint_grant(
        &operator_key_path,
        &granted_id.fingerprint().to_hex(),
        CLUSTER,
        None,
        Some(grant_path.clone()),
    )
    .unwrap();

    let hub_addr = reserve_udp_port();
    let granted_addr = reserve_udp_port();
    let ungranted_addr = reserve_udp_port();

    // The hub enforces grants; the two spokes just gossip.
    let hub = Agent::start(
        build_config(
            dir_hub.path(),
            hub_addr,
            vec![],
            operator_pubkey_b64.clone(),
            EnrollmentPolicy::Grant,
            None,
        ),
        Arc::new(Identity::generate()),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start hub");

    let granted = Agent::start(
        build_config(
            dir_granted.path(),
            granted_addr,
            vec![hub_addr.to_string()],
            operator_pubkey_b64.clone(),
            EnrollmentPolicy::Tofu,
            Some(grant_path),
        ),
        granted_id.clone(),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start granted");

    let ungranted = Agent::start(
        build_config(
            dir_ungranted.path(),
            ungranted_addr,
            vec![hub_addr.to_string()],
            operator_pubkey_b64,
            EnrollmentPolicy::Tofu,
            None,
        ),
        ungranted_id.clone(),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start ungranted");

    assert!(
        wait_for_pins(&hub, 1, Duration::from_secs(20)).await,
        "hub never pinned the granted peer"
    );

    // Give the ungranted peer as much time again to be (wrongly) pinned.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let pinned = hub.known_neighbors().fingerprints();
    assert!(
        pinned.contains(&granted_id.fingerprint()),
        "a peer with a valid grant must be pinned; pinned = {pinned:?}"
    );
    assert!(
        !pinned.contains(&ungranted_id.fingerprint()),
        "a peer with NO grant must not be pinned under enrollment=grant — \
         this is exactly what TOFU would have admitted; pinned = {pinned:?}"
    );

    hub.shutdown().await.expect("shutdown hub");
    granted.shutdown().await.expect("shutdown granted");
    ungranted.shutdown().await.expect("shutdown ungranted");
}

/// Under the default `tofu` policy nothing changes — an existing fleet
/// keeps forming a mesh after upgrading, which is why that remains the
/// default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tofu_policy_still_pins_a_peer_with_no_grant() {
    let operator = Identity::generate();
    let operator_pubkey_b64 = BASE64.encode(operator.verifying_key().to_bytes());

    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let addr_a = reserve_udp_port();
    let addr_b = reserve_udp_port();

    let a = Agent::start(
        build_config(
            dir_a.path(),
            addr_a,
            vec![addr_b.to_string()],
            operator_pubkey_b64.clone(),
            EnrollmentPolicy::Tofu,
            None,
        ),
        Arc::new(Identity::generate()),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start a");
    let b = Agent::start(
        build_config(
            dir_b.path(),
            addr_b,
            vec![addr_a.to_string()],
            operator_pubkey_b64,
            EnrollmentPolicy::Tofu,
            None,
        ),
        Arc::new(Identity::generate()),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start b");

    assert!(
        wait_for_pins(&a, 1, Duration::from_secs(20)).await,
        "tofu must keep working — upgrading a fleet must not partition it"
    );

    a.shutdown().await.expect("shutdown a");
    b.shutdown().await.expect("shutdown b");
}
