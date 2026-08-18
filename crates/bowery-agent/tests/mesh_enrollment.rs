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

mod common;
use common::reserve_udp_port;

const CLUSTER: &str = "bowery-test-enrollment";

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
        monitor: bowery_agent::config::MonitorConfig::default(),
        yara: bowery_agent::config::YaraConfig::default(),
        detection: bowery_agent::config::DetectionConfig::default(),
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

/// The operational case that matters most: adding an agent to a fleet
/// that has been running for a while.
///
/// The bootstrap window exists to bound TOFU — when "showed up on the
/// gossip port" is the only admission evidence, that evidence must
/// expire. An operator-signed grant is strictly stronger and does not,
/// so it must pin even with the window long closed. Gating it on the
/// window would mean a granted agent could never join an established
/// fleet, which is exactly the friction grants exist to remove.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_granted_peer_joins_after_the_bootstrap_window_has_closed() {
    let operator = Identity::generate();
    let operator_pubkey_b64 = BASE64.encode(operator.verifying_key().to_bytes());

    let dir_hub = TempDir::new().unwrap();
    let dir_new = TempDir::new().unwrap();
    let op_key = dir_hub.path().join("operator.key");
    operator.save(&op_key).unwrap();

    let new_id = Arc::new(Identity::generate());
    let grant_path = dir_new.path().join("grant.b64");
    bowery_cli::mesh_trust::mint_grant(
        &op_key,
        &new_id.fingerprint().to_hex(),
        CLUSTER,
        None,
        Some(grant_path.clone()),
    )
    .unwrap();

    let hub_addr = reserve_udp_port();
    let new_addr = reserve_udp_port();

    let mut cfg_hub = build_config(
        dir_hub.path(),
        hub_addr,
        vec![],
        operator_pubkey_b64.clone(),
        EnrollmentPolicy::Grant,
        None,
    );
    // Already expired: this is the established-fleet condition.
    cfg_hub.known_neighbors.bootstrap_window = Duration::from_millis(1);

    let hub = Agent::start(
        cfg_hub,
        Arc::new(Identity::generate()),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start hub");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !hub.known_neighbors().bootstrap_active(),
        "precondition: the hub's bootstrap window must be closed"
    );

    let newcomer = Agent::start(
        build_config(
            dir_new.path(),
            new_addr,
            vec![hub_addr.to_string()],
            operator_pubkey_b64,
            EnrollmentPolicy::Tofu,
            Some(grant_path),
        ),
        new_id.clone(),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start newcomer");

    assert!(
        wait_for_pins(&hub, 1, Duration::from_secs(20)).await,
        "a granted peer must join an established fleet; the bootstrap \
         window must not gate operator-signed admission"
    );
    assert!(
        hub.known_neighbors()
            .fingerprints()
            .contains(&new_id.fingerprint())
    );

    hub.shutdown().await.expect("shutdown hub");
    newcomer.shutdown().await.expect("shutdown newcomer");
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

/// A revocation pushed to one agent must reach its peers and take effect
/// there — the gap that made revocation nearly useless when delivery was
/// manual per-agent.
///
/// Also pins the convergence property: a re-delivered revocation reports
/// `already_known` and is not forwarded again, which is what stops a
/// flood from echoing around a cyclic peer graph. The store is the
/// seen-set, because revocations are permanent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pushed_revocation_propagates_to_peers_and_converges() {
    let operator = Identity::generate();
    let operator_pubkey_b64 = BASE64.encode(operator.verifying_key().to_bytes());

    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let addr_a = reserve_udp_port();
    let addr_b = reserve_udp_port();
    let op_key = dir_a.path().join("operator.key");
    operator.save(&op_key).unwrap();

    let id_a = Arc::new(Identity::generate());
    let id_b = Arc::new(Identity::generate());

    let mut cfg_a = build_config(
        dir_a.path(),
        addr_a,
        vec![addr_b.to_string()],
        operator_pubkey_b64.clone(),
        EnrollmentPolicy::Tofu,
        None,
    );
    // A fixed whisper port so the operator can dial `a` deterministically.
    let whisper_a = reserve_udp_port();
    cfg_a.whisper.bind_addr = whisper_a;
    let cfg_b = build_config(
        dir_b.path(),
        addr_b,
        vec![addr_a.to_string()],
        operator_pubkey_b64,
        EnrollmentPolicy::Tofu,
        None,
    );

    let a = Agent::start(cfg_a, id_a.clone(), Box::new(NoopEventSource))
        .await
        .expect("start a");
    let b = Agent::start(cfg_b, id_b.clone(), Box::new(NoopEventSource))
        .await
        .expect("start b");

    // Let them find and pin each other, so `a` has somewhere to forward.
    assert!(
        wait_for_pins(&a, 1, Duration::from_secs(20)).await,
        "a never pinned b"
    );
    assert!(
        wait_for_pins(&b, 1, Duration::from_secs(20)).await,
        "b never pinned a"
    );

    // Revoke a third identity neither agent has met, so the assertion is
    // strictly about the revocation propagating, not about eviction.
    let victim = Identity::generate();
    let rev_b64 = bowery_cli::mesh_trust::mint_revocation(
        &op_key,
        &victim.fingerprint().to_hex(),
        CLUSTER,
        "propagation test",
        None,
        false,
    )
    .unwrap();

    let a_pub = BASE64.encode(id_a.verifying_key().to_bytes());
    // b seals its report for the operator directly, so the operator must
    // hold b's key to verify it.
    let b_pub = BASE64.encode(id_b.verifying_key().to_bytes());
    bowery_cli::exec::revoke_push(
        op_key.clone(),
        whisper_a,
        id_a.fingerprint().to_hex(),
        a_pub.clone(),
        vec![b_pub.clone()],
        rev_b64.clone(),
        Duration::from_secs(10),
        true,
        4,
    )
    .await
    .expect("push revocation");

    // Both the dialled agent and its peer must now hold it.
    assert!(
        a.revocations().is_revoked(&victim.fingerprint()),
        "the dialled agent must apply the revocation"
    );
    assert!(
        b.revocations().is_revoked(&victim.fingerprint()),
        "the revocation must reach the peer — manual per-agent delivery is what this replaces"
    );

    // Re-push: converges rather than re-flooding.
    bowery_cli::exec::revoke_push(
        op_key,
        whisper_a,
        id_a.fingerprint().to_hex(),
        a_pub,
        vec![b_pub],
        rev_b64,
        Duration::from_secs(10),
        true,
        4,
    )
    .await
    .expect("re-push revocation");
    assert_eq!(
        a.revocations().len(),
        1,
        "a re-delivered revocation must not duplicate"
    );

    a.shutdown().await.expect("shutdown a");
    b.shutdown().await.expect("shutdown b");
}
