//! Phase 5 integration: a high-suspicion exec on alpha triggers a
//! whisper Q&A round; beta — pre-seeded with the same sha256 in its
//! baseline — replies; alpha emits `WhisperContextReady` carrying
//! beta's sighting.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, HeartbeatConfig, IdentityConfig,
    InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig, OperatorsConfig, ResponseConfig,
    RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_crypto::Identity;
use bowery_events::source::{MockEventSource, NoopEventSource};
use bowery_events::{Event, ProcessExec};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

mod common;
use common::{loopback_ephemeral, reserve_udp_port};

fn build_config(dir: &Path, mesh_addr: SocketAddr, seeds: Vec<String>, quorum: usize) -> Config {
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
            cluster_id: Some("bowery-test-whisper-qa".to_string()),
        },
        whisper: WhisperConfig {
            advertise_addr: None,
            qa: WhisperQaConfig {
                threshold: 0.5, // first-time exec scores 1.0; well above
                fanout: 4,
                timeout: Duration::from_secs(3),
                min_similarity: -1.0, // accept anything; tiny test fleet
                quorum,
                max_concurrent_rounds: 4,
                min_baseline_binaries: bowery_agent::config::WhisperQaConfig::default()
                    .min_baseline_binaries,
                // The count bar stays at its production value — the
                // empty-baseline regression test below depends on it.
                // The AGE bar has to be off: a test cannot age a
                // baseline by three days, and seeded rows are all
                // milliseconds old. The age bound is covered by unit
                // tests in whisper_qa.rs instead.
                min_baseline_age: Duration::ZERO,
            },
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
            // Faster than the default so the test doesn't stall waiting
            // for beta's role vector to land in alpha's mesh KV.
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
        // Disabled: these fixtures predate the event log and don't
        // need a writer task (the default path isn't writable in CI).
        detection: bowery_agent::config::DetectionConfig::default(),
        eventlog: bowery_agent::config::EventLogConfig {
            enabled: false,
            ..Default::default()
        },
    }
}

fn make_exec(pid: u32, exe_path: std::path::PathBuf) -> Event {
    Event::ProcessExec(ProcessExec {
        pid,
        ppid: 1,
        parent_comm: String::new(),
        uid: 0,
        comm: "test".into(),
        exe_path: Some(exe_path),
        args: vec!["whisper-test".into()],
        ts: SystemTime::now(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // one linear scenario; splitting hides the ordering
async fn high_suspicion_exec_triggers_whisper_round_and_aggregates_beta_sighting() {
    const QUORUM: usize = 2;
    let workdir_alpha = TempDir::new().unwrap();
    let workdir_beta = TempDir::new().unwrap();

    // alpha's exec target; beta will be pre-seeded with the matching sha.
    let payload_path = workdir_alpha.path().join("payload");
    let payload_bytes = b"phase-5-whisper-test-binary";
    std::fs::write(&payload_path, payload_bytes).unwrap();
    let payload_sha: [u8; 32] = Sha256::digest(payload_bytes).into();

    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();

    let id_alpha = Arc::new(Identity::generate());
    let id_beta = Arc::new(Identity::generate());

    let cfg_alpha = build_config(
        workdir_alpha.path(),
        mesh_addr_alpha,
        vec![mesh_addr_beta.to_string()],
        QUORUM,
    );
    let cfg_beta = build_config(
        workdir_beta.path(),
        mesh_addr_beta,
        vec![mesh_addr_alpha.to_string()],
        QUORUM,
    );

    // Alpha: send the exec event after a delay long enough for mesh
    // discovery, mutual pinning, and a role-vector exchange. The Q&A
    // task then has actual peers to query.
    let alpha_source = Box::new(
        MockEventSource::new(vec![make_exec(1234, payload_path)])
            .with_delay(Duration::from_secs(2)),
    );

    let agent_alpha = Agent::start(cfg_alpha, id_alpha.clone(), alpha_source)
        .await
        .expect("start alpha");
    let agent_beta = Agent::start(cfg_beta, id_beta.clone(), Box::new(NoopEventSource))
        .await
        .expect("start beta");

    let alpha_fp = agent_alpha.fingerprint();
    let beta_fp = agent_beta.fingerprint();
    assert_ne!(alpha_fp, beta_fp);

    // Pre-seed beta's baseline with the payload sha. The whisper
    // responder scans the baseline by tier-1 fingerprint and replies
    // with the aggregated seen_count.
    agent_beta
        .baseline()
        .upsert_binary(&payload_sha)
        .expect("upsert beta");
    agent_beta
        .baseline()
        .upsert_binary(&payload_sha)
        .expect("upsert beta again"); // seen_count = 2

    // Wait until alpha sees a WhisperContextReady whose tier1 matches
    // our payload's tier1. Timeout generously; the round has to wait
    // for mesh+pin+role-publish before it can fire.
    let mut events = agent_alpha.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let context = loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !timeout.is_zero(),
            "timed out waiting for WhisperContextReady"
        );
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::WhisperContextReady(ctx))) => break ctx,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed early"),
            Err(tokio::time::error::Elapsed { .. }) => {
                panic!("timed out waiting for WhisperContextReady")
            }
        }
    };

    assert_eq!(
        context.peers.len(),
        1,
        "expected exactly beta in the round, got {:?}",
        context.peers.iter().map(|p| p.peer).collect::<Vec<_>>()
    );
    let beta_sighting = &context.peers[0];
    assert_eq!(beta_sighting.peer, beta_fp);
    assert!(
        beta_sighting.reply.observed().is_some(),
        "beta should have replied (no transport error / timeout)"
    );
    // Beta clears the coverage check by having actually seen the
    // binary: a hit outranks the baseline-size threshold, because
    // "I have this too" is honest however little else you have observed.
    let s = beta_sighting.reply.observed().unwrap();
    assert_eq!(s.seen_count, 2, "beta upserted twice");
    assert_eq!(context.corroborating_peers, 1);
    assert_eq!(context.total_seen_count, 2);

    // Beta HAS the binary, which argues it's a normal fleet artifact —
    // the opposite of what confirms. No confirmed alert may exist.
    let (alerts, _) = agent_alpha.inbox().read_since(0, 100);
    assert!(
        !alerts
            .iter()
            .any(|a| a.confirmation.is_some_and(|c| c.confirmed)),
        "a binary every peer already has must never be quorum-confirmed"
    );

    // After the whisper round, the agent should have submitted the
    // verdict to the LLM with the neighborhood sightings folded into
    // ctx.extra. We assert by waiting for LlmVerdict — its presence
    // proves whisper_qa_task did the LLM submission. (The mock LLM
    // doesn't roundtrip ctx.extra into its rationale; the prompt
    // contents are tested directly in the unit test for
    // `inject_whisper_context`.)
    let deadline_llm = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let timeout = deadline_llm.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for LlmVerdict");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::LlmVerdict { episode_id, .. })) => {
                assert_eq!(episode_id, context.episode_id);
                break;
            }
            Ok(Ok(AgentEvent::LlmShed { reason, .. })) => {
                panic!("LLM shed unexpectedly after whisper round: {reason:?}")
            }
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed early"),
            Err(tokio::time::error::Elapsed { .. }) => {
                panic!("timed out waiting for LlmVerdict")
            }
        }
    }

    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}

/// Phase-5 asker-side bloom filter: beta has *not* observed the
/// payload sha. Beta's bloom advert (gossiped via mesh KV) reflects
/// that. Alpha's whisper round should skip beta entirely instead of
/// dialing it, and report the skip in `peers_skipped_by_bloom`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whisper_round_skips_peers_whose_bloom_advert_excludes_tier1() {
    let workdir_alpha = TempDir::new().unwrap();
    let workdir_beta = TempDir::new().unwrap();

    let payload_path = workdir_alpha.path().join("payload");
    let payload_bytes = b"phase-5-asker-skip-test-binary";
    std::fs::write(&payload_path, payload_bytes).unwrap();

    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();

    let id_alpha = Arc::new(Identity::generate());
    let id_beta = Arc::new(Identity::generate());

    // Configure both with a fast bloom publish_interval so beta has
    // time to gossip its (empty) advert before alpha's exec event
    // fires.
    // quorum 0 — the bloom skip is a pure dial-avoidance optimization
    // and deliberately stands down when confirmation is enabled, since
    // it would filter out exactly the never-seen-it peers a quorum
    // counts (see `run_round`).
    let mut cfg_alpha = build_config(
        workdir_alpha.path(),
        mesh_addr_alpha,
        vec![mesh_addr_beta.to_string()],
        0,
    );
    cfg_alpha.bloom.publish_interval = Duration::from_millis(200);

    let mut cfg_beta = build_config(
        workdir_beta.path(),
        mesh_addr_beta,
        vec![mesh_addr_alpha.to_string()],
        0,
    );
    cfg_beta.bloom.publish_interval = Duration::from_millis(200);

    // Alpha's exec event arrives 3s in, giving the bloom + role
    // gossip several ticks to converge.
    let alpha_source = Box::new(
        MockEventSource::new(vec![make_exec(7777, payload_path)])
            .with_delay(Duration::from_secs(3)),
    );

    let agent_alpha = Agent::start(cfg_alpha, id_alpha.clone(), alpha_source)
        .await
        .expect("start alpha");
    let agent_beta = Agent::start(cfg_beta, id_beta.clone(), Box::new(NoopEventSource))
        .await
        .expect("start beta");

    // Deliberately do NOT seed beta's baseline. Beta's advert will
    // (correctly) tell alpha "I haven't seen anything matching this
    // tier-1." Alpha should skip the dial.

    let mut events = agent_alpha.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let context = loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !timeout.is_zero(),
            "timed out waiting for WhisperContextReady"
        );
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::WhisperContextReady(ctx))) => break ctx,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed early"),
            Err(tokio::time::error::Elapsed { .. }) => {
                panic!("timed out waiting for WhisperContextReady")
            }
        }
    };

    assert_eq!(
        context.peers.len(),
        0,
        "expected no dial; got peers: {:?}",
        context.peers.iter().map(|p| p.peer).collect::<Vec<_>>()
    );
    assert_eq!(
        context.peers_skipped_by_bloom, 1,
        "expected exactly beta to be skipped by the bloom filter, got {}",
        context.peers_skipped_by_bloom
    );
    assert_eq!(context.corroborating_peers, 0);
    assert_eq!(context.total_seen_count, 0);

    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}

/// Quorum confirmation, end to end over a real two-agent whisper round.
///
/// Beta has *never* seen the payload, so its signed `Answer` carries
/// `seen_count == 0` — the rarity signal confirmation is built from. With
/// `quorum: 1` that single never-seen-it vote is enough, and alpha must
/// append a superseding alert marked confirmed.
///
/// Note the polarity, which is the easiest thing to get backwards here:
/// a peer that HAS the binary argues it is a normal fleet artifact, so it
/// counts *against* confirmation. `high_suspicion_exec_..._beta_sighting`
/// covers that direction.
#[allow(clippy::too_many_lines)] // two-agent fixture plus the round assertions
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn neighbourhood_quorum_confirms_an_alert_nobody_else_has_seen() {
    let workdir_alpha = TempDir::new().unwrap();
    let workdir_beta = TempDir::new().unwrap();

    let payload_path = workdir_alpha.path().join("payload");
    // Unique bytes so beta's baseline cannot coincidentally hold it.
    std::fs::write(&payload_path, b"quorum-confirm-never-seen-anywhere-else").unwrap();

    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();

    let cfg_alpha = build_config(
        workdir_alpha.path(),
        mesh_addr_alpha,
        vec![mesh_addr_beta.to_string()],
        1,
    );
    let cfg_beta = build_config(
        workdir_beta.path(),
        mesh_addr_beta,
        vec![mesh_addr_alpha.to_string()],
        1,
    );

    let alpha_source = Box::new(
        MockEventSource::new(vec![make_exec(4242, payload_path)])
            .with_delay(Duration::from_secs(2)),
    );

    let agent_alpha = Agent::start(cfg_alpha, Arc::new(Identity::generate()), alpha_source)
        .await
        .expect("start alpha");
    let agent_beta = Agent::start(
        cfg_beta,
        Arc::new(Identity::generate()),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start beta");

    // Beta must be a *credible* witness, not merely a silent one. Seed
    // its baseline past the coverage threshold with unrelated binaries:
    // the claim under test is "a host that watches this fleet has never
    // seen your payload", and a host that has observed nothing at all
    // cannot make it. Leaving the baseline empty here is what the live
    // fleet was doing when it confirmed /usr/bin/ssh as an anomaly.
    let min = bowery_agent::config::WhisperQaConfig::default().min_baseline_binaries;
    for i in 0..(min + 4) {
        let mut sha = [0u8; 32];
        sha[0..8].copy_from_slice(&i.to_le_bytes());
        agent_beta
            .baseline()
            .upsert_binary(&sha)
            .expect("seed beta");
    }

    let mut events = agent_alpha.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let context = loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !timeout.is_zero(),
            "timed out waiting for WhisperContextReady"
        );
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::WhisperContextReady(ctx))) => break ctx,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed early"),
            Err(tokio::time::error::Elapsed { .. }) => {
                panic!("timed out waiting for WhisperContextReady")
            }
        }
    };

    // Beta must actually have been dialled: with confirmation enabled the
    // bloom filter stands down precisely so never-seen-it peers are asked
    // rather than skipped.
    assert_eq!(
        context.peers_skipped_by_bloom, 0,
        "bloom skip must stand down when quorum > 0, or nothing can ever confirm"
    );
    assert_eq!(context.peers.len(), 1, "expected beta in the round");
    let sighting = context.peers[0]
        .reply
        .observed()
        .expect("beta should have looked and answered, not refused or timed out");
    assert_eq!(sighting.seen_count, 0, "beta has never seen this payload");
    assert_eq!(context.corroborating_peers, 0);

    // Both agents are this machine, so beta's answer *is* comparable and
    // must be classified as such.
    //
    // This guards the inverse of the bug the platform gate was added
    // for. Getting the comparison backwards — or shipping a responder
    // that omits its platform — would make every peer incomparable, and
    // confirmation would stop working fleet-wide without a single test
    // failing anywhere else. The failure would look exactly like a quiet
    // network.
    assert!(
        !matches!(
            context.peers[0].reply,
            bowery_agent::whisper_qa::PeerReply::Incomparable { .. }
        ),
        "a same-platform peer must be comparable, got {:?}",
        context.peers[0].reply
    );

    // The superseding alert is appended before WhisperContextReady is
    // broadcast, so it is already readable.
    let (alerts, _) = agent_alpha.inbox().read_since(0, 100);
    let confirmed: Vec<_> = alerts
        .iter()
        .filter(|a| a.episode_id == context.episode_id)
        .filter_map(|a| a.confirmation)
        .collect();
    assert_eq!(
        confirmed.len(),
        1,
        "expected exactly one confirmed alert for the episode, got {} of {} alerts",
        confirmed.len(),
        alerts.len()
    );
    assert_eq!(
        confirmed[0].peers_incomparable, 0,
        "same-platform round must report nothing incomparable"
    );
    assert_eq!(
        confirmed[0].comparable(),
        1,
        "beta's answer must have been weighable"
    );
    let c = confirmed[0];
    assert!(c.confirmed, "quorum of 1 never-seen-it vote must confirm");
    assert_eq!(c.peers_unseen, 1);
    assert_eq!(c.peers_seen, 0);
    assert_eq!(c.peers_no_reply, 0);
    assert_eq!(c.peers_refused, 0, "beta was seeded past the coverage bar");
    assert_eq!(c.peers_asked, 1);
    assert_eq!(c.quorum, 1);

    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}

/// A peer with an empty baseline must not confirm anything.
///
/// This is the bug as found in production, reduced. Two agents were
/// running with no working event source, so their baselines were empty,
/// so they answered "never seen it" to every question — and a quorum of
/// "never seen it" is exactly what confirms an alert. Every alert on
/// their neighbour was being confirmed unanimously by two hosts that had
/// observed nothing whatsoever, `/usr/bin/ssh` among them.
///
/// The distinction that fixes it: "I watch this fleet and your binary is
/// not part of it" is evidence; "I am not watching" is not. Only the
/// first may count toward a quorum.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_with_an_empty_baseline_refuses_and_never_confirms() {
    let workdir_alpha = TempDir::new().unwrap();
    let workdir_beta = TempDir::new().unwrap();

    let payload_path = workdir_alpha.path().join("payload");
    std::fs::write(&payload_path, b"blind-witness-regression").unwrap();

    let mesh_addr_alpha = reserve_udp_port();
    let mesh_addr_beta = reserve_udp_port();

    // A quorum of one: the weakest possible bar, so if anything is going
    // to confirm on a blind peer's say-so, it will be this.
    let cfg_alpha = build_config(
        workdir_alpha.path(),
        mesh_addr_alpha,
        vec![mesh_addr_beta.to_string()],
        1,
    );
    let cfg_beta = build_config(
        workdir_beta.path(),
        mesh_addr_beta,
        vec![mesh_addr_alpha.to_string()],
        1,
    );

    let alpha_source = Box::new(
        MockEventSource::new(vec![make_exec(4321, payload_path)])
            .with_delay(Duration::from_secs(2)),
    );
    let agent_alpha = Agent::start(cfg_alpha, Arc::new(Identity::generate()), alpha_source)
        .await
        .expect("start alpha");
    // Beta observes nothing, ever — exactly the Pis' situation.
    let agent_beta = Agent::start(
        cfg_beta,
        Arc::new(Identity::generate()),
        Box::new(NoopEventSource),
    )
    .await
    .expect("start beta");
    assert_eq!(
        agent_beta.baseline_binary_count().unwrap(),
        0,
        "beta must be genuinely blind for this test to mean anything"
    );

    let mut events = agent_alpha.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let context = loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for the round");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::WhisperContextReady(ctx))) => break ctx,
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("event channel closed early"),
            Err(tokio::time::error::Elapsed { .. }) => panic!("timed out waiting for the round"),
        }
    };

    assert_eq!(context.peers.len(), 1, "expected beta in the round");
    // Beta answered — it is reachable and working. It just declined.
    assert!(
        matches!(
            context.peers[0].reply,
            bowery_agent::whisper_qa::PeerReply::Refused(_)
        ),
        "a blind peer must refuse, not report never-seen-it: {:?}",
        context.peers[0].reply
    );

    let (alerts, _) = agent_alpha.inbox().read_since(0, 100);
    assert!(
        !alerts
            .iter()
            .any(|a| a.confirmation.is_some_and(|c| c.confirmed)),
        "a blind peer's refusal must never confirm an alert"
    );
    // And the refusal is visible to the operator rather than silently
    // folded into "no reply", which would read as an unreachable peer.
    let confirmations: Vec<_> = alerts.iter().filter_map(|a| a.confirmation).collect();
    if let Some(c) = confirmations.first() {
        assert_eq!(c.peers_refused, 1);
        assert_eq!(c.peers_unseen, 0, "a refusal is not a never-seen-it vote");
        assert_eq!(c.peers_no_reply, 0, "beta answered; it is not silent");
    }

    agent_alpha.shutdown().await.expect("shutdown alpha");
    agent_beta.shutdown().await.expect("shutdown beta");
}
