//! Integration: an operator-configured file watch produces an alert when
//! the watched file changes, end-to-end through a real agent (inotify →
//! pipeline → alert inbox).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, FileRule, HeartbeatConfig, IdentityConfig,
    InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig, MonitorConfig, OperatorsConfig,
    ProcessRule, ResponseConfig, RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_agent::{Agent, AgentEvent};
use bowery_analysis::RuleSeverity;
use bowery_crypto::Identity;
use bowery_events::source::{EventGate, MockEventSource};
use bowery_events::{Event, FileOpen};
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;

mod common;
use common::{loopback_ephemeral, reserve_udp_port};

fn build_config(dir: &Path, mesh_addr: SocketAddr, monitor: MonitorConfig) -> Config {
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
            seeds: Vec::new(),
            cluster_id: Some("bowery-test-file-monitor".to_string()),
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
            interval: Duration::from_mins(1),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
        role: RoleConfig {
            publish_interval: Duration::from_mins(1),
        },
        llm: LlmConfig::default(),
        operators: OperatorsConfig::default(),
        inbox: InboxConfig::default(),
        alerts: AlertsConfig::default(),
        bloom: BloomConfig::default(),
        response: ResponseConfig::default(),
        sql: bowery_agent::config::SqlConfig::default(),
        monitor,
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

/// A source that emits nothing until the returned gate is opened.
///
/// These tests watch the agent through its event broadcast, which does
/// not replay. `Agent::start` spawns the pipeline before it returns, so
/// an ungated source can be drained to completion in the microseconds
/// before `subscribe()` lands — and the test then waits out its whole
/// deadline for an alert that was already delivered. Open the gate once
/// every observer is attached.
fn gated_source(events: Vec<Event>) -> (Box<MockEventSource>, EventGate) {
    let (source, gate) = MockEventSource::new(events).gated();
    (Box::new(source), gate)
}

/// Wait for an `AlertEmitted` event, or panic on timeout.
async fn wait_for_alert(
    events: &mut tokio::sync::broadcast::Receiver<AgentEvent>,
) -> (String, f32) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!timeout.is_zero(), "timed out waiting for AlertEmitted");
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Ok(AgentEvent::AlertEmitted {
                episode_id,
                suspicion,
            })) => return (episode_id, suspicion),
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) => panic!("agent event channel closed"),
            Err(tokio::time::error::Elapsed { .. }) => {
                panic!("timed out waiting for AlertEmitted")
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watched_file_change_emits_alert() {
    let workdir = TempDir::new().unwrap();
    let watched = workdir.path().join("sensitive.conf");
    std::fs::write(&watched, b"original").unwrap();

    let monitor = MonitorConfig {
        file_rules: vec![FileRule {
            id: Some("sensitive".to_string()),
            path: watched.clone(),
            // Default ops (modify/attrib/delete/move) — set explicitly so the
            // test doesn't silently depend on the default set.
            ops: vec![bowery_events::FileOp::Modify],
            severity: RuleSeverity::High,
        }],
        process_rules: Vec::new(),
    };

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port(), monitor);
    // No kernel events in this test — the file monitor is the only producer.
    let source = Box::new(MockEventSource::new(Vec::new()));
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    let mut events = agent.subscribe();

    // Give the inotify watch a moment to be registered before mutating.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // IN_CLOSE_WRITE fires when the writer closes the fd.
    std::fs::write(&watched, b"tampered").unwrap();

    let (episode_id, suspicion) = wait_for_alert(&mut events).await;
    assert!(
        episode_id.starts_with("file-sensitive-"),
        "episode id should name the rule, got {episode_id}"
    );
    // High severity → 0.9 suspicion (mirrors the analyzer's severity weights).
    assert!(
        (suspicion - 0.9).abs() < f32::EPSILON,
        "expected high-severity suspicion 0.9, got {suspicion}"
    );

    agent.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unwatched_file_change_emits_no_alert() {
    let workdir = TempDir::new().unwrap();
    let watched = workdir.path().join("watched.conf");
    let other = workdir.path().join("other.conf");
    std::fs::write(&watched, b"a").unwrap();
    std::fs::write(&other, b"b").unwrap();

    let monitor = MonitorConfig {
        file_rules: vec![FileRule {
            id: None,
            path: watched.clone(),
            ops: vec![bowery_events::FileOp::Modify],
            severity: RuleSeverity::High,
        }],
        process_rules: Vec::new(),
    };

    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port(), monitor);
    let source = Box::new(MockEventSource::new(Vec::new()));
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    let mut events = agent.subscribe();

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Touch a DIFFERENT file in the same watched directory: the directory
    // watch sees it, but the basename doesn't match the rule, so no alert.
    std::fs::write(&other, b"changed").unwrap();

    // Timing out is the expected outcome; any non-alert agent event is fine.
    // `sensor-*` episodes are the probe watchdog reporting on the event
    // source, not the file monitor — this test is about the file rule.
    if let Ok(Ok(AgentEvent::AlertEmitted { episode_id, .. })) =
        tokio::time::timeout(Duration::from_secs(2), events.recv()).await
        && !episode_id.starts_with("sensor-")
    {
        panic!("unwatched file must not alert, got {episode_id}");
    }

    agent.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_rejects_process_rule_with_no_matcher() {
    // A rule with no matchers would fire on every exec — the agent must
    // refuse to start rather than silently alert on everything.
    let workdir = TempDir::new().unwrap();
    let monitor = MonitorConfig {
        file_rules: Vec::new(),
        process_rules: vec![ProcessRule {
            id: Some("catch-all".to_string()),
            exe_prefix: None,
            comm: None,
            arg_substr: None,
            severity: RuleSeverity::High,
        }],
    };
    let identity = Arc::new(Identity::generate());
    let cfg = build_config(workdir.path(), reserve_udp_port(), monitor);
    let source = Box::new(MockEventSource::new(Vec::new()));
    let err = Agent::start(cfg, identity, source)
        .await
        .expect_err("agent must reject an all-empty process rule");
    assert!(
        format!("{err}").contains("no matcher"),
        "unexpected error: {err}"
    );
}

/// A write to a built-in watch path alerts, with the process named.
///
/// Distinct from the operator-configured file rules above: nobody has to
/// know in advance that `/etc/ld.so.preload` matters. The path here is a
/// temp-dir stand-in, so the assertion is on the *rule firing*, which is
/// unit-tested against the real paths in `bowery_analysis::file_watch`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_to_a_persistence_path_alerts_and_names_the_process() {
    let workdir = TempDir::new().unwrap();
    let cfg = build_config(workdir.path(), reserve_udp_port(), MonitorConfig::default());

    // Feed the event the kernel sensor would produce, held until we are
    // watching — see `EventGate`.
    let (source, gate) = gated_source(vec![Event::FileOpen(FileOpen {
        pid: 4242,
        comm: "curl".into(),
        path: "/root/.ssh/authorized_keys".into(),
        flags: 0o1101,
        truncated: false,
        sensitive_read: false,
        ts: SystemTime::now(),
    })]);

    let identity = Arc::new(Identity::generate());
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    let mut events = agent.subscribe();
    gate.open();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let episode = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !left.is_zero(),
            "timed out waiting for the file-watch alert"
        );
        if let Ok(Ok(AgentEvent::AlertEmitted { episode_id, .. })) =
            tokio::time::timeout(left, events.recv()).await
            && episode_id.starts_with("file-persist.authorized_keys-")
        {
            break episode_id;
        }
    };

    let (alerts, _) = agent.inbox().read_since(0, 100);
    let alert = alerts
        .iter()
        .find(|a| a.episode_id == episode)
        .expect("alert in the inbox");
    assert!(alert.rationale.contains("/root/.ssh/authorized_keys"));
    // The process is the lead an operator follows next.
    assert!(alert.rationale.contains("curl"), "{}", alert.rationale);
    assert!(alert.rationale.contains("pid 4242"), "{}", alert.rationale);
    // And it explains why the path matters at all.
    assert!(
        alert.rationale.contains("passwordless login"),
        "{}",
        alert.rationale
    );
    assert!(alert.suspicion > 0.9);

    agent.shutdown().await.expect("shutdown");
}

/// The same finding, twice, produces one alert.
///
/// This is the exact shape the live fleet produced: one pid read one
/// host key twice in the same second, and the operator was told twice.
/// Sixty-one of 63 alerts on a three-host fleet were restatements like
/// this one.
///
/// The reader is unresolvable here (pid 4242 does not exist), which is
/// deliberate — it is the case where the agent knows least, and it must
/// still fold rather than restate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_identical_finding_repeated_is_folded_into_one_alert() {
    let workdir = TempDir::new().unwrap();
    let cfg = build_config(workdir.path(), reserve_udp_port(), MonitorConfig::default());

    let dup = || {
        Event::FileOpen(FileOpen {
            pid: 4242,
            comm: "curl".into(),
            path: "/root/.ssh/authorized_keys".into(),
            flags: 0o1101,
            truncated: false,
            sensitive_read: false,
            ts: SystemTime::now(),
        })
    };
    let (source, gate) = gated_source(vec![dup(), dup(), dup(), dup()]);

    let identity = Arc::new(Identity::generate());
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    let mut events = agent.subscribe();
    gate.open();

    // Wait for the first alert, then give the remaining three events
    // room to be processed and folded.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "timed out waiting for the first alert");
        if let Ok(Ok(AgentEvent::AlertEmitted { episode_id, .. })) =
            tokio::time::timeout(left, events.recv()).await
            && episode_id.starts_with("file-persist.authorized_keys-")
        {
            break;
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (alerts, _) = agent.inbox().read_since(0, 100);
    let raised = alerts
        .iter()
        .filter(|a| a.episode_id.starts_with("file-persist.authorized_keys-"))
        .count();
    assert_eq!(
        raised, 1,
        "four identical findings must produce one alert, got {raised}"
    );

    agent.shutdown().await.expect("shutdown");
}

/// A process that has already exited can still be named, so the
/// sanctioned-reader exemption can still be earned.
///
/// This is the last mechanical source of credential-read noise on the
/// live fleet, in its exact shape: PAM forks `unix_chkpwd`, it reads
/// `/etc/shadow`, it exits in milliseconds, and `/proc/<pid>/exe` is
/// gone before the agent looks. Failing closed made that an alert every
/// time — correct, but useless, because the exemption could not be
/// earned when the question could not be asked.
///
/// The exec is fed through the same pipeline first, exactly as the
/// kernel would report it. The assertion is on the *rationale naming
/// the resolved path* rather than on silence, because this test host's
/// binary is not a packaged `unix_chkpwd` and so is legitimately not
/// exempt — what is being pinned is that the agent can now name a
/// binary it could not name before. `bowery_analysis::file_watch`
/// covers the exemption decision itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_that_already_exited_is_still_named_from_the_exec_record() {
    let workdir = TempDir::new().unwrap();
    let cfg = build_config(workdir.path(), reserve_udp_port(), MonitorConfig::default());

    // A pid that certainly does not exist, so /proc cannot answer and
    // only the recorded exec can.
    let ghost = 4_194_301;
    let now = SystemTime::now();
    let (source, gate) = gated_source(vec![
        Event::ProcessExec(bowery_events::ProcessExec {
            pid: ghost,
            ppid: 1,
            parent_comm: "sshd".into(),
            uid: 0,
            comm: "unix_chkpwd".into(),
            exe_path: Some("/usr/sbin/unix_chkpwd".into()),
            args: vec!["/usr/sbin/unix_chkpwd".into()],
            ts: now,
        }),
        Event::FileOpen(FileOpen {
            pid: ghost,
            comm: "unix_chkpwd".into(),
            path: "/root/.ssh/authorized_keys".into(),
            flags: 0o1101,
            truncated: false,
            sensitive_read: false,
            ts: now,
        }),
    ]);

    let identity = Arc::new(Identity::generate());
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    let mut events = agent.subscribe();
    gate.open();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let episode = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "timed out waiting for the alert");
        if let Ok(Ok(AgentEvent::AlertEmitted { episode_id, .. })) =
            tokio::time::timeout(left, events.recv()).await
            && episode_id.starts_with("file-persist.authorized_keys-")
        {
            break episode_id;
        }
    };

    let (alerts, _) = agent.inbox().read_since(0, 100);
    let alert = alerts
        .iter()
        .find(|a| a.episode_id == episode)
        .expect("alert in the inbox");
    assert!(
        alert.rationale.contains("/usr/sbin/unix_chkpwd"),
        "the exited reader must be named from the exec record, got: {}",
        alert.rationale
    );
    // And the context carries it too, rather than disagreeing with the
    // rationale about who the reader was.
    assert!(
        alert
            .context
            .iter()
            .any(|a| a.key == "exe" && a.value == "/usr/sbin/unix_chkpwd"),
        "context must name the same binary the rationale does"
    );

    agent.shutdown().await.expect("shutdown");
}

/// The counter reflects a rule that actually fired, end to end.
///
/// Unit tests prove the counter counts. This proves it is *wired* to a
/// real detection — which is exactly the property that was missing from
/// six other things today, each of them correct in isolation and
/// connected to nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fired_rule_shows_up_in_the_detection_counters() {
    let workdir = TempDir::new().unwrap();
    let cfg = build_config(workdir.path(), reserve_udp_port(), MonitorConfig::default());

    let (source, gate) = gated_source(vec![Event::FileOpen(FileOpen {
        pid: 4242,
        comm: "curl".into(),
        path: "/root/.ssh/authorized_keys".into(),
        flags: 0o1101,
        truncated: false,
        sensitive_read: false,
        ts: SystemTime::now(),
    })]);

    let identity = Arc::new(Identity::generate());
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    let mut events = agent.subscribe();
    gate.open();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "timed out waiting for the alert");
        if let Ok(Ok(AgentEvent::AlertEmitted { episode_id, .. })) =
            tokio::time::timeout(left, events.recv()).await
            && episode_id.starts_with("file-persist.authorized_keys-")
        {
            break;
        }
    }

    let snap = agent.detection_stats().snapshot();
    let fired = snap
        .iter()
        .find(|(id, _)| *id == "persist.authorized_keys")
        .expect("the rule must have a row at all")
        .1;
    assert_eq!(
        fired.fired, 1,
        "the rule that just fired must be counted, not merely present"
    );
    assert!(fired.last_unix_ms.is_some());

    // And a rule that did not fire is still a row, at zero — the whole
    // reason the table is seeded from the registry rather than filled
    // on first fire.
    let never = snap
        .iter()
        .find(|(id, _)| *id == "impact.mass_write_new_extension")
        .expect("a never-fired rule must still be a row")
        .1;
    assert_eq!(never.fired, 0);
    assert_eq!(never.last_unix_ms, None);

    agent.shutdown().await.expect("shutdown");
}

/// Build a dpkg database registering `conffile` as belonging to `pkg`.
///
/// `load_dpkg` reads `<dir>/*.conffiles` and takes the paths verbatim,
/// so a tempdir path can stand in for `/etc/sudoers` without touching
/// anything real.
fn dpkg_db_with_conffile(dir: &Path, pkg: &str, conffile: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join(format!("{pkg}.conffiles")),
        format!("{}\n", conffile.display()),
    )
    .unwrap();
}

/// Install `index` on a started agent, after its own startup load lands.
async fn install_index(agent: &Agent, index: bowery_analysis::provenance::PackageIndex) {
    let settle = tokio::time::Instant::now() + Duration::from_secs(10);
    while !agent.packages().is_ready() && tokio::time::Instant::now() < settle {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    agent.packages().install(index);
}

/// Ubuntu's own unattended-upgrades, in the shape the fleet produced it.
///
/// otter1 alerted on `/etc/sudoers` three times in one second at 0.95,
/// 0.90 and 0.70. The process tree said exactly what it was:
/// `apt.systemd.daily` → `unattended-upgrade` → `dpkg --unpack
/// sudo_1.9.15p5-3ubuntu5.24.04_amd64.deb`. The `sudo` *package* was
/// being upgraded, and `/etc/sudoers` is a conffile of `sudo`, so dpkg
/// rewriting it is the upgrade rather than a finding about it.
///
/// The threshold is dropped so the damped alert is still stored and can
/// be asserted on. In production 0.135 is below the 0.7 default and the
/// operator never sees it — but the access stays in the event log,
/// which is the difference between damping and silencing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conffile_rewritten_during_a_package_transaction_is_damped() {
    let workdir = TempDir::new().unwrap();
    let watched = workdir.path().join("sudoers");
    std::fs::write(&watched, b"original").unwrap();

    let monitor = MonitorConfig {
        file_rules: vec![FileRule {
            id: Some("sudoers".to_string()),
            path: watched.clone(),
            ops: vec![bowery_events::FileOp::Modify],
            severity: RuleSeverity::High,
        }],
        process_rules: Vec::new(),
    };

    // Written now, so the database's mtime says a transaction is
    // running by the same measure the agent uses on a real host.
    let db = workdir.path().join("dpkg-info");
    dpkg_db_with_conffile(&db, "sudo", &watched);

    let identity = Arc::new(Identity::generate());
    let mut cfg = build_config(workdir.path(), reserve_udp_port(), monitor);
    cfg.alerts.threshold = 0.01;
    let source = Box::new(MockEventSource::new(Vec::new()));
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    install_index(
        &agent,
        bowery_analysis::provenance::PackageIndex::load_dpkg(&db),
    )
    .await;
    assert!(
        agent.packages().housekeeping(&watched, None).is_some(),
        "the fixture must actually reach the state under test"
    );

    let mut events = agent.subscribe();
    tokio::time::sleep(Duration::from_millis(300)).await;
    std::fs::write(&watched, b"rewritten by the upgrade").unwrap();

    let (episode_id, suspicion) = wait_for_alert(&mut events).await;
    assert!(episode_id.starts_with("file-sudoers-"), "got {episode_id}");
    assert!(
        (suspicion - 0.135).abs() < 0.001,
        "high severity 0.9 damped as housekeeping should be 0.135, got {suspicion}"
    );

    let (alerts, _) = agent.inbox().read_since(0, 100);
    let alert = alerts
        .iter()
        .find(|a| a.episode_id == episode_id)
        .expect("alert in the inbox");
    assert!(
        alert.rationale.contains("conffile of `sudo`"),
        "the damping must name the entitlement it credited, got: {}",
        alert.rationale
    );

    agent.shutdown().await.expect("shutdown");
}

/// The same rewrite, with no transaction running, is undamped.
///
/// The contrast is the point. Without it this would be a blanket
/// "conffiles are exempt", which would mean an edit to `/etc/sudoers`
/// at three in the morning read the same as dpkg's own — and that edit
/// is the finding the rule exists for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_conffile_rewritten_outside_a_transaction_is_not_damped() {
    let workdir = TempDir::new().unwrap();
    let watched = workdir.path().join("sudoers");
    std::fs::write(&watched, b"original").unwrap();

    let monitor = MonitorConfig {
        file_rules: vec![FileRule {
            id: Some("sudoers".to_string()),
            path: watched.clone(),
            ops: vec![bowery_events::FileOp::Modify],
            severity: RuleSeverity::High,
        }],
        process_rules: Vec::new(),
    };

    let db = workdir.path().join("dpkg-info");
    dpkg_db_with_conffile(&db, "sudo", &watched);
    // Age the database past the transaction window. Set before the
    // index is read so the stamp records the same quiet state.
    let handle = std::fs::File::open(&db).unwrap();
    handle
        .set_times(std::fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
        .unwrap();

    let identity = Arc::new(Identity::generate());
    let mut cfg = build_config(workdir.path(), reserve_udp_port(), monitor);
    cfg.alerts.threshold = 0.01;
    let source = Box::new(MockEventSource::new(Vec::new()));
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    install_index(
        &agent,
        bowery_analysis::provenance::PackageIndex::load_dpkg(&db),
    )
    .await;
    assert!(
        agent.packages().housekeeping(&watched, None).is_none(),
        "no transaction is running, so nothing should be credited"
    );

    let mut events = agent.subscribe();
    tokio::time::sleep(Duration::from_millis(300)).await;
    std::fs::write(&watched, b"edited by someone").unwrap();

    let (_, suspicion) = wait_for_alert(&mut events).await;
    assert!(
        (suspicion - 0.9).abs() < f32::EPSILON,
        "an edit outside a transaction must keep its full severity, got {suspicion}"
    );

    agent.shutdown().await.expect("shutdown");
}

/// The read side of the same false positive, through the exec record.
///
/// `process_file_open` is the path that *can* attribute an actor, and
/// it passes `Some(provenance)` where the inotify path passes `None`.
/// The unit tests cover which provenances earn the exemption; this
/// covers that the pipeline asks at all.
///
/// The actor is a real packaged binary whose digest is read off the
/// disk at test time, because `load_dpkg` only indexes paths under the
/// system's own binary directories — a tempdir binary can never be
/// `PackagedIntact`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conffile_read_by_the_package_manager_mid_transaction_is_damped() {
    let workdir = TempDir::new().unwrap();
    let actor = ["/usr/bin/dpkg", "/usr/bin/true", "/bin/true"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
        .expect("a packaged system binary to stand in for the package manager");
    let digest = bowery_analysis::provenance::file_md5(&actor).expect("digest");

    let db = workdir.path().join("dpkg-info");
    dpkg_db_with_conffile(&db, "sudo", Path::new("/etc/sudoers"));
    std::fs::write(
        db.join("dpkg.md5sums"),
        format!(
            "{}  {}\n",
            digest.iter().fold(String::new(), |mut acc, b| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{b:02x}");
                acc
            }),
            actor.display().to_string().trim_start_matches('/')
        ),
    )
    .unwrap();

    let ghost = 4_194_299;
    let now = SystemTime::now();
    let (source, gate) = gated_source(vec![
        Event::ProcessExec(bowery_events::ProcessExec {
            pid: ghost,
            ppid: 1,
            parent_comm: "unattended-upgr".into(),
            uid: 0,
            comm: "dpkg".into(),
            exe_path: Some(actor.clone()),
            args: vec![actor.display().to_string()],
            ts: now,
        }),
        Event::FileOpen(FileOpen {
            pid: ghost,
            comm: "dpkg".into(),
            path: "/etc/sudoers".into(),
            flags: 0,
            truncated: false,
            sensitive_read: true,
            ts: now,
        }),
    ]);

    let identity = Arc::new(Identity::generate());
    let mut cfg = build_config(workdir.path(), reserve_udp_port(), MonitorConfig::default());
    cfg.alerts.threshold = 0.01;
    let agent = Agent::start(cfg, identity, source).await.expect("start");
    install_index(
        &agent,
        bowery_analysis::provenance::PackageIndex::load_dpkg(&db),
    )
    .await;
    assert_eq!(
        agent.packages().classify(&actor, &[0u8; 32]),
        bowery_analysis::provenance::Provenance::PackagedIntact,
        "the fixture's actor must be one a package vouches for"
    );

    let mut events = agent.subscribe();
    gate.open();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (episode, suspicion) = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "timed out waiting for the alert");
        if let Ok(Ok(AgentEvent::AlertEmitted {
            episode_id,
            suspicion,
        })) = tokio::time::timeout(left, events.recv()).await
            && episode_id.starts_with("file-recon.read_sudoers-")
        {
            break (episode_id, suspicion);
        }
    };

    assert!(
        (suspicion - 0.105).abs() < 0.001,
        "recon.read_sudoers at 0.70 damped as housekeeping should be 0.105, got {suspicion}"
    );
    let (alerts, _) = agent.inbox().read_since(0, 100);
    let alert = alerts
        .iter()
        .find(|a| a.episode_id == episode)
        .expect("alert in the inbox");
    assert!(
        alert.rationale.contains("conffile of `sudo`"),
        "got: {}",
        alert.rationale
    );

    agent.shutdown().await.expect("shutdown");
}
