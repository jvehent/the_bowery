//! End-to-end: an event observed by the pipeline becomes a row an
//! operator can `SELECT`.
//!
//! This is the property the whole feature exists for, and it spans four
//! pieces that are each unit-tested separately but had never been proven
//! to line up: pipeline → bounded writer → `SQLite` file → read-only
//! `ATTACH` behind the SQL surface.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_agent::Agent;
use bowery_agent::config::{
    AlertsConfig, BaselineConfig, BloomConfig, Config, EventLogConfig, HeartbeatConfig,
    IdentityConfig, InboxConfig, KnownNeighborsConfig, LlmConfig, MeshConfig, OperatorsConfig,
    ResponseConfig, RoleConfig, WhisperConfig, WhisperQaConfig,
};
use bowery_crypto::Identity;
use bowery_events::source::MockEventSource;
use bowery_events::{Event, NetFamily, NetworkConnect, ProcessExec, ProcessExit};
use tempfile::TempDir;

fn reserve_udp_port() -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.local_addr().unwrap()
}

fn build_config(dir: &Path, eventlog_path: PathBuf) -> Config {
    let mesh_addr = reserve_udp_port();
    Config {
        identity: IdentityConfig {
            path: dir.join("identity.key"),
        },
        known_neighbors: KnownNeighborsConfig {
            path: dir.join("known_neighbors.json"),
            bootstrap_window: Duration::from_mins(1),
            max_pinned_peers: 16,
            // Phase-3 defaults: unchanged TOFU behaviour.
            enrollment: bowery_agent::config::EnrollmentPolicy::Tofu,
            grant_path: None,
            revocations_path: dir.join("revocations.json"),
        },
        mesh: MeshConfig {
            listen_addr: mesh_addr,
            advertise_addr: Some(mesh_addr),
            seeds: vec![],
            cluster_id: Some("bowery-test-eventlog".to_string()),
        },
        whisper: WhisperConfig {
            advertise_addr: None,
            qa: WhisperQaConfig {
                threshold: 0.99, // keep whisper rounds out of this test
                fanout: 1,
                timeout: Duration::from_secs(1),
                min_similarity: 0.0,
                quorum: 0,
                max_concurrent_rounds: 1,
                min_baseline_binaries: bowery_agent::config::WhisperQaConfig::default()
                    .min_baseline_binaries,
            },
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            // Left at the production default so every existing
            // two-agent fixture also exercises the corroboration
            // engine's startup and shutdown paths.
            corroboration: bowery_agent::config::CorroborationConfig::default(),
        },
        heartbeat: HeartbeatConfig {
            interval: Duration::from_secs(30),
        },
        baseline: BaselineConfig {
            path: ":memory:".into(),
        },
        role: RoleConfig {
            publish_interval: Duration::from_secs(30),
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
        eventlog: EventLogConfig {
            enabled: true,
            path: eventlog_path,
            // Long enough that the maintenance timer can't prune the
            // rows out from under the assertions.
            retention: Duration::from_hours(1),
            max_rows: 10_000,
            maintenance_interval: Duration::from_hours(1),
            queue_capacity: 256,
        },
    }
}

fn exec(pid: u32, path: &str) -> Event {
    Event::ProcessExec(ProcessExec {
        pid,
        ppid: 1,
        uid: 0,
        comm: "probe".into(),
        exe_path: Some(PathBuf::from(path)),
        args: vec!["--flag".into()],
        ts: SystemTime::now(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_events_become_queryable_history() {
    let workdir = TempDir::new().unwrap();
    let log_path = workdir.path().join("events.db");

    // Deliberately includes an exit and a connect: the analyzer has no
    // scoring path for either, so before the event log they were
    // collected by the eBPF loader and dropped on the floor. If these
    // two show up in a query, the "record first, analyse second"
    // ordering is doing its job.
    let source = Box::new(MockEventSource::new(vec![
        exec(4242, "/tmp/probe"),
        Event::ProcessExit(ProcessExit {
            pid: 4242,
            exit_code: 0,
            ts: SystemTime::now(),
        }),
        Event::NetworkConnect(NetworkConnect {
            pid: 4242,
            comm: String::new(),
            family: NetFamily::V4,
            daddr: "203.0.113.9".parse().unwrap(),
            local_addr: "0.0.0.0".parse().unwrap(),
            dport: 4444,
            local_port: 51000,
            direction: bowery_events::NetDirection::Outbound,
            ts: SystemTime::now(),
        }),
    ]));

    let cfg = build_config(workdir.path(), log_path.clone());
    let agent = Agent::start(cfg, Arc::new(Identity::generate()), source)
        .await
        .expect("start agent");

    // The writer is async and batched, so poll until the rows land
    // rather than sleeping a fixed amount.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for events to reach the log"
        );
        let log = bowery_eventlog::EventLog::open(&log_path).unwrap();
        let rows = log.stats().unwrap().rows;
        drop(log);
        if rows >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Now query it the way an operator would: through a fresh connection
    // that attaches the file read-only.
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let table = bowery_agent::sql_tables::BoweryEventsTable::new(Some(Arc::new(
        bowery_eventlog::EventLog::open(&log_path).unwrap(),
    )));
    bowery_tables::BoweryTable::register(&table, &conn).unwrap();

    let kinds: Vec<String> = conn
        .prepare("SELECT kind FROM bowery_events ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        kinds.contains(&"exec".to_string()),
        "exec missing: {kinds:?}"
    );
    assert!(
        kinds.contains(&"exit".to_string()),
        "ProcessExit must be retained even though nothing scores it: {kinds:?}"
    );
    assert!(
        kinds.contains(&"connect".to_string()),
        "NetworkConnect must be retained even though nothing scores it: {kinds:?}"
    );

    // The timeline query this feature exists to answer.
    let (exe, args): (String, String) = conn
        .query_row(
            "SELECT exe_path, args FROM bowery_events WHERE kind = 'exec' AND pid = 4242",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(exe, "/tmp/probe");
    assert_eq!(args, "--flag");

    let (addr, port): (String, i64) = conn
        .query_row(
            "SELECT dst_addr, dst_port FROM bowery_events WHERE kind = 'connect'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((addr.as_str(), port), ("203.0.113.9", 4444));

    // The view is read-only: `register` runs before the SELECT-only
    // authorizer is installed, so the mode=ro attach is what enforces
    // this at that point.
    let write = conn.execute(
        "INSERT INTO bowery_eventlog_db.events (ts_unix_ms, kind) VALUES (1, 'forged')",
        [],
    );
    assert!(write.is_err(), "attached history must reject writes");

    agent.shutdown().await.expect("shutdown");
}

/// Recording and query-ability are different failures, and an operator
/// needs to tell them apart: an empty `bowery_events` looks the same
/// whether the host was quiet or stopped recording.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_view_reports_a_disabled_log_as_not_recording() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let table = bowery_agent::sql_tables::BoweryEventLogStatusTable::new(None, None);
    bowery_tables::BoweryTable::register(&table, &conn).unwrap();

    let (recording, queryable, rows): (i64, i64, i64) = conn
        .query_row(
            "SELECT recording, queryable, rows FROM bowery_eventlog_status",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((recording, queryable, rows), (0, 0, 0));

    // An in-memory log records but cannot be reached by a query
    // connection — the one case where those two answers differ.
    let log = Arc::new(bowery_eventlog::EventLog::open_in_memory().unwrap());
    let conn2 = rusqlite::Connection::open_in_memory().unwrap();
    let table = bowery_agent::sql_tables::BoweryEventLogStatusTable::new(Some(log), None);
    bowery_tables::BoweryTable::register(&table, &conn2).unwrap();
    let (recording, queryable): (i64, i64) = conn2
        .query_row(
            "SELECT recording, queryable FROM bowery_eventlog_status",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (recording, queryable),
        (1, 0),
        "an in-memory log records but is not queryable; both must be visible"
    );
}

/// The tests above register the table on a bare connection. Production
/// goes through `bowery_sql::Sql`, which installs a SELECT-only
/// authorizer *after* registration — and an authorizer that rejected
/// reads through a temp view over an attached database would break the
/// feature in exactly the way unit tests wouldn't notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_is_readable_through_the_real_authorized_engine() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("events.db");
    {
        let log = bowery_eventlog::EventLog::open(&log_path).unwrap();
        log.append_batch(&[
            exec(11, "/usr/bin/curl"),
            Event::NetworkConnect(NetworkConnect {
                pid: 11,
                comm: String::new(),
                family: NetFamily::V4,
                daddr: "198.51.100.4".parse().unwrap(),
                local_addr: "0.0.0.0".parse().unwrap(),
                dport: 443,
                local_port: 51000,
                direction: bowery_events::NetDirection::Outbound,
                ts: SystemTime::now(),
            }),
        ])
        .unwrap();
        log.checkpoint().unwrap();
    }

    let store = Arc::new(bowery_eventlog::EventLog::open(&log_path).unwrap());
    let engine = bowery_sql::Sql::new()
        .with_extra_table(Arc::new(bowery_agent::sql_tables::BoweryEventsTable::new(
            Some(store.clone()),
        )))
        .with_extra_table(Arc::new(
            bowery_agent::sql_tables::BoweryEventLogStatusTable::new(Some(store), None),
        ));

    let rows = engine
        .query(
            "SELECT kind, exe_path, dst_addr FROM bowery_events ORDER BY seq",
            Duration::from_secs(10),
        )
        .await
        .expect("the authorizer must allow reads through the attached history");
    assert_eq!(rows.len(), 2, "both rows must come back through the engine");

    // And the status view, which is the fleet-wide "am I blind?" query.
    let status = engine
        .query(
            "SELECT recording, queryable, rows FROM bowery_eventlog_status",
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(status.len(), 1);

    // Writes must still be refused by the authorizer, not just by the
    // read-only attach.
    let write = engine
        .query(
            "INSERT INTO bowery_events (kind) VALUES ('forged')",
            Duration::from_secs(10),
        )
        .await;
    assert!(write.is_err(), "SELECT-only authorizer must reject writes");
}

/// The fleet connection graph: an outbound connection must land in the
/// destination baseline and be queryable, because that view under
/// `--fanout` is what makes lateral movement visible at all — the two
/// halves of a hop live on different hosts and neither is remarkable
/// alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_connections_become_a_queryable_destination_graph() {
    let workdir = TempDir::new().unwrap();
    let log_path = workdir.path().join("events.db");

    let source = Box::new(MockEventSource::new(vec![
        Event::NetworkConnect(NetworkConnect {
            pid: 900,
            comm: String::new(),
            family: NetFamily::V4,
            daddr: "198.51.100.22".parse().unwrap(),
            local_addr: "0.0.0.0".parse().unwrap(),
            dport: 22,
            local_port: 51000,
            direction: bowery_events::NetDirection::Outbound,
            ts: SystemTime::now(),
        }),
        // Same endpoint twice: the count must reflect repetition, since
        // "contacted once, ever" is the signal and "contacted daily" is
        // not.
        Event::NetworkConnect(NetworkConnect {
            pid: 901,
            comm: String::new(),
            family: NetFamily::V4,
            daddr: "198.51.100.22".parse().unwrap(),
            local_addr: "0.0.0.0".parse().unwrap(),
            dport: 22,
            local_port: 51000,
            direction: bowery_events::NetDirection::Outbound,
            ts: SystemTime::now(),
        }),
    ]));

    let mut cfg = build_config(workdir.path(), log_path);
    // A real baseline file so the destination table survives the query.
    cfg.baseline.path = workdir.path().join("baseline.db");
    let agent = Agent::start(cfg, Arc::new(Identity::generate()), source)
        .await
        .expect("start agent");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for the destination to be recorded"
        );
        let count = agent
            .baseline()
            .snapshot_net_destinations()
            .unwrap()
            .iter()
            .find(|d| d.dst_key == "198.51.100.22:22")
            .map_or(0, |d| d.seen_count);
        if count >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // And it must be visible through the SQL surface an operator uses.
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let table = bowery_agent::sql_tables::BoweryNetDestinationsTable::new(agent.baseline().clone());
    bowery_tables::BoweryTable::register(&table, &conn).unwrap();
    let (addr, port, count): (String, i64, i64) = conn
        .query_row(
            "SELECT addr, port, seen_count FROM bowery_net_destinations \
             WHERE dst_key = '198.51.100.22:22'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((addr.as_str(), port, count), ("198.51.100.22", 22, 2));

    agent.shutdown().await.expect("shutdown");
}
