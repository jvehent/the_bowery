//! Probe: can a fresh in-memory connection ATTACH the event-log file
//! read-only via a URI filename? The SQL surface's whole design depends
//! on it, so it is asserted rather than assumed.

use std::time::SystemTime;

use bowery_eventlog::EventLog;
use bowery_events::{Event, ProcessExec};
use rusqlite::Connection;

#[test]
fn readonly_uri_attach_sees_committed_rows_and_refuses_writes() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("events.db");
    let log = EventLog::open(&path).unwrap();
    log.append_batch(&[Event::ProcessExec(ProcessExec {
        pid: 7,
        ppid: 1,
        parent_comm: String::new(),
        uid: 0,
        comm: "probe".into(),
        exe_path: Some("/bin/probe".into()),
        args: vec![],
        ts: SystemTime::now(),
    })])
    .unwrap();
    log.checkpoint().unwrap();

    let conn = Connection::open_in_memory().unwrap();
    let uri = format!("file:{}?mode=ro", path.display());
    conn.execute("ATTACH DATABASE ?1 AS el", [&uri])
        .expect("read-only URI attach must work");

    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM el.events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "attached log must expose committed rows");

    let write = conn.execute(
        "INSERT INTO el.events (ts_unix_ms, kind) VALUES (1, 'x')",
        [],
    );
    assert!(write.is_err(), "mode=ro attach must reject writes");
}

/// Does a read-only attach see rows that are still only in the WAL?
///
/// The answer sets the checkpoint cadence: if un-checkpointed writes are
/// invisible, the checkpoint interval *is* the query lag, and a freshly
/// started agent looks blind until the first one runs.
#[test]
fn readonly_attach_visibility_of_uncheckpointed_writes() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("events.db");
    let log = EventLog::open(&path).unwrap();
    log.append_batch(&[Event::ProcessExec(ProcessExec {
        pid: 1,
        ppid: 1,
        parent_comm: String::new(),
        uid: 0,
        comm: "a".into(),
        exe_path: None,
        args: vec![],
        ts: SystemTime::now(),
    })])
    .unwrap();
    log.checkpoint().unwrap();

    // Second write, deliberately NOT checkpointed.
    log.append_batch(&[Event::ProcessExec(ProcessExec {
        pid: 2,
        ppid: 1,
        parent_comm: String::new(),
        uid: 0,
        comm: "b".into(),
        exe_path: None,
        args: vec![],
        ts: SystemTime::now(),
    })])
    .unwrap();

    let conn = Connection::open_in_memory().unwrap();
    let uri = format!("file:{}?mode=ro", path.display());
    conn.execute("ATTACH DATABASE ?1 AS el", [&uri]).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM el.events", [], |r| r.get(0))
        .unwrap();
    println!("VISIBLE_ROWS_WITHOUT_CHECKPOINT={n}");
    assert!(n >= 1, "checkpointed row must always be visible");
}
