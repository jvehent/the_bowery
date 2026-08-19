//! Seed an archive with representative alerts, to exercise
//! `bowery alerts history` without a fleet.
//!
//! ```text
//! cargo run -p bowery-cli --example archive_seed -- /tmp/alerts.db
//! ```
use bowery_cli::archive::Archive;
use bowery_proto::{Alert, AlertConfirmation, Attribute};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "alerts.db".into());
    let mut a = Archive::open(&path).expect("open");
    let base: u64 = 1_755_400_000_000;

    let mk = |fp: u8, ep: &str, rule: &str, ts: u64, sus: f32, path: &str, why: &str| Alert {
        originator_fp: vec![fp; 32],
        rule_id: rule.into(),
        episode_id: ep.into(),
        exe_sha256_hex: "9f2c4e1b".repeat(8),
        exe_path: path.into(),
        suspicion: sus,
        rationale: why.into(),
        suggested_actions: vec![],
        ts_unix_ms: ts,
        backend: "llama-cpp/qwen3-0.6b".into(),
        confirmation: None,
        context: vec![Attribute {
            key: "argv".into(),
            value: format!("{path} --quiet"),
        }],
    };

    let mut confirmed = mk(
        0x3a,
        "ep-7f3a91",
        "cred.read_aws",
        base,
        0.92,
        "/tmp/.x/harvest",
        "Read ~/.aws/credentials from a world-writable path with no provenance",
    );
    confirmed.confirmation = Some(AlertConfirmation {
        peers_asked: 3,
        peers_unseen: 3,
        peers_seen: 0,
        peers_no_reply: 0,
        peers_refused: 0,
        quorum: 2,
        confirmed: true,
    });

    // Same episode, superseded twice: raised, then downgraded by the mesh.
    let raised = mk(
        0x3a,
        "ep-2b8d05",
        "file.access",
        base + 1000,
        0.85,
        "/usr/bin/dd",
        "write-intent open of /dev/watchdog0",
    );
    let downgraded = mk(
        0x3a,
        "ep-2b8d05",
        "file.access",
        base + 60_000,
        0.30,
        "/usr/bin/dd",
        "downgraded: 3 peers report the same binary touches the same path",
    );

    let other = mk(
        0x7c,
        "ep-c41e77",
        "privesc.uid_transition_no_helper",
        base + 5000,
        0.55,
        "/usr/bin/install",
        "privilege transition to root with no set-id helper (declined=ParentGone)",
    );

    a.record(&[confirmed, raised, downgraded], Some("otter1"))
        .expect("record");
    a.record(&[other], Some("legolas")).expect("record");
    println!("seeded {path}: {:?}", a.stats().expect("stats"));
}
