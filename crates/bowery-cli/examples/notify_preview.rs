//! Render a representative digest to HTML, to look at in a browser.
//!
//! `bowery notify --html-out` does this with real alerts, but it needs a
//! reachable fleet with something to report. This needs nothing, and it
//! deliberately covers the cases that are awkward to produce on demand:
//! a confirmed alert, an unconfirmed one, a rationale long enough to
//! wrap, and context attributes.
//!
//! ```text
//! cargo run -p bowery-cli --example notify_preview -- /tmp/digest.html
//! ```

use bowery_cli::notify::{HostAlerts, VerdictMap, body, body_html};
use bowery_proto::{Alert, AlertConfirmation, Attribute};

fn main() {
    let mk = |ep: &str,
              rule: &str,
              sus: f32,
              path: &str,
              why: &str,
              conf: Option<AlertConfirmation>,
              ctx: Vec<(&str, &str)>| Alert {
        originator_fp: vec![0x3a; 32],
        rule_id: rule.into(),
        episode_id: ep.into(),
        exe_sha256_hex: "9f2c4e1b".repeat(8),
        exe_path: path.into(),
        suspicion: sus,
        rationale: why.into(),
        suggested_actions: vec![],
        ts_unix_ms: 1_755_400_000_000,
        backend: "llama-cpp/qwen3-0.6b".into(),
        confirmation: conf,
        context: ctx
            .into_iter()
            .map(|(k, v)| Attribute {
                key: k.into(),
                value: v.into(),
            })
            .collect(),
    };
    let hosts = vec![
        HostAlerts {
            host: "otter1".into(),
            alerts: vec![
                mk(
                    "ep-7f3a91c2d4e8",
                    "cred.read_aws",
                    0.92,
                    "/tmp/.x/harvest",
                    "Read ~/.aws/credentials from a binary in a world-writable path with no package \
                    provenance | lineage: sshd -> bash -> harvest | the process had no prior read of \
                    any file under $HOME, so this is not a tool being used, it is a tool looking",
                    Some(AlertConfirmation {
                        peers_asked: 3,
                        peers_unseen: 3,
                        peers_seen: 0,
                        peers_no_reply: 0,
                        peers_incomparable: 0,
                        peers_familiar: 0,
                        peers_refused: 0,
                        quorum: 2,
                        confirmed: true,
                    }),
                    vec![
                        ("argv", "./harvest --out /dev/shm/.k --quiet"),
                        ("cwd", "/tmp/.x"),
                        ("uid", "0 (was 1000)"),
                    ],
                ),
                mk(
                    "ep-2b8d05aa71ff",
                    "evade.watchdog_disarm",
                    0.80,
                    "/usr/bin/dd",
                    "Write-intent open of /dev/watchdog0. Disarming the hardware watchdog removes the \
                    thing that would reboot this host if it stopped responding",
                    Some(AlertConfirmation {
                        peers_asked: 2,
                        peers_unseen: 0,
                        peers_seen: 0,
                        peers_no_reply: 0,
                        peers_incomparable: 2,
                        peers_familiar: 0,
                        peers_refused: 0,
                        quorum: 2,
                        confirmed: false,
                    }),
                    vec![("argv", "dd if=/dev/zero of=/dev/watchdog0")],
                ),
            ],
        },
        HostAlerts {
            host: "legolas".into(),
            alerts: vec![mk(
                "ep-c41e77b09a35",
                "privesc.uid_transition_no_helper",
                0.55,
                "/usr/bin/install",
                "Privilege transition to root with no set-id helper on the path (declined=ParentGone; \
                 a short-lived sudo that exited before the parent could be read is the usual benign cause)",
                None,
                vec![("argv", "install -m 0755 bowery-agent /usr/local/bin/")],
            )],
        },
    ];
    let vt = VerdictMap::new();
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "digest.html".to_string());
    std::fs::write(&out, body_html(&hosts, &vt)).expect("writing HTML preview");
    let text = std::path::Path::new(&out).with_extension("txt");
    std::fs::write(&text, body(&hosts, &vt)).expect("writing text preview");
    println!("wrote {out} and {}", text.display());
}
