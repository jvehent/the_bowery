//! Replay a fleet's real file history through the impact detections.
//!
//! Answers the only question that matters about a rule with a
//! false-positive budget: *what would this have said about the traffic we
//! actually have?* Reasoning about it is how the mass-write rule nearly
//! shipped keyed on a write rate, and how five detections shipped correct
//! and unable to fire.
//!
//! Timestamps are honoured, so the tumbling window behaves as it does in
//! production. Replaying every event at one instant collapses a day of
//! package upgrades into a single window and reports findings that could
//! never happen — which this example did, before it read the clock.
//!
//! Produce the input from any host holding the operator manifest:
//!
//! ```text
//! bowery exec sql --fanout --sql \
//!   'SELECT ts_unix_ms, comm, path FROM bowery_events
//!    WHERE kind = "file_open" ORDER BY ts_unix_ms' > opens.tsv
//! cargo run -p bowery-analysis --example replay_impact -- opens.tsv
//! ```
//!
//! Columns are `agent, fingerprint, ts_unix_ms, comm, path` — the fan-out
//! prefixes the first two. A header line is skipped if present.

use bowery_analysis::mass_write::{ImpactFinding, MassWriteTracker};
use std::collections::HashMap;
use std::io::BufRead;
use std::time::{Duration, Instant};

/// Production defaults, from `[detection]` in the agent config.
const WINDOW: Duration = Duration::from_mins(1);
const MIN_FILES: usize = 50;
const MIN_DIRS: usize = 5;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: replay_impact <opens.tsv>");
        std::process::exit(2);
    };
    let file = std::fs::File::open(&path).expect("open input");

    // One tracker per host: pids are only unique within a host, and a
    // shared tracker would pool unrelated processes into one window.
    let mut trackers: HashMap<String, MassWriteTracker> = HashMap::new();
    // The log carries `comm`, not pid, so each distinct writer on a host
    // gets a synthetic pid. That over-merges a program run many times —
    // it makes the rule look *more* trigger-happy than it is, which is
    // the safe direction for a false-positive measurement.
    let mut synthetic: HashMap<String, u32> = HashMap::new();
    let mut next_pid = 1_u32;

    let base = Instant::now();
    let mut epoch: Option<u64> = None;
    let (mut notes, mut sweeps, mut total) = (0_usize, 0_usize, 0_usize);

    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        let col: Vec<&str> = line.split('\t').collect();
        if col.len() < 5 {
            continue;
        }
        let (agent, comm, p) = (col[0], col[3], col[4]);
        let Ok(ts) = col[2].parse::<u64>() else {
            continue; // header row
        };
        total += 1;
        let start = *epoch.get_or_insert(ts);
        let now = base + Duration::from_millis(ts.saturating_sub(start));

        let key = format!("{agent}\u{1}{comm}");
        let pid = *synthetic.entry(key.clone()).or_insert_with(|| {
            next_pid += 1;
            next_pid
        });
        let tracker = trackers
            .entry(agent.to_string())
            .or_insert_with(|| MassWriteTracker::new(WINDOW, MIN_FILES, MIN_DIRS));

        match tracker.observe(pid, p, now) {
            Some(ImpactFinding::Note(n)) => {
                notes += 1;
                println!(
                    "NOTE   {agent:10} {comm:20} {:3} dirs under {:22} name={}",
                    n.dirs, n.common_ancestor, n.name
                );
            }
            Some(ImpactFinding::Sweep(b)) => {
                sweeps += 1;
                println!(
                    "SWEEP  {agent:10} {comm:20} {:3} files across {:3} dirs .{}",
                    b.files, b.dirs, b.extension
                );
            }
            None => {}
        }
    }

    println!(
        "\nreplayed {total} write-intent opens at production thresholds \
         (window {WINDOW:?}, {MIN_FILES} files, {MIN_DIRS} dirs): \
         {notes} note findings, {sweeps} sweep findings"
    );
    println!(
        "note: the package-tool exemption is applied in the agent, not here — \
         findings by dpkg/mandb/apt-key/unsquashfs are suppressed in production"
    );
}
