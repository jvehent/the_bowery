//! Phase 3–7 detection pipeline: the path from a kernel event to an
//! alert.
//!
//! Split out of `agent.rs`, which had grown to 5,168 lines across five
//! unrelated concerns. This is one of them: everything that happens
//! *after* an event arrives and *before* it reaches the inbox.
//!
//! # Why a context struct
//!
//! Every detection added over the last stretch needed one or two more
//! pieces of shared state — a tracker, a config field, a counter — and
//! each one was threaded by hand through four signatures. `spawn` took
//! **27 parameters** and `process_event` **25**, both under
//! `#[allow(clippy::too_many_arguments)]`, and adding a detection meant
//! editing four parameter lists and six call sites in the right order.
//!
//! That was not merely ugly. Three separate bugs in one session came
//! from it: a parameter bound twice in the same signature, a value
//! passed at the wrong position, and a field constructed after the line
//! that used it. The compiler caught all three, but only because the
//! types happened to differ; two `Arc<...>` of different inner types in
//! the wrong order would have compiled.
//!
//! [`PipelineContext`] holds it once. Adding a detection is now a field
//! and a use, not a transcription exercise.

use std::sync::Arc;
use std::time::Duration;

use bowery_analysis::{AlertSuppressor, Analyzer, DiscoveryTracker, Episode, MassWriteTracker};
use bowery_baseline::Baseline;
use bowery_crypto::Fingerprint;
use bowery_events::{Event, ProcessExec, enrich};
use bowery_llm::{AnalysisContext, Submitter};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::agent::{
    AgentEvent, leading_rule_id, leading_rule_message, parent_privilege_helper, sha_to_hex,
};
use crate::config::{CorroborationConfig, DetectionConfig};
use crate::detection_stats::DetectionStats;
use crate::eventlog_writer::EventLogHandle;
use crate::inbox::AlertInbox;
use crate::inbox::current_unix_ms;
use crate::monitor::MonitorRules;
use crate::proc_table::ProcTable;
use crate::whisper_qa::WhisperQaTrigger;

/// Everything the pipeline needs, assembled once at startup.
///
/// Cloneable because each task holds its own handle; every field is
/// already an `Arc` or a small `Copy`/config value, so a clone is cheap.
#[derive(Clone)]
pub(crate) struct PipelineContext {
    // -- stores and engines -------------------------------------------
    pub baseline: Arc<Baseline>,
    /// Keeps per-hash enrichment (the binary descriptor) to once per
    /// hash per TTL rather than once per exec.
    pub described: Arc<crate::seen::RecentlySeen>,
    pub analyzer: Arc<Analyzer>,
    pub packages: Arc<bowery_analysis::provenance::ProvenanceCache>,
    pub eventlog: Option<EventLogHandle>,
    /// The queryable log, distinct from the write handle above: the
    /// handle records asynchronously, this reads.
    pub eventlog_store: Option<Arc<bowery_eventlog::EventLog>>,

    // -- operator-facing ----------------------------------------------
    pub inbox: Arc<AlertInbox>,
    pub monitor_rules: Arc<MonitorRules>,
    pub originator_fp: Fingerprint,
    pub backend_label: String,
    pub alert_threshold: f32,
    pub events_tx: broadcast::Sender<AgentEvent>,

    // -- LLM + mesh ---------------------------------------------------
    pub llm_submitter: Submitter,
    pub llm_threshold: f32,
    pub whisper_threshold: f32,
    pub whisper_qa_tx: mpsc::Sender<WhisperQaTrigger>,
    pub claims: Option<crate::corroboration::ClaimSink>,
    pub corroboration: CorroborationConfig,

    // -- detection state ----------------------------------------------
    pub detection: DetectionConfig,
    pub detections: Arc<DetectionStats>,
    pub discovery: Arc<DiscoveryTracker>,
    pub suppressor: Arc<AlertSuppressor>,
    pub suppress_window: Duration,
    pub procs: Arc<ProcTable>,
    pub mass_writes: Option<Arc<MassWriteTracker>>,
    pub beacons: Option<Arc<bowery_analysis::BeaconTracker>>,
}

impl std::fmt::Debug for PipelineContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineContext")
            .field("backend_label", &self.backend_label)
            .field("alert_threshold", &self.alert_threshold)
            .finish_non_exhaustive()
    }
}

/// Drive both event sources until shutdown.
pub(crate) fn spawn(
    ctx: PipelineContext,
    mut events: mpsc::Receiver<Event>,
    mut file_events: mpsc::Receiver<Event>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Each source can end independently, and a closed channel returns
        // `None` on every poll — which would spin the select. Track both and
        // disable the drained branch; exit only when BOTH are done. Notably
        // a dead kernel event source (e.g. the BPF source exiting) must not
        // take operator file monitoring down with it, and vice versa.
        let mut events_open = true;
        let mut file_events_open = true;
        loop {
            if !events_open && !file_events_open {
                break;
            }
            tokio::select! {
                event = events.recv(), if events_open => {
                    let Some(event) = event else { events_open = false; continue };
                    process_event(&ctx, event).await;
                }
                // Operator-configured file watches (inotify) fan in here.
                file_event = file_events.recv(), if file_events_open => {
                    match file_event {
                        Some(event) => {
                            process_event(&ctx, event).await;
                        }
                        None => file_events_open = false,
                    }
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

async fn process_event(ctx: &PipelineContext, event: Event) {
    // Record first, analyse second. Every event goes to the log
    // regardless of whether anything downstream scores it — the whole
    // value of a history is that it contains the things nobody thought
    // were interesting at the time. This is also the only consumer of
    // ProcessExit / NetworkConnect / FileOpen, which the ctx.analyzer
    // pipeline still has no scoring path for.
    if let Some(log) = ctx.eventlog.as_ref() {
        log.record(event.clone());
    }

    // Remember pid → exe *before* dispatching, so a file access by a
    // process that has already exited can still name its binary. Done
    // here rather than by querying the event log because the log is
    // written through an mpsc drained by a writer task: the exec row is
    // usually not committed yet when the file-open for the same pid
    // arrives, and the lookup would lose exactly the short-lived
    // processes it exists to catch.
    match &event {
        Event::ProcessExec(e) => {
            if let Some(exe) = e.exe_path.as_deref() {
                ctx.procs.record(e.pid, exe, e.ts);
            }
        }
        // Close the pid-reuse window as soon as the kernel tells us,
        // rather than waiting out the TTL.
        Event::ProcessExit(e) => {
            ctx.procs.forget(e.pid);
            if let Some(m) = ctx.mass_writes.as_ref() {
                m.forget(e.pid);
            }
        }
        _ => {}
    }

    // ProcessExec drives the full ctx.analyzer pipeline; FileChange is the
    // operator-configured file-integrity signal. The rest are recorded
    // above and carry no scoring path yet.
    match event {
        Event::ProcessExec(exec) => {
            process_exec(ctx, exec).await;
        }
        Event::FileChange(change) => {
            process_file_change(ctx, change).await;
        }
        Event::ModuleLoad(m) => process_module_load(ctx, &m),
        Event::Ptrace(t) => process_ptrace(ctx, &t).await,
        Event::NetworkConnect(conn) => {
            process_network_connect(ctx, &conn).await;
        }
        Event::FileOpen(open) => {
            process_file_open(ctx, &open).await;
        }
        // Recorded to the event log above; no ctx.analyzer path yet.
        Event::ProcessExit(_) => {}
    }
}

/// Handle a connection event: fold outbound into the destination
/// ctx.baseline, and raise a ctx.corroboration claim for inbound.
///
/// The two directions carry different information and get different
/// treatment, which is the point of measuring direction at all.
///
/// **Outbound** is the local half of a fleet-wide rarity signal. On its
/// own, "this host has never contacted this endpoint" is weak — every
/// legitimate first connection looks the same. It becomes strong when
/// the same question is asked across the mesh, because an endpoint *no
/// host in the fleet* has ever contacted is the shape of C2, exfil, or
/// lateral movement to somewhere new.
///
/// **Inbound** is somebody else's choice, and this host cannot judge
/// it. It never touches the destination ctx.baseline — a host that gets
/// scanned would otherwise accumulate hundreds of "destinations" it
/// never contacted, and every one of them would then look normal
/// fleet-wide. Instead it becomes a claim: the host it came from is
/// asked whether it made the connection, and a denial is the finding.
/// One process took control of another.
///
/// The kernel probe already filtered to the requests that write to or
/// seize a process, so what remains is a judgement about *who* is doing
/// it. `ptrace` is how debuggers work and a host that never runs one is
/// not a host anyone develops on — so a packaged debugger at a path this
/// rule names is exempt, on the same two-condition footing as the
/// credential readers.
///
/// Did this pid become root by exec'ing a set-id helper in place?
///
/// `Some` only when the previous exec of this same pid was a packaged,
/// unmodified set-id-root binary — the `pkexec` shape. `None` means
/// "this does not apply", leaving the parent check to answer, and never
/// "this is suspicious": an unknown previous exec is not evidence.
async fn self_exec_privilege_helper(
    ctx: &PipelineContext,
    exec: &bowery_events::ProcessExec,
) -> Option<crate::agent::HelperCheck> {
    let previous = ctx.procs.previous_exe(exec.pid, exec.ts)?;
    let (setuid, _) = bowery_analysis::provenance::setid_bits(&previous)?;
    if !setuid {
        return None;
    }
    let packages = ctx.packages.clone();
    tokio::task::spawn_blocking(move || {
        let shown = previous.display().to_string();
        let sha = bowery_events::enrich::sha256_file(&previous).ok()?;
        let provenance = packages.classify(&previous, &sha);
        bowery_analysis::provenance::is_privilege_helper(true, provenance)
            .then_some(crate::agent::HelperCheck::SelfExecHelper { exe: shown })
    })
    .await
    .ok()
    .flatten()
}

/// What this host can say about the binary it just recorded.
///
/// Deliberately cheap: a `stat`, a map lookup, and two compile-time
/// constants. Anything requiring a file parse belongs in a later slice
/// — this runs inside the exec path, and the descriptor exists to make
/// cross-host comparison possible, not to make exec slower.
fn describe_binary(
    exec: &bowery_events::ProcessExec,
    ctx: &PipelineContext,
) -> bowery_baseline::BinaryDescriptor {
    let path = exec.exe_path.as_ref();
    bowery_baseline::BinaryDescriptor {
        exe_path: path.map(|p| p.display().to_string()),
        size_bytes: path
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len()),
        pkg: path.and_then(|p| ctx.packages.package_for(p)),
        platform: Some(bowery_proto::platform_key()),
    }
}

/// Resolving the caller's provenance costs a sha256, and it runs only
/// here, on a syscall the kernel filter has already made rare.
async fn process_ptrace(ctx: &PipelineContext, t: &bowery_events::Ptrace) {
    let exe = bowery_events::enrich::pid_exe_path(t.pid).or_else(|| ctx.procs.exe_at(t.pid, t.ts));
    let (_, provenance) = hash_and_classify(ctx, exe.as_ref()).await;
    let exe_str = exe.as_ref().map(|p| p.display().to_string());
    if bowery_analysis::injection::is_sanctioned_debugger(exe_str.as_deref(), provenance) {
        debug!(
            pid = t.pid,
            target = t.target_pid,
            exe = exe_str.as_deref().unwrap_or("<unresolved>"),
            "packaged debugger; not a finding"
        );
        return;
    }
    // Repeats fold: a debugger-shaped tool stepping through a process
    // issues thousands of these, and restating each one is the noise
    // this project keeps removing.
    let subject = format!("{}->{}", t.pid, t.target_pid);
    let folded = match ctx.suppressor.observe(
        bowery_analysis::injection::RULE_ID,
        &subject,
        exe_str.as_deref(),
        std::time::Instant::now(),
    ) {
        bowery_analysis::SuppressDecision::Suppress => return,
        bowery_analysis::SuppressDecision::Report { folded } => folded,
    };
    let note = bowery_analysis::suppress::folded_note(folded, ctx.suppress_window);
    let request = bowery_analysis::injection::request_name(t.request);
    ctx.detections.record(bowery_analysis::injection::RULE_ID);
    warn!(
        rule = bowery_analysis::injection::RULE_ID,
        pid = t.pid,
        target = t.target_pid,
        request = t.request,
        "process injection attempt"
    );
    let episode_id = format!("inject-{}-{}", t.pid, current_unix_ms());
    let alert = crate::alert_builder::AlertBuilder::new(
        ctx.originator_fp,
        &ctx.backend_label,
        bowery_analysis::injection::RULE_ID,
        episode_id.clone(),
        0.9,
        format!(
            "{} (pid {}) issued ptrace {request} against pid {} and is not a packaged \
             debugger. Code injected this way inherits the identity of the process it \
             lands in, so every provenance and lineage check here would keep vouching \
             for that process afterwards — which is what makes this worth reading even \
             though the target may be entirely ordinary{note}",
            exe_str.as_deref().unwrap_or(&t.comm),
            t.pid,
            t.target_pid
        ),
    )
    .subject(exe_str.clone().unwrap_or_else(|| t.comm.clone()))
    .context(vec![
        bowery_proto::Attribute::new("pid", t.pid.to_string()),
        bowery_proto::Attribute::new("target_pid", t.target_pid.to_string()),
        bowery_proto::Attribute::new("request", request),
        bowery_proto::Attribute::new("comm", t.comm.clone()),
    ])
    .build();
    let appended = ctx.inbox.append(alert);
    if appended.stored() {
        let _ = ctx.events_tx.send(AgentEvent::AlertEmitted {
            episode_id,
            suspicion: 0.9,
        });
    }
}

/// A kernel module entered the kernel.
///
/// Reported only when the kernel itself declines to vouch for it —
/// out-of-tree or unsigned. A stock host loads modules constantly: at
/// boot, on hotplug, the first time a filesystem is mounted. Alerting on
/// all of them would bury the operator on every reboot, and the taint
/// flags already draw the line the kernel itself draws.
///
/// The severity is high because of what a module *is*. Every other
/// detection in this agent runs in userspace and can be lied to by code
/// running in the kernel — including the probe that reported this. The
/// load is the last moment anything here is trustworthy about it.
use bowery_analysis::kmod::RULE_ID as MODULE_RULE_ID;

fn process_module_load(ctx: &PipelineContext, m: &bowery_events::ModuleLoad) {
    let Some(reason) = m.taint_reason() else {
        return;
    };
    ctx.detections.record(MODULE_RULE_ID);
    warn!(
        rule = MODULE_RULE_ID,
        module = %m.name,
        comm = %m.comm,
        pid = m.pid,
        taints = m.taints,
        "untrusted kernel module loaded"
    );
    let episode_id = format!("mod-{}-{}", m.name, current_unix_ms());
    let alert = crate::alert_builder::AlertBuilder::new(
        ctx.originator_fp,
        &ctx.backend_label,
        bowery_analysis::kmod::RULE_ID,
        episode_id.clone(),
        0.95,
        format!(
            "kernel module `{}` was loaded by {} (pid {}) and is {reason}. A module runs in              kernel context: it can hide processes, files and sockets from every other              detection here, including the probe that reported it, so this is the last              point at which anything this agent says about it can be trusted. A stock host              loads only in-tree signed modules, so this is either a driver someone              installed deliberately or something that should not be there",
            m.name, m.comm, m.pid
        ),
    )
    .subject(m.name.clone())
    .context(vec![
        bowery_proto::Attribute::new("module", m.name.clone()),
        bowery_proto::Attribute::new("loaded_by", m.comm.clone()),
        bowery_proto::Attribute::new("pid", m.pid.to_string()),
        bowery_proto::Attribute::new("taints", format!("{:#x}", m.taints)),
        bowery_proto::Attribute::new("taint_reason", reason),
    ])
    .build();
    let appended = ctx.inbox.append(alert);
    if appended.stored() {
        let _ = ctx.events_tx.send(AgentEvent::AlertEmitted {
            episode_id,
            suspicion: 0.95,
        });
    }
}

async fn process_network_connect(ctx: &PipelineContext, conn: &bowery_events::NetworkConnect) {
    if conn.direction != bowery_events::NetDirection::Outbound {
        if let Some(claims) = ctx.claims.as_ref()
            && let Some(claim) = crate::corroboration::net_inbound::claim_for(
                conn,
                ctx.corroboration.half_window,
                ctx.corroboration.suspicion,
            )
        {
            claims.raise(claim);
        }
        // The inbound record still reaches the event log, which is where
        // the peer's own correlating question gets answered from.
        return;
    }
    let _baseline = ctx.baseline.clone();
    let baseline = ctx.baseline.clone();
    let addr = conn.daddr.to_string();
    let port = conn.dport;
    // spawn_blocking: SQLite is synchronous, and connect events arrive
    // at a much higher rate than execs on a busy host.
    // Beaconing, judged before the upsert so the destination's age is
    // what it was *before* this connection.
    //
    // Periodicity alone is not the finding — NTP, package mirrors and
    // monitoring agents all beacon, and a rule that fired on regularity
    // would fire on every host forever. Novelty is what separates them,
    // and it is answered from the baseline rather than from a list of
    // known-good endpoints, which would be endless and an evasion
    // target both.
    if let Some(beacons) = ctx.beacons.as_ref()
        && let Some(beacon) = beacons.observe(
            &conn.daddr.to_string(),
            conn.dport,
            std::time::Instant::now(),
        )
    {
        let known = ctx
            .baseline
            .net_destination(&beacon.dst_addr, beacon.dst_port)
            .ok()
            .flatten();
        let age_hours = known.as_ref().and_then(|r| {
            std::time::SystemTime::now()
                .duration_since(r.first_seen)
                .ok()
                .map(|d| d.as_secs() / 3600)
        });
        // Established infrastructure: this host has been talking to it
        // for long enough that its regularity says nothing. Forgotten
        // rather than merely unreported, so the series does not sit in
        // memory re-deciding the same thing.
        let established = age_hours.is_some_and(|h| h >= ctx.detection.beacon_min_novelty_hours);
        if established {
            beacons.forget(&beacon.dst_addr, beacon.dst_port);
        } else {
            let why = bowery_analysis::beacon::rationale(&beacon, age_hours);
            ctx.detections.record(bowery_analysis::beacon::RULE_ID);
            warn!(
                rule = bowery_analysis::beacon::RULE_ID,
                dst = %beacon.dst_addr,
                port = beacon.dst_port,
                interval_s = beacon.interval.as_secs(),
                "possible C2 beaconing"
            );
            let episode_id = format!("net-c2.beacon-{}", current_unix_ms());
            let alert = crate::alert_builder::AlertBuilder::new(
                ctx.originator_fp,
                &ctx.backend_label,
                bowery_analysis::beacon::RULE_ID,
                episode_id.clone(),
                0.85,
                why,
            )
            .subject(format!("{}:{}", beacon.dst_addr, beacon.dst_port))
            .context(vec![
                bowery_proto::Attribute::new("dst_addr", beacon.dst_addr.clone()),
                bowery_proto::Attribute::new("dst_port", beacon.dst_port.to_string()),
                bowery_proto::Attribute::new("interval_s", beacon.interval.as_secs().to_string()),
                bowery_proto::Attribute::new("jitter_pct", format!("{:.0}", beacon.jitter * 100.0)),
                bowery_proto::Attribute::new("connections", beacon.samples.to_string()),
            ])
            .build();
            let appended = ctx.inbox.append(alert);
            if appended.stored() {
                let _ = ctx.events_tx.send(AgentEvent::AlertEmitted {
                    episode_id,
                    suspicion: 0.85,
                });
            }
        }
    }

    let outcome =
        tokio::task::spawn_blocking(move || baseline.upsert_net_destination(&addr, port)).await;
    match outcome {
        Ok(Ok(bowery_baseline::UpsertOutcome::Inserted)) => {
            debug!(dst = %conn.daddr, port = conn.dport, "first contact with destination");
        }
        Ok(Ok(bowery_baseline::UpsertOutcome::Updated { .. })) => {}
        Ok(Err(e)) => warn!(error = %e, "recording network destination failed"),
        Err(e) => warn!(error = %e, "destination upsert task panicked"),
    }
}

/// Alert on a write to a path the built-in watch set covers.
///
/// The kernel sensor reports every write-intent open; this is what makes
/// the ones that matter reach an operator. Persistence, privilege
/// escalation, credential and log-tampering paths are built in rather
/// than configured, because an operator should not have to know in
/// advance that `/etc/ld.so.preload` is how a host gets owned.
///
/// # Two filters stand between a match and an operator
///
/// A live three-host fleet produced 63 alerts in 24 minutes, 61 of which
/// were `sshd` and `unix_chkpwd` doing their job. Two different
/// mechanisms produced that flood and they need different answers.
///
/// **The sanctioned reader.** `sshd` reads host keys and `/etc/shadow`
/// because that is what it is for; the rule's own text already said so
/// and alerted anyway. So the reader's exe is resolved from `/proc` and
/// checked against the rule's sanctioned set — but only when package
/// provenance vouches for that binary, so a trojanised or impostor
/// `sshd` is not covered. Resolved from `/proc/<pid>/exe`, never from
/// `comm`: `comm` is 16 bytes any process sets with `prctl`, so keying
/// the exemption on it would be an instruction for reading every key on
/// the host in silence.
///
/// **The repeat.** The same pid read the same host key twice in the same
/// second and produced two alerts. Repeats inside a window are folded
/// into the next report, which states how many it stands for — a
/// suppressed run is counted, never discarded, because "read a host key"
/// and "read a host key 4,000 times" are different events.
///
/// No whisper confirmation is attached. "Did anyone else write this
/// file" is a question the ctx.corroboration substrate could answer — and a
/// package upgrade writing the same unit on every host is exactly what
/// it would explain away — but the kind is not registered yet, and
/// stamping an unconfirmed block on the alert would imply a check that
/// never ran.
/// Turn an impact finding into the rule and rationale to report, or
/// `None` when it should not be reported at all.
///
/// The exemption lives here rather than in the tracker because it costs a
/// sha256: the writer's provenance is resolved only once a finding has
/// already been produced, which on an ordinary host is close to never.
/// The same shape the privilege-transition rule uses — the cheap
/// conjunction first, the expensive check only where an alert was about
/// to be raised.
async fn impact_finding_to_report(
    ctx: &PipelineContext,
    open: &bowery_events::FileOpen,
    finding: &bowery_analysis::mass_write::ImpactFinding,
) -> Option<(&'static str, String)> {
    use bowery_analysis::mass_write;
    match finding {
        mass_write::ImpactFinding::Sweep(burst) => {
            warn!(
                rule = mass_write::RULE_ID,
                pid = burst.pid,
                files = burst.files,
                dirs = burst.dirs,
                extension = %burst.extension,
                "possible ransomware"
            );
            Some((mass_write::RULE_ID, mass_write::rationale(burst)))
        }
        mass_write::ImpactFinding::Note(note) => {
            let exe = bowery_events::enrich::pid_exe_path(open.pid);
            let exe_str = exe.as_ref().map(|p| p.display().to_string());
            let (_, provenance) = hash_and_classify(ctx, exe.as_ref()).await;
            if mass_write::writer_is_package_tool(exe_str.as_deref(), provenance) {
                debug!(
                    rule = mass_write::NOTE_RULE_ID,
                    exe = exe_str.as_deref().unwrap_or("?"),
                    name = %note.name,
                    "fan-out by a package tool, not reported"
                );
                return None;
            }
            warn!(
                rule = mass_write::NOTE_RULE_ID,
                pid = note.pid,
                name = %note.name,
                dirs = note.dirs,
                ancestor = %note.common_ancestor,
                "possible ransom note"
            );
            Some((mass_write::NOTE_RULE_ID, mass_write::note_rationale(note)))
        }
    }
}

/// Hash a binary and classify it against the package database.
///
/// Returns the hash too, because two of the three callers want it and
/// recomputing would double the cost of the expensive half. Runs on a
/// blocking thread: it reads the whole file, and the pipeline it is
/// called from is what the sensor feeds.
///
/// Extracted at the third copy. Provenance is the exemption every rule
/// anchors on — a binary a package vouches for and has not changed — so
/// the number of places computing it only grows, and three hand-written
/// versions is where that becomes a liability rather than a repetition.
async fn hash_and_classify(
    ctx: &PipelineContext,
    exe: Option<&std::path::PathBuf>,
) -> (Option<[u8; 32]>, bowery_analysis::provenance::Provenance) {
    let unknown = bowery_analysis::provenance::Provenance::Unknown;
    let Some(exe) = exe.cloned() else {
        return (None, unknown);
    };
    let packages = ctx.packages.clone();
    tokio::task::spawn_blocking(move || {
        let sha = enrich::sha256_file(&exe).ok()?;
        let provenance = packages.classify(&exe, &sha);
        Some((sha, provenance))
    })
    .await
    .ok()
    .flatten()
    .map_or((None, unknown), |(sha, p)| (Some(sha), p))
}

#[allow(clippy::too_many_lines)] // one linear scoring path
async fn process_file_open(ctx: &PipelineContext, open: &bowery_events::FileOpen) {
    let path = open.path.display().to_string();

    // Mass writes are scored before rule matching, because a ransomware
    // sweep touches files no watch rule names — the whole point is that
    // it goes after a user's documents, not `/etc/ld.so.preload`. Every
    // write-intent open feeds the tracker; only the conjunction it
    // looks for produces an alert.
    if !open.sensitive_read
        && let Some(mass) = ctx.mass_writes.as_ref()
        && let Some(finding) = mass.observe(open.pid, &path, std::time::Instant::now())
        && let Some((rule_id, why)) = impact_finding_to_report(ctx, open, &finding).await
    {
        ctx.detections.record(rule_id);
        let episode_id = format!("file-{rule_id}-{}", current_unix_ms());
        let alert = crate::alert_builder::AlertBuilder::new(
            ctx.originator_fp,
            &ctx.backend_label,
            rule_id,
            episode_id.clone(),
            0.95,
            why,
        )
        .subject(path.clone())
        .context(file_open_context(
            open,
            bowery_events::enrich::pid_exe_path(open.pid)
                .map(|p| p.display().to_string())
                .as_deref(),
        ))
        .build();
        let appended = ctx.inbox.append(alert);
        if appended.stored() {
            let _ = ctx.events_tx.send(AgentEvent::AlertEmitted {
                episode_id,
                suspicion: 0.95,
            });
        }
    }

    // The same path means different things read and written: reading
    // /etc/shadow is credential theft, writing it is an account change.
    let hit = if open.sensitive_read {
        bowery_analysis::file_watch::classify_read(&path)
    } else {
        bowery_analysis::file_watch::classify(&path)
    };
    let Some(hit) = hit else {
        return;
    };

    // Who read it, and does a package vouch for them?
    //
    // Both answers are best-effort and both fail towards alerting: a
    // process that exited before /proc could be read earns no exemption.
    // That is the opposite default from the uid-transition rule, where an
    // unreadable parent reports nothing — there a fact could not be
    // established, here an exemption could not be earned, and a ctx.detection
    // that goes quiet whenever it cannot look is one an attacker only has
    // to outrun.
    // /proc first — it is authoritative for a process that still
    // exists. When the process has already gone, fall back to the exec
    // we recorded for that pid.
    //
    // That fallback is the whole reason `unix_chkpwd` was the last
    // source of credential-read noise on the fleet: PAM forks it, it
    // reads /etc/shadow, it exits, and /proc/<pid>/exe is gone before
    // the agent can look. Failing closed made that an alert every time,
    // which was correct but useless — the exemption could not be earned
    // because the question could not be asked.
    //
    // This does not weaken failing closed. It improves the agent's
    // ability to *look*; when neither source can name the binary, the
    // finding is still raised.
    let exe = bowery_events::enrich::pid_exe_path(open.pid)
        .or_else(|| ctx.procs.exe_at(open.pid, open.ts));
    let (exe_sha, provenance) = hash_and_classify(ctx, exe.as_ref()).await;
    let exe_str = exe.as_ref().map(|p| p.display().to_string());

    // Record the attributed access BEFORE the sanctioned check, and
    // regardless of whether it becomes an alert.
    //
    // The ctx.corroboration question a peer asks is "does this happen on
    // your host", not "is it a finding there". A host whose own sshd is
    // sanctioned must still be able to say that its sshd reads host
    // keys — otherwise the only agents able to corroborate are the ones
    // with the same problem you are asking about.
    if let (Some(log), Some(exe)) = (ctx.eventlog_store.as_ref(), exe_str.as_deref())
        && let Err(e) = log.record_file_access(
            open.pid,
            &open.comm,
            exe,
            &path,
            open.sensitive_read,
            open.ts,
        )
    {
        debug!(error = %e, "recording attributed file access failed");
    }

    if bowery_analysis::file_watch::reader_is_sanctioned(&hit, exe_str.as_deref(), provenance) {
        debug!(
            rule = hit.rule_id,
            path = %path,
            exe = exe_str.as_deref().unwrap_or("<unresolved>"),
            "sanctioned reader; not a finding"
        );
        return;
    }

    // Repeats of an identical finding are folded rather than restated.
    let folded = match ctx.suppressor.observe(
        hit.rule_id,
        &path,
        exe_str.as_deref(),
        std::time::Instant::now(),
    ) {
        bowery_analysis::SuppressDecision::Suppress => {
            debug!(rule = hit.rule_id, path = %path, "repeat folded into the open window");
            return;
        }
        bowery_analysis::SuppressDecision::Report { folded } => folded,
    };
    let folded_note = bowery_analysis::suppress::folded_note(folded, ctx.suppress_window);
    // A truncated path may have matched a prefix rule on the part we
    // did see. Say so rather than quoting a path that is not the whole
    // one — an investigator matching against it needs to know.
    let path_note = if open.truncated {
        " (path truncated by the sensor)"
    } else {
        ""
    };
    let episode_id = format!("file-{}-{}", hit.rule_id, current_unix_ms());
    let alert = crate::alert_builder::AlertBuilder::new(
        ctx.originator_fp,
        &ctx.backend_label,
        hit.rule_id,
        episode_id.clone(),
        hit.severity,
        format!(
            "{} {} {path}{path_note} by {} (pid {}) — {}{folded_note}",
            hit.category.label(),
            if open.sensitive_read {
                "read of"
            } else {
                "write to"
            },
            // The resolved binary, because `comm` is 16 bytes any
            // process can set to whatever it likes. It is still reported
            // in the context, where a human can weigh it.
            exe_str.as_deref().unwrap_or(if open.comm.is_empty() {
                "an unnamed process"
            } else {
                open.comm.as_str()
            }),
            open.pid,
            hit.why
        ),
    )
    .subject(path.clone())
    .exe_sha256_hex(exe_sha.as_ref().map(sha_to_hex).unwrap_or_default())
    .context(file_open_context(open, exe_str.as_deref()))
    .build();
    ctx.detections.record(hit.rule_id);
    warn!(
        rule = hit.rule_id,
        path = %path,
        comm = %open.comm,
        pid = open.pid,
        "file watch hit"
    );
    let appended = ctx.inbox.append(alert);
    if appended.stored() {
        let _ = ctx.events_tx.send(AgentEvent::AlertEmitted {
            episode_id: episode_id.clone(),
            suspicion: hit.severity,
        });
    }

    // Ask the neighbourhood whether this is just what the fleet does.
    //
    // Raised *after* the alert, never instead of it. A ctx.detection that
    // waits for the mesh says nothing on a single-node install, on a
    // partitioned network, or when every peer is down — which are
    // exactly the moments it matters most. The round can only supersede
    // what was already reported, with a lower score, and only when peers
    // actually answered.
    if let Some(claims) = ctx.claims.as_ref()
        && let Some(claim) = crate::corroboration::file_access::claim_for(
            exe_str.as_deref(),
            &path,
            open.sensitive_read,
            episode_id,
            open.ts,
            ctx.corroboration.half_window,
            ctx.corroboration.explained_suspicion,
        )
    {
        claims.raise(claim);
    }
}

/// Everything an operator needs to judge an exec alert without logging
/// in to the host.
///
/// "A rare binary ran" is not actionable. "`sshd → bash → curl`, run by
/// uid 1000 from /tmp, with `curl -s http://…/x.sh | sh`, holding a
/// socket to 203.0.113.9:80" is. The pieces are cheap — most are
/// already on the event, the rest are one `/proc` read each — and
/// without them the operator's next step is always the same manual
/// investigation.
///
/// Best-effort throughout. A short-lived process is gone before the
/// `/proc` reads happen, so anything unavailable is **omitted rather
/// than reported as empty**: "no open files" and "the process had
/// already exited" must not look the same.
fn exec_context(exec: &ProcessExec) -> Vec<bowery_proto::Attribute> {
    use bowery_proto::Attribute;

    let mut ctx = Vec::new();
    ctx.push(Attribute::new("uid", exec.uid.to_string()));
    if !exec.args.is_empty() {
        // The full command line, not the first argument. Arguments are
        // where the intent usually is — a downloader's URL, an
        // interpreter's inline script.
        ctx.push(Attribute::new("cmdline", exec.args.join(" ")));
    }
    if let Some(cwd) = bowery_events::enrich::pid_cwd(exec.pid) {
        ctx.push(Attribute::new("cwd", cwd.display().to_string()));
    }

    // Ancestry, nearest first. Depth 6 reaches init on any normal tree
    // and bounds the walk on a pathological one.
    let chain = bowery_events::enrich::pid_ancestry(exec.pid, 6);
    if !chain.is_empty() {
        let rendered: Vec<String> = std::iter::once(format!("{}[{}]", exec.comm, exec.pid))
            .chain(chain.iter().map(|(pid, comm)| format!("{comm}[{pid}]")))
            .collect();
        // Root-first reads the way an operator thinks about it.
        ctx.push(Attribute::new(
            "ancestry",
            rendered.into_iter().rev().collect::<Vec<_>>().join(" → "),
        ));
    }

    // What the process had open at this instant. Distinguishing "could
    // not look" from "had nothing open" is the whole reason this is an
    // Option.
    match bowery_events::enrich::pid_open_files(exec.pid, 12) {
        Some((paths, sockets)) => {
            if !paths.is_empty() {
                let listed: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
                ctx.push(Attribute::new("open_files", listed.join(", ")));
            }
            // Resolving the inode is what turns "held 3 sockets" into
            // somewhere to look next.
            let peers = bowery_events::enrich::resolve_tcp_sockets(&sockets, 8);
            if !peers.is_empty() {
                ctx.push(Attribute::new("connections", peers.join(", ")));
            } else if !sockets.is_empty() {
                ctx.push(Attribute::new(
                    "connections",
                    format!("{} socket(s), none resolvable to a TCP peer", sockets.len()),
                ));
            }
        }
        None => ctx.push(Attribute::new(
            "open_files",
            "not sampled — the process had already exited",
        )),
    }
    ctx
}

/// Context for a file-watch alert: who touched it, and what else they
/// had open at the time.
fn file_open_context(
    open: &bowery_events::FileOpen,
    exe: Option<&str>,
) -> Vec<bowery_proto::Attribute> {
    use bowery_proto::Attribute;

    let mut ctx = vec![Attribute::new("pid", open.pid.to_string())];
    // The resolved binary, which is what the sanctioned-reader check
    // ran against. `comm` travels beside it rather than instead of it:
    // a disagreement between the two ("comm sshd, exe /tmp/x") is itself
    // the finding, and collapsing them would hide it.
    if let Some(exe) = exe {
        ctx.push(Attribute::new("exe", exe.to_string()));
    }
    if !open.comm.is_empty() {
        ctx.push(Attribute::new("comm", open.comm.clone()));
    }
    if let Some(cmdline) = bowery_events::enrich::pid_cmdline(open.pid)
        && !cmdline.is_empty()
    {
        ctx.push(Attribute::new("cmdline", cmdline.join(" ")));
    }
    let chain = bowery_events::enrich::pid_ancestry(open.pid, 6);
    if !chain.is_empty() {
        let mut rendered: Vec<String> = chain
            .iter()
            .map(|(pid, comm)| format!("{comm}[{pid}]"))
            .collect();
        rendered.reverse();
        rendered.push(format!("{}[{}]", open.comm, open.pid));
        ctx.push(Attribute::new("ancestry", rendered.join(" → ")));
    }
    if let Some((_, sockets)) = bowery_events::enrich::pid_open_files(open.pid, 0) {
        let peers = bowery_events::enrich::resolve_tcp_sockets(&sockets, 8);
        if !peers.is_empty() {
            ctx.push(Attribute::new("connections", peers.join(", ")));
        }
    }
    ctx
}

/// Emit an alert for a change to an operator-watched file.
///
/// Unlike exec events there's no scoring step: the operator explicitly asked
/// to be told about this file, so a matching change always alerts. The rule's
/// severity becomes the alert's suspicion so existing consumers (ctx.inbox
/// ordering, the console, `bowery_alerts`) rank it sensibly.
///
/// The file is hashed after the change so the operator sees what it became;
/// a deleted (or unreadable) file yields an empty hash rather than dropping
/// the alert — "it's gone" is exactly what you want to hear about.
async fn process_file_change(ctx: &PipelineContext, change: bowery_events::FileChange) {
    // The watcher only emits changes that already matched a rule, but
    // re-resolve here so the alert can name it (and so a future producer
    // can't inject unmatched paths).
    let Some(rule) = ctx
        .monitor_rules
        .file_rules()
        .iter()
        .find(|r| r.path == change.path && r.ops.contains(&change.op))
    else {
        return;
    };

    let path_for_hash = change.path.clone();
    let sha_hex =
        match tokio::task::spawn_blocking(move || enrich::sha256_file(&path_for_hash)).await {
            Ok(Ok(sha)) => sha_to_hex(&sha),
            // Deleted/unreadable file: still alert, just without a hash.
            Ok(Err(_)) | Err(_) => String::new(),
        };

    let op = crate::monitor::file_op_label(change.op);
    let suspicion = crate::monitor::severity_weight(rule.severity);
    let alert = crate::alert_builder::AlertBuilder::for_operator_rule(
        ctx.originator_fp,
        &ctx.backend_label,
        rule.id.clone(),
        format!("file-{}-{}", rule.id, current_unix_ms()),
        suspicion,
        format!(
            "file rule `{}`: {} was {}",
            rule.id,
            change.path.display(),
            op
        ),
    )
    .subject(change.path.display().to_string())
    .exe_sha256_hex(sha_hex)
    .build();
    let episode_id = alert.episode_id.clone();
    info!(rule = %rule.id, path = %change.path.display(), op, "file monitor alert");
    let appended = ctx.inbox.append(alert);
    if appended.stored() {
        let _ = ctx.events_tx.send(AgentEvent::AlertEmitted {
            episode_id,
            suspicion,
        });
    }
}

/// Fold a directly-scored finding into an exec's verdict.
///
/// Four detections used to do this by hand, and all four did it the same
/// way: raise `suspicion`, append to `score.reason`, bump the counter.
/// None of them recorded a [`RuleHit`] — and that is the only channel the
/// alert rationale and the model prompt read. The result was an alert
/// whose entire explanation was the fallback string "pre-filter score
/// above threshold", and a prompt that told the model "Rule hits: none"
/// while asking it to judge an episode scored 0.9.
///
/// One function, so a fifth detection cannot rediscover the same gap.
fn fold_finding(
    ctx: &PipelineContext,
    verdict: &mut bowery_analysis::Verdict,
    rule_id: &'static str,
    severity: f32,
    why: String,
) {
    if severity > verdict.suspicion {
        verdict.suspicion = severity;
    }
    verdict.score.reason = format!("{} | {why}", verdict.score.reason);
    verdict.rule_hits.push(bowery_analysis::RuleHit {
        rule_id,
        severity: bowery_analysis::RuleSeverity::from_weight(severity),
        reason: why,
    });
    ctx.detections.record(rule_id);
}

#[allow(clippy::too_many_lines)] // one linear scoring path
async fn process_exec(ctx: &PipelineContext, exec: ProcessExec) {
    let Some(exe_path) = exec.exe_path.clone() else {
        debug!(
            pid = exec.pid,
            "exec event missing exe_path; skipping ctx.baseline"
        );
        return;
    };

    let sha = match tokio::task::spawn_blocking(move || enrich::sha256_file(&exe_path)).await {
        Ok(Ok(sha)) => sha,
        Ok(Err(e)) => {
            debug!(pid = exec.pid, error = %e, "exe sha256 failed");
            return;
        }
        Err(e) => {
            warn!(pid = exec.pid, error = %e, "sha256 task panicked");
            return;
        }
    };

    // Phase 3 ordering: build the episode and analyze BEFORE upserting,
    // so the ctx.baseline scorer sees the prior history (count = 0 for a
    // first-time exec, not 1).
    let episode = Episode::from_exec(exec.clone());
    let analyzer_for_call = ctx.analyzer.clone();
    let episode_for_call = episode.clone();
    let verdict = match tokio::task::spawn_blocking(move || {
        analyzer_for_call.analyze(&episode_for_call, &sha)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(pid = exec.pid, error = %e, "ctx.analyzer task panicked");
            return;
        }
    };

    // Count what the pre-filter rules found. `fold_finding` counts the
    // directly-scored detections below, but these three come back from
    // `analyze` and nothing had ever counted them — so `bowery_detections`
    // had no row for the three oldest rules in the agent, and asking
    // whether the writable-path rule had ever fired returned nothing
    // rather than a number.
    for hit in &verdict.rule_hits {
        ctx.detections.record(hit.rule_id);
    }

    // Provenance: was this on the disk before anyone logged in?
    //
    // Consulted on EVERY execution, not just the first. The rarity curve
    // decays slowly — seen once, twice, three times still scores 0.89,
    // 0.80, 0.73 — so gating this on "never seen before" left every one
    // of those above the alert threshold. It did, and `/usr/bin/column`
    // alerted at 0.80 on a host whose index had loaded correctly. The
    // hash is memoised per path, so the cost after warm-up is a map
    // lookup.
    let mut verdict = verdict;
    let mut exec_provenance = bowery_analysis::provenance::Provenance::Unknown;
    if let Some(exe) = exec.exe_path.clone() {
        let index = ctx.packages.clone();
        if let Ok(provenance) =
            tokio::task::spawn_blocking(move || index.classify(&exe, &sha)).await
        {
            exec_provenance = provenance;
            let (adjusted, why) =
                bowery_analysis::provenance::adjust_score(verdict.suspicion, provenance);
            if (adjusted - verdict.suspicion).abs() > f32::EPSILON {
                debug!(
                    pid = exec.pid,
                    from = verdict.suspicion,
                    to = adjusted,
                    provenance = provenance.label(),
                    "provenance adjusted the verdict"
                );
            }
            verdict.suspicion = adjusted;
            verdict.score.reason = format!("{} ({why})", verdict.score.reason);
        }
    }
    // Set-id: a setuid-root binary is how an unprivileged process
    // becomes root. The distribution ships a short, known list of them;
    // one that arrived any other way is a foothold made permanent.
    // Composes with provenance, which is what tells the two apart.
    let setid = exec
        .exe_path
        .as_ref()
        .and_then(|exe| bowery_analysis::provenance::setid_bits(exe));
    if let Some(exe) = exec.exe_path.as_ref()
        && let Some((setuid, setgid)) = setid
        && let Some((rule_id, severity, why)) =
            bowery_analysis::provenance::setid_finding(setuid, setgid, exec_provenance)
    {
        warn!(
            rule = rule_id,
            exe = %exe.display(),
            pid = exec.pid,
            "set-id binary finding"
        );
        fold_finding(ctx, &mut verdict, rule_id, severity, why.to_string());
    }

    // Privilege transition: did this process reach root, and if so, how?
    //
    // The uid on the event is the *real* uid — `bpf_get_current_uid_gid`
    // returns `current_uid()`, not the effective one — which is the same
    // thing `pid_uid` reads for the parent, so the two are comparable.
    // That matters: a setuid binary changes the effective uid while the
    // real one still names whoever ran it, and comparing across the two
    // would call every `sudo` a transition and every real one nothing.
    //
    // Read *before* the parent can exit. Even so it is often gone, which
    // is why an unknown parent reports nothing rather than guessing.
    if ctx.detection.uid_transitions && exec.uid == 0 {
        let parent_uid = bowery_events::enrich::pid_uid(exec.ppid);
        // Resolving the parent's provenance costs a sha256 and a package
        // lookup, so it is done only once the cheap preconditions hold:
        // a root process whose parent is not root. That is rare — on an
        // ordinary host it is `sudo` and little else — so the expensive
        // half runs only where an alert was otherwise about to be
        // raised.
        let helper = if parent_uid.is_some_and(|u| u != 0) {
            // Two sanctioned shapes, and the second was missing.
            //
            // `sudo` forks, so the helper is the parent. `pkexec` execs
            // in place, so the helper is *this pid's previous exec* and
            // neither the parent nor the current binary is set-id:
            //
            //   pid 563558  uid 1000  /usr/bin/pkexec  <- the helper
            //   pid 563558  uid 0     /usr/bin/dash    <- the transition
            //
            // The parent there is `update-notifier`, which is not set-id,
            // so the rule fired. On this fleet that shape accounts for a
            // large share of `privesc.uid_transition_no_helper` — 206
            // fires in a fortnight, and Ubuntu's update-notifier runs on
            // a timer.
            match self_exec_privilege_helper(ctx, &exec).await {
                Some(check) => check,
                None => parent_privilege_helper(exec.ppid, &ctx.packages).await,
            }
        } else {
            crate::agent::HelperCheck::Helper
        };
        if let Some(hit) = bowery_analysis::uid_transition(
            exec.uid,
            parent_uid,
            exec_provenance,
            setid.is_some_and(|(setuid, _)| setuid),
            helper.is_helper(),
        ) {
            // Say which check declined the exemption. Without it, an
            // ordinary `sudo`-driven deploy and a real escalation
            // produce identical lines.
            warn!(
                rule = hit.rule_id,
                pid = exec.pid,
                ppid = exec.ppid,
                parent_uid,
                declined = ?helper,
                "privilege transition to root"
            );
            let why = format!("{}{}", hit.why, helper.why());
            fold_finding(ctx, &mut verdict, hit.rule_id, hit.severity, why);
        }
    }

    // Discovery: one recon command is nothing; five different ones from
    // the same parent in a minute is someone working out where they are.
    //
    // Folded into this exec's verdict rather than emitted separately —
    // the command that completes the burst is the one an operator wants
    // to see, and it already carries the ancestry that says who ran it.
    if ctx.detection.discovery_bursts
        && let Some(name) = exec
            .exe_path
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| (!exec.comm.is_empty()).then(|| exec.comm.clone()))
        && let Some(burst) = ctx
            .discovery
            .observe(exec.ppid, &name, std::time::Instant::now())
    {
        warn!(
            rule = bowery_analysis::escalation::DISCOVERY_RULE_ID,
            pid = exec.pid,
            ppid = exec.ppid,
            commands = %burst.commands.join(","),
            "reconnaissance burst"
        );
        fold_finding(
            ctx,
            &mut verdict,
            bowery_analysis::escalation::DISCOVERY_RULE_ID,
            0.75,
            bowery_analysis::escalation::discovery_rationale(&burst),
        );
    }

    // Switching a defence off. Read from the arguments, which the
    // sensor has carried all along and nothing scored — `iptables` and
    // `nft` were only ever counted as reconnaissance, so a bare
    // `iptables -F` needed four other recon commands to be noticed.
    if ctx.detection.defense_tampering
        && let Some(exe) = exec.exe_path.as_ref()
        && let Some(hit) =
            bowery_analysis::defense::classify(&exe.display().to_string(), &exec.args)
    {
        warn!(
            rule = hit.rule_id,
            pid = exec.pid,
            exe = %exe.display(),
            "a host defence was switched off"
        );
        fold_finding(ctx, &mut verdict, hit.rule_id, hit.severity(), hit.why);
    }

    // Lineage: who asked for this?
    //
    // Every binary a lineage rule names is legitimate somewhere — `sh`
    // and `curl` are not suspicious. The parent is the signal, and it is
    // one comparison against data the sensor now carries.
    //
    // Applied after provenance on purpose: `/bin/sh` is a packaged,
    // unmodified binary and would otherwise be damped to 15% precisely
    // when nginx started it.
    if !exec.parent_comm.is_empty()
        && let Some(child) = exec.exe_path.as_ref().map(|p| p.display().to_string())
        && let Some(hit) =
            bowery_analysis::lineage::classify_exec(&exec.parent_comm, &child, &exec.args)
    {
        warn!(
            rule = hit.rule_id,
            parent = %exec.parent_comm,
            child = %child,
            pid = exec.pid,
            "lineage hit"
        );
        fold_finding(
            ctx,
            &mut verdict,
            hit.rule_id,
            hit.severity,
            format!("{} spawned {}: {}", exec.parent_comm, child, hit.why),
        );
    }
    let verdict = verdict;

    let baseline_for_write = ctx.baseline.clone();
    let outcome =
        match tokio::task::spawn_blocking(move || baseline_for_write.upsert_binary(&sha)).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                warn!(pid = exec.pid, error = %e, "ctx.baseline upsert failed");
                return;
            }
            Err(e) => {
                warn!(pid = exec.pid, error = %e, "ctx.baseline task panicked");
                return;
            }
        };

    // Record what this hash *was*.
    //
    // Gating this on `Inserted` was wrong, and wrong in the way that
    // does not show up in a test: on a host whose baseline already held
    // 366 hashes, exactly one of them ever got described, because every
    // other exec is an `Updated`. The descriptor table would stay empty
    // on precisely the long-lived hosts it exists to serve.
    //
    // So it runs for any hash not described recently, with a TTL'd set
    // keeping it to once per hash per half hour rather than once per
    // exec. The TTL is deliberate rather than a permanent "done" flag:
    // the package index loads asynchronously, so an early write can
    // legitimately not know the package, and expiry is what lets a
    // later exec fill it in.
    //
    // Failure is logged and swallowed. This is enrichment for the mesh;
    // an exec that could not be described must still be scored and
    // alerted on, and a monitor that stops working because an
    // enrichment write failed is the failure this codebase keeps
    // finding.
    if ctx
        .described
        .check_and_record("descriptor", &sha_to_hex(&sha))
    {
        let descriptor = describe_binary(&exec, ctx);
        let baseline = ctx.baseline.clone();
        if let Ok(Err(e)) =
            tokio::task::spawn_blocking(move || baseline.record_descriptor(&sha, &descriptor)).await
        {
            debug!(pid = exec.pid, error = %e, "binary descriptor write failed");
        }
    }

    let _ = ctx
        .events_tx
        .send(AgentEvent::BinaryRecorded { sha, outcome });

    // Build the LLM context once. Both paths (direct LLM submission
    // below, and the whisper-mediated submission performed by
    // whisper_qa_task) consume the same shape; whisper_qa_task
    // additionally injects neighborhood sightings into `ctx.extra`
    // before submitting.
    // Sampled once, here, while the process is most likely still alive.
    // Both the alert and the LLM-refined alert reuse it rather than
    // re-reading /proc: by the time inference returns the process is
    // usually gone, and a second sample would report "already exited"
    // for something that was running when it mattered.
    let context = exec_context(&exec);

    let mut llm_ctx = AnalysisContext::new(verdict.clone())
        .with_exe_sha256(&sha)
        .with_exe_pid(exec.pid)
        .with_exe_comm(exec.comm.clone());
    // The same context the alert carries, so the model sees the command
    // line and ancestry too — that is most of what a human would use to
    // judge this, and it was previously invisible to the LLM as well.
    for a in &context {
        llm_ctx.extra.push((a.key.clone(), a.value.clone()));
    }
    if let Some(p) = exec.exe_path.as_ref() {
        llm_ctx = llm_ctx.with_exe_path(p.clone());
    }
    if !exec.args.is_empty() {
        llm_ctx = llm_ctx.with_args(exec.args.clone());
    }

    // Phase 4 + 5 routing: when the whisper threshold is met, defer
    // the LLM submission to whisper_qa_task so the LLM sees peer
    // sightings. Otherwise (LLM threshold met but whisper threshold
    // not), submit directly with no neighborhood context.
    let going_through_whisper = verdict.suspicion >= ctx.whisper_threshold;
    if !going_through_whisper && verdict.suspicion >= ctx.llm_threshold {
        let episode_id = verdict.episode_id.clone();
        if let Err(reason) = ctx.llm_submitter.submit(llm_ctx.clone()) {
            let _ = ctx.events_tx.send(AgentEvent::LlmShed {
                episode_id,
                reason: reason.into(),
            });
        }
    }

    if going_through_whisper
        && let Err(e) = ctx
            .whisper_qa_tx
            .send(WhisperQaTrigger {
                episode_id: verdict.episode_id.clone(),
                sha,
                ctx: llm_ctx.clone(),
            })
            .await
    {
        debug!(error = %e, "whisper Q&A trigger channel closed");
    }

    // Phase 6: append an Alert to the operator ctx.inbox if the verdict
    // crosses the alert threshold. We use the *pre-verdict's*
    // suspicion + rule rationale here; a later phase can re-emit a
    // refined alert when the LLM's verdict comes back.
    if verdict.suspicion >= ctx.alert_threshold {
        let rationale = leading_rule_message(&verdict)
            .unwrap_or_else(|| "pre-filter score above threshold".to_string());
        let alert = crate::alert_builder::AlertBuilder::new(
            ctx.originator_fp,
            &ctx.backend_label,
            leading_rule_id(&verdict),
            verdict.episode_id.clone(),
            verdict.suspicion,
            rationale,
        )
        .subject(
            exec.exe_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        )
        .exe_sha256_hex(sha_to_hex(&sha))
        .context(context.clone())
        .build();
        let episode_id = alert.episode_id.clone();
        let suspicion = alert.suspicion;
        let appended = ctx.inbox.append(alert);
        if appended.stored() {
            let _ = ctx.events_tx.send(AgentEvent::AlertEmitted {
                episode_id,
                suspicion,
            });
        }
    }

    let _ = ctx.events_tx.send(AgentEvent::EpisodeAnalyzed { verdict });
}
