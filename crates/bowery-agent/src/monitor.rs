//! Operator-configurable monitoring rules — file-integrity watches and
//! process detections — validated once at startup from [`MonitorConfig`].
//!
//! The validated [`MonitorRules`] snapshot is shared (via `Arc`) with three
//! consumers: the inotify file-monitor task (file rules), the analyzer
//! (process rules, layered onto the built-in detections), and the
//! `bowery_monitor_rules` SQL table (lists both so the operator can query
//! the effective config with `bowery exec sql`).

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bowery_analysis::RuleSeverity;
use bowery_events::{Event, FileChange, FileOp};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::{FileRule, MonitorConfig, ProcessRule};

/// A validated file-watch rule (id resolved).
#[derive(Debug, Clone)]
pub struct FileRuleSpec {
    pub id: String,
    pub path: PathBuf,
    pub ops: Vec<FileOp>,
    pub severity: RuleSeverity,
}

/// A validated process-detection rule (id resolved; at least one matcher set).
#[derive(Debug, Clone)]
pub struct ProcessRuleSpec {
    pub id: String,
    pub exe_prefix: Option<String>,
    pub comm: Option<String>,
    pub arg_substr: Option<String>,
    pub severity: RuleSeverity,
}

/// Validated snapshot of the operator's monitoring config.
#[derive(Debug, Clone, Default)]
pub struct MonitorRules {
    file_rules: Vec<FileRuleSpec>,
    process_rules: Vec<ProcessRuleSpec>,
}

impl MonitorRules {
    /// Validate + resolve config rules. Rejects (returns a human-readable
    /// error) a process rule with NO matcher — it would fire on every exec —
    /// and a file rule whose path has no parent directory to watch.
    pub fn from_config(cfg: &MonitorConfig) -> Result<Self, String> {
        let mut file_rules = Vec::with_capacity(cfg.file_rules.len());
        for (i, r) in cfg.file_rules.iter().enumerate() {
            if r.path.parent().is_none() {
                return Err(format!(
                    "monitor.file_rules[{i}]: path {} has no parent directory to watch",
                    r.path.display()
                ));
            }
            if r.ops.is_empty() {
                return Err(format!(
                    "monitor.file_rules[{i}] ({}): `ops` is empty — nothing would alert",
                    resolve_file_id(r, i)
                ));
            }
            file_rules.push(FileRuleSpec {
                id: resolve_file_id(r, i),
                path: r.path.clone(),
                ops: r.ops.clone(),
                severity: r.severity,
            });
        }

        let mut process_rules = Vec::with_capacity(cfg.process_rules.len());
        for (i, r) in cfg.process_rules.iter().enumerate() {
            if r.exe_prefix.is_none() && r.comm.is_none() && r.arg_substr.is_none() {
                return Err(format!(
                    "monitor.process_rules[{i}]: no matcher set (exe_prefix/comm/arg_substr); \
                     an all-empty rule would match every process"
                ));
            }
            process_rules.push(ProcessRuleSpec {
                id: resolve_process_id(r, i),
                exe_prefix: r.exe_prefix.clone(),
                comm: r.comm.clone(),
                arg_substr: r.arg_substr.clone(),
                severity: r.severity,
            });
        }

        Ok(Self {
            file_rules,
            process_rules,
        })
    }

    pub fn file_rules(&self) -> &[FileRuleSpec] {
        &self.file_rules
    }

    pub fn process_rules(&self) -> &[ProcessRuleSpec] {
        &self.process_rules
    }

    pub fn is_empty(&self) -> bool {
        self.file_rules.is_empty() && self.process_rules.is_empty()
    }
}

fn resolve_file_id(r: &FileRule, i: usize) -> String {
    r.id.clone().unwrap_or_else(|| {
        r.path.file_name().map_or_else(
            || format!("file-rule-{}", i + 1),
            |n| n.to_string_lossy().into_owned(),
        )
    })
}

fn resolve_process_id(r: &ProcessRule, i: usize) -> String {
    if let Some(id) = &r.id {
        return id.clone();
    }
    if let Some(c) = &r.comm {
        return format!("comm={c}");
    }
    if let Some(p) = &r.exe_prefix {
        return format!("exe={p}");
    }
    if let Some(a) = &r.arg_substr {
        return format!("arg={a}");
    }
    format!("process-rule-{}", i + 1)
}

/// Stable lowercase label for a [`FileOp`] (matches the serde encoding), for
/// the `bowery_monitor_rules` SQL table and alert rationales.
pub fn file_op_label(op: FileOp) -> &'static str {
    match op {
        FileOp::Modify => "modify",
        FileOp::Attrib => "attrib",
        FileOp::Delete => "delete",
        FileOp::Move => "move",
        FileOp::Create => "create",
    }
}

/// Suspicion weight for a severity — mirrors `rule_hits_weight` in
/// `bowery_analysis::analyzer` so a file alert ranks the same as an exec
/// rule hit of equal severity.
pub fn severity_weight(sev: RuleSeverity) -> f32 {
    match sev {
        RuleSeverity::Info => 0.1,
        RuleSeverity::Low => 0.3,
        RuleSeverity::Medium => 0.6,
        RuleSeverity::High => 0.9,
    }
}

/// Stable lowercase label for a [`RuleSeverity`] (matches the serde encoding).
pub fn severity_label(sev: RuleSeverity) -> &'static str {
    match sev {
        RuleSeverity::Info => "info",
        RuleSeverity::Low => "low",
        RuleSeverity::Medium => "medium",
        RuleSeverity::High => "high",
    }
}

// ---------------------------------------------------------------------------
// inotify file monitor
// ---------------------------------------------------------------------------

/// Watch the PARENT DIRECTORY of each rule's file, not the file itself.
/// Editors and package managers replace config files atomically (write a
/// temp file, then `rename()` over the target), which detaches an
/// inode-level watch — the file appears "unchanged" forever after. Watching
/// the directory and filtering by basename catches replace-style edits as
/// well as in-place writes.
fn watch_mask() -> AddWatchFlags {
    AddWatchFlags::IN_CLOSE_WRITE
        | AddWatchFlags::IN_ATTRIB
        | AddWatchFlags::IN_MOVED_TO
        | AddWatchFlags::IN_MOVED_FROM
        | AddWatchFlags::IN_CREATE
        | AddWatchFlags::IN_DELETE
}

/// Map an inotify event mask to our [`FileOp`]. Returns `None` for masks we
/// don't classify (e.g. `IN_IGNORED` bookkeeping).
fn classify(mask: AddWatchFlags) -> Option<FileOp> {
    if mask.contains(AddWatchFlags::IN_CLOSE_WRITE) {
        Some(FileOp::Modify)
    } else if mask.contains(AddWatchFlags::IN_ATTRIB) {
        Some(FileOp::Attrib)
    } else if mask.contains(AddWatchFlags::IN_DELETE) {
        Some(FileOp::Delete)
    } else if mask.contains(AddWatchFlags::IN_MOVED_TO)
        || mask.contains(AddWatchFlags::IN_MOVED_FROM)
    {
        Some(FileOp::Move)
    } else if mask.contains(AddWatchFlags::IN_CREATE) {
        Some(FileOp::Create)
    } else {
        None
    }
}

/// Spawn the file-integrity watcher. Returns `None` when there are no file
/// rules (nothing to watch) or when inotify can't be initialised — in both
/// cases the agent keeps running without file monitoring rather than
/// failing to start.
///
/// Each emitted [`Event::FileChange`] goes to `tx`, which the agent's
/// pipeline task consumes alongside the kernel event source.
pub fn spawn_file_monitor_task(
    rules: &MonitorRules,
    tx: mpsc::Sender<Event>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if rules.file_rules().is_empty() {
        return None;
    }

    let inotify = match Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC) {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "inotify init failed; file monitoring disabled");
            return None;
        }
    };

    // dir watch descriptor → the rules whose file lives in that directory,
    // keyed by basename so one watch can serve several rules.
    let mut by_wd: HashMap<WatchDescriptor, Vec<FileRuleSpec>> = HashMap::new();
    let mut dir_wds: HashMap<PathBuf, WatchDescriptor> = HashMap::new();

    for rule in rules.file_rules() {
        let Some(dir) = rule.path.parent() else {
            warn!(rule = %rule.id, path = %rule.path.display(), "file rule has no parent dir; skipping");
            continue;
        };
        let wd = if let Some(wd) = dir_wds.get(dir) {
            *wd
        } else {
            match inotify.add_watch(dir, watch_mask()) {
                Ok(wd) => {
                    dir_wds.insert(dir.to_path_buf(), wd);
                    wd
                }
                Err(e) => {
                    // A missing/unreadable directory shouldn't kill the
                    // whole monitor — the other rules still work.
                    warn!(
                        rule = %rule.id, dir = %dir.display(), error = %e,
                        "cannot watch directory; this file rule is inactive"
                    );
                    continue;
                }
            }
        };
        by_wd.entry(wd).or_default().push(rule.clone());
    }

    if by_wd.is_empty() {
        warn!("no watchable file rules; file monitoring disabled");
        return None;
    }

    info!(
        rules = rules.file_rules().len(),
        dirs = dir_wds.len(),
        "file monitor watching"
    );

    Some(tokio::spawn(async move {
        // AsyncFd lets us await readability on the inotify fd instead of
        // blocking a runtime worker. nix's `Inotify` implements `AsFd` but
        // not `AsRawFd` (which AsyncFd requires), so wrap it.
        let async_fd = match AsyncFd::new(InotifyFd(inotify)) {
            Ok(fd) => fd,
            Err(e) => {
                warn!(error = %e, "inotify AsyncFd registration failed; file monitoring disabled");
                return;
            }
        };
        loop {
            tokio::select! {
                readable = async_fd.readable() => {
                    let mut guard = match readable {
                        Ok(g) => g,
                        Err(e) => {
                            warn!(error = %e, "inotify readability wait failed; stopping file monitor");
                            return;
                        }
                    };
                    let events = match guard.get_inner().0.read_events() {
                        Ok(evs) => { guard.clear_ready(); evs }
                        Err(nix::errno::Errno::EAGAIN) => { guard.clear_ready(); continue }
                        Err(e) => {
                            warn!(error = %e, "inotify read failed; stopping file monitor");
                            return;
                        }
                    };
                    for ev in events {
                        let Some(rules_for_wd) = by_wd.get(&ev.wd) else { continue };
                        let Some(op) = classify(ev.mask) else { continue };
                        // Directory watches report the basename of the entry
                        // that changed; match it against each rule's target.
                        let Some(name) = ev.name.as_ref() else { continue };
                        for rule in rules_for_wd {
                            if !matches_rule(rule, name, op) {
                                continue;
                            }
                            debug!(rule = %rule.id, path = %rule.path.display(), ?op, "file change matched");
                            let change = Event::FileChange(FileChange {
                                path: rule.path.clone(),
                                op,
                                ts: SystemTime::now(),
                            });
                            if tx.send(change).await.is_err() {
                                // Pipeline is gone; nothing left to feed.
                                return;
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => return,
            }
        }
    }))
}

/// Newtype giving nix's `Inotify` an `AsRawFd` impl, which `AsyncFd`
/// requires (nix only provides `AsFd`). Owns the instance so the fd stays
/// alive for the lifetime of the registration.
#[derive(Debug)]
struct InotifyFd(Inotify);

impl std::os::fd::AsRawFd for InotifyFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsFd;
        self.0.as_fd().as_raw_fd()
    }
}

/// True when an inotify entry name + classified op satisfy this rule.
fn matches_rule(rule: &FileRuleSpec, name: &OsString, op: FileOp) -> bool {
    rule.ops.contains(&op) && file_name_of(&rule.path).is_some_and(|n| n == name.as_os_str())
}

fn file_name_of(path: &Path) -> Option<&std::ffi::OsStr> {
    path.file_name()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MonitorConfig;

    #[test]
    fn rejects_process_rule_with_no_matcher() {
        let cfg: MonitorConfig = toml::from_str(
            r#"
            [[process_rules]]
            severity = "high"
            "#,
        )
        .unwrap();
        let err = MonitorRules::from_config(&cfg).unwrap_err();
        assert!(err.contains("no matcher"), "{err}");
    }

    #[test]
    fn resolves_ids_and_defaults() {
        let cfg: MonitorConfig = toml::from_str(
            r#"
            [[file_rules]]
            path = "/etc/sudoers"

            [[process_rules]]
            comm = "nc"
            "#,
        )
        .unwrap();
        let rules = MonitorRules::from_config(&cfg).unwrap();
        assert_eq!(rules.file_rules()[0].id, "sudoers");
        // default ops = modify/attrib/delete/move; default severity high
        assert_eq!(rules.file_rules()[0].ops.len(), 4);
        assert_eq!(rules.file_rules()[0].severity, RuleSeverity::High);
        assert_eq!(rules.process_rules()[0].id, "comm=nc");
    }
}
