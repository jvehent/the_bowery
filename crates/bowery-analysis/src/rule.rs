//! Rule pre-filter.
//!
//! Rules are deterministic, fast, suspicion-pattern checks that run before
//! the (expensive) statistical baseline scorer and (very expensive) LLM
//! analyzer. Each Rule examines an Episode and optionally produces a
//! [`RuleHit`] explaining why it fired.
//!
//! Phase 3 ships three rules tuned for the ProcessExec event type:
//! [`ExecFromWritablePathRule`], [`ExecMissingExePathRule`],
//! [`ExecWithSuspiciousArgsRule`]. More land as we get more event types.

use serde::{Deserialize, Serialize};

use crate::episode::Episode;

/// Severity buckets. Used by the response engine to decide how aggressively
/// to gate further actions; not a literal CVSS score. `Deserialize` so
/// operator-configured rules can set it from TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleHit {
    pub rule_id: &'static str,
    pub severity: RuleSeverity,
    pub reason: String,
}

/// A single deterministic check. Implementations are stateless by design.
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn check(&self, episode: &Episode) -> Option<RuleHit>;
}

/// Run every rule against `episode`, collect hits.
pub fn evaluate_all(rules: &[Box<dyn Rule>], episode: &Episode) -> Vec<RuleHit> {
    rules.iter().filter_map(|r| r.check(episode)).collect()
}

// ---------------------------------------------------------------------------
// Built-in rules
// ---------------------------------------------------------------------------

/// Default Phase 3 rule set. Callers can extend or replace this.
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ExecFromWritablePathRule::default()),
        Box::new(ExecMissingExePathRule),
        Box::new(ExecWithSuspiciousArgsRule::default()),
    ]
}

/// Fires when an exec'd binary lives under a path that's commonly
/// world-writable on standard Linux distributions: `/tmp`, `/var/tmp`,
/// `/dev/shm`. Legitimate uses exist (build pipelines, CI) but the signal
/// is high enough to warrant attention from later phases.
#[derive(Debug, Clone)]
pub struct ExecFromWritablePathRule {
    prefixes: Vec<&'static str>,
}

impl Default for ExecFromWritablePathRule {
    fn default() -> Self {
        Self {
            prefixes: vec!["/tmp/", "/var/tmp/", "/dev/shm/"],
        }
    }
}

impl Rule for ExecFromWritablePathRule {
    fn id(&self) -> &'static str {
        "exec_from_writable_path"
    }

    fn check(&self, episode: &Episode) -> Option<RuleHit> {
        let path = episode.root.exe_path.as_deref()?;
        let path_str = path.to_string_lossy();
        let prefix = self.prefixes.iter().find(|p| path_str.starts_with(*p))?;
        Some(RuleHit {
            rule_id: self.id(),
            severity: RuleSeverity::Medium,
            reason: format!("exec from world-writable path {prefix} ({path_str})"),
        })
    }
}

/// Fires when ProcessExec arrives without a resolved exe path. Usually
/// means the kernel-side enrichment couldn't follow `/proc/<pid>/exe` —
/// either because the process exited very quickly, or because it's in a
/// namespace we couldn't traverse. Either case is worth surfacing because
/// it blinds the rest of the pipeline.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecMissingExePathRule;

impl Rule for ExecMissingExePathRule {
    fn id(&self) -> &'static str {
        "exec_missing_exe_path"
    }

    fn check(&self, episode: &Episode) -> Option<RuleHit> {
        if episode.root.exe_path.is_some() {
            return None;
        }
        Some(RuleHit {
            rule_id: self.id(),
            severity: RuleSeverity::Low,
            reason: format!(
                "ProcessExec for pid {} has no exe_path; downstream enrichment will be blind",
                episode.root.pid
            ),
        })
    }
}

/// Fires when argv contains classic foothold patterns: interactive shell
/// (`bash -i`, `sh -i`), reverse shell helpers (`nc -e`, `bash -c '...'`),
/// pipe-to-shell idioms (`curl | sh`).
#[derive(Debug, Clone)]
pub struct ExecWithSuspiciousArgsRule {
    /// Substrings checked against the joined argv. Lowercase comparison.
    needles: Vec<&'static str>,
}

impl Default for ExecWithSuspiciousArgsRule {
    fn default() -> Self {
        Self {
            needles: vec![
                "bash -i",
                "sh -i",
                "/bin/bash -i",
                " -e /bin/sh",
                " -e /bin/bash",
                "curl | sh",
                "wget | sh",
                "curl | bash",
                "wget | bash",
            ],
        }
    }
}

impl Rule for ExecWithSuspiciousArgsRule {
    fn id(&self) -> &'static str {
        "exec_suspicious_args"
    }

    fn check(&self, episode: &Episode) -> Option<RuleHit> {
        if episode.root.args.is_empty() {
            return None;
        }
        let joined = episode.root.args.join(" ").to_lowercase();
        let hit = self.needles.iter().find(|n| joined.contains(*n))?;
        Some(RuleHit {
            rule_id: self.id(),
            severity: RuleSeverity::High,
            reason: format!("suspicious argv pattern: {hit}"),
        })
    }
}

// ---------------------------------------------------------------------------
// Operator-defined rules
// ---------------------------------------------------------------------------

/// An operator-configured process detection (`[monitor] process_rules` in
/// the agent config), layered onto [`default_rules`].
///
/// Every matcher that is `Some` must hit (AND semantics); the agent rejects
/// an all-`None` rule at load so it can never match every exec. Matching is
/// case-sensitive and deliberately simple — prefix on `exe_path`, exact on
/// `comm`, substring on any argv element — so an operator can predict
/// exactly what fires without learning a query language.
///
/// `id` is `&'static str` to satisfy [`RuleHit`]; the agent leaks the
/// configured id once at construction (rules live for the process lifetime).
#[derive(Debug, Clone)]
pub struct OperatorProcessRule {
    id: &'static str,
    exe_prefix: Option<String>,
    comm: Option<String>,
    arg_substr: Option<String>,
    severity: RuleSeverity,
}

impl OperatorProcessRule {
    pub fn new(
        id: &'static str,
        exe_prefix: Option<String>,
        comm: Option<String>,
        arg_substr: Option<String>,
        severity: RuleSeverity,
    ) -> Self {
        Self {
            id,
            exe_prefix,
            comm,
            arg_substr,
            severity,
        }
    }
}

impl Rule for OperatorProcessRule {
    fn id(&self) -> &'static str {
        self.id
    }

    fn check(&self, episode: &Episode) -> Option<RuleHit> {
        let mut why: Vec<String> = Vec::new();

        if let Some(prefix) = &self.exe_prefix {
            let path = episode.root.exe_path.as_deref()?;
            if !path.to_string_lossy().starts_with(prefix.as_str()) {
                return None;
            }
            why.push(format!("exe_prefix={prefix}"));
        }
        if let Some(comm) = &self.comm {
            if episode.root.comm != *comm {
                return None;
            }
            why.push(format!("comm={comm}"));
        }
        if let Some(needle) = &self.arg_substr {
            if !episode
                .root
                .args
                .iter()
                .any(|a| a.contains(needle.as_str()))
            {
                return None;
            }
            why.push(format!("arg_substr={needle}"));
        }

        // An all-`None` rule would match everything; the agent rejects that
        // at config load, but stay defensive here too.
        if why.is_empty() {
            return None;
        }

        Some(RuleHit {
            rule_id: self.id,
            severity: self.severity,
            reason: format!("operator rule matched ({})", why.join(", ")),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::SystemTime;

    use bowery_events::ProcessExec;

    use super::*;

    fn make_exec(args: Vec<&str>, exe: Option<&str>) -> Episode {
        Episode::from_exec(ProcessExec {
            pid: 1234,
            ppid: 1,
            parent_comm: String::new(),
            uid: 1000,
            comm: "x".into(),
            exe_path: exe.map(PathBuf::from),
            args: args.into_iter().map(String::from).collect(),
            ts: SystemTime::UNIX_EPOCH,
        })
    }

    #[test]
    fn writable_path_fires_on_tmp() {
        let r = ExecFromWritablePathRule::default();
        let ep = make_exec(vec!["x"], Some("/tmp/payload"));
        let hit = r.check(&ep).expect("should fire");
        assert_eq!(hit.rule_id, "exec_from_writable_path");
        assert_eq!(hit.severity, RuleSeverity::Medium);
        assert!(hit.reason.contains("/tmp/"));
    }

    #[test]
    fn writable_path_does_not_fire_on_distro_path() {
        let r = ExecFromWritablePathRule::default();
        let ep = make_exec(vec!["x"], Some("/usr/bin/curl"));
        assert!(r.check(&ep).is_none());
    }

    #[test]
    fn missing_exe_path_fires() {
        let r = ExecMissingExePathRule;
        let ep = make_exec(vec!["x"], None);
        let hit = r.check(&ep).expect("should fire");
        assert_eq!(hit.rule_id, "exec_missing_exe_path");
        assert_eq!(hit.severity, RuleSeverity::Low);
    }

    #[test]
    fn missing_exe_path_silent_when_present() {
        let r = ExecMissingExePathRule;
        let ep = make_exec(vec!["x"], Some("/usr/bin/curl"));
        assert!(r.check(&ep).is_none());
    }

    #[test]
    fn suspicious_args_detects_bash_dash_i() {
        let r = ExecWithSuspiciousArgsRule::default();
        let ep = make_exec(vec!["bash", "-i"], Some("/bin/bash"));
        let hit = r.check(&ep).expect("should fire");
        assert_eq!(hit.severity, RuleSeverity::High);
    }

    #[test]
    fn suspicious_args_silent_for_normal_invocation() {
        let r = ExecWithSuspiciousArgsRule::default();
        let ep = make_exec(vec!["curl", "https://example.com/"], Some("/usr/bin/curl"));
        assert!(r.check(&ep).is_none());
    }

    #[test]
    fn evaluate_all_collects_multiple_hits() {
        let rules = default_rules();
        // tmp + suspicious args together
        let ep = make_exec(vec!["bash", "-i"], Some("/tmp/x"));
        let hits = evaluate_all(&rules, &ep);
        assert_eq!(hits.len(), 2);
        let ids: Vec<_> = hits.iter().map(|h| h.rule_id).collect();
        assert!(ids.contains(&"exec_from_writable_path"));
        assert!(ids.contains(&"exec_suspicious_args"));
    }

    fn make_exec_comm(comm: &str, args: Vec<&str>, exe: Option<&str>) -> Episode {
        Episode::from_exec(ProcessExec {
            pid: 42,
            ppid: 1,
            parent_comm: String::new(),
            uid: 1000,
            comm: comm.into(),
            exe_path: exe.map(PathBuf::from),
            args: args.into_iter().map(String::from).collect(),
            ts: SystemTime::UNIX_EPOCH,
        })
    }

    #[test]
    fn operator_rule_matchers_are_anded() {
        // exe_prefix AND comm AND arg_substr — all must hit.
        let r = OperatorProcessRule::new(
            "netcat-exec",
            Some("/usr/bin/nc".to_string()),
            Some("nc".to_string()),
            Some("-e".to_string()),
            RuleSeverity::High,
        );

        let hit = r
            .check(&make_exec_comm(
                "nc",
                vec!["nc", "-e", "/bin/sh"],
                Some("/usr/bin/nc"),
            ))
            .expect("all three matchers hit");
        assert_eq!(hit.rule_id, "netcat-exec");
        assert_eq!(hit.severity, RuleSeverity::High);

        // Each individual mismatch suppresses the hit.
        assert!(
            r.check(&make_exec_comm(
                "nc",
                vec!["nc", "-e"],
                Some("/usr/bin/curl")
            ))
            .is_none(),
            "exe_prefix mismatch must not fire"
        );
        assert!(
            r.check(&make_exec_comm(
                "curl",
                vec!["nc", "-e"],
                Some("/usr/bin/nc")
            ))
            .is_none(),
            "comm mismatch must not fire"
        );
        assert!(
            r.check(&make_exec_comm("nc", vec!["nc", "-l"], Some("/usr/bin/nc")))
                .is_none(),
            "arg_substr mismatch must not fire"
        );
    }

    #[test]
    fn operator_rule_with_single_matcher_fires() {
        let r = OperatorProcessRule::new(
            "any-nc",
            None,
            Some("nc".to_string()),
            None,
            RuleSeverity::Medium,
        );
        let hit = r
            .check(&make_exec_comm("nc", vec!["nc"], Some("/usr/bin/nc")))
            .expect("comm-only rule fires");
        assert_eq!(hit.severity, RuleSeverity::Medium);
        assert!(r.check(&make_exec_comm("ls", vec!["ls"], None)).is_none());
    }

    #[test]
    fn operator_rule_exe_prefix_requires_known_exe_path() {
        // exe_path None must not panic or match an exe_prefix rule.
        let r = OperatorProcessRule::new(
            "exe-only",
            Some("/usr/bin/".to_string()),
            None,
            None,
            RuleSeverity::High,
        );
        assert!(r.check(&make_exec_comm("x", vec!["x"], None)).is_none());
    }
}
