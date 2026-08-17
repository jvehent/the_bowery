//! `bowery notify` — email an operator who isn't watching.
//!
//! Every alert otherwise waits in a per-agent inbox until somebody runs
//! `bowery alerts` or opens the console. A confirmed lateral-movement
//! finding at 03:00 sits there until morning.
//!
//! This closes that gap without any backend: it drains alerts through
//! the **existing signed `Subscribe` transport**, filters them, and
//! sends one digest email through an SMTP relay the operator already
//! has (Gmail, their own server, anything). Run it from a systemd timer
//! on a box that is always on — the timer holds the CLI open on the
//! operator's behalf, which is the actual requirement.
//!
//! # Why the bridge sends, and not the agents
//!
//! Agents could POST their own alerts to a webhook. They deliberately
//! do not:
//!
//! - **A credential on every monitored host** is a credential every
//!   compromised host has. It lets an attacker flood the operator
//!   (denial of attention, and a way to bury the one alert that
//!   matters), read the secret, or watch for their own detection.
//! - **The bridge only forwards alerts that already verified.** They
//!   arrive in signed envelopes over the operator transport, so nothing
//!   reaches the mailbox without an operator key having authenticated
//!   the source.
//! - **Monitored hosts gain no new egress path.** They keep talking
//!   only to the mesh.
//!
//! # What goes in the message, and what doesn't
//!
//! Alert text is attacker-influenced — an `exe_path` is whatever
//! somebody managed to execute. Two rules follow:
//!
//! - **Nothing attacker-controlled reaches a header.** The subject is
//!   built from host names (which come from the operator's own peer
//!   manifest) and counts. This is what makes header injection
//!   structurally impossible rather than filtered-for.
//! - **Body fields are sanitised and capped.** Control characters
//!   become spaces, lengths are bounded, and the body is `text/plain`
//!   with no HTML, so a crafted `rationale` cannot render as anything
//!   but text.
//!
//! Detail *is* included in the body, unlike the webhook case, and the
//! distinction is deliberate: a webhook body traverses a third-party
//! service and is a plausible exfil channel, whereas this lands in the
//! operator's own mailbox — somewhere the attacker cannot read. The
//! cost of withholding it is an operator woken at 03:00 who cannot
//! triage without a laptop, and that trade is not worth making.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bowery_proto::Alert;
use serde::{Deserialize, Serialize};

use crate::peers::Manifest;
use crate::virustotal::Verdict;

/// SHA-256 (lowercase hex) → what `VirusTotal` said about it.
pub type VerdictMap = std::collections::HashMap<String, Verdict>;

/// Cap on any single field copied into the body.
const FIELD_CAP: usize = 160;
/// Cap on alerts enumerated in one email. Beyond this the digest says
/// how many were omitted — a flood must not become a megabyte message.
const MAX_ENUMERATED: usize = 25;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    pub email: EmailConfig,
    #[serde(default)]
    pub filter: FilterConfig,
    #[serde(default)]
    pub virustotal: VtConfig,
}

/// Optional `VirusTotal` screening, to keep known-clean binaries out of an
/// operator's inbox.
///
/// Off by default, and deliberately: a hash lookup discloses to
/// `VirusTotal` that somebody is investigating that hash, which for a
/// targeted implant is a tip-off to whoever planted it. Turning this on
/// is a judgement an operator makes about their own estate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VtConfig {
    #[serde(default)]
    pub enabled: bool,
    /// File containing only the API key, mode 0600.
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// Drop alerts whose binary no engine flags.
    #[serde(default = "default_true")]
    pub suppress_known_clean: bool,
    /// Ceiling on lookups per run. The public API allows 4 a minute and
    /// 500 a day, so a digest full of new hashes must not try to spend
    /// the quota in one go.
    #[serde(default = "default_vt_max_lookups")]
    pub max_lookups: usize,
    #[serde(default)]
    pub cache_file: Option<PathBuf>,
}

impl Default for VtConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key_file: None,
            suppress_known_clean: true,
            max_lookups: default_vt_max_lookups(),
            cache_file: None,
        }
    }
}

const fn default_vt_max_lookups() -> usize {
    20
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    /// Recipients.
    pub to: Vec<String>,
    /// Envelope sender. With Gmail this must be the authenticated
    /// account, or the message is rewritten or rejected.
    pub from: String,
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    pub username: String,
    /// Path to a file containing only the password, mode 0600.
    ///
    /// A separate file, not an inline string, because this config is
    /// the sort of thing that ends up in a dotfiles repo.
    pub password_file: PathBuf,
    /// STARTTLS on 587 (the default) versus implicit TLS on 465.
    #[serde(default = "default_true")]
    pub starttls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    /// Minimum suspicion to notify about.
    #[serde(default = "default_min_suspicion")]
    pub min_suspicion: f32,
    /// Only alerts a peer quorum confirmed.
    ///
    /// Off by default: confirmation requires mature peers, and a fleet
    /// that cannot yet confirm would silently notify about nothing.
    #[serde(default)]
    pub confirmed_only: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            min_suspicion: default_min_suspicion(),
            confirmed_only: false,
        }
    }
}

const fn default_smtp_port() -> u16 {
    587
}
const fn default_true() -> bool {
    true
}
const fn default_min_suspicion() -> f32 {
    0.9
}

impl NotifyConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading notify config at {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing notify config at {}", path.display()))?;
        if cfg.email.to.is_empty() {
            bail!("notify config has no recipients ([email] to = [...])");
        }
        Ok(cfg)
    }

    /// Read the SMTP password.
    ///
    /// Refuses a file any other user can read. The same reasoning as the
    /// eBPF loader's ownership check: a secret readable by every account
    /// on the box is not a secret, and failing loudly at setup beats
    /// discovering it after a credential is abused.
    pub fn password(&self) -> Result<String> {
        let path = expand_tilde(&self.email.password_file);
        let meta = fs::metadata(&path)
            .with_context(|| format!("reading SMTP password file {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = meta.permissions().mode() & 0o077;
            if mode != 0 {
                bail!(
                    "SMTP password file {} is group/world accessible (mode {:o}); \
                     run: chmod 600 {}",
                    path.display(),
                    meta.permissions().mode() & 0o777,
                    path.display()
                );
            }
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("reading SMTP password file {}", path.display()))?;
        let pw = raw.trim().to_string();
        if pw.is_empty() {
            bail!("SMTP password file {} is empty", path.display());
        }
        Ok(pw)
    }
}

/// Expand a leading `~` — `PathBuf` does not, and every operator writes
/// `~/.bowery/...` in a config file (and in a `--flag` default).
#[must_use]
pub fn expand_tilde(p: &Path) -> PathBuf {
    let Ok(rest) = p.strip_prefix("~") else {
        return p.to_path_buf();
    };
    std::env::var("HOME").map_or_else(|_| p.to_path_buf(), |home| PathBuf::from(home).join(rest))
}

// ---------------------------------------------------------------------------
// Cursors
// ---------------------------------------------------------------------------

/// Per-agent delivery cursor, so a run only reports what is new.
///
/// Keyed by fingerprint rather than name so renaming a host in the
/// manifest cannot silently replay its whole inbox.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Cursors {
    #[serde(default)]
    pub by_fp: BTreeMap<String, u64>,
}

impl Cursors {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading notify cursors at {}", path.display()))?;
        Ok(serde_json::from_str(&raw).unwrap_or_default())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let raw = serde_json::to_string_pretty(self)?;
        fs::write(path, raw)
            .with_context(|| format!("writing notify cursors to {}", path.display()))?;
        Ok(())
    }

    #[must_use]
    pub fn since(&self, fp: &str) -> u64 {
        self.by_fp.get(fp).copied().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Digest composition
// ---------------------------------------------------------------------------

/// One agent's contribution to a digest.
#[derive(Debug, Clone)]
pub struct HostAlerts {
    pub host: String,
    pub alerts: Vec<Alert>,
}

/// Strip anything that could break out of a plain-text line, and bound
/// the length.
///
/// Control characters become spaces — newlines above all, because a
/// value that can inject a line break can forge structure in the body.
#[must_use]
pub fn sanitize(s: &str, cap: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.chars().count() <= cap {
        return trimmed.to_string();
    }
    let kept: String = trimmed.chars().take(cap).collect();
    format!("{kept}…")
}

/// Subject line. Built only from host names and counts — never from
/// alert content, so header injection is impossible by construction
/// rather than by escaping.
#[must_use]
pub fn subject(hosts: &[HostAlerts], vt: &VerdictMap) -> String {
    let total: usize = hosts.iter().map(|h| h.alerts.len()).sum();
    let confirmed: usize = hosts
        .iter()
        .flat_map(|h| &h.alerts)
        .filter(|a| a.confirmation.is_some_and(|c| c.confirmed))
        .count();
    let names: Vec<&str> = hosts
        .iter()
        .filter(|h| !h.alerts.is_empty())
        .map(|h| h.host.as_str())
        .collect();
    let where_ = match names.len() {
        0 => String::new(),
        1 => format!(" on {}", names[0]),
        2 => format!(" on {}, {}", names[0], names[1]),
        n => format!(" on {}, {} +{}", names[0], names[1], n - 2),
    };
    let flagged = hosts
        .iter()
        .flat_map(|h| &h.alerts)
        .filter(|a| {
            vt.get(&a.exe_sha256_hex.to_ascii_lowercase())
                .is_some_and(Verdict::is_malicious)
        })
        .count();
    // A VirusTotal hit is the loudest thing a digest can carry, so it
    // leads the subject rather than hiding in the body.
    let confirmed_note = if flagged > 0 {
        format!(" [{flagged} VT-FLAGGED]")
    } else if confirmed > 0 {
        format!(" [{confirmed} confirmed]")
    } else {
        String::new()
    };
    format!(
        "[bowery] {total} alert{}{}{}",
        if total == 1 { "" } else { "s" },
        where_,
        confirmed_note
    )
}

/// Plain-text digest body.
#[must_use]
pub fn body(hosts: &[HostAlerts], vt: &VerdictMap) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let total: usize = hosts.iter().map(|h| h.alerts.len()).sum();
    let _ = writeln!(out, "{total} new alert(s) from the Bowery mesh.\n");

    for host in hosts.iter().filter(|h| !h.alerts.is_empty()) {
        let _ = writeln!(out, "== {} ({} alert(s))", host.host, host.alerts.len());
        for a in host.alerts.iter().take(MAX_ENUMERATED) {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "  suspicion : {:.2}{}",
                a.suspicion,
                match a.confirmation {
                    Some(c) if c.confirmed => format!(
                        "  CONFIRMED by {}/{} peers with no record of it",
                        c.peers_unseen, c.peers_asked
                    ),
                    Some(c) => format!(
                        "  (not confirmed: {}/{} unseen, {} refused)",
                        c.peers_unseen, c.peers_asked, c.peers_refused
                    ),
                    None => String::new(),
                }
            );
            let _ = writeln!(out, "  episode   : {}", sanitize(&a.episode_id, FIELD_CAP));
            if !a.exe_path.is_empty() {
                let _ = writeln!(out, "  exe       : {}", sanitize(&a.exe_path, FIELD_CAP));
            }
            if !a.exe_sha256_hex.is_empty() {
                let _ = writeln!(
                    out,
                    "  sha256    : {}",
                    sanitize(&a.exe_sha256_hex, FIELD_CAP)
                );
            }
            let _ = writeln!(out, "  why       : {}", sanitize(&a.rationale, FIELD_CAP));
            // Per alert, not just as a digest total: an operator triaging
            // one finding needs the verdict for *that* binary.
            if let Some(v) = vt.get(&a.exe_sha256_hex.to_ascii_lowercase()) {
                let _ = writeln!(out, "  vt        : {}", v.summary());
            }
        }
        if host.alerts.len() > MAX_ENUMERATED {
            let _ = writeln!(
                out,
                "\n  … and {} more, not listed.",
                host.alerts.len() - MAX_ENUMERATED
            );
        }
        let _ = writeln!(out);
    }

    out.push_str(
        "\n--\nFields above come from the monitored host and are\n\
         attacker-influenceable; treat them as leads, not facts.\n\
         Verify against the signed source:\n\
         \n  bowery alerts tail --agent-addr <addr> --agent-fp <fp> …\n\
         \nSent by `bowery notify`. Nothing was stored off-host.\n",
    );
    out
}

/// Collapse alerts that supersede each other, keeping the newest.
///
/// An episode legitimately produces several alerts: the pre-filter
/// raises one, the LLM refines it, a whisper quorum confirms it. Each
/// later one *replaces* its predecessor — the inbox has no update path,
/// so superseding is how a verdict changes. The console already collapses
/// them; without the same rule here, every email reports each finding two
/// or three times and an operator learns to skim.
///
/// An empty `episode_id` is never an identity: those alerts are distinct
/// events that happen to lack an id, and folding them together would
/// silently drop findings.
#[must_use]
pub fn dedup_by_episode(alerts: Vec<Alert>) -> Vec<Alert> {
    let mut newest: BTreeMap<String, Alert> = BTreeMap::new();
    let mut unkeyed: Vec<Alert> = Vec::new();
    for a in alerts {
        if a.episode_id.is_empty() {
            unkeyed.push(a);
            continue;
        }
        match newest.get(&a.episode_id) {
            Some(prev) if prev.ts_unix_ms >= a.ts_unix_ms => {}
            _ => {
                newest.insert(a.episode_id.clone(), a);
            }
        }
    }
    let mut out: Vec<Alert> = newest.into_values().chain(unkeyed).collect();
    // Most suspicious first: an operator reading on a phone sees the
    // worst thing without scrolling.
    out.sort_by(|a, b| {
        b.suspicion
            .partial_cmp(&a.suspicion)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.ts_unix_ms.cmp(&a.ts_unix_ms))
    });
    out
}

/// What `VirusTotal` screening did to a digest.
///
/// Reported in the email itself. A filter that silently removes alerts
/// is indistinguishable from one that is broken, and this one removes
/// alerts on the word of a third party — so the operator is told how
/// many, and that they can be read in full with `bowery alerts`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct VtOutcome {
    pub looked_up: usize,
    pub suppressed: usize,
    pub flagged: usize,
    /// Hashes `VirusTotal` has never seen. Not reassuring, and counted
    /// separately so a digest cannot imply otherwise.
    pub unknown: usize,
    /// Lookups that could not be made — no key, quota spent, API down.
    /// These suppress nothing, and their count is stated so an operator
    /// can tell "nothing was malicious" from "nothing was checked".
    pub unavailable: usize,
}

impl VtOutcome {
    #[must_use]
    pub fn line(&self) -> Option<String> {
        use std::fmt::Write as _;

        if self.looked_up == 0 {
            return None;
        }
        let mut s = format!("VirusTotal: {} hash(es) checked", self.looked_up);
        if self.flagged > 0 {
            let _ = write!(s, ", {} FLAGGED", self.flagged);
        }
        if self.unknown > 0 {
            // Without this, "2 checked" and nothing else reads as
            // "checked and fine", when it may mean VT has never seen
            // either hash — which is not reassurance.
            let _ = write!(s, ", {} unknown to VT", self.unknown);
        }
        if self.suppressed > 0 {
            let _ = write!(s, ", {} alert(s) held back as known-clean", self.suppressed);
        }
        if self.unavailable > 0 {
            let _ = write!(
                s,
                ", {} could not be checked (sent anyway)",
                self.unavailable
            );
        }
        Some(s)
    }
}

/// Decide an alert's fate given a `VirusTotal` verdict.
///
/// The safety property, stated as code: an alert is dropped **only** on
/// a positive clean verdict, and only when the operator asked for that.
/// Every other outcome — unknown hash, missing key, rate limit, network
/// failure — keeps the alert. A monitoring system must not fall silent
/// because a third-party API had a bad day.
#[must_use]
pub fn vt_decision(verdict: &crate::virustotal::Verdict, suppress_known_clean: bool) -> bool {
    if verdict.may_suppress() && suppress_known_clean {
        return false; // drop it
    }
    true // keep it
}

/// Does this alert clear the operator's filter?
#[must_use]
pub fn passes(alert: &Alert, filter: &FilterConfig) -> bool {
    if alert.suspicion < filter.min_suspicion {
        return false;
    }
    if filter.confirmed_only && !alert.confirmation.is_some_and(|c| c.confirmed) {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RunArgs {
    pub operator_key: PathBuf,
    pub config_path: PathBuf,
    pub manifest_path: PathBuf,
    pub cursor_path: PathBuf,
    pub dry_run: bool,
}

/// Poll every agent in the manifest, and email whatever is new.
///
/// # Errors
///
/// Any failure to load config, or to send. Polling failures for an
/// individual agent are reported and skipped — one unreachable host
/// must not suppress alerts from the rest of the fleet, which is
/// precisely when you most want the mail to arrive.
pub async fn run(args: &RunArgs) -> Result<()> {
    let cfg = NotifyConfig::load(&args.config_path)?;
    let manifest = Manifest::load(&args.manifest_path)?;
    let mut cursors = Cursors::load(&args.cursor_path)?;

    if manifest.peers.is_empty() {
        bail!(
            "peer manifest {} is empty; add agents with `bowery peers add`",
            args.manifest_path.display()
        );
    }

    let mut hosts: Vec<HostAlerts> = Vec::new();
    let mut advanced: BTreeMap<String, u64> = BTreeMap::new();
    let mut poll_failures = 0usize;

    for peer in &manifest.peers {
        let Some(addr_str) = peer.addr.as_deref() else {
            continue; // fan-out-only entry, nothing to dial
        };
        let addr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("notify: peer {} has an unusable addr: {e}", peer.name);
                poll_failures += 1;
                continue;
            }
        };
        let since = cursors.since(&peer.fp);
        match crate::alerts::poll_once(&args.operator_key, addr, &peer.fp, &peer.pubkey_b64, since)
            .await
        {
            Ok((alerts, cursor)) => {
                let kept: Vec<Alert> = dedup_by_episode(
                    alerts
                        .into_iter()
                        .filter(|a| passes(a, &cfg.filter))
                        .collect(),
                );
                advanced.insert(peer.fp.clone(), cursor);
                if !kept.is_empty() {
                    hosts.push(HostAlerts {
                        host: peer.name.clone(),
                        alerts: kept,
                    });
                }
            }
            Err(e) => {
                eprintln!("notify: polling {} failed: {e}", peer.name);
                poll_failures += 1;
            }
        }
    }

    if hosts.is_empty() {
        // Still advance cursors: alerts below the filter were seen and
        // consciously skipped, and replaying them next run would mean
        // the filter never takes effect.
        for (fp, cursor) in advanced {
            cursors.by_fp.insert(fp, cursor);
        }
        cursors.save(&args.cursor_path)?;
        if poll_failures > 0 {
            bail!("no alerts to send, but {poll_failures} agent(s) could not be polled");
        }
        return Ok(());
    }

    // VirusTotal screening. Only ever removes alerts on a positive
    // clean verdict; a missing key, a spent quota or an API outage
    // leaves the digest exactly as it was.
    let (vt, verdicts) = screen_with_virustotal(&cfg, &mut hosts).await;
    if hosts.iter().all(|h| h.alerts.is_empty()) {
        for (fp, cursor) in advanced {
            cursors.by_fp.insert(fp, cursor);
        }
        cursors.save(&args.cursor_path)?;
        if let Some(line) = vt.line() {
            println!("notify: nothing to send — {line}");
        }
        return Ok(());
    }

    let subject = subject(&hosts, &verdicts);
    let body = format!(
        "{}{}",
        body(&hosts, &verdicts),
        vt.line()
            .map(|l| format!("\n{l}\nHeld-back alerts remain readable with `bowery alerts`.\n"))
            .unwrap_or_default()
    );

    if args.dry_run {
        println!("--- would send ---");
        println!("To: {}", cfg.email.to.join(", "));
        println!("Subject: {subject}");
        println!("\n{body}");
        println!("--- cursors NOT advanced (dry run) ---");
        return Ok(());
    }

    send_email(&cfg, &subject, &body).await?;

    // Only now. A cursor advanced before a successful send would drop
    // the alerts on the floor: the inbox has already handed them over,
    // and nothing re-delivers.
    for (fp, cursor) in advanced {
        cursors.by_fp.insert(fp, cursor);
    }
    cursors.save(&args.cursor_path)?;

    let total: usize = hosts.iter().map(|h| h.alerts.len()).sum();
    println!("notify: emailed {total} alert(s) to {}", cfg.email.to.len());
    if poll_failures > 0 {
        bail!("sent, but {poll_failures} agent(s) could not be polled");
    }
    Ok(())
}

/// Look up each alert's binary and drop the ones no engine flags.
///
/// Returns what happened, for the digest to report. Never returns an
/// error: a failure here must leave the alerts alone rather than
/// abort the run.
async fn screen_with_virustotal(
    cfg: &NotifyConfig,
    hosts: &mut [HostAlerts],
) -> (VtOutcome, VerdictMap) {
    use crate::virustotal::{VtCache, VtClient, default_cache_path, now_unix_s, read_api_key};

    let mut outcome = VtOutcome::default();
    let mut verdicts = VerdictMap::new();
    if !cfg.virustotal.enabled {
        return (outcome, verdicts);
    }
    let Some(key_path) = cfg.virustotal.api_key_file.as_ref() else {
        eprintln!("notify: [virustotal] enabled but no api_key_file; skipping screening");
        return (outcome, verdicts);
    };
    let key = match read_api_key(&expand_tilde(key_path)) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("notify: VirusTotal key unusable ({e}); sending unscreened");
            return (outcome, verdicts);
        }
    };
    let Ok(client) = VtClient::new(key) else {
        eprintln!("notify: could not build the VirusTotal client; sending unscreened");
        return (outcome, verdicts);
    };

    let cache_path = cfg
        .virustotal
        .cache_file
        .clone()
        .map_or_else(default_cache_path, |p| expand_tilde(&p));
    let mut cache = VtCache::load(&cache_path);
    let now = now_unix_s();
    let mut budget = cfg.virustotal.max_lookups;

    for host in hosts.iter_mut() {
        let mut kept: Vec<Alert> = Vec::with_capacity(host.alerts.len());
        for alert in std::mem::take(&mut host.alerts) {
            if alert.exe_sha256_hex.is_empty() {
                kept.push(alert);
                continue;
            }
            let verdict = if let Some(v) = cache.get(&alert.exe_sha256_hex, now) {
                v
            } else if budget == 0 {
                // Out of budget is not a clean bill of health.
                outcome.unavailable += 1;
                kept.push(alert);
                continue;
            } else {
                budget -= 1;
                let v = client.lookup(&alert.exe_sha256_hex).await;
                cache.put(&alert.exe_sha256_hex, &v, now);
                v
            };
            outcome.looked_up += 1;
            if verdict.is_malicious() {
                outcome.flagged += 1;
            }
            match &verdict {
                Verdict::Unavailable(_) => outcome.unavailable += 1,
                Verdict::Unknown => outcome.unknown += 1,
                _ => {}
            }
            verdicts.insert(alert.exe_sha256_hex.to_ascii_lowercase(), verdict.clone());
            if vt_decision(&verdict, cfg.virustotal.suppress_known_clean) {
                kept.push(alert);
            } else {
                outcome.suppressed += 1;
            }
        }
        // A VirusTotal hit leads the host's list. An operator reading
        // on a phone should not have to scroll past clean findings to
        // reach the one an engine flagged.
        kept.sort_by_key(|a| {
            !verdicts
                .get(&a.exe_sha256_hex.to_ascii_lowercase())
                .is_some_and(Verdict::is_malicious)
        });
        host.alerts = kept;
    }
    if let Err(e) = cache.save(&cache_path) {
        eprintln!("notify: could not save the VirusTotal cache: {e}");
    }
    (outcome, verdicts)
}

async fn send_email(cfg: &NotifyConfig, subject: &str, body: &str) -> Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header};

    let password = cfg.password()?;

    let mut builder = Message::builder()
        .from(
            cfg.email
                .from
                .parse()
                .with_context(|| format!("parsing [email] from = {:?}", cfg.email.from))?,
        )
        .subject(subject)
        .header(header::ContentType::TEXT_PLAIN);
    for to in &cfg.email.to {
        builder = builder.to(to
            .parse()
            .with_context(|| format!("parsing recipient {to:?}"))?);
    }
    let email = builder.body(body.to_string())?;

    let creds = Credentials::new(cfg.email.username.clone(), password);
    let transport: AsyncSmtpTransport<Tokio1Executor> = if cfg.email.starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.email.smtp_host)
            .with_context(|| format!("configuring STARTTLS relay {}", cfg.email.smtp_host))?
            .port(cfg.email.smtp_port)
            .credentials(creds)
            .build()
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.email.smtp_host)
            .with_context(|| format!("configuring TLS relay {}", cfg.email.smtp_host))?
            .port(cfg.email.smtp_port)
            .credentials(creds)
            .build()
    };

    // The error is deliberately not wrapped with the credential in
    // scope; lettre's SMTP errors carry server text, never the password.
    if let Err(e) = transport.send(email).await {
        let text = e.to_string();
        let hint = auth_hint(&text)
            .map(|h| format!("\n\nhint: {h}"))
            .unwrap_or_default();
        bail!(
            "sending via {}:{}: {text}{hint}",
            cfg.email.smtp_host,
            cfg.email.smtp_port
        );
    }
    Ok(())
}

/// Turn an SMTP rejection into something an operator can act on.
///
/// Authentication is where first runs fail, and the server's own text —
/// "Application-specific password required", say — assumes you already
/// know what that means and where to get one. Matched on response text
/// rather than a typed error because the useful distinctions live in the
/// enhanced status codes, which the SMTP crate does not model.
#[must_use]
pub fn auth_hint(err_text: &str) -> Option<&'static str> {
    let t = err_text.to_ascii_lowercase();
    if t.contains("application-specific password") || t.contains("invalidsecondfactor") {
        return Some(
            "Gmail rejects account passwords over SMTP. Create an App Password \
             (which requires 2-Step Verification on the account) at \
             https://myaccount.google.com/apppasswords — it is 16 lowercase \
             letters shown as 4 groups of 4. Store it WITHOUT the spaces in the \
             file named by [email] password_file.",
        );
    }
    if t.contains("username and password not accepted")
        || t.contains("invalid login")
        || t.contains("535")
    {
        return Some(
            "The relay rejected the credential. Check that [email] username is \
             the mailbox owning the password, and that the password file holds \
             only the password — no quotes, no comment, no trailing text.",
        );
    }
    if t.contains("must issue a starttls command") {
        return Some("The relay wants STARTTLS: set [email] starttls = true (port 587).");
    }
    if t.contains("wrong version number") || t.contains("record overflow") {
        return Some(
            "TLS failed in the way a port/mode mismatch usually looks: use \
             starttls = true with port 587, or starttls = false with port 465.",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_proto::AlertConfirmation;

    fn alert(episode: &str, suspicion: f32, confirmed: bool) -> Alert {
        Alert {
            originator_fp: vec![0xab; 32],
            episode_id: episode.into(),
            exe_sha256_hex: "ab".repeat(32),
            exe_path: "/tmp/payload".into(),
            suspicion,
            rationale: "exec from world-writable path".into(),
            suggested_actions: vec![],
            ts_unix_ms: 1_700_000_000_000,
            backend: "test".into(),
            confirmation: confirmed.then_some(AlertConfirmation {
                peers_asked: 3,
                peers_unseen: 3,
                peers_seen: 0,
                peers_no_reply: 0,
                peers_refused: 0,
                quorum: 2,
                confirmed: true,
            }),
        }
    }

    #[test]
    fn sanitize_strips_newlines_and_controls() {
        // A rationale that can inject a line break can forge structure
        // in the body — a fake "== otherhost" section, say.
        let nasty = "line one\nline two\r\n== fake-host (99 alerts)\ttab";
        let clean = sanitize(nasty, 200);
        assert!(!clean.contains('\n'), "{clean}");
        assert!(!clean.contains('\r'), "{clean}");
        assert!(!clean.contains('\t'), "{clean}");
        assert!(
            clean.contains("fake-host"),
            "content is kept, just flattened"
        );
    }

    #[test]
    fn sanitize_caps_length() {
        let long = "a".repeat(5000);
        let clean = sanitize(&long, 160);
        assert_eq!(clean.chars().count(), 161, "160 + ellipsis");
    }

    #[test]
    fn sanitize_is_utf8_safe_at_the_boundary() {
        // Truncating by bytes would split a multi-byte char and panic.
        let s = "é".repeat(300);
        let clean = sanitize(&s, 10);
        assert_eq!(clean.chars().count(), 11);
    }

    #[test]
    fn subject_never_contains_alert_text() {
        // The one rule that makes header injection structurally
        // impossible: the subject is built from manifest host names and
        // counts, never from anything the monitored host said.
        let hosts = vec![HostAlerts {
            host: "otter1".into(),
            alerts: vec![alert("ep-1\nSubject: spoofed", 0.99, true)],
        }];
        let s = subject(&hosts, &VerdictMap::new());
        assert!(!s.contains('\n'));
        assert!(!s.contains("spoofed"), "{s}");
        assert!(s.contains("otter1"));
        assert!(s.contains("1 alert"));
        assert!(s.contains("[1 confirmed]"), "{s}");
    }

    #[test]
    fn subject_summarises_many_hosts() {
        let hosts: Vec<HostAlerts> = ["a", "b", "c", "d"]
            .iter()
            .map(|h| HostAlerts {
                host: (*h).to_string(),
                alerts: vec![alert("ep", 0.95, false)],
            })
            .collect();
        let s = subject(&hosts, &VerdictMap::new());
        assert!(s.contains("4 alerts"), "{s}");
        assert!(s.contains("+2"), "{s}");
    }

    #[test]
    fn body_lists_detail_and_flags_it_as_untrusted() {
        let hosts = vec![HostAlerts {
            host: "otter1".into(),
            alerts: vec![alert("ep-1", 0.99, true)],
        }];
        let b = body(&hosts, &VerdictMap::new());
        assert!(
            b.contains("/tmp/payload"),
            "operator needs the path to triage"
        );
        assert!(b.contains("CONFIRMED by 3/3"));
        // The reader must be told the content is not authenticated.
        assert!(b.contains("attacker-influenceable"), "{b}");
        assert!(b.contains("bowery alerts tail"), "and how to verify");
    }

    #[test]
    fn body_truncates_a_flood_rather_than_growing_without_bound() {
        let alerts: Vec<Alert> = (0..500)
            .map(|i| alert(&format!("ep-{i}"), 0.99, false))
            .collect();
        let hosts = vec![HostAlerts {
            host: "noisy".into(),
            alerts,
        }];
        let b = body(&hosts, &VerdictMap::new());
        assert!(b.contains("and 475 more"), "{}", &b[b.len() - 400..]);
        assert!(
            b.len() < 100_000,
            "digest stayed bounded: {} bytes",
            b.len()
        );
    }

    #[test]
    fn supersedes_collapse_to_the_newest_alert_for_an_episode() {
        // Observed live: a dry run against the real fleet reported every
        // episode twice — the pre-filter alert and its LLM-refined
        // supersession — because only the console was deduping.
        let mut first = alert("ep-1", 1.0, false);
        first.ts_unix_ms = 100;
        first.rationale = "pre-filter score above threshold".into();
        let mut refined = alert("ep-1", 0.89, false);
        refined.ts_unix_ms = 200;
        refined.rationale = "mock backend echoing pre-filter".into();

        let out = dedup_by_episode(vec![first, refined]);
        assert_eq!(out.len(), 1, "one episode is one finding");
        assert_eq!(out[0].rationale, "mock backend echoing pre-filter");
        assert_eq!(out[0].ts_unix_ms, 200, "the newest wins, not the loudest");
    }

    #[test]
    fn dedup_orders_by_suspicion_and_keeps_unkeyed_alerts() {
        let mut low = alert("ep-low", 0.5, false);
        low.ts_unix_ms = 1;
        let mut high = alert("ep-high", 0.99, false);
        high.ts_unix_ms = 2;
        let mut anon = alert("", 0.7, false);
        anon.ts_unix_ms = 3;
        let mut anon2 = alert("", 0.7, false);
        anon2.ts_unix_ms = 4;

        let out = dedup_by_episode(vec![low, high, anon, anon2]);
        assert_eq!(out.len(), 4, "an empty episode_id is not an identity");
        assert!(
            (out[0].suspicion - 0.99).abs() < f32::EPSILON,
            "worst first, so a phone screen shows it"
        );
    }

    #[test]
    fn a_flagged_hash_is_shown_per_alert_and_leads_the_subject() {
        // The digest previously reported only a total ("2 hash(es)
        // checked"), which told an operator nothing about any specific
        // finding — and a VirusTotal hit had no more prominence than a
        // clean one.
        let a = alert("ep-1", 0.95, false);
        let sha = a.exe_sha256_hex.to_ascii_lowercase();
        let hosts = vec![HostAlerts {
            host: "web-1".into(),
            alerts: vec![a],
        }];
        let mut vt = VerdictMap::new();
        vt.insert(
            sha,
            Verdict::Malicious {
                malicious: 41,
                total: 62,
            },
        );

        let b = body(&hosts, &vt);
        assert!(b.contains("41/62"), "the verdict belongs on the alert: {b}");
        let s = subject(&hosts, &vt);
        assert!(s.contains("VT-FLAGGED"), "{s}");
    }

    #[test]
    fn an_unknown_hash_is_counted_so_the_total_is_not_misread() {
        // "2 checked" with nothing else reads as "checked and fine",
        // when it may mean VT has never seen either hash.
        let outcome = VtOutcome {
            looked_up: 2,
            unknown: 2,
            ..VtOutcome::default()
        };
        let line = outcome.line().unwrap();
        assert!(line.contains("2 unknown to VT"), "{line}");
    }

    #[test]
    fn filter_respects_suspicion_and_confirmation() {
        let strict = FilterConfig {
            min_suspicion: 0.9,
            confirmed_only: true,
        };
        assert!(passes(&alert("a", 0.95, true), &strict));
        assert!(!passes(&alert("b", 0.95, false), &strict), "unconfirmed");
        assert!(!passes(&alert("c", 0.5, true), &strict), "below threshold");

        let loose = FilterConfig {
            min_suspicion: 0.9,
            confirmed_only: false,
        };
        assert!(passes(&alert("d", 0.95, false), &loose));
    }

    #[test]
    fn the_gmail_first_run_failure_explains_itself() {
        // Verbatim from a real first run against smtp.gmail.com. The
        // server's wording says nothing about where to get an app
        // password, or that it requires 2FA to exist at all.
        let real = "permanent error (534): 5.7.9 Application-specific password required. \
                    For more information, go to \
                    https://support.google.com/mail/?p=InvalidSecondFactor - gsmtp";
        let hint = auth_hint(real).expect("THE first-run failure must explain itself");
        assert!(hint.contains("apppasswords"), "points at where to get one");
        assert!(hint.contains("2-Step"), "and what it requires first");
        assert!(
            hint.contains("WITHOUT the spaces"),
            "and the formatting trap"
        );
    }

    #[test]
    fn generic_auth_and_tls_failures_are_recognised() {
        assert!(auth_hint("535 5.7.8 Username and Password not accepted").is_some());
        assert!(auth_hint("Must issue a STARTTLS command first").is_some());
        assert!(auth_hint("tls handshake: wrong version number").is_some());
        // Not every failure has advice; inventing some is worse than the
        // server's own text.
        assert!(auth_hint("452 4.2.2 mailbox full").is_none());
    }

    #[test]
    fn cursors_round_trip_and_default_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursors.json");
        let mut c = Cursors::load(&path).unwrap();
        assert_eq!(c.since("deadbeef"), 0, "unknown agent starts at zero");
        c.by_fp.insert("deadbeef".into(), 42);
        c.save(&path).unwrap();
        let reloaded = Cursors::load(&path).unwrap();
        assert_eq!(reloaded.since("deadbeef"), 42);
    }

    #[test]
    fn a_corrupt_cursor_file_does_not_replay_forever_or_crash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursors.json");
        fs::write(&path, "{ not json").unwrap();
        // Degrades to "start from zero" rather than failing the run —
        // a re-send is recoverable, a notifier that refuses to start is
        // silence.
        assert_eq!(Cursors::load(&path).unwrap().since("x"), 0);
    }

    #[test]
    fn config_parses_the_documented_gmail_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.toml");
        fs::write(
            &path,
            r#"
[email]
to            = ["julien.vehent@gmail.com"]
from          = "julien.vehent@gmail.com"
smtp_host     = "smtp.gmail.com"
smtp_port     = 587
username      = "julien.vehent@gmail.com"
password_file = "~/.bowery/smtp-password"
starttls      = true

[filter]
min_suspicion  = 0.9
confirmed_only = false
"#,
        )
        .unwrap();
        let cfg = NotifyConfig::load(&path).expect("documented config must parse");
        assert_eq!(cfg.email.smtp_host, "smtp.gmail.com");
        assert_eq!(cfg.email.smtp_port, 587);
        assert!(cfg.email.starttls);
        assert!((cfg.filter.min_suspicion - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn config_without_recipients_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.toml");
        fs::write(
            &path,
            r#"
[email]
to = []
from = "a@b.c"
smtp_host = "smtp.example.com"
username = "a@b.c"
password_file = "/dev/null"
"#,
        )
        .unwrap();
        // A notifier that sends to nobody is the failure mode this whole
        // feature exists to prevent.
        assert!(NotifyConfig::load(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_password_file_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let pw = dir.path().join("smtp-password");
        fs::write(&pw, "hunter2").unwrap();
        fs::set_permissions(&pw, fs::Permissions::from_mode(0o644)).unwrap();

        let cfg = NotifyConfig {
            email: EmailConfig {
                to: vec!["a@b.c".into()],
                from: "a@b.c".into(),
                smtp_host: "smtp.example.com".into(),
                smtp_port: 587,
                username: "a@b.c".into(),
                password_file: pw.clone(),
                starttls: true,
            },
            filter: FilterConfig::default(),
            virustotal: VtConfig::default(),
        };
        let err = cfg.password().unwrap_err().to_string();
        assert!(err.contains("group/world accessible"), "{err}");

        fs::set_permissions(&pw, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(cfg.password().unwrap(), "hunter2");
    }
}
