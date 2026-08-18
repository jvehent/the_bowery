//! Telling the fleet a finding is benign.
//!
//! `bowery alerts silence <episode-id>` reads one alert, derives the
//! pattern it stands for, shows what that pattern would have swallowed,
//! and — only after the operator agrees — signs and pushes it.
//!
//! # An episode id is not a pattern
//!
//! `file-cred.read_netrc-1787054761` names one occurrence and will never
//! recur, so silencing it silences nothing. The id is a *handle* on an
//! alert; what gets signed is the triple that alert stands for — its
//! rule, the binary's hash, and the path. Deriving that from something
//! the operator already looked at is the whole point: nobody should be
//! composing match specs by hand for a record that turns detection off.
//!
//! # The blast radius is the safety feature
//!
//! Before anything is signed, the derived spec is run back against the
//! agent's own inbox and the operator is told how many alerts it would
//! have covered, with examples. Signing a silence blind is the mistake
//! this command exists to prevent — a spec one field wider than intended
//! looks identical on the command line and behaves nothing alike.
//!
//! # What it refuses
//!
//! - A spec naming no binary, unless `--any-binary` is passed. A silence
//!   keyed only on a path is inherited by whatever an attacker later
//!   writes there.
//! - A spec that constrains nothing at all, which the agent would refuse
//!   anyway; catching it here saves a round trip and says so plainly.
//! - An expiry beyond a year, or none. An unbounded silence is a
//!   permanent blind spot nobody revisits.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bowery_analysis::silence::SilenceSpec;
use bowery_crypto::Identity;
use bowery_proto::AlertSilence;

use bowery_proto::SqlRow;

use crate::exec::SqlSink;

/// Longest life a silence may be given.
///
/// A year is already long enough that nobody will remember why; beyond
/// it, "temporary" stops being a meaningful word.
// Not a `const`: `from_hours` is what clippy wants here and it is not
// const-stable, so this is a function instead. The cap itself is the
// point, not where it lives.
#[must_use]
pub fn max_lifetime() -> Duration {
    Duration::from_hours(365 * 24)
}

/// A sink that keeps rows instead of printing them.
#[derive(Debug, Default)]
struct Collect {
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl SqlSink for Collect {
    fn header(&mut self, columns: &[String]) {
        if self.columns.is_empty() {
            self.columns = columns.to_vec();
        }
    }

    fn row(&mut self, _columns: &[String], _agent_fp: &[u8], row: &SqlRow) {
        self.rows.push(row.values.iter().map(plain).collect());
    }

    fn finish(&mut self) {}
}

/// A cell's exact text.
///
/// Not `render_value`, which quotes and truncates for a terminal: these
/// values become a match spec, and a hash cut short at 48 characters
/// would silence the wrong thing — or nothing, which is the better of
/// the two failures but still wrong.
fn plain(v: &bowery_proto::SqlValue) -> String {
    use bowery_proto::SqlValueKind as K;
    match &v.value {
        Some(K::Integer(i)) => i.to_string(),
        Some(K::Real(f)) => f.to_string(),
        Some(K::Text(t)) => t.clone(),
        Some(K::Blob(b)) => format!("<{} bytes>", b.len()),
        None => String::new(),
    }
}

impl Collect {
    fn get<'a>(&self, row: &'a [String], column: &str) -> Option<&'a String> {
        let i = self.columns.iter().position(|c| c == column)?;
        row.get(i)
    }
}

/// Where the alert came from and how to reach it.
#[derive(Debug, Clone)]
pub struct Target {
    pub operator_key: PathBuf,
    pub addr: SocketAddr,
    pub fp_hex: String,
    pub pubkey_b64: String,
    pub peer_pubkeys_b64: Vec<String>,
    pub timeout: Duration,
}

/// How wide the operator wants the silence to be.
#[derive(Debug, Clone)]
pub struct Widen {
    /// Cover the rule and binary at any path.
    pub any_path: bool,
    /// Cover the rule and path for any binary. Refused unless set,
    /// because it is the one that can be inherited by an attacker.
    pub any_binary: bool,
    /// Restrict to the host that raised the alert.
    pub this_host_only: bool,
}

/// Derive a silence from one alert, preview it, and push it.
#[allow(clippy::too_many_arguments)]
pub async fn silence_alert(
    target: Target,
    cluster_id: String,
    episode_id: String,
    reason: String,
    weight: f32,
    expires_in: Duration,
    widen: &Widen,
    fanout: bool,
    ttl: u32,
    assume_yes: bool,
) -> Result<()> {
    if reason.trim().is_empty() {
        bail!("--reason is required: a silence with no stated reason is unauditable");
    }
    if !(0.0..=1.0).contains(&weight) {
        bail!("--weight must be between 0.0 (silence) and 1.0 (record only)");
    }
    if expires_in.is_zero() {
        bail!("--expires must be a duration; an unbounded silence is a permanent blind spot");
    }
    if expires_in > max_lifetime() {
        bail!(
            "--expires is capped at 365d; re-issue a silence you still want rather than \
             minting one nobody will revisit"
        );
    }

    // 1. Find the alert the operator is pointing at.
    let alert = fetch_alert(&target, &episode_id).await?;

    // 2. Derive the pattern it stands for.
    let spec = derive_spec(&alert, widen);
    if spec.constrains() == 0 {
        bail!(
            "that would match nothing and everything — widening removed every field. \
             Drop --any-path or --any-binary."
        );
    }
    if !spec.constrains_binary() && !widen.any_binary {
        bail!(
            "this alert carries no binary hash, so the silence would cover whatever \
             later appears at {:?}. Pass --any-binary if that is genuinely what you \
             mean.",
            spec.exe_path
        );
    }

    // 3. Say what it would have swallowed, before anything is signed.
    let radius = blast_radius(&target, &spec).await?;
    print_preview(&spec, &alert, weight, expires_in, &reason, &radius);

    if !assume_yes && !confirm()? {
        println!("nothing signed.");
        return Ok(());
    }

    // 4. Mint, sign, push.
    let identity = Identity::load(&target.operator_key).with_context(|| {
        format!(
            "loading operator key from {}",
            target.operator_key.display()
        )
    })?;
    let silence = mint(&identity, &cluster_id, &spec, weight, &reason, expires_in)?;
    println!("silence {} signed; pushing…", silence.id);
    crate::exec::silence_push(&target, &silence, fanout, ttl).await
}

/// Re-issue a silence at full weight, which stops it suppressing
/// anything without leaving a hole where a record used to be.
#[allow(clippy::too_many_arguments)]
pub async fn unsilence(
    target: Target,
    cluster_id: String,
    spec: SilenceSpec,
    reason: String,
    fanout: bool,
    ttl: u32,
) -> Result<()> {
    let identity = Identity::load(&target.operator_key).with_context(|| {
        format!(
            "loading operator key from {}",
            target.operator_key.display()
        )
    })?;
    // Full weight rather than deletion: agents converge on the newest
    // record for an id, and a *record* saying "no longer suppressed"
    // propagates, where an absence does not.
    let silence = mint(
        &identity,
        &cluster_id,
        &spec,
        1.0,
        &reason,
        Duration::from_hours(24),
    )?;
    println!("revoking silence {}…", silence.id);
    crate::exec::silence_push(&target, &silence, fanout, ttl).await
}

/// The alert fields a silence is derived from.
#[derive(Debug, Clone)]
pub struct AlertRow {
    pub rule_id: String,
    pub exe_sha256_hex: String,
    pub exe_path: String,
    pub host_fp_hex: String,
    pub rationale: String,
}

async fn fetch_alert(target: &Target, episode_id: &str) -> Result<AlertRow> {
    let quoted = episode_id.replace('\'', "''");
    let mut sink = Collect::default();
    crate::exec::sql(
        target.operator_key.clone(),
        target.addr,
        target.fp_hex.clone(),
        target.pubkey_b64.clone(),
        target.peer_pubkeys_b64.clone(),
        format!(
            "SELECT rule_id, exe_sha256_hex, exe_path, originator_fp_hex, rationale \
             FROM bowery_alerts WHERE episode_id = '{quoted}' LIMIT 1"
        ),
        target.timeout,
        false,
        false,
        &mut sink,
    )
    .await
    .context("looking up the alert")?;

    let Some(row) = sink.rows.first() else {
        bail!(
            "no alert with episode id {episode_id:?} on that agent. Inbox retention is \
             finite, so an alert from days ago may simply have rotated out — silence it \
             from a current one, or build the spec by hand."
        );
    };
    Ok(AlertRow {
        rule_id: sink.get(row, "rule_id").cloned().unwrap_or_default(),
        exe_sha256_hex: sink.get(row, "exe_sha256_hex").cloned().unwrap_or_default(),
        exe_path: sink.get(row, "exe_path").cloned().unwrap_or_default(),
        host_fp_hex: sink
            .get(row, "originator_fp_hex")
            .cloned()
            .unwrap_or_default(),
        rationale: sink.get(row, "rationale").cloned().unwrap_or_default(),
    })
}

fn derive_spec(alert: &AlertRow, widen: &Widen) -> SilenceSpec {
    SilenceSpec {
        rule_id: alert.rule_id.clone(),
        exe_sha256_hex: if widen.any_binary {
            String::new()
        } else {
            alert.exe_sha256_hex.clone()
        },
        exe_path: if widen.any_path {
            String::new()
        } else {
            alert.exe_path.clone()
        },
        host_fp_hex: if widen.this_host_only {
            alert.host_fp_hex.clone()
        } else {
            String::new()
        },
    }
}

/// What the derived spec would have covered, from the agent's own inbox.
async fn blast_radius(target: &Target, spec: &SilenceSpec) -> Result<Vec<String>> {
    let mut where_clauses = vec![String::from("1=1")];
    for (column, value) in [
        ("rule_id", &spec.rule_id),
        ("exe_sha256_hex", &spec.exe_sha256_hex),
        ("exe_path", &spec.exe_path),
        ("originator_fp_hex", &spec.host_fp_hex),
    ] {
        if !value.is_empty() {
            where_clauses.push(format!("{column} = '{}'", value.replace('\'', "''")));
        }
    }
    let mut sink = Collect::default();
    crate::exec::sql(
        target.operator_key.clone(),
        target.addr,
        target.fp_hex.clone(),
        target.pubkey_b64.clone(),
        target.peer_pubkeys_b64.clone(),
        format!(
            "SELECT episode_id FROM bowery_alerts WHERE {} ORDER BY ts_unix_ms DESC",
            where_clauses.join(" AND ")
        ),
        target.timeout,
        false,
        false,
        &mut sink,
    )
    .await
    .context("measuring what the silence would cover")?;
    Ok(sink
        .rows
        .iter()
        .filter_map(|r| r.first().cloned())
        .collect())
}

fn print_preview(
    spec: &SilenceSpec,
    alert: &AlertRow,
    weight: f32,
    expires_in: Duration,
    reason: &str,
    radius: &[String],
) {
    println!("\nthis alert:");
    println!("  {}", truncate(&alert.rationale, 100));
    println!("\nwould be silenced by the pattern:");
    println!("  rule       {}", show(&spec.rule_id, "(any rule)"));
    println!(
        "  binary     {}",
        show(&spec.exe_sha256_hex, "(ANY BINARY)")
    );
    println!("  path       {}", show(&spec.exe_path, "(any path)"));
    println!(
        "  host       {}",
        show(&spec.host_fp_hex, "(every host in the mesh)")
    );
    println!(
        "\n  effect     {}",
        if weight <= f32::EPSILON {
            "silenced entirely".to_string()
        } else if (weight - 1.0).abs() < f32::EPSILON {
            "no change to any score; matches are only counted".to_string()
        } else {
            format!("suspicion multiplied by {weight:.2}")
        }
    );
    println!("  expires    in {}", humantime::format_duration(expires_in));
    println!("  reason     {reason}");

    println!(
        "\nit would have covered {} of the alerts currently held by this agent:",
        radius.len()
    );
    for episode in radius.iter().take(5) {
        println!("  {episode}");
    }
    if radius.len() > 5 {
        println!("  … and {} more", radius.len() - 5);
    }
    if radius.is_empty() {
        println!(
            "  (none — the inbox may have rotated, or the pattern is narrower than you meant)"
        );
    }
}

fn show(value: &str, empty: &str) -> String {
    if value.is_empty() {
        empty.to_string()
    } else {
        value.to_string()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}…")
}

fn confirm() -> Result<bool> {
    use std::io::{BufRead as _, Write as _};
    print!("\nsign and push this silence? [y/N] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// Build and sign the record.
fn mint(
    identity: &Identity,
    cluster_id: &str,
    spec: &SilenceSpec,
    weight: f32,
    reason: &str,
    expires_in: Duration,
) -> Result<AlertSilence> {
    let now = now_unix_ms();
    let expires = now.saturating_add(
        u64::try_from(expires_in.as_millis()).context("expiry does not fit in a timestamp")?,
    );
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let weight_permille = (weight.clamp(0.0, 1.0) * 1000.0).round() as u32;

    let mut silence = AlertSilence {
        id: spec.id(cluster_id),
        cluster_id: cluster_id.to_string(),
        rule_id: spec.rule_id.clone(),
        exe_sha256_hex: spec.exe_sha256_hex.clone(),
        exe_path: spec.exe_path.clone(),
        host_fp: decode_hex(&spec.host_fp_hex),
        weight_permille,
        reason: reason.to_string(),
        issued_unix_ms: now,
        expires_unix_ms: expires,
        operator_fp: identity.fingerprint().as_bytes().to_vec(),
        sig: Vec::new(),
    };
    let input = silence
        .to_signing_input()
        .context("building the signing input")?;
    silence.sig = identity.sign(&input).to_bytes().to_vec();
    Ok(silence)
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Peer names, for rendering fan-out reports.
#[must_use]
pub fn agent_names() -> HashMap<String, String> {
    let mut names = HashMap::new();
    if let Ok(path) = crate::peers::default_path()
        && let Ok(manifest) = crate::peers::Manifest::load(&path)
    {
        for peer in &manifest.peers {
            names.insert(peer.fp.to_ascii_lowercase(), peer.name.clone());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert() -> AlertRow {
        AlertRow {
            rule_id: "cred.read_netrc".into(),
            exe_sha256_hex: "8353a512".into(),
            exe_path: "/home/j/.netrc".into(),
            host_fp_hex: "aabb".into(),
            rationale: "credential-access read".into(),
        }
    }

    fn widen() -> Widen {
        Widen {
            any_path: false,
            any_binary: false,
            this_host_only: false,
        }
    }

    /// The default is the narrowest useful spec: exactly what was seen,
    /// everywhere in the mesh.
    #[test]
    fn the_default_spec_is_the_full_triple_fleet_wide() {
        let s = derive_spec(&alert(), &widen());
        assert_eq!(s.rule_id, "cred.read_netrc");
        assert_eq!(s.exe_sha256_hex, "8353a512");
        assert_eq!(s.exe_path, "/home/j/.netrc");
        assert!(s.host_fp_hex.is_empty(), "fleet-wide unless narrowed");
        assert_eq!(s.constrains(), 3);
    }

    #[test]
    fn widening_drops_exactly_the_field_it_names() {
        let any_path = derive_spec(
            &alert(),
            &Widen {
                any_path: true,
                ..widen()
            },
        );
        assert!(any_path.exe_path.is_empty());
        assert_eq!(any_path.exe_sha256_hex, "8353a512");

        let any_binary = derive_spec(
            &alert(),
            &Widen {
                any_binary: true,
                ..widen()
            },
        );
        assert!(any_binary.exe_sha256_hex.is_empty());
        assert_eq!(any_binary.exe_path, "/home/j/.netrc");
    }

    #[test]
    fn narrowing_to_one_host_pins_the_originator() {
        let s = derive_spec(
            &alert(),
            &Widen {
                this_host_only: true,
                ..widen()
            },
        );
        assert_eq!(s.host_fp_hex, "aabb");
        assert_eq!(s.constrains(), 4);
    }

    /// Signing must produce a record the agent will accept: the
    /// signature has to verify over the fields as sent.
    #[test]
    fn a_minted_silence_verifies_under_the_operators_key() {
        let op = Identity::generate();
        let spec = derive_spec(&alert(), &widen());
        let s = mint(&op, "prod", &spec, 0.0, "benign", Duration::from_hours(1)).expect("mints");
        let input = s.to_signing_input().expect("signable");
        let sig: [u8; 64] = s.sig.as_slice().try_into().expect("64 bytes");
        assert!(
            Identity::verify(
                &op.verifying_key(),
                &input,
                &ed25519_dalek::Signature::from_bytes(&sig)
            )
            .is_ok()
        );
        assert!(s.expires_unix_ms > s.issued_unix_ms, "must expire later");
        assert_eq!(s.weight_permille, 0);
    }

    #[test]
    fn weight_maps_onto_permille_without_surprises() {
        let op = Identity::generate();
        let spec = derive_spec(&alert(), &widen());
        for (weight, expected) in [(0.0, 0), (0.3, 300), (0.5, 500), (1.0, 1000)] {
            let s = mint(&op, "prod", &spec, weight, "r", Duration::from_mins(1)).unwrap();
            assert_eq!(s.weight_permille, expected, "weight {weight}");
        }
    }

    /// The same judgement issued twice carries the same id, so it
    /// replaces rather than stacking.
    #[test]
    fn the_id_is_stable_for_the_same_pattern() {
        let op = Identity::generate();
        let spec = derive_spec(&alert(), &widen());
        let a = mint(&op, "prod", &spec, 0.0, "x", Duration::from_mins(1)).unwrap();
        let b = mint(&op, "prod", &spec, 0.5, "y", Duration::from_mins(10)).unwrap();
        assert_eq!(a.id, b.id, "the id covers the pattern, not the weight");
    }

    #[test]
    fn a_host_fingerprint_round_trips_through_hex() {
        assert_eq!(decode_hex("aabb"), vec![0xaa, 0xbb]);
        assert!(decode_hex("").is_empty());
        // Odd length is truncated rather than panicking.
        assert_eq!(decode_hex("aab"), vec![0xaa]);
    }
}
