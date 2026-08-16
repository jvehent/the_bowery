//! VirusTotal lookups, for `bowery vt` and the `bowery notify` filter.
//!
//! # Operator-side only, and deliberately
//!
//! Agents never call this. Three reasons, and the first is the one that
//! matters:
//!
//! **A hash lookup is disclosure.** Querying VirusTotal tells VirusTotal
//! — and anyone with Intelligence access — that somebody is looking at
//! that hash. Adversaries monitor VT for their own samples, so an
//! automatic lookup from a compromised host is a tip-off that you have
//! found the implant, sent before you have decided what to do about it.
//! That is a judgement call an operator makes, not a reflex an agent
//! performs on every unpackaged binary.
//!
//! Secondly, an API key on every monitored host is a key every
//! compromised host has. Thirdly, the public API allows 4 requests a
//! minute; one busy host's first-exec stream would exhaust the daily
//! quota before lunch.
//!
//! Hashes only — no file is ever uploaded. A lookup reveals that you
//! are interested in a hash; it does not hand over the sample.
//!
//! # The rule that governs suppression
//!
//! **A lookup may only ever suppress on a positive clean signal, and it
//! must fail open.** If the API is down, the key is missing, the quota
//! is spent, or the response is unparseable, every alert goes out
//! unchanged. An outage that silences alerts would be far worse than the
//! false positives this is meant to reduce — that is a monitoring system
//! failing in the one direction it must not.
//!
//! [`Verdict`] encodes that: only [`Verdict::Clean`] can suppress, and
//! it is reachable only from a successful, parsed response.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// What VirusTotal knows about a hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// At least one engine flags it. Never suppressed — escalated.
    Malicious { malicious: u32, total: u32 },
    /// VT has analysed it and no engine flags it.
    ///
    /// The only verdict that may suppress an alert, and still not proof
    /// of innocence: a freshly built implant is unknown to every engine.
    /// It means "the industry has looked at this and says nothing",
    /// which is a reasonable bar for *not paging someone at 03:00* and
    /// no bar at all for concluding a host is healthy.
    Clean { total: u32 },
    /// VT has never seen this hash. Notable in itself for a binary that
    /// claims to be common, and never a reason to suppress.
    Unknown,
    /// The question could not be asked. Carries why, and suppresses
    /// nothing.
    Unavailable(String),
}

impl Verdict {
    /// May an alert be dropped on the strength of this?
    ///
    /// Only a positive clean result. Everything else — unknown, error,
    /// rate limit, missing key — leaves the alert alone.
    #[must_use]
    pub fn may_suppress(&self) -> bool {
        matches!(self, Self::Clean { .. })
    }

    #[must_use]
    pub fn is_malicious(&self) -> bool {
        matches!(self, Self::Malicious { .. })
    }

    /// One line for an email or a terminal.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Malicious { malicious, total } => {
                format!("VirusTotal: {malicious}/{total} engines flag this")
            }
            Self::Clean { total } => format!("VirusTotal: 0/{total} engines flag this"),
            Self::Unknown => "VirusTotal: hash unknown to VT".to_string(),
            Self::Unavailable(why) => format!("VirusTotal: not checked ({why})"),
        }
    }
}

/// Parse a `/api/v3/files/{sha}` body into a verdict.
///
/// Split out from the HTTP so the mapping — especially "anything I
/// cannot parse is Unavailable, never Clean" — is testable without a
/// network or a key.
#[must_use]
pub fn parse_verdict(body: &str) -> Verdict {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return Verdict::Unavailable("unparseable response".into());
    };
    let Some(stats) = json
        .get("data")
        .and_then(|d| d.get("attributes"))
        .and_then(|a| a.get("last_analysis_stats"))
    else {
        return Verdict::Unavailable("response had no analysis stats".into());
    };
    let get = |k: &str| stats.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
    let malicious = u32::try_from(get("malicious")).unwrap_or(u32::MAX);
    let suspicious = u32::try_from(get("suspicious")).unwrap_or(0);
    let total = u32::try_from(
        get("malicious") + get("suspicious") + get("undetected") + get("harmless"),
    )
    .unwrap_or(u32::MAX);

    // No engine has an opinion at all. Treated as "cannot say" rather
    // than clean: a zero-engine result is a response we do not
    // understand, and understanding it wrongly would suppress an alert.
    if total == 0 {
        return Verdict::Unavailable("no engine results in response".into());
    }
    // `suspicious` counts toward malicious. An engine hedging is still
    // an engine saying something, and this is the direction to err in.
    if malicious + suspicious > 0 {
        return Verdict::Malicious {
            malicious: malicious + suspicious,
            total,
        };
    }
    Verdict::Clean { total }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    verdict: Verdict,
    fetched_unix_s: u64,
}

/// Persistent hash → verdict memo.
///
/// Not an optimisation so much as a quota strategy: the public API
/// allows 4 requests a minute and 500 a day, and a fleet re-running the
/// same binaries would spend that on questions already answered. Only
/// *answers* are cached — an `Unavailable` is a failure to ask, and
/// caching it would turn one outage into a lasting blind spot.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VtCache {
    #[serde(default)]
    by_sha: BTreeMap<String, CacheEntry>,
}

/// How long a verdict is reused. Engines do add detections for a hash
/// they once called clean, so this is a week rather than forever.
pub const CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

impl VtCache {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing VT cache to {}", path.display()))?;
        Ok(())
    }

    #[must_use]
    pub fn get(&self, sha: &str, now_unix_s: u64) -> Option<Verdict> {
        let entry = self.by_sha.get(&sha.to_ascii_lowercase())?;
        if now_unix_s.saturating_sub(entry.fetched_unix_s) > CACHE_TTL.as_secs() {
            return None;
        }
        Some(entry.verdict.clone())
    }

    pub fn put(&mut self, sha: &str, verdict: &Verdict, now_unix_s: u64) {
        // Never cache a failure to ask. Caching it would convert a
        // transient outage into a week of not looking.
        if matches!(verdict, Verdict::Unavailable(_)) {
            return;
        }
        self.by_sha.insert(
            sha.to_ascii_lowercase(),
            CacheEntry {
                verdict: verdict.clone(),
                fetched_unix_s: now_unix_s,
            },
        );
    }
}

#[must_use]
pub fn now_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Reads an API key from a file, refusing one any other user can read.
///
/// Same reasoning as the SMTP password: a secret every account on the
/// box can read is not a secret, and failing at setup beats discovering
/// it after the key is abused.
pub fn read_api_key(path: &Path) -> Result<String> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading VirusTotal key file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!(
                "VirusTotal key file {} is group/world accessible; run: chmod 600 {}",
                path.display(),
                path.display()
            );
        }
    }
    let key = std::fs::read_to_string(path)?.trim().to_string();
    if key.is_empty() {
        bail!("VirusTotal key file {} is empty", path.display());
    }
    Ok(key)
}

pub struct VtClient {
    api_key: String,
    http: reqwest::Client,
    /// Set once the API reports the quota is spent. Every later lookup
    /// short-circuits to `Unavailable` rather than hammering a limit
    /// that is already refusing us.
    exhausted: std::cell::Cell<bool>,
}

impl std::fmt::Debug for VtClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key.
        f.debug_struct("VtClient")
            .field("exhausted", &self.exhausted.get())
            .finish_non_exhaustive()
    }
}

impl VtClient {
    pub fn new(api_key: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("bowery/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            api_key,
            http,
            exhausted: std::cell::Cell::new(false),
        })
    }

    /// Look one hash up. Never returns an error: every failure becomes
    /// [`Verdict::Unavailable`], because a caller must not be able to
    /// turn a network problem into a suppressed alert by mistake.
    pub async fn lookup(&self, sha256: &str) -> Verdict {
        if self.exhausted.get() {
            return Verdict::Unavailable("daily/minute quota exhausted".into());
        }
        let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
        let response = match self
            .http
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return Verdict::Unavailable(format!("request failed: {e}")),
        };
        match response.status().as_u16() {
            200 => match response.text().await {
                Ok(body) => parse_verdict(&body),
                Err(e) => Verdict::Unavailable(format!("reading response: {e}")),
            },
            // VT's "we have never seen this file".
            404 => Verdict::Unknown,
            401 | 403 => Verdict::Unavailable("API key rejected".into()),
            429 => {
                self.exhausted.set(true);
                Verdict::Unavailable("rate limited (4/min, 500/day on the public API)".into())
            }
            other => Verdict::Unavailable(format!("HTTP {other}")),
        }
    }
}

/// Where the cache lives by default.
#[must_use]
pub fn default_cache_path() -> PathBuf {
    std::env::var("HOME").map_or_else(
        |_| PathBuf::from(".bowery-vt-cache.json"),
        |h| PathBuf::from(h).join(".bowery").join("vt-cache.json"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = r#"{"data":{"attributes":{"last_analysis_stats":
        {"malicious":0,"suspicious":0,"undetected":10,"harmless":52}}}}"#;
    const FLAGGED: &str = r#"{"data":{"attributes":{"last_analysis_stats":
        {"malicious":41,"suspicious":2,"undetected":9,"harmless":0}}}}"#;

    #[test]
    fn a_clean_file_parses_and_may_suppress() {
        let v = parse_verdict(CLEAN);
        assert_eq!(v, Verdict::Clean { total: 62 });
        assert!(v.may_suppress());
        assert!(v.summary().contains("0/62"));
    }

    #[test]
    fn a_flagged_file_is_malicious_and_never_suppresses() {
        let v = parse_verdict(FLAGGED);
        // Suspicious counts toward malicious: an engine hedging is still
        // an engine saying something.
        assert_eq!(
            v,
            Verdict::Malicious {
                malicious: 43,
                total: 52
            }
        );
        assert!(v.is_malicious());
        assert!(!v.may_suppress());
    }

    #[test]
    fn nothing_unparseable_can_ever_suppress() {
        // The core safety property: only a positive clean signal
        // suppresses, and it is reachable only from a response we fully
        // understood. Anything else must leave the alert alone.
        for body in [
            "",
            "not json",
            "{}",
            r#"{"data":{}}"#,
            r#"{"error":{"code":"NotFoundError"}}"#,
            r#"{"data":{"attributes":{"last_analysis_stats":{}}}}"#,
        ] {
            let v = parse_verdict(body);
            assert!(!v.may_suppress(), "{body:?} must not suppress, got {v:?}");
        }
    }

    #[test]
    fn a_zero_engine_result_is_unavailable_not_clean() {
        // "No engine has an opinion" is a response we do not understand.
        // Reading it as clean would suppress on the strength of nothing.
        let v = parse_verdict(
            r#"{"data":{"attributes":{"last_analysis_stats":
               {"malicious":0,"suspicious":0,"undetected":0,"harmless":0}}}}"#,
        );
        assert!(matches!(v, Verdict::Unavailable(_)), "{v:?}");
    }

    #[test]
    fn unknown_and_unavailable_never_suppress() {
        assert!(!Verdict::Unknown.may_suppress());
        assert!(!Verdict::Unavailable("down".into()).may_suppress());
    }

    #[test]
    fn the_cache_round_trips_and_expires() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vt.json");
        let mut cache = VtCache::load(&path);
        let now = 1_000_000u64;
        cache.put("ABCD", &Verdict::Clean { total: 60 }, now);
        cache.save(&path).unwrap();

        let reloaded = VtCache::load(&path);
        // Lookup is case-insensitive: hashes get pasted in both cases.
        assert_eq!(
            reloaded.get("abcd", now),
            Some(Verdict::Clean { total: 60 })
        );
        // Expired entries are refetched — engines do change their minds.
        assert_eq!(reloaded.get("abcd", now + CACHE_TTL.as_secs() + 1), None);
    }

    #[test]
    fn failures_are_never_cached() {
        // Caching "could not ask" would turn one outage into a week of
        // not looking.
        let mut cache = VtCache::default();
        cache.put("aa", &Verdict::Unavailable("timeout".into()), 100);
        assert_eq!(cache.get("aa", 100), None);
    }

    #[test]
    fn a_corrupt_cache_file_degrades_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vt.json");
        std::fs::write(&path, "{ not json").unwrap();
        assert_eq!(VtCache::load(&path).get("aa", 0), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("vt.key");
        std::fs::write(&key, "deadbeef").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_api_key(&key).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_api_key(&key).unwrap(), "deadbeef");
    }
}
