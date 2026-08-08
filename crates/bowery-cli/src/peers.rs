//! Phase-9 final-8: operator-side peer manifest at
//! `~/.bowery/peers.toml`.
//!
//! Pre-populates the operator's verifier resolver with the
//! Ed25519 pubkey of every peer that might respond to a
//! `bowery exec sql --fanout` query. Without this, fan-out
//! responses fail with `BadSignature` because the operator's
//! `StaticResolver` doesn't know the peer's key.
//!
//! ## File format
//!
//! ```toml
//! [[peer]]
//! name = "web-1"
//! fp = "<64 hex chars>"
//! pubkey_b64 = "<base64 Ed25519 pubkey>"
//! ```
//!
//! Operators add entries via `bowery peers add --name … --fp …
//! --pubkey-b64 …`, list them with `bowery peers list`, remove
//! with `bowery peers remove --fp …`.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default, rename = "peer")]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub name: String,
    pub fp: String,
    pub pubkey_b64: String,
    /// Optional whisper address (`host:port`) this agent is reachable
    /// at. Populated via `bowery peers add --addr …`. Enables
    /// `bowery peers check` (reachability probe) and direct
    /// per-agent queries. Left out for fan-out-only manifests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
}

impl Manifest {
    /// Load from `path`. Returns an empty manifest when the file
    /// doesn't exist (first-run convenience).
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read_to_string(path)
            .with_context(|| format!("reading peer manifest at {}", path.display()))?;
        let mf: Self = toml::from_str(&bytes)
            .with_context(|| format!("parsing peer manifest at {}", path.display()))?;
        Ok(mf)
    }

    /// Atomically save to `path`. Creates parent directories as
    /// needed. Operator-controlled file; we write 0600.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let bytes = toml::to_string_pretty(self).context("serialising peer manifest")?;
        let tmp = path.with_extension("toml.tmp");
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .with_context(|| format!("opening {}", tmp.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perm = f.metadata()?.permissions();
                perm.set_mode(0o600);
                f.set_permissions(perm)?;
            }
            f.write_all(bytes.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

/// Default location: `$HOME/.bowery/peers.toml`. Returns an
/// error when `$HOME` isn't set; callers can override with an
/// explicit path.
pub fn default_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("$HOME is not set"))?;
    Ok(PathBuf::from(home).join(".bowery").join("peers.toml"))
}

/// `bowery peers add` — append (or replace) a peer entry.
pub fn add(path: &Path, name: &str, fp: &str, pubkey_b64: &str, addr: Option<&str>) -> Result<()> {
    validate_fp(fp)?;
    validate_pubkey(pubkey_b64)?;
    if let Some(a) = addr {
        a.parse::<SocketAddr>()
            .map_err(|e| anyhow!("--addr {a:?} is not a valid host:port: {e}"))?;
    }
    let mut mf = Manifest::load(path)?;
    mf.peers.retain(|p| p.fp != fp);
    mf.peers.push(Peer {
        name: name.to_string(),
        fp: fp.to_string(),
        pubkey_b64: pubkey_b64.to_string(),
        addr: addr.map(str::to_string),
    });
    mf.save(path)?;
    println!("added peer {name} ({}) to {}", &fp[..16], path.display());
    Ok(())
}

/// `bowery peers list` — print the manifest as a table.
pub fn list(path: &Path) -> Result<()> {
    let mf = Manifest::load(path)?;
    if mf.peers.is_empty() {
        println!("(no peers in {})", path.display());
        return Ok(());
    }
    let name_w = mf
        .peers
        .iter()
        .map(|p| p.name.chars().count())
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "{:name_w$}  {:22}  fingerprint",
        "name",
        "addr",
        name_w = name_w
    );
    println!(
        "{}  {}  {}",
        "-".repeat(name_w),
        "-".repeat(22),
        "-".repeat(64)
    );
    for p in &mf.peers {
        println!(
            "{:name_w$}  {:22}  {}",
            p.name,
            p.addr.as_deref().unwrap_or("-"),
            p.fp,
            name_w = name_w
        );
    }
    Ok(())
}

/// `bowery peers check` — dial every peer that has an `addr` and
/// report reachability. A peer is "OK" when the full round-trip
/// succeeds: QUIC handshake + cert pin match + operator
/// authorisation + a `SELECT 1` against its SQL surface. Anything
/// short of that (timeout, cert mismatch, `policy_denied`) is a
/// failure with the reason. Returns `true` if every addressed peer
/// was reachable. Reuses [`crate::exec::sql`], so it exercises the
/// exact path a real query takes.
pub async fn check(path: &Path, operator_key: &Path, timeout: Duration) -> Result<bool> {
    let mf = Manifest::load(path)?;
    if mf.peers.is_empty() {
        println!(
            "(no peers in {} — add some with `bowery peers add`)",
            path.display()
        );
        return Ok(true);
    }
    let name_w = mf
        .peers
        .iter()
        .map(|p| p.name.chars().count())
        .max()
        .unwrap_or(4)
        .max(4);
    println!("{:name_w$}  {:22}  status", "name", "addr", name_w = name_w);
    println!(
        "{}  {}  {}",
        "-".repeat(name_w),
        "-".repeat(22),
        "-".repeat(30)
    );

    let mut all_ok = true;
    for p in &mf.peers {
        let Some(addr_str) = p.addr.as_deref() else {
            println!(
                "{:name_w$}  {:22}  SKIP (no addr — `peers add --addr host:port`)",
                p.name,
                "-",
                name_w = name_w
            );
            continue;
        };
        let addr: SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                all_ok = false;
                println!(
                    "{:name_w$}  {:22}  BAD ADDR: {e}",
                    p.name,
                    addr_str,
                    name_w = name_w
                );
                continue;
            }
        };
        let mut sink = crate::exec::CollectSink::default();
        let start = Instant::now();
        let res = crate::exec::sql(
            operator_key.to_path_buf(),
            addr,
            p.fp.clone(),
            p.pubkey_b64.clone(),
            Vec::new(),
            "SELECT 1".to_string(),
            timeout,
            false,
            &mut sink,
        )
        .await;
        match res {
            Ok(()) => println!(
                "{:name_w$}  {:22}  OK ({} ms)",
                p.name,
                addr_str,
                start.elapsed().as_millis(),
                name_w = name_w
            ),
            Err(e) => {
                all_ok = false;
                // One-line reason: the top-level context is the most
                // useful (e.g. "dialing agent … timed out").
                println!(
                    "{:name_w$}  {:22}  UNREACHABLE: {e}",
                    p.name,
                    addr_str,
                    name_w = name_w
                );
            }
        }
    }
    Ok(all_ok)
}

/// `bowery peers remove --fp …`. Idempotent.
pub fn remove(path: &Path, fp: &str) -> Result<()> {
    validate_fp(fp)?;
    let mut mf = Manifest::load(path)?;
    let before = mf.peers.len();
    mf.peers.retain(|p| p.fp != fp);
    mf.save(path)?;
    if mf.peers.len() == before {
        println!("(no peer with fp {fp} in manifest; nothing changed)");
    } else {
        println!("removed peer {} from {}", &fp[..16], path.display());
    }
    Ok(())
}

fn validate_fp(fp: &str) -> Result<()> {
    if fp.len() != 64 {
        bail!("fingerprint must be 64 hex chars (got {})", fp.len());
    }
    if !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("fingerprint must be hex");
    }
    Ok(())
}

fn validate_pubkey(b64: &str) -> Result<()> {
    let bytes = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| anyhow!("base64 decode: {e}"))?;
    if bytes.len() != 32 {
        bail!("pubkey must be 32 bytes (got {})", bytes.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");
        add(
            &path,
            "alpha",
            &"a".repeat(64),
            &BASE64.encode([1u8; 32]),
            None,
        )
        .unwrap();
        add(
            &path,
            "beta",
            &"b".repeat(64),
            &BASE64.encode([2u8; 32]),
            Some("100.0.0.2:9902"),
        )
        .unwrap();
        let mf = Manifest::load(&path).unwrap();
        assert_eq!(mf.peers.len(), 2);
        assert_eq!(mf.peers[1].addr.as_deref(), Some("100.0.0.2:9902"));
        remove(&path, &"a".repeat(64)).unwrap();
        let mf = Manifest::load(&path).unwrap();
        assert_eq!(mf.peers.len(), 1);
        assert_eq!(mf.peers[0].name, "beta");
    }

    #[test]
    fn add_replaces_same_fp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");
        add(
            &path,
            "alpha",
            &"a".repeat(64),
            &BASE64.encode([1u8; 32]),
            None,
        )
        .unwrap();
        add(
            &path,
            "alpha-renamed",
            &"a".repeat(64),
            &BASE64.encode([1u8; 32]),
            None,
        )
        .unwrap();
        let mf = Manifest::load(&path).unwrap();
        assert_eq!(mf.peers.len(), 1);
        assert_eq!(mf.peers[0].name, "alpha-renamed");
    }

    #[test]
    fn add_rejects_bad_addr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");
        assert!(
            add(
                &path,
                "x",
                &"a".repeat(64),
                &BASE64.encode([1u8; 32]),
                Some("not-an-addr")
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_bad_fp() {
        assert!(validate_fp("too-short").is_err());
        assert!(validate_fp(&"z".repeat(64)).is_err());
        assert!(validate_fp(&"a".repeat(64)).is_ok());
    }
}
