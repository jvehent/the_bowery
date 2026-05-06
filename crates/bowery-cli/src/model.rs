//! `bowery model {list, fetch}` — manage local LLM model artifacts.
//!
//! The agent expects an already-on-disk GGUF file at the path it's
//! configured with (`[llm.llama_cpp] model_path`). We don't download
//! at agent startup or at compile time — operators run `bowery model
//! fetch` once per host (or in a provisioning script) and the agent
//! just reads from the resulting file.
//!
//! Per the DESIGN doc this will eventually become an air-gapped
//! `bowery model push <file>` flow with a signed manifest. For now
//! it's a curated registry pointing at `HuggingFace` mirrors with
//! `sha256` verification.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

/// One entry in the curated model registry.
struct ModelEntry {
    /// Stable identifier used as the CLI name and as the on-disk
    /// filename (with `.gguf` appended).
    name: &'static str,
    /// Source URL. Choose a stable mirror (we currently use unsloth's
    /// `HuggingFace` repo, which has been responsive about keeping its
    /// quants in sync with upstream Qwen releases).
    url: &'static str,
    /// SHA-256 of the file contents. `None` means "trust the GGUF
    /// magic + length sanity check"; we'll fill these in over time as
    /// we lock specific quantizations.
    sha256_hex: Option<&'static str>,
    /// Approximate on-disk size, used as a sanity check after
    /// download. The real check is the sha256 (when set); the size is
    /// just a quick "did we get the wrong artifact entirely" probe.
    expected_bytes: u64,
}

/// First four bytes of every GGUF file. Used to bail early when an
/// HTTP error page (e.g. a 404 saved-as-the-file) sneaks past curl.
const GGUF_MAGIC: &[u8; 4] = b"GGUF";

/// Curated registry. Add entries here as we adopt new models. Keeping
/// this hardcoded (rather than a JSON manifest fetched at runtime) is
/// deliberate: it forces us to vet new entries via code review.
const REGISTRY: &[ModelEntry] = &[
    ModelEntry {
        // Agent-side alert verdict path (Phase 4b). Tuned for
        // ChatML-style JSON-emit prompts.
        name: "qwen3-0.6b-q4_k_m",
        url: "https://huggingface.co/unsloth/Qwen3-0.6B-GGUF/resolve/main/Qwen3-0.6B-Q4_K_M.gguf",
        sha256_hex: None,
        expected_bytes: 380 * 1024 * 1024, // ~380 MiB
    },
    ModelEntry {
        // Operator-side console chat (Console phase C-6). Gemma 4
        // E2B-it — 2.3B effective params, 128K context window,
        // <start_of_turn> chat template. Use this on the operator
        // workstation, not on agents (agents stay on Qwen3).
        //
        // Source: Unsloth's public Gemma-4-E2B-it GGUF repo (no
        // HF auth required). The Monster/* mirror returned 401 on
        // first try, so we point at the better-maintained
        // unsloth/* one instead.
        name: "gemma-4-e2b-it-q4_k_m",
        url: "https://huggingface.co/unsloth/gemma-4-E2B-it-GGUF/resolve/main/gemma-4-E2B-it-Q4_K_M.gguf",
        sha256_hex: None,
        expected_bytes: 3_100 * 1024 * 1024, // 3.11 GiB per the repo listing
    },
];

pub fn list() {
    println!("{:<24} {:>10}  url", "name", "size");
    for entry in REGISTRY {
        println!(
            "{:<24} {:>10}  {}",
            entry.name,
            human_size(entry.expected_bytes),
            entry.url
        );
    }
}

/// Default cache directory: `~/.bowery/models/`.
pub fn default_out_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("$HOME is not set; pass --out to choose an explicit directory"))?;
    Ok(PathBuf::from(home).join(".bowery").join("models"))
}

pub fn fetch(name: &str, out_dir: &Path, force: bool) -> Result<()> {
    let entry = REGISTRY
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| anyhow!("unknown model `{name}`; run `bowery model list` to see options"))?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating cache directory {}", out_dir.display()))?;
    let target = out_dir.join(format!("{}.gguf", entry.name));

    if target.exists() && !force {
        // Check the existing file is sane before declaring success — if
        // the previous run wrote half a file or an HTTP error, force
        // a re-download.
        match validate(&target, entry) {
            Ok(()) => {
                println!("{} already present at {}", entry.name, target.display());
                return Ok(());
            }
            Err(e) => {
                eprintln!(
                    "warning: existing {} failed validation ({e}); re-downloading",
                    target.display()
                );
            }
        }
    }

    println!(
        "fetching {name} ({size}) from {url}",
        name = entry.name,
        size = human_size(entry.expected_bytes),
        url = entry.url,
    );
    download(entry.url, &target)?;
    validate(&target, entry).with_context(|| {
        format!(
            "validation failed for {} after download — file is at {}",
            entry.name,
            target.display()
        )
    })?;
    println!("ok: {}", target.display());
    println!();
    println!("Add this to the agent's [llm.llama_cpp] config:");
    println!("    model_path = \"{}\"", target.display());
    Ok(())
}

/// Stream `url` to `target` using a blocking HTTP client. We lean on
/// `ureq` here (already pulled in via tracing's transitive deps?
/// Actually no — we use a tiny shell-out to curl/wget to avoid a new
/// dep). Returns once the body has been fully written + flushed.
fn download(url: &str, target: &Path) -> Result<()> {
    let tmp = with_extension(target, "downloading");
    // Best-effort cleanup of any leftover tmp from a prior crash.
    let _ = std::fs::remove_file(&tmp);

    // Using curl for the HTTP fetch keeps `bowery-cli`'s dep graph
    // small and matches what operators are likely to have on any
    // production host. Falls back to wget if curl is missing.
    let downloader = pick_downloader()?;
    let status = match downloader {
        Downloader::Curl => std::process::Command::new("curl")
            .arg("--fail") // nonzero exit on HTTP errors instead of writing the error page
            .arg("--location")
            .arg("--progress-bar")
            .arg("--retry")
            .arg("3")
            .arg("--connect-timeout")
            .arg("30")
            .arg("--output")
            .arg(&tmp)
            .arg(url)
            .status()
            .context("invoking curl")?,
        Downloader::Wget => std::process::Command::new("wget")
            .arg("--tries=3")
            .arg("--timeout=60")
            .arg("--show-progress")
            .arg("-O")
            .arg(&tmp)
            .arg(url)
            .status()
            .context("invoking wget")?,
    };
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        bail!("downloader exited {status}");
    }

    std::fs::rename(&tmp, target)
        .with_context(|| format!("renaming {} → {}", tmp.display(), target.display()))?;
    Ok(())
}

enum Downloader {
    Curl,
    Wget,
}

fn pick_downloader() -> Result<Downloader> {
    if which("curl") {
        return Ok(Downloader::Curl);
    }
    if which("wget") {
        return Ok(Downloader::Wget);
    }
    bail!("neither curl nor wget found in PATH; install one or fetch manually")
}

fn which(bin: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| {
        let p = dir.join(bin);
        if !p.is_file() {
            return false;
        }
        match std::fs::metadata(&p) {
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            Err(_) => false,
        }
    })
}

/// Validate that the file exists, starts with the GGUF magic, and (if
/// the registry pinned a sha256) has the expected hash.
fn validate(path: &Path, entry: &ModelEntry) -> Result<()> {
    let mut file =
        File::open(path).with_context(|| format!("opening {} for validation", path.display()))?;

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .with_context(|| format!("reading magic from {}", path.display()))?;
    if &magic != GGUF_MAGIC {
        bail!(
            "file does not start with `GGUF` magic (got {magic:?}). The download likely captured \
             an HTTP error response — re-run with --force or fetch manually."
        );
    }

    let actual_size = file.metadata()?.len();
    // ±25% tolerance on the expected size to cover quantization tweaks
    // upstream without needing to bump the registry every release.
    let lower = entry.expected_bytes * 3 / 4;
    let upper = entry.expected_bytes * 5 / 4;
    if !(lower..=upper).contains(&actual_size) {
        bail!(
            "size {actual_size} out of expected band [{lower}, {upper}] for {name}",
            name = entry.name,
        );
    }

    if let Some(want_hex) = entry.sha256_hex {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        // Re-open from offset 0 — we already advanced 4 bytes for the magic.
        let mut f = File::open(path)?;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let got = hex_lower(&hasher.finalize());
        if got != want_hex {
            bail!("sha256 mismatch: got {got}, expected {want_hex}");
        }
    }

    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    // The cast loses precision in principle (u64 → f64), but model
    // sizes are bounded by `expected_bytes` which we keep under a few
    // GiB. The display is approximate by design.
    #[allow(clippy::cast_precision_loss)]
    let f = |bytes: u64, denom: u64| (bytes as f64) / (denom as f64);
    if bytes >= GIB {
        format!("{:.1} GiB", f(bytes, GIB))
    } else if bytes >= MIB {
        format!("{:.0} MiB", f(bytes, MIB))
    } else {
        format!("{bytes} B")
    }
}

fn with_extension(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}
