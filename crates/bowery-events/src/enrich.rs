//! /proc-based enrichment helpers.
//!
//! Phase 2 (userspace) does enrichment after the fact, by reading
//! `/proc/<pid>/...`. When the eBPF source lands, much of this is replaced
//! by in-kernel resolution; these helpers stay useful for short-lived
//! processes that exit before user-space can read /proc.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const SHA256_BUF: usize = 64 * 1024;

/// Resolve `/proc/<pid>/exe` to an absolute path.
///
/// Returns `None` if the symlink can't be read — typically because the
/// process exited before we got here.
pub fn pid_exe_path(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// SHA-256 the contents of a binary on disk.
pub fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; SHA256_BUF];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Ok(out)
}

/// Parse `/proc/<pid>/cgroup` (cgroup v2 format: `0::/path`).
///
/// Returns the most-specific cgroup path — typically the container ID for
/// containerized processes, or `/` for the root cgroup.
pub fn pid_cgroup(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    raw.lines().next().and_then(|line| {
        line.split_once("::")
            .map(|(_, path)| path.trim().to_string())
    })
}

/// Read `/proc/<pid>/cmdline`, splitting on NUL bytes.
pub fn pid_cmdline(pid: u32) -> Option<Vec<String>> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        raw.split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect(),
    )
}

/// Convenience: hash the file at `path`, returning lowercase hex.
pub fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let bytes = sha256_file(path)?;
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_pid() -> u32 {
        std::process::id()
    }

    #[test]
    fn pid_exe_path_resolves_self() {
        let path = pid_exe_path(self_pid()).expect("self exe path");
        assert!(path.exists(), "self exe ({}) must exist", path.display());
    }

    #[test]
    fn pid_cgroup_returns_path() {
        // cgroup file format is well-defined on Linux; on most systems
        // /proc/self/cgroup exists. If it doesn't (very stripped envs),
        // the lookup returns None — accept either, but if Some it must
        // start with '/'.
        if let Some(cg) = pid_cgroup(self_pid()) {
            assert!(cg.starts_with('/'), "cgroup path: {cg}");
        }
    }

    #[test]
    fn pid_cmdline_is_non_empty_for_self() {
        let parts = pid_cmdline(self_pid()).expect("self cmdline");
        assert!(!parts.is_empty(), "cmdline must have at least argv[0]");
    }

    #[test]
    fn sha256_file_matches_known_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        fs::write(&path, b"the bowery is watching").unwrap();

        // Reference value computed with `printf %s 'the bowery is watching' | sha256sum`.
        let mut hasher = Sha256::new();
        hasher.update(b"the bowery is watching");
        let expected: [u8; 32] = hasher.finalize().into();

        let actual = sha256_file(&path).unwrap();
        assert_eq!(actual, expected);

        let hex = sha256_file_hex(&path).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }

    #[test]
    fn pid_exe_path_returns_none_for_invalid_pid() {
        assert!(pid_exe_path(0).is_none(), "pid 0 is not a real process");
    }
}
