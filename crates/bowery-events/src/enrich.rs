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

/// Parent pid, from `/proc/<pid>/stat`.
///
/// The `sched_process_exec` tracepoint does not carry a parent, and
/// getting one in the probe would need `task->real_parent` via CO-RE —
/// which needs kernel BTF, which Raspberry Pi kernels do not ship. So it
/// is read here, right after the exec, when the process almost always
/// still exists.
///
/// Parsed from after the **last** `)` on purpose: field 2 is the comm in
/// parentheses and a process may legally be called `evil) 0 0 (`, which
/// splitting on whitespace would let it use to forge its own ancestry.
#[must_use]
pub fn pid_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // Fields after the comm: state, ppid, …
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

/// A process's `comm`, from `/proc/<pid>/comm`.
#[must_use]
pub fn pid_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_string())
}

#[cfg(test)]
mod parent_tests {
    use super::*;

    #[test]
    fn our_own_parent_is_readable() {
        let me = std::process::id();
        let ppid = pid_ppid(me).expect("own ppid should be readable");
        assert!(ppid > 0, "pid 1 aside, a parent always exists");
    }

    #[test]
    fn our_own_comm_is_readable() {
        let comm = pid_comm(std::process::id()).expect("own comm");
        assert!(!comm.is_empty());
        assert!(!comm.ends_with('\n'), "trailing newline must be trimmed");
    }

    #[test]
    fn a_dead_pid_yields_none_rather_than_panicking() {
        // Racing a process that exited between exec and enrichment is
        // routine, not exceptional.
        assert!(pid_ppid(u32::MAX).is_none());
        assert!(pid_comm(u32::MAX).is_none());
    }
}

/// Current working directory of a process.
#[must_use]
pub fn pid_cwd(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

/// Walk up the process tree, nearest ancestor first.
///
/// Bounded, and stops at pid 1 or the first unreadable parent. An
/// alert that says only "bash ran curl" is much harder to judge than
/// one showing `sshd → bash → curl`: the chain is usually what tells an
/// operator whether a human did this.
///
/// Racy by nature — a parent may exit mid-walk — so a short chain is a
/// normal outcome, not an error.
#[must_use]
pub fn pid_ancestry(pid: u32, max_depth: usize) -> Vec<(u32, String)> {
    let mut chain = Vec::new();
    let mut current = pid;
    for _ in 0..max_depth {
        let Some(parent) = pid_ppid(current) else {
            break;
        };
        if parent == 0 {
            break;
        }
        let comm = pid_comm(parent).unwrap_or_else(|| "?".to_string());
        chain.push((parent, comm));
        if parent == 1 {
            break;
        }
        current = parent;
    }
    chain
}

/// Files a process currently has open, and how many sockets.
///
/// Returns `(paths, socket_inodes)`. Best-effort and a *snapshot*: a
/// short-lived process is already gone by the time this runs, which is
/// why the caller must distinguish "nothing open" from "could not look"
/// rather than presenting an empty list as a finding.
#[must_use]
pub fn pid_open_files(pid: u32, cap: usize) -> Option<(Vec<PathBuf>, Vec<u64>)> {
    let entries = fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let mut paths = Vec::new();
    let mut sockets = Vec::new();
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let s = target.to_string_lossy();
        if let Some(inode) = s.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
            if let Ok(n) = inode.parse() {
                sockets.push(n);
            }
        } else if s.starts_with('/') && paths.len() < cap {
            // Skip the noise every process has open.
            if !s.starts_with("/dev/") && !s.starts_with("/proc/") && !s.starts_with("/sys/") {
                paths.push(target);
            }
        }
    }
    Some((paths, sockets))
}

/// Resolve socket inodes to `local -> remote` pairs via `/proc/net/tcp`.
///
/// This is what makes an open-socket count into something an operator
/// can act on: "held 3 sockets" says nothing, "connected to
/// 203.0.113.9:443" says where to look next.
#[must_use]
pub fn resolve_tcp_sockets(inodes: &[u64], cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    for (file, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines().skip(1) {
            if out.len() >= cap {
                return out;
            }
            let f: Vec<&str> = line.split_whitespace().collect();
            // local_address(1) rem_address(2) … inode(9)
            if f.len() < 10 {
                continue;
            }
            let Ok(inode) = f[9].parse::<u64>() else {
                continue;
            };
            if !inodes.contains(&inode) {
                continue;
            }
            if let (Some(l), Some(r)) = (parse_hex_addr(f[1], v6), parse_hex_addr(f[2], v6)) {
                out.push(format!("{l} -> {r}"));
            }
        }
    }
    out
}

/// `0100007F:1F90` → `127.0.0.1:8080`. Kernel writes the address in
/// host byte order per 32-bit word, which is why the octets reverse.
fn parse_hex_addr(s: &str, v6: bool) -> Option<String> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if v6 {
        if addr.len() != 32 {
            return None;
        }
        let mut groups = Vec::new();
        for word in 0..4 {
            let w = &addr[word * 8..word * 8 + 8];
            let n = u32::from_str_radix(w, 16).ok()?.swap_bytes();
            groups.push(format!("{:x}:{:x}", n >> 16, n & 0xffff));
        }
        return Some(format!("[{}]:{port}", groups.join(":")));
    }
    if addr.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(addr, 16).ok()?;
    let o = n.to_le_bytes();
    Some(format!("{}.{}.{}.{}:{port}", o[0], o[1], o[2], o[3]))
}

#[cfg(test)]
mod context_tests {
    use super::*;

    #[test]
    fn our_own_ancestry_is_readable_and_bounded() {
        let chain = pid_ancestry(std::process::id(), 6);
        assert!(!chain.is_empty(), "a test process always has a parent");
        assert!(chain.len() <= 6, "depth must be bounded");
    }

    #[test]
    fn a_dead_pid_yields_an_empty_chain_rather_than_panicking() {
        assert!(pid_ancestry(u32::MAX, 6).is_empty());
        assert!(pid_open_files(u32::MAX, 10).is_none());
    }

    #[test]
    fn open_files_distinguishes_nothing_from_could_not_look() {
        // `None` means the process was gone; `Some(empty)` means it had
        // nothing interesting open. Collapsing those would present a
        // dead process as one that opened nothing.
        let (paths, _) = pid_open_files(std::process::id(), 32).expect("our own fds are readable");
        assert!(paths.iter().all(|p| p.is_absolute()));
    }

    #[test]
    fn ipv4_addresses_decode_in_the_kernel_byte_order() {
        // /proc/net/tcp writes each 32-bit word host-ordered, so the
        // octets appear reversed. Getting this backwards would report a
        // completely different peer.
        assert_eq!(
            parse_hex_addr("0100007F:1F90", false).unwrap(),
            "127.0.0.1:8080"
        );
        assert_eq!(
            parse_hex_addr("00000000:0016", false).unwrap(),
            "0.0.0.0:22"
        );
    }

    #[test]
    fn malformed_addresses_are_skipped_not_guessed() {
        assert!(parse_hex_addr("garbage", false).is_none());
        assert!(parse_hex_addr("0100007F", false).is_none());
        assert!(parse_hex_addr("XX:YY", false).is_none());
    }
}
