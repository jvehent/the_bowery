//! Where did this binary come from?
//!
//! The agent scores a binary it has never seen at 1.0, and that is the
//! single largest source of noise it produces. On a live fleet it
//! confirmed `/usr/bin/ssh`, `/usr/bin/nice` and `/usr/bin/pkexec` as
//! anomalies — all first executions of ordinary distribution binaries.
//! An operator who learns to close that tab is a defence that has
//! already failed, so this is the highest-value item in the roadmap.
//!
//! The distinction that fixes it is *provenance*: a binary the package
//! manager installed, whose contents still match what the package says,
//! is not interesting the first time it runs. It was on the disk before
//! anyone logged in.
//!
//! # The same index is also a detection
//!
//! Once you know what a packaged file *should* hash to, a mismatch is
//! not noise-suppression at all — it is a packaged system binary whose
//! contents have changed, which is a trojanised binary and one of the
//! stronger findings this agent can produce. The lookup that removes
//! hundreds of false positives adds one real detection, from the same
//! data.
//!
//! # Why md5, of all things
//!
//! Not a security choice — dpkg records md5 and that is the ground
//! truth being compared against. It is used only to answer "does this
//! file still match what the package manager installed", never to
//! establish trust: an attacker who can rewrite `/usr/bin/nice` can
//! also rewrite the `.md5sums` file next to it. What this defeats is
//! the *ordinary* case, where a binary is replaced and the package
//! metadata is left alone. The baseline's SHA-256 remains the identity.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Where a binary came from, as far as the package manager knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Installed by a package, and the file still matches.
    PackagedIntact,
    /// Installed by a package, and the contents have since changed.
    ///
    /// A finding, not a suppression: something rewrote a system binary.
    PackagedModified,
    /// A real path that no package owns — a build output, something
    /// downloaded, something dropped. Not suspicious by itself; most of
    /// `/usr/local` and every developer's `~/bin` lands here.
    Unpackaged,
    /// No package database, or it could not be read. The honest answer
    /// when the question cannot be asked.
    Unknown,
}

impl Provenance {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::PackagedIntact => "distro-packaged, unmodified",
            Self::PackagedModified => "distro-packaged but MODIFIED",
            Self::Unpackaged => "not owned by any package",
            Self::Unknown => "provenance unknown",
        }
    }
}

/// Path → the digest the package manager recorded for it.
///
/// Only paths that could plausibly be executed are kept. A full dpkg
/// index is ~226,000 entries, of which ~2,400 live in a binary
/// directory; since this is only ever consulted for something that just
/// ran, the other 99% is memory a Raspberry Pi should not spend.
#[derive(Debug, Default)]
pub struct PackageIndex {
    by_path: HashMap<PathBuf, [u8; 16]>,
    /// False when no package database was found, which makes every
    /// answer [`Provenance::Unknown`] rather than
    /// [`Provenance::Unpackaged`]. Reporting "no package owns this" on a
    /// host with no dpkg would mark every binary as unowned and quietly
    /// invert the whole feature.
    available: bool,
}

/// Does this look like something that gets executed?
fn is_executable_path(rel: &str) -> bool {
    const DIRS: [&str; 6] = [
        "bin/",
        "sbin/",
        "usr/bin/",
        "usr/sbin/",
        "usr/libexec/",
        "usr/games/",
    ];
    DIRS.iter().any(|d| rel.starts_with(d))
        // Helper binaries live under a package's own lib directory,
        // e.g. usr/lib/systemd/systemd or usr/lib/openssh/sftp-server.
        // Shared objects are mapped, not exec'd, and they are the bulk
        // of usr/lib. Excluding them is what keeps the index small.
        || (rel.starts_with("usr/lib/") && !rel.contains(".so"))
}

impl PackageIndex {
    /// Empty index that answers [`Provenance::Unknown`] to everything.
    #[must_use]
    pub fn unavailable() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_available(&self) -> bool {
        self.available
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    /// Build from dpkg's per-package `.md5sums` files.
    ///
    /// Reads `<dir>/*.md5sums`, whose lines are `<md5>  <relative path>`
    /// with no leading slash. Unreadable files are skipped rather than
    /// failing the load: a partially-built index suppresses less noise
    /// than a complete one, which is strictly better than none.
    #[must_use]
    pub fn load_dpkg(dir: &Path) -> Self {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Self::unavailable();
        };
        let mut by_path = HashMap::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "md5sums") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in text.lines() {
                let Some((digest, rel)) = line.split_once("  ") else {
                    continue;
                };
                if !is_executable_path(rel) {
                    continue;
                }
                let Some(md5) = parse_md5(digest) else {
                    continue;
                };
                by_path.insert(PathBuf::from("/").join(rel), md5);
            }
        }
        Self {
            by_path,
            available: true,
        }
    }

    /// Standard dpkg location; [`Provenance::Unknown`] everywhere else.
    #[must_use]
    pub fn load_system() -> Self {
        Self::load_dpkg(Path::new("/var/lib/dpkg/info"))
    }

    /// Classify a binary, given the md5 of its current contents.
    ///
    /// `file_md5` is `None` when the file could not be read — which is
    /// not evidence of anything, so a packaged path with no digest is
    /// reported as `Unknown` rather than as modified. Accusing a binary
    /// because the agent lost a race with `rm` would be its own false
    /// positive.
    #[must_use]
    pub fn classify(&self, path: &Path, file_md5: Option<[u8; 16]>) -> Provenance {
        if !self.available {
            return Provenance::Unknown;
        }
        match (self.by_path.get(path), file_md5) {
            (None, _) => Provenance::Unpackaged,
            (Some(_), None) => Provenance::Unknown,
            (Some(expected), Some(actual)) => {
                if *expected == actual {
                    Provenance::PackagedIntact
                } else {
                    Provenance::PackagedModified
                }
            }
        }
    }
}

/// md5 of a file's current contents, for comparison against the digest
/// the package manager recorded.
///
/// Only ever called for a binary the host has *not* seen before, which
/// after warm-up is rare — steady-state cost is nil.
#[must_use]
pub fn file_md5(path: &Path) -> Option<[u8; 16]> {
    use md5::Digest as _;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = md5::Md5::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
    Some(hasher.finalize().into())
}

fn parse_md5(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// How provenance changes a rarity score.
///
/// Rarity asks "has this host run this before". Provenance answers a
/// different question — "was this here before anyone logged in" — and
/// the second one dominates. A first execution of an unmodified
/// packaged binary is the boring case that was drowning the alert
/// stream.
///
/// Returns the adjusted score and the reason, so an operator reading an
/// alert can see the adjustment rather than wonder why a number moved.
#[must_use]
pub fn adjust_score(score: f32, provenance: Provenance) -> (f32, &'static str) {
    match provenance {
        // Damped hard, not zeroed. A packaged binary can still be
        // abused — `curl` and `bash` ship with the distro — so other
        // signals (writable-path exec, suspicious args, lineage) must
        // still be able to push an episode over the threshold on their
        // own.
        Provenance::PackagedIntact => (
            score * 0.15,
            "damped: distro-packaged and unmodified, so a first execution says nothing",
        ),
        // Not a dampener. Something rewrote a file the package manager
        // owns.
        Provenance::PackagedModified => (
            1.0,
            "a packaged system binary no longer matches what the package installed",
        ),
        Provenance::Unpackaged => (score, "no package owns this path"),
        Provenance::Unknown => (score, "provenance could not be established"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_md5sums(dir: &Path, pkg: &str, lines: &[&str]) {
        std::fs::write(dir.join(format!("{pkg}.md5sums")), lines.join("\n")).unwrap();
    }

    const NICE_MD5: &str = "eb447078f44000fd5e083d474316fcfb";

    fn nice_bytes() -> [u8; 16] {
        parse_md5(NICE_MD5).unwrap()
    }

    #[test]
    fn an_unmodified_packaged_binary_is_recognised() {
        let dir = tempfile::tempdir().unwrap();
        write_md5sums(
            dir.path(),
            "coreutils",
            &[&format!("{NICE_MD5}  usr/bin/nice")],
        );
        let idx = PackageIndex::load_dpkg(dir.path());
        assert_eq!(
            idx.classify(Path::new("/usr/bin/nice"), Some(nice_bytes())),
            Provenance::PackagedIntact
        );
    }

    #[test]
    fn a_modified_packaged_binary_is_a_finding_not_a_suppression() {
        // The payoff: the same index that removes hundreds of false
        // positives turns a rewritten system binary into a detection.
        let dir = tempfile::tempdir().unwrap();
        write_md5sums(
            dir.path(),
            "coreutils",
            &[&format!("{NICE_MD5}  usr/bin/nice")],
        );
        let idx = PackageIndex::load_dpkg(dir.path());
        let tampered = [0xffu8; 16];
        assert_eq!(
            idx.classify(Path::new("/usr/bin/nice"), Some(tampered)),
            Provenance::PackagedModified
        );
        let (score, why) = adjust_score(0.1, Provenance::PackagedModified);
        assert!((score - 1.0).abs() < f32::EPSILON, "must not be damped");
        assert!(why.contains("no longer matches"));
    }

    #[test]
    fn an_unreadable_file_is_unknown_rather_than_modified() {
        // Losing a race with `rm` must not accuse the binary.
        let dir = tempfile::tempdir().unwrap();
        write_md5sums(
            dir.path(),
            "coreutils",
            &[&format!("{NICE_MD5}  usr/bin/nice")],
        );
        let idx = PackageIndex::load_dpkg(dir.path());
        assert_eq!(
            idx.classify(Path::new("/usr/bin/nice"), None),
            Provenance::Unknown
        );
    }

    #[test]
    fn a_path_no_package_owns_is_unpackaged() {
        let dir = tempfile::tempdir().unwrap();
        write_md5sums(
            dir.path(),
            "coreutils",
            &[&format!("{NICE_MD5}  usr/bin/nice")],
        );
        let idx = PackageIndex::load_dpkg(dir.path());
        assert_eq!(
            idx.classify(Path::new("/tmp/payload"), Some([1u8; 16])),
            Provenance::Unpackaged
        );
        // …and stays at full score, which is the whole point.
        let (score, _) = adjust_score(1.0, Provenance::Unpackaged);
        assert!((score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn no_package_database_means_unknown_not_unpackaged() {
        // On a host with no dpkg, calling every binary "unowned" would
        // invert the feature and mark the entire system suspicious.
        let idx = PackageIndex::load_dpkg(Path::new("/nonexistent/dpkg/info"));
        assert!(!idx.is_available());
        assert_eq!(
            idx.classify(Path::new("/usr/bin/nice"), Some([1u8; 16])),
            Provenance::Unknown
        );
        let (score, _) = adjust_score(1.0, Provenance::Unknown);
        assert!((score - 1.0).abs() < f32::EPSILON, "unknown must not damp");
    }

    #[test]
    fn only_executable_paths_are_indexed() {
        // 226k packaged paths, ~2.4k of them executable. Indexing the
        // rest is memory a Pi should not spend on paths never looked up.
        let dir = tempfile::tempdir().unwrap();
        write_md5sums(
            dir.path(),
            "mixed",
            &[
                &format!("{NICE_MD5}  usr/bin/nice"),
                &format!("{NICE_MD5}  usr/share/doc/coreutils/README"),
                &format!("{NICE_MD5}  usr/share/man/man1/nice.1.gz"),
                &format!("{NICE_MD5}  etc/default/something"),
            ],
        );
        let idx = PackageIndex::load_dpkg(dir.path());
        assert_eq!(idx.len(), 1, "only the binary should be indexed");
    }

    #[test]
    fn the_noise_case_is_actually_suppressed() {
        // /usr/bin/nice at first execution: the exact alert the live
        // fleet was quorum-confirming as an anomaly.
        let (score, why) = adjust_score(1.0, Provenance::PackagedIntact);
        assert!(
            score < 0.2,
            "first-exec noise must fall well below alerting"
        );
        assert!(why.contains("says nothing"));
    }

    #[test]
    fn damping_is_not_zeroing() {
        // A packaged binary can still be abused — bash and curl ship
        // with the distro — so other signals must still be able to
        // carry an episode on their own.
        let (score, _) = adjust_score(1.0, Provenance::PackagedIntact);
        assert!(score > 0.0, "must not erase the signal entirely");
    }

    #[test]
    fn malformed_md5sums_lines_are_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        write_md5sums(
            dir.path(),
            "broken",
            &[
                "not-a-digest  usr/bin/thing",
                "onlyonefield",
                "",
                &format!("{NICE_MD5}  usr/bin/nice"),
            ],
        );
        let idx = PackageIndex::load_dpkg(dir.path());
        assert!(idx.is_available());
        assert_eq!(idx.len(), 1, "the good line still loaded");
    }
}
