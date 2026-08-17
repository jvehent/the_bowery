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

/// A [`PackageIndex`] plus a memo of what has already been hashed.
///
/// Provenance must be consulted on **every** execution, not just the
/// first. The rarity curve decays slowly — a binary seen once, twice,
/// three times still scores 0.89, 0.80, 0.73 — so gating on
/// "never seen before" leaves every one of those above the alert
/// threshold. That gating shipped, and `/usr/bin/column` alerted at 0.80
/// on a host whose provenance index had loaded correctly.
///
/// Hashing on every exec would be the obvious cost, so it is memoised
/// by path. The stored digest is checked against the caller's SHA-256:
/// if the file's contents changed, the entry is stale and is recomputed,
/// which is exactly the trojanised-binary case the index exists to
/// catch.
#[derive(Debug)]
pub struct ProvenanceCache {
    /// Behind a lock because it arrives *after* startup — see
    /// [`Self::install`].
    index: std::sync::RwLock<PackageIndex>,
    memo: std::sync::Mutex<HashMap<PathBuf, ([u8; 32], Provenance)>>,
    max_entries: usize,
}

impl ProvenanceCache {
    /// A cache with no index yet: everything is
    /// [`Provenance::Unknown`], which damps nothing.
    ///
    /// Startup must not wait for this. Reading dpkg's metadata took five
    /// seconds on a CI runner with 53,000 packaged executables, and
    /// blocking on it delayed every later task — including the file
    /// monitor, which meant five seconds of a "running" agent not
    /// watching the files it was configured to watch. An optimisation
    /// must never gate the sensors.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            index: std::sync::RwLock::new(PackageIndex::unavailable()),
            memo: std::sync::Mutex::new(HashMap::new()),
            // A host runs a few thousand distinct binaries at most; this
            // bounds a pathological case rather than a real one.
            max_entries: 8192,
        }
    }

    #[must_use]
    pub fn new(index: PackageIndex) -> Self {
        let cache = Self::empty();
        cache.install(index);
        cache
    }

    /// Publish a loaded index, once it is ready.
    ///
    /// Clears the memo: entries recorded while the index was still
    /// loading answered `Unknown`, and keeping them would make the
    /// index permanently useless for every binary that ran during
    /// startup — which on a booting host is most of them.
    pub fn install(&self, index: PackageIndex) {
        if let Ok(mut guard) = self.index.write() {
            *guard = index;
        }
        if let Ok(mut memo) = self.memo.lock() {
            memo.clear();
        }
    }

    /// Is an index loaded yet?
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.index.read().is_ok_and(|i| i.is_available())
    }

    /// Executables indexed, for startup logging.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.read().map_or(0, |i| i.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Provenance of `path`, whose current contents hash to `sha`.
    ///
    /// `sha` is the SHA-256 the pipeline already computed, used here
    /// only as a cache key — the comparison against the package
    /// manager's record is still md5, because that is what dpkg stores.
    #[must_use]
    pub fn classify(&self, path: &Path, sha: &[u8; 32]) -> Provenance {
        let Ok(index) = self.index.read() else {
            return Provenance::Unknown;
        };
        if !index.is_available() {
            // Still loading, or no package database. Either way the
            // question cannot be answered, and Unknown damps nothing.
            return Provenance::Unknown;
        }
        if let Ok(memo) = self.memo.lock()
            && let Some((cached_sha, provenance)) = memo.get(path)
            && cached_sha == sha
        {
            return *provenance;
        }
        let provenance = index.classify(path, file_md5(path));
        if let Ok(mut memo) = self.memo.lock() {
            // Crude eviction: a host that legitimately runs 8192
            // distinct binaries is rare, and re-hashing after a clear is
            // cheaper than tracking recency.
            if memo.len() >= self.max_entries {
                memo.clear();
            }
            memo.insert(path.to_path_buf(), (*sha, provenance));
        }
        provenance
    }
}

/// Is this file setuid- or setgid-root?
///
/// Returns `(setuid, setgid)`. `None` when the file cannot be stat'd,
/// which is not evidence of anything.
#[must_use]
pub fn setid_bits(path: &Path) -> Option<(bool, bool)> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(path).ok()?;
    let mode = md.mode();
    // Only root-owned set-id matters here. A setuid binary owned by an
    // unprivileged user grants that user's own authority, which is not
    // an escalation.
    let root_owned = md.uid() == 0;
    Some((
        root_owned && mode & 0o4000 != 0,
        root_owned && mode & 0o2000 != 0,
    ))
}

/// Does a set-id binary at this provenance warrant an alert?
///
/// A setuid-root binary is how an unprivileged process becomes root, so
/// the distribution ships a short, well-known list of them: `sudo`,
/// `su`, `passwd`, `mount`, `ping`. Those are expected and silent.
///
/// One that **no package owns**, or one that a package owns but no
/// longer matches, is a different thing entirely: it is the classic way
/// a foothold is made permanent, and it survives every reboot without
/// touching a service file.
///
/// Returns `None` when there is nothing to say.
#[must_use]
pub fn setid_finding(
    setuid: bool,
    setgid: bool,
    provenance: Provenance,
) -> Option<(&'static str, f32, &'static str)> {
    if !setuid && !setgid {
        return None;
    }
    match provenance {
        // The distro's own sudo/su/passwd. Expected, and saying so on
        // every invocation would bury everything else.
        Provenance::PackagedIntact => None,
        Provenance::PackagedModified => Some((
            "privesc.setid_packaged_modified",
            1.0,
            "a setuid-root binary that a package owns no longer matches what the package              installed — a backdoored privilege-escalation path that looks legitimate in              any file listing",
        )),
        Provenance::Unpackaged => Some((
            "privesc.setid_unpackaged",
            0.95,
            "a setuid-root binary that no package owns. Distributions ship a short,              well-known set of these; one that arrived any other way is how a foothold              becomes permanent root without touching a service file",
        )),
        // Cannot establish provenance, so cannot say whether this is
        // `sudo` or a backdoor. Silence here would hide the finding on
        // any host without a package manager, so it is reported quietly.
        Provenance::Unknown => Some((
            "privesc.setid_unknown_provenance",
            0.6,
            "a setuid-root binary whose provenance could not be established; confirm it              is one your distribution ships",
        )),
    }
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
    fn a_packaged_setuid_binary_is_silent() {
        // sudo, su, passwd and mount are setuid-root by design. Alerting
        // on them would fire on every privilege escalation a human
        // performs and bury everything else.
        assert!(setid_finding(true, false, Provenance::PackagedIntact).is_none());
    }

    #[test]
    fn an_unpackaged_setuid_binary_is_a_finding() {
        let (id, severity, why) =
            setid_finding(true, false, Provenance::Unpackaged).expect("must alert");
        assert_eq!(id, "privesc.setid_unpackaged");
        assert!(severity > 0.9);
        assert!(why.contains("no package owns"));
    }

    #[test]
    fn a_modified_packaged_setuid_binary_is_the_worst_case() {
        // Looks legitimate in any listing, and is root.
        let (_, severity, _) =
            setid_finding(true, false, Provenance::PackagedModified).expect("must alert");
        assert!((severity - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn a_binary_with_no_setid_bits_says_nothing() {
        for p in [
            Provenance::Unpackaged,
            Provenance::PackagedIntact,
            Provenance::PackagedModified,
            Provenance::Unknown,
        ] {
            assert!(setid_finding(false, false, p).is_none());
        }
    }

    #[test]
    fn setgid_counts_too_but_only_when_root_owned() {
        assert!(setid_finding(false, true, Provenance::Unpackaged).is_some());
        // The root-owned check lives in `setid_bits`; a setuid binary
        // owned by an unprivileged user grants only that user's own
        // authority, which is not an escalation.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("plain");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(setid_bits(&f), Some((false, false)));
        assert_eq!(setid_bits(Path::new("/nonexistent/binary")), None);
    }

    #[test]
    fn the_cache_applies_at_every_execution_not_just_the_first() {
        // The shipped bug: provenance was gated on baseline_seen_count
        // == 0, but rarity stays above the alert threshold for the first
        // several runs (0.89, 0.80, 0.73). /usr/bin/column alerted at
        // 0.80 on a host whose index had loaded fine.
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("nice");
        std::fs::write(&bin, b"binary contents").unwrap();
        let md5 = file_md5(&bin).unwrap();

        let mut by_path = HashMap::new();
        by_path.insert(bin.clone(), md5);
        let index = PackageIndex {
            by_path,
            available: true,
        };
        let cache = ProvenanceCache::new(index);
        let sha = [7u8; 32];

        // Every call answers, however many times it has run before.
        for _ in 0..5 {
            assert_eq!(cache.classify(&bin, &sha), Provenance::PackagedIntact);
        }
    }

    #[test]
    fn an_unloaded_cache_answers_unknown_and_damps_nothing() {
        // Startup must not block on the index, so there is a window
        // where it has not arrived. Unknown is the honest answer and
        // leaves scores alone.
        let cache = ProvenanceCache::empty();
        assert!(!cache.is_ready());
        assert_eq!(
            cache.classify(Path::new("/usr/bin/nice"), &[0u8; 32]),
            Provenance::Unknown
        );
        let (score, _) = adjust_score(1.0, Provenance::Unknown);
        assert!((score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn installing_an_index_clears_answers_given_while_it_loaded() {
        // Otherwise every binary that ran during startup — on a booting
        // host, most of them — would be permanently memoised as Unknown
        // and the index would never apply to them.
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("nice");
        std::fs::write(&bin, b"contents").unwrap();
        let md5 = file_md5(&bin).unwrap();

        let cache = ProvenanceCache::empty();
        let sha = [3u8; 32];
        assert_eq!(cache.classify(&bin, &sha), Provenance::Unknown);

        let mut by_path = HashMap::new();
        by_path.insert(bin.clone(), md5);
        cache.install(PackageIndex {
            by_path,
            available: true,
        });

        assert!(cache.is_ready());
        assert_eq!(
            cache.classify(&bin, &sha),
            Provenance::PackagedIntact,
            "the stale Unknown must not survive the install"
        );
    }

    #[test]
    fn a_changed_binary_invalidates_its_cache_entry() {
        // Otherwise the memo would keep vouching for a file that has
        // since been rewritten — turning the cache into a way to hide
        // exactly what the index exists to catch.
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("nice");
        std::fs::write(&bin, b"original").unwrap();
        let md5 = file_md5(&bin).unwrap();

        let mut by_path = HashMap::new();
        by_path.insert(bin.clone(), md5);
        let cache = ProvenanceCache::new(PackageIndex {
            by_path,
            available: true,
        });

        assert_eq!(cache.classify(&bin, &[1u8; 32]), Provenance::PackagedIntact);

        // Contents replaced: new sha, and the file no longer matches.
        std::fs::write(&bin, b"trojanised").unwrap();
        assert_eq!(
            cache.classify(&bin, &[2u8; 32]),
            Provenance::PackagedModified,
            "a new sha must force a re-read rather than reuse the memo"
        );
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
