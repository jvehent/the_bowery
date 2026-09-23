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
use std::time::{Duration, SystemTime};

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
    /// Path → owning package name.
    ///
    /// Free to collect: the name is the `.md5sums` filename that was
    /// already being read. Retained because it is the one identity that
    /// survives an architecture boundary — two hosts running the same
    /// distro have `dash` from package `dash` whether they are x86-64 or
    /// aarch64, while the file's hash differs on both. That makes it the
    /// first dimension the fuzzy corroboration work can actually compare
    /// across a mixed fleet; see DESIGN-FUZZY-CORROBORATION.md §3.1.
    pkg_by_path: HashMap<PathBuf, String>,
    /// Distinct package names, for "is this installed at all".
    ///
    /// Kept beside `pkg_by_path` rather than derived from it because
    /// the derivation is a scan. Measured on a live host the map holds
    /// 54,919 entries, and the whisper responder consults this once per
    /// question — a peer asking in a loop would otherwise buy a 55,000
    /// string comparisons apiece. The distinct names are a couple of
    /// thousand, so the set is small next to what it indexes.
    pkg_names: std::collections::HashSet<String>,
    /// Absolute path → the package that registers it as a *conffile*.
    ///
    /// dpkg records these in `<pkg>.conffiles` beside the `.md5sums`
    /// this index was already reading. A conffile is a file the package
    /// manager owns and is expected to rewrite during an upgrade:
    /// `/etc/sudoers` belongs to `sudo`, `/etc/pam.d/*` to the PAM
    /// packages. That ownership is what separates "dpkg is installing
    /// the package this file belongs to" from "something is editing the
    /// sudo policy".
    conffiles: HashMap<PathBuf, String>,
    /// When this snapshot was taken, so that a stale one can decline to
    /// accuse — see [`DbStamp`]. `None` for an index built in memory,
    /// or from a directory whose state could not be stat'd; neither can
    /// be checked for drift, so neither downgrades anything.
    stamp: Option<DbStamp>,
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
        // Helper binaries under a package's own lib directory, in both
        // spellings: dpkg records `lib/systemd/systemd` on a merged-/usr
        // host and `usr/lib/openssh/sftp-server` on the same one, because
        // it writes whatever the package shipped. Dropping the aliased
        // form here would discard the entry before `merged_usr_alias`
        // ever saw it.
        || ((rel.starts_with("usr/lib/") || rel.starts_with("lib/")) && !rel.contains(".so"))
}

/// The `/usr`-prefixed spelling of a path dpkg recorded under an
/// aliased directory, or `None` when there is no alias.
///
/// # Why this is necessary rather than cosmetic
///
/// On a merged-`/usr` system — every current Debian and Ubuntu —
/// `/bin`, `/sbin` and `/lib` are symlinks into `/usr`. dpkg records
/// paths **as the package shipped them**, so `systemd` appears in
/// `md5sums` as `lib/systemd/systemd`. But provenance looks a binary up
/// by the path `/proc/<pid>/exe` reports, and that is the *resolved*
/// real path: `/usr/lib/systemd/systemd`. The two spellings name one
/// file and never compare equal, so every such binary classified as
/// `Unpackaged`.
///
/// That was not a rare corner. On a live Debian 12 host, **16,975 of
/// 146,517** `md5sums` entries — 12% — are recorded under the aliased
/// directories, and the misclassification is silent and expensive in
/// both directions: rarity damping never applies, and worse,
/// [`setid_finding`] reports `privesc.setid_unpackaged` at 0.95 for a
/// setuid binary the distribution itself installed under `/sbin`.
///
/// Found by a live agent alerting on `/usr/lib/systemd/systemd` reading
/// `/etc/shadow` *after* that path had been added to the sanctioned
/// readers — the exemption also requires `PackagedIntact`, so the
/// provenance bug kept the finding alive and made itself visible.
///
/// Both spellings are inserted rather than one rewritten: on a system
/// that has *not* merged `/usr`, the two are genuinely different files
/// and the alias simply never matches anything.
fn merged_usr_alias(rel: &str) -> Option<PathBuf> {
    const ALIASED: [&str; 3] = ["bin/", "sbin/", "lib/"];
    ALIASED
        .iter()
        .any(|d| rel.starts_with(d))
        .then(|| PathBuf::from("/usr").join(rel))
}

/// The state of the package database at the moment an index was read.
///
/// # Why a snapshot has to know when it was taken
///
/// [`PackageIndex::load_dpkg`] is a snapshot of a database that keeps
/// moving. Every `apt upgrade` rewrites the `.md5sums` of each upgraded
/// package, so afterwards the binaries from those packages no longer
/// match the digests an *earlier* snapshot recorded — and
/// [`PackageIndex::classify`] reports precisely that as
/// [`Provenance::PackagedModified`], the strongest finding this file
/// can produce.
///
/// Measured on a live host, not imagined: an agent running since 24 Aug
/// saw 129 packages upgraded from 2 Sep onwards, and then reported
/// every execution of `cp`, `tr`, `date`, `rm` and seventy other
/// coreutils as a modified system binary — 8,432 alerts, 98% of
/// everything it produced in thirty days. The detection did not merely
/// get loud: a genuinely trojanised binary would have been
/// indistinguishable from `cp`.
///
/// So the snapshot carries its own provenance, and a "modified" verdict
/// drawn from a snapshot the database has since moved past is
/// downgraded to [`Provenance::Unknown`]. *Cannot establish* and *was
/// tampered with* are opposite claims, and one must never be served in
/// place of the other.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DbStamp {
    /// The `info/` directory the `.md5sums` files were read from.
    dir: PathBuf,
    /// mtimes of that directory and of dpkg's `status` file, kept
    /// apart rather than reduced. Their *maximum* was the first
    /// attempt, and it cannot see a timestamp move backwards: a
    /// database restored from a backup left the larger of the two
    /// unchanged and read as in-step. Caught by the test below, which
    /// steps `status` backwards precisely because that is the case a
    /// summary statistic loses.
    mtimes: [Option<SystemTime>; 2],
}

/// How long after the package database was last written a transaction
/// still counts as running.
///
/// dpkg touches `status` at every step of an unpack and configure, so
/// this only has to span the gap *between* packages, not a whole
/// upgrade. Long enough that a slow maintainer script does not end the
/// window early; short enough that it closes minutes after `apt`
/// finishes rather than vouching for the rest of the afternoon.
const TRANSACTION_WINDOW: Duration = Duration::from_mins(2);

/// A cheap fingerprint of dpkg's state: two stats, no directory walk.
///
/// Both halves earn their place. `status` is rewritten on every install,
/// removal and configure; the `info/` directory's own mtime moves when
/// dpkg creates and renames the per-package `.md5sums` files that an
/// upgrade replaces. Either one alone misses cases the other catches.
fn dpkg_mtimes(info_dir: &Path) -> [Option<SystemTime>; 2] {
    let mtime = |p: PathBuf| std::fs::metadata(p).ok()?.modified().ok();
    [
        mtime(info_dir.to_path_buf()),
        info_dir.parent().map(|p| p.join("status")).and_then(mtime),
    ]
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
        // Read the database's state *before* the entries, never after.
        // A package upgraded while the loop below runs would otherwise
        // be stamped as already-included, leaving the index looking
        // fresh while missing it. A false "fresh" is the entire bug
        // this mechanism exists to prevent; a false "stale" costs one
        // reload.
        let mtimes = dpkg_mtimes(dir);
        let stamp = mtimes.iter().any(Option::is_some).then(|| DbStamp {
            dir: dir.to_path_buf(),
            mtimes,
        });
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Self::unavailable();
        };
        let mut by_path = HashMap::new();
        let mut pkg_by_path: HashMap<PathBuf, String> = HashMap::new();
        let mut pkg_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut conffiles: HashMap<PathBuf, String> = HashMap::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let kind = path.extension().and_then(|e| e.to_str());
            if !matches!(kind, Some("md5sums" | "conffiles")) {
                continue;
            }
            // `coreutils.md5sums` and `coreutils:amd64.md5sums` both
            // name the package `coreutils`; the architecture qualifier
            // is exactly what must not be part of an identity meant to
            // compare across architectures.
            let pkg = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.split(':').next().unwrap_or(s).to_string());
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if kind == Some("conffiles") {
                // One absolute path per line. Newer dpkg appends a flag
                // (`remove-on-upgrade`), so take the first field only.
                if let Some(pkg) = pkg.clone() {
                    for line in text.lines() {
                        let Some(file) = line.split_whitespace().next() else {
                            continue;
                        };
                        if file.starts_with('/') {
                            conffiles.insert(PathBuf::from(file), pkg.clone());
                        }
                    }
                }
                continue;
            }
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
                let abs = PathBuf::from("/").join(rel);
                if let Some(pkg) = pkg.clone() {
                    pkg_names.insert(pkg.clone());
                    pkg_by_path.insert(abs.clone(), pkg);
                }
                by_path.insert(abs, md5);
                // ...and again under merged-`/usr`, which is how the
                // file will actually be named when we look it up.
                if let Some(alias) = merged_usr_alias(rel) {
                    if let Some(pkg) = pkg.clone() {
                        pkg_by_path.insert(alias.clone(), pkg);
                    }
                    by_path.insert(alias, md5);
                }
            }
        }
        Self {
            by_path,
            pkg_by_path,
            pkg_names,
            conffiles,
            stamp,
            available: true,
        }
    }

    /// Build an index directly from `(path, package, digest)` triples.
    ///
    /// The seam that makes [`Provenance::PackagedModified`] reachable
    /// from a test. [`Self::load_dpkg`] indexes only paths under the
    /// system's own binary directories — that filter is what keeps the
    /// index small enough for a Pi — so the sole other way to produce a
    /// mismatch is to rewrite a real binary in `/usr/bin`, which no
    /// test has any business doing.
    ///
    /// Carries no stamp, so [`Self::database_moved`] is false and an
    /// index built this way never downgrades its own answers.
    #[must_use]
    pub fn from_entries<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = (PathBuf, S, [u8; 16])>,
        S: Into<String>,
    {
        let mut by_path = HashMap::new();
        let mut pkg_by_path = HashMap::new();
        let mut pkg_names = std::collections::HashSet::new();
        for (path, pkg, digest) in entries {
            let pkg = pkg.into();
            pkg_names.insert(pkg.clone());
            pkg_by_path.insert(path.clone(), pkg);
            by_path.insert(path, digest);
        }
        Self {
            by_path,
            pkg_by_path,
            pkg_names,
            conffiles: HashMap::new(),
            stamp: None,
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

    /// The package that owns `path`, if any.
    ///
    /// `None` covers both "no package owns it" and "there is no package
    /// database", which are different facts — [`Self::classify`] is
    /// where that distinction is drawn, and it stays there rather than
    /// being duplicated with a third spelling here.
    #[must_use]
    pub fn package_for(&self, path: &Path) -> Option<&str> {
        if !self.available {
            return None;
        }
        self.pkg_by_path.get(path).map(String::as_str)
    }

    /// Is this package installed here at all?
    ///
    /// Answers from the package database rather than from what has
    /// executed, and that difference is the point. A host's baseline
    /// only knows programs it has *run*: measured on the fleet, a peer
    /// asked about `/usr/bin/hostname` could not recognise it despite
    /// having the file, because it had never executed it. The package
    /// database knows what is *installed*, which is the honest answer
    /// to "do you have this program".
    #[must_use]
    pub fn has_package(&self, name: &str) -> bool {
        if !self.available || name.is_empty() {
            return false;
        }
        self.pkg_names.contains(name)
    }

    /// Is anything installed at this path?
    #[must_use]
    pub fn has_path(&self, path: &Path) -> bool {
        self.available && self.by_path.contains_key(path)
    }

    /// The package that registers `path` as a conffile, if any.
    #[must_use]
    pub fn conffile_package(&self, path: &Path) -> Option<&str> {
        if !self.available {
            return None;
        }
        self.conffiles.get(path).map(String::as_str)
    }

    /// Is the package manager in the middle of a transaction?
    ///
    /// dpkg rewrites `status` continuously while unpacking and
    /// configuring, so "the database was written moments ago" is a
    /// reliable, name-free way to know a transaction is running. The
    /// window is generous enough to span the gaps between one package
    /// finishing and the next starting.
    ///
    /// `false` when there is no stamp to name the directory, and when
    /// the newest mtime is in the future — a clock that disagrees with
    /// the filesystem is not evidence of an upgrade, and the
    /// conservative answer keeps the finding alive.
    #[must_use]
    pub fn transaction_active(&self) -> bool {
        let Some(stamp) = self.stamp.as_ref() else {
            return false;
        };
        let Some(newest) = dpkg_mtimes(&stamp.dir).into_iter().flatten().max() else {
            return false;
        };
        SystemTime::now()
            .duration_since(newest)
            .is_ok_and(|age| age <= TRANSACTION_WINDOW)
    }

    /// Has the package database changed since this index was read?
    ///
    /// Two stats, and the answer that decides whether a mismatch is
    /// allowed to be called tampering — see [`DbStamp`].
    ///
    /// Inequality rather than "newer than": a database restored from a
    /// backup, or a clock that stepped backwards, has moved out from
    /// under the snapshot just as surely as one that was upgraded, and
    /// `>` would wave both through.
    ///
    /// `false` only when there is no stamp at all — an index built in
    /// memory, or read from a directory that could not be stat'd even
    /// then. Those could never be checked, and absence of evidence is
    /// not evidence of change; treating it as such would silently
    /// disable the modified-binary finding on every such host. But once
    /// a state *has* been recorded, any deviation from it counts,
    /// including the database becoming unreadable: a snapshot whose
    /// freshness can no longer be confirmed is one that cannot accuse.
    #[must_use]
    pub fn database_moved(&self) -> bool {
        let Some(stamp) = self.stamp.as_ref() else {
            return false;
        };
        dpkg_mtimes(&stamp.dir) != stamp.mtimes
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
        let provenance = match index.classify(path, file_md5(path)) {
            // A packaged file that no longer matches is the strongest
            // claim this module makes, so it is the one answer worth
            // two extra stats to be sure of — and the rarest, which is
            // why the check sits here rather than on the hot path. If
            // the database has moved since this index was read, the
            // mismatch is at least as likely an upgrade as a tamper,
            // and the honest answer is that we cannot tell.
            Provenance::PackagedModified if index.database_moved() => Provenance::Unknown,
            other => other,
        };
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

    /// The package owning `path`, as far as the loaded index knows.
    ///
    /// `None` while the index is still loading, which is why callers
    /// must treat it as "not known yet" and never as "unpackaged" — the
    /// index takes seconds to read on a large host, and most of what a
    /// booting machine executes runs inside that window.
    #[must_use]
    pub fn package_for(&self, path: &Path) -> Option<String> {
        self.index
            .read()
            .ok()
            .and_then(|i| i.package_for(path).map(str::to_string))
    }

    /// Is this package installed on this host?
    #[must_use]
    pub fn has_package(&self, name: &str) -> bool {
        self.index.read().is_ok_and(|i| i.has_package(name))
    }

    /// Is anything installed at this path?
    #[must_use]
    pub fn has_path(&self, path: &Path) -> bool {
        self.index.read().is_ok_and(|i| i.has_path(path))
    }

    /// Is this file finding the package manager doing its own job?
    ///
    /// Returns the explanation when it is, so the damping an operator
    /// sees can be read back rather than guessed at.
    ///
    /// # What this is for
    ///
    /// `unattended-upgrades` upgrading the `sudo` package has dpkg
    /// rewrite `/etc/sudoers`, and three rules fire on it —
    /// `privesc.sudoers` at 0.95, the `sudoers` file rule at 0.90 and
    /// `recon.read_sudoers` at 0.70. That is the package manager
    /// installing the package the file belongs to, on a schedule the
    /// distribution set, and it happens on every Ubuntu host there is.
    /// Traced on otter1: `apt.systemd.daily` → `unattended-upgrade` →
    /// `dpkg --unpack sudo_1.9.15p5-3ubuntu5.24.04_amd64.deb`.
    ///
    /// Three conditions, all required, and none of them a name:
    ///
    /// - the path is a **registered conffile**, so some package is
    ///   entitled to rewrite it;
    /// - a **transaction is running**, so the entitlement is being
    ///   exercised now and not at three in the morning;
    /// - the actor, where one could be identified, is **packaged and
    ///   unmodified**.
    ///
    /// `actor` is `None` on the inotify path, which sees that a file
    /// changed without ever seeing who changed it. The other two
    /// conditions still have to hold.
    ///
    /// # The gap this leaves
    ///
    /// A maintainer script from a malicious `.deb` runs inside a real
    /// transaction, as a packaged binary, writing a real conffile. It
    /// is indistinguishable from a legitimate one by construction and
    /// nothing here closes that. Which is why this damps rather than
    /// silences: the access is recorded either way and stays
    /// queryable, and an operator reading the rationale is told exactly
    /// which entitlement was credited.
    #[must_use]
    pub fn housekeeping(&self, path: &Path, actor: Option<Provenance>) -> Option<String> {
        // An actor we *could* identify has to be one a package vouches
        // for. Anchored on provenance rather than on a name, for the
        // same reason the credential-reader exemptions are: `comm` is
        // sixteen bytes any process sets to whatever it likes.
        if matches!(actor, Some(p) if p != Provenance::PackagedIntact) {
            return None;
        }
        let index = self.index.read().ok()?;
        let pkg = index.conffile_package(path)?.to_string();
        if !index.transaction_active() {
            return None;
        }
        Some(match actor {
            Some(_) => format!(
                "damped: a package transaction is running and this is a conffile of \
                 `{pkg}`, touched by a binary the package manager vouches for"
            ),
            None => format!(
                "damped: a package transaction is running and this is a conffile of \
                 `{pkg}`; the watcher sees the change without seeing who made it"
            ),
        })
    }

    /// Has the package database changed since the loaded index was read?
    ///
    /// What the agent's refresher polls. Two stats, so it can be asked
    /// often; [`PackageIndex::database_moved`] carries the reasoning.
    #[must_use]
    pub fn database_moved(&self) -> bool {
        self.index.read().is_ok_and(|i| i.database_moved())
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

/// Every rule id this module can return.
///
/// Hand-maintained alongside the matches below; the test at the bottom
/// of this module proves the two agree.
#[must_use]
pub const fn rule_ids() -> &'static [&'static str] {
    &[
        MODIFIED_RULE,
        "privesc.setid_packaged_modified",
        "privesc.setid_unpackaged",
        "privesc.setid_unknown_provenance",
    ]
}

/// Rule id for a packaged binary whose contents no longer match.
pub const MODIFIED_RULE: &str = "integrity.packaged_modified";

/// A packaged binary that no longer matches its package, where no
/// set-id bit makes [`setid_finding`] the more specific description.
///
/// # Why this needed an id of its own
///
/// The adjustment in [`adjust_score`] raised suspicion to 1.0 without
/// recording a rule hit, so the alert was attributed to whatever score
/// it had overwritten — `baseline.rarity`. Thirty days of "a system
/// binary was rewritten" findings therefore reached the operator
/// labelled "this host has not run this before". The two call for
/// completely different responses, and only one of them is urgent.
///
/// The severity matches [`setid_finding`]'s modified case: the set-id
/// bit changes what an attacker gains, not whether the file was
/// rewritten.
#[must_use]
pub const fn modified_finding() -> (&'static str, f32, &'static str) {
    (
        MODIFIED_RULE,
        1.0,
        "a binary owned by a package no longer matches what the package installed, and              the package database has not changed since this index was read — something              rewrote a system binary",
    )
}

/// Is this binary a privilege helper the distribution vouches for?
///
/// The sanctioned path to root: `sudo`, `su`, `pkexec`, `newgrp`,
/// `doas`. Both halves are required — setuid-root *and* owned by a
/// package whose contents still match — so a binary merely *named*
/// `sudo`, or a trojanised real one, is not a helper.
#[must_use]
pub fn is_privilege_helper(setuid: bool, provenance: Provenance) -> bool {
    setuid && provenance == Provenance::PackagedIntact
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

/// How much a finding is damped when it is package-manager housekeeping.
///
/// The same factor [`adjust_score`] uses for a packaged, unmodified
/// binary, and for the same reason: enough to drop routine housekeeping
/// below any sane alert threshold, not so much that the finding stops
/// existing. 0.95 becomes 0.14.
#[must_use]
pub fn damp_housekeeping(severity: f32) -> f32 {
    severity * 0.15
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
mod package_lookup_tests {
    use super::*;

    /// Build an index the way `load_dpkg` would, without touching disk.
    fn index_with(entries: &[(&str, &str)]) -> PackageIndex {
        let mut by_path = HashMap::new();
        let mut pkg_by_path = HashMap::new();
        let mut pkg_names = std::collections::HashSet::new();
        for (path, pkg) in entries {
            by_path.insert(PathBuf::from(path), [0u8; 16]);
            pkg_by_path.insert(PathBuf::from(path), (*pkg).to_string());
            pkg_names.insert((*pkg).to_string());
        }
        PackageIndex {
            by_path,
            pkg_by_path,
            pkg_names,
            conffiles: HashMap::new(),
            stamp: None,
            available: true,
        }
    }

    #[test]
    fn an_installed_package_is_recognised_by_name() {
        let idx = index_with(&[
            ("/usr/bin/ls", "coreutils"),
            ("/usr/bin/cat", "coreutils"),
            ("/usr/bin/dash", "dash"),
        ]);
        assert!(idx.has_package("coreutils"));
        assert!(idx.has_package("dash"));
        assert!(!idx.has_package("nothing-here"));
        assert!(
            !idx.has_package(""),
            "an unknown package is not every package"
        );
        assert!(idx.has_path(Path::new("/usr/bin/ls")));
        assert!(!idx.has_path(Path::new("/tmp/dropped")));
    }

    /// Without an index, "not installed" and "cannot tell" are the same
    /// answer here — and both must be `false`, never a claim.
    #[test]
    fn an_unavailable_index_recognises_nothing() {
        let idx = PackageIndex::unavailable();
        assert!(!idx.has_package("coreutils"));
        assert!(!idx.has_path(Path::new("/usr/bin/ls")));
    }

    /// The lookup must not be a scan of the path map.
    ///
    /// The whisper responder calls this once per question, and on a
    /// live host the path map holds 54,919 entries — measured, not
    /// estimated. A peer asking in a loop would otherwise buy 55,000
    /// string comparisons apiece on the answering side, which is a cost
    /// the asker chooses and the responder pays.
    ///
    /// Asserted as a bound on work rather than on time: a name set of
    /// one, over a path map of many, is only possible if the two are
    /// stored apart.
    #[test]
    fn the_package_lookup_does_not_scale_with_the_path_map() {
        let entries: Vec<(String, String)> = (0..50_000)
            .map(|i| (format!("/usr/bin/prog{i}"), "coreutils".to_string()))
            .collect();
        let refs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(p, k)| (p.as_str(), k.as_str()))
            .collect();
        let idx = index_with(&refs);

        assert_eq!(idx.pkg_by_path.len(), 50_000, "the path map is large");
        assert_eq!(
            idx.pkg_names.len(),
            1,
            "and the name set is not, which is the whole point"
        );
        assert!(idx.has_package("coreutils"));
        assert!(!idx.has_package("absent"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The set-id rule ids are enumerated by hand for the ATT&CK map;
    /// prove they match what `setid_finding` returns for every possible
    /// provenance.
    #[test]
    fn rule_ids_matches_what_setid_finding_can_return() {
        use std::collections::HashSet;
        let reachable: HashSet<&str> = [
            Provenance::PackagedIntact,
            Provenance::PackagedModified,
            Provenance::Unpackaged,
            Provenance::Unknown,
        ]
        .into_iter()
        .filter_map(|p| setid_finding(true, false, p).map(|(id, _, _)| id))
        .chain(std::iter::once(modified_finding().0))
        .collect();
        let declared: HashSet<&str> = rule_ids().iter().copied().collect();
        assert_eq!(reachable, declared);
    }

    /// The merged-`/usr` bug, in the exact shape a live agent hit it.
    ///
    /// dpkg records `lib/systemd/systemd`; `/proc/<pid>/exe` reports
    /// `/usr/lib/systemd/systemd`, because `/lib` is a symlink into
    /// `/usr`. Before this, that binary — and 12% of every packaged file
    /// on a Debian host — classified as `Unpackaged`.
    #[test]
    fn a_binary_dpkg_recorded_under_aliased_lib_is_found_by_its_usr_path() {
        let dir = tempfile::tempdir().unwrap();
        write_md5sums(
            dir.path(),
            "systemd",
            &[&format!("{NICE_MD5}  lib/systemd/systemd")],
        );
        let idx = PackageIndex::load_dpkg(dir.path());
        assert_eq!(
            idx.classify(Path::new("/usr/lib/systemd/systemd"), Some(nice_bytes())),
            Provenance::PackagedIntact,
            "the resolved merged-/usr path must resolve to the package"
        );
        // And the spelling dpkg recorded, for a host that never merged.
        assert_eq!(
            idx.classify(Path::new("/lib/systemd/systemd"), Some(nice_bytes())),
            Provenance::PackagedIntact
        );
    }

    /// `/sbin` aliases the same way, and this is the expensive case: a
    /// packaged setuid binary misread as unpackaged is not a missed
    /// suppression but a fabricated 0.95 finding.
    #[test]
    fn an_aliased_sbin_binary_does_not_fabricate_a_setid_finding() {
        let dir = tempfile::tempdir().unwrap();
        write_md5sums(
            dir.path(),
            "shadow",
            &[&format!("{NICE_MD5}  sbin/unix_chkpwd")],
        );
        let idx = PackageIndex::load_dpkg(dir.path());
        let provenance = idx.classify(Path::new("/usr/sbin/unix_chkpwd"), Some(nice_bytes()));
        assert_eq!(provenance, Provenance::PackagedIntact);
        assert!(
            setid_finding(true, false, provenance).is_none(),
            "the distribution's own setuid helper must stay silent"
        );
    }

    /// The alias must not launder a modified file into an intact one.
    #[test]
    fn the_alias_still_compares_contents() {
        let dir = tempfile::tempdir().unwrap();
        write_md5sums(
            dir.path(),
            "systemd",
            &[&format!("{NICE_MD5}  lib/systemd/systemd")],
        );
        let idx = PackageIndex::load_dpkg(dir.path());
        assert_eq!(
            idx.classify(Path::new("/usr/lib/systemd/systemd"), Some([0xab; 16])),
            Provenance::PackagedModified,
            "a rewritten binary must be a finding, whichever spelling found it"
        );
    }

    #[test]
    fn only_the_aliased_directories_gain_a_usr_prefix() {
        assert_eq!(
            merged_usr_alias("sbin/unix_chkpwd"),
            Some(PathBuf::from("/usr/sbin/unix_chkpwd"))
        );
        assert_eq!(
            merged_usr_alias("bin/su"),
            Some(PathBuf::from("/usr/bin/su"))
        );
        assert_eq!(merged_usr_alias("usr/bin/sudo"), None, "no double /usr");
        assert_eq!(merged_usr_alias("etc/passwd"), None);
    }

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
            pkg_by_path: HashMap::new(),
            pkg_names: std::collections::HashSet::new(),
            conffiles: HashMap::new(),
            stamp: None,
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
            pkg_by_path: HashMap::new(),
            pkg_names: std::collections::HashSet::new(),
            conffiles: HashMap::new(),
            stamp: None,
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
            pkg_by_path: HashMap::new(),
            pkg_names: std::collections::HashSet::new(),
            by_path,
            conffiles: HashMap::new(),
            stamp: None,
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

    /// Build a dpkg layout: `<root>/info/` beside `<root>/status`.
    fn dpkg_layout() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let info = root.path().join("info");
        std::fs::create_dir(&info).unwrap();
        std::fs::write(root.path().join("status"), b"Package: coreutils\n").unwrap();
        (root, info)
    }

    /// Move a file's mtime to a known instant, so drift is exact rather
    /// than a race against filesystem timestamp granularity.
    fn set_mtime(path: &Path, at: SystemTime) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(at))
            .unwrap();
    }

    /// The thirty-day false-positive storm, in one test.
    ///
    /// An agent's index was read on 24 Aug; 129 packages were upgraded
    /// from 2 Sep onwards; every execution of `cp`, `tr`, `date` and
    /// seventy others then reported a rewritten system binary, at
    /// suspicion 1.0, forever. 8,432 alerts — 98% of everything the
    /// host produced.
    ///
    /// The contrast is the whole point: the *same* file, with the
    /// *same* mismatch, is a finding from a current snapshot and an
    /// admission of ignorance from a stale one.
    #[test]
    fn a_mismatch_from_a_stale_snapshot_is_not_an_accusation() {
        let (root, info) = dpkg_layout();
        let bin = root.path().join("cp");
        std::fs::write(&bin, b"the packaged contents").unwrap();
        let packaged = file_md5(&bin).unwrap();

        let mut by_path = HashMap::new();
        by_path.insert(bin.clone(), packaged);
        let snapshot_taken_at = |mtimes| PackageIndex {
            by_path: by_path.clone(),
            pkg_by_path: HashMap::new(),
            pkg_names: std::collections::HashSet::new(),
            conffiles: HashMap::new(),
            stamp: Some(DbStamp {
                dir: info.clone(),
                mtimes,
            }),
            available: true,
        };

        // `apt upgrade`: the binary's contents change, and so does the
        // database that says what they should be.
        std::fs::write(&bin, b"the upgraded contents").unwrap();

        let current = ProvenanceCache::new(snapshot_taken_at(dpkg_mtimes(&info)));
        assert_eq!(
            current.classify(&bin, &[9u8; 32]),
            Provenance::PackagedModified,
            "a snapshot in step with the database must still report a mismatch — \
             this fix must not cost the detection it protects"
        );

        let stale = snapshot_taken_at([Some(SystemTime::UNIX_EPOCH); 2]);
        assert!(stale.database_moved());
        let outdated = ProvenanceCache::new(stale);
        assert_eq!(
            outdated.classify(&bin, &[9u8; 32]),
            Provenance::Unknown,
            "a snapshot the database has moved past cannot tell an upgrade \
             from a tamper, and must say so"
        );
        let (score, _) = adjust_score(0.73, Provenance::Unknown);
        assert!(
            (score - 0.73).abs() < f32::EPSILON,
            "and Unknown must leave the score alone rather than force 1.0"
        );
    }

    /// A freshly loaded index sees the next package operation.
    #[test]
    fn a_loaded_index_notices_the_database_moving_underneath_it() {
        let (root, info) = dpkg_layout();
        std::fs::write(
            info.join("coreutils.md5sums"),
            format!("{NICE_MD5}  usr/bin/nice"),
        )
        .unwrap();

        let idx = PackageIndex::load_dpkg(&info);
        assert!(idx.is_available());
        assert!(!idx.database_moved(), "nothing has happened yet");

        // dpkg rewrites `status` on every install, removal and
        // configure. Backwards in time on purpose: a database restored
        // from a backup has moved just as surely as one upgraded, and
        // a "newer than" test would wave it through.
        set_mtime(
            &root.path().join("status"),
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
        );
        assert!(idx.database_moved(), "a package operation must be visible");
    }

    /// The degrade must not become a blanket off-switch.
    ///
    /// An index with nothing to compare against — built in memory, or
    /// loaded from a directory that cannot be stat'd — has no evidence
    /// the database moved, and absence of evidence must not silence the
    /// strongest finding in this module.
    #[test]
    fn an_index_that_cannot_check_for_drift_still_accuses() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("nice");
        std::fs::write(&bin, b"original").unwrap();
        let md5 = file_md5(&bin).unwrap();
        let mut by_path = HashMap::new();
        by_path.insert(bin.clone(), md5);
        let idx = PackageIndex {
            by_path,
            pkg_by_path: HashMap::new(),
            pkg_names: std::collections::HashSet::new(),
            conffiles: HashMap::new(),
            stamp: None,
            available: true,
        };
        assert!(!idx.database_moved(), "no stamp is not a change");

        std::fs::write(&bin, b"trojanised").unwrap();
        let cache = ProvenanceCache::new(idx);
        assert_eq!(
            cache.classify(&bin, &[1u8; 32]),
            Provenance::PackagedModified
        );

        // And a missing database records no stamp to begin with.
        assert!(!PackageIndex::load_dpkg(Path::new("/nonexistent/dpkg/info")).database_moved());
    }

    /// A rewritten system binary is its own finding, not a rare one.
    #[test]
    fn a_modified_binary_is_attributed_to_integrity_not_to_rarity() {
        // For thirty days these alerts reached the operator labelled
        // `baseline.rarity` — "this host has not run this before" —
        // because the provenance adjustment moved the score without
        // recording a rule hit. Different finding, different response.
        let (id, severity, why) = modified_finding();
        assert_eq!(id, "integrity.packaged_modified");
        assert_ne!(id, "baseline.rarity");
        assert!((severity - 1.0).abs() < f32::EPSILON);
        assert!(why.contains("rewrote a system binary"));
    }

    /// Build a dpkg layout whose database says a transaction is running.
    fn dpkg_with_conffile(pkg: &str, conffile: &str) -> (tempfile::TempDir, PackageIndex) {
        let root = tempfile::tempdir().unwrap();
        let info = root.path().join("info");
        std::fs::create_dir(&info).unwrap();
        std::fs::write(root.path().join("status"), b"Package: sudo\n").unwrap();
        std::fs::write(
            info.join(format!("{pkg}.conffiles")),
            format!("{conffile}\n"),
        )
        .unwrap();
        let idx = PackageIndex::load_dpkg(&info);
        (root, idx)
    }

    #[test]
    fn conffiles_are_read_alongside_the_digests() {
        let (_root, idx) = dpkg_with_conffile("sudo", "/etc/sudoers");
        assert_eq!(
            idx.conffile_package(Path::new("/etc/sudoers")),
            Some("sudo")
        );
        assert_eq!(idx.conffile_package(Path::new("/etc/passwd")), None);
        // Newer dpkg appends a flag; only the path is the path.
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("x.conffiles"),
            "/etc/foo.conf remove-on-upgrade\n",
        )
        .unwrap();
        let idx = PackageIndex::load_dpkg(root.path());
        assert_eq!(idx.conffile_package(Path::new("/etc/foo.conf")), Some("x"));
    }

    /// The exemption has to be *earned*, and provenance is what earns it.
    #[test]
    fn only_a_binary_the_package_manager_vouches_for_is_credited() {
        let (_root, idx) = dpkg_with_conffile("sudo", "/etc/sudoers");
        assert!(idx.transaction_active(), "the database was just written");
        let cache = ProvenanceCache::new(idx);
        let sudoers = Path::new("/etc/sudoers");

        assert!(
            cache
                .housekeeping(sudoers, Some(Provenance::PackagedIntact))
                .is_some(),
            "dpkg rewriting a conffile mid-upgrade is the upgrade"
        );
        assert!(
            cache.housekeeping(sudoers, None).is_some(),
            "the inotify path never sees an actor and must still be damped"
        );

        // The cases that must survive. A rewritten binary editing the
        // sudo policy during an upgrade is *more* interesting, not
        // less, and an unpackaged one has no entitlement at all.
        for actor in [
            Provenance::PackagedModified,
            Provenance::Unpackaged,
            Provenance::Unknown,
        ] {
            assert!(
                cache.housekeeping(sudoers, Some(actor)).is_none(),
                "{} must not earn the exemption",
                actor.label()
            );
        }

        // A path no package registers is not housekeeping either.
        assert!(
            cache
                .housekeeping(Path::new("/etc/passwd"), Some(Provenance::PackagedIntact))
                .is_none()
        );
    }

    /// No transaction, no exemption — otherwise this is just "conffiles
    /// are exempt", and an edit to /etc/sudoers at 3am reads the same
    /// as dpkg's own.
    #[test]
    fn a_quiet_database_credits_nothing() {
        let (root, _) = dpkg_with_conffile("sudo", "/etc/sudoers");
        let info = root.path().join("info");
        for f in [info.clone(), root.path().join("status")] {
            let h = std::fs::File::open(&f).unwrap();
            h.set_times(std::fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
                .unwrap();
        }
        let idx = PackageIndex::load_dpkg(&info);
        assert!(!idx.transaction_active());
        let cache = ProvenanceCache::new(idx);
        assert!(
            cache
                .housekeeping(Path::new("/etc/sudoers"), Some(Provenance::PackagedIntact))
                .is_none()
        );
    }

    #[test]
    fn damping_drops_housekeeping_below_any_sane_threshold() {
        // The three rules the live false positive fired.
        for severity in [0.95_f32, 0.90, 0.70] {
            let damped = damp_housekeeping(severity);
            assert!(damped < 0.2, "{severity} damped to {damped}");
            assert!(damped > 0.0, "the finding must not stop existing");
        }
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
