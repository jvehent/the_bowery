//! Ransomware, from the only evidence the sensor actually has.
//!
//! `T1486` has been an uncovered row on the ATT&CK map since the map
//! existed. The file probe reports every write-intent open on the host,
//! so the raw material was always there and nothing scored it.
//!
//! # Why a write *rate* is not the detection
//!
//! The obvious rule — "N files written in T seconds" — fires on `tar
//! -x`, on `apt upgrade`, on `cargo build`, on `rsync`, on `git
//! checkout`, on every backup job. It would be the loudest rule in the
//! agent and every single hit would be wrong. That is the failure this
//! project has now made three times, and the standing constraint is that
//! an operator who learns to close the tab is a defence that has already
//! failed.
//!
//! So volume alone is deliberately **not** a finding here. What
//! separates encryption from a busy compiler is a conjunction:
//!
//! 1. **Many distinct files** — not one file written repeatedly.
//! 2. **Across many distinct directories** — a build writes a lot into
//!    a target tree; encryption sweeps a home directory.
//! 3. **Sharing one final extension that is not a normal one.** This is
//!    the load-bearing condition. Ransomware renames what it encrypts —
//!    `.locked`, `.encrypted`, `.crypt`, a campaign id — and the result
//!    is hundreds of files whose last extension is identical and is not
//!    something software normally produces.
//!
//! An unpacked source tree fails (3): `.rs` and `.c` are ordinary. A
//! build fails (2) and usually (3). A photo import fails (3). A
//! directory of `report.docx.locked` fails none of them.
//!
//! # What this cannot see, stated plainly
//!
//! The probe reports `openat` write intent. It does not report
//! `rename`, `unlink`, or file contents, so:
//!
//! - **In-place encryption that keeps the filename is invisible** *to
//!   the sweep rule above*. Some families do exactly that. That gap is
//!   what [`NoteFanout`] closes from the other side: whether or not the
//!   encryption renames anything, the note telling the victim how to pay
//!   still has to be written, and written where they will find it.
//! - **No entropy check.** A file being encrypted and a file being
//!   compressed look identical from here.
//! - **A family that uses a common extension** — writing everything as
//!   `.zip` — evades the third condition. That is the cost of the
//!   condition that makes the rule usable at all.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Extensions ordinary software produces in bulk.
///
/// A guard against false positives, not a signature list: being wrong
/// here costs a false positive, never a miss. Kept deliberately broad
/// for that reason — every entry is an extension some legitimate tool
/// writes hundreds of at a time.
const COMMON_EXTENSIONS: &[&str] = &[
    // source and build output
    "rs",
    "c",
    "h",
    "cc",
    "cpp",
    "hpp",
    "go",
    "py",
    "pyc",
    "pyo",
    "js",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "jsx",
    "java",
    "class",
    "jar",
    "rb",
    "php",
    "pl",
    "sh",
    "bash",
    "lua",
    "sql",
    "swift",
    "kt",
    "cs",
    "vb",
    "scala",
    "clj",
    "ex",
    "exs",
    "erl",
    "hs",
    "ml",
    "r",
    "m",
    "mm",
    "o",
    "a",
    "so",
    "lib",
    "dll",
    "exe",
    "obj",
    "d",
    "rlib",
    "rmeta",
    "bc",
    "ll",
    "s",
    "asm",
    "map",
    "pdb",
    // markup, config, docs
    "md",
    "rst",
    "txt",
    "html",
    "htm",
    "xml",
    "json",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "properties",
    "lock",
    "csv",
    "tsv",
    "log",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "odt",
    "ods",
    "tex",
    "bib",
    // media
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "svg",
    "ico",
    "webp",
    "tiff",
    "raw",
    "psd",
    "mp3",
    "wav",
    "flac",
    "ogg",
    "opus",
    "aac",
    "mp4",
    "mkv",
    "avi",
    "mov",
    "webm",
    "ttf",
    "otf",
    "woff",
    "woff2",
    // archives and packages
    "gz",
    "bz2",
    "xz",
    "zst",
    "zip",
    "tar",
    "7z",
    "rar",
    "deb",
    "rpm",
    "apk",
    "whl",
    "egg",
    "iso",
    "img",
    // data and state
    "db",
    "sqlite",
    "sqlite3",
    "parquet",
    "avro",
    "orc",
    "pb",
    "bin",
    "dat",
    "idx",
    "pack",
    "tmp",
    "temp",
    "bak",
    "swp",
    "part",
    "cache",
    "pid",
    "sock",
    "journal",
    "wal",
    "shm",
    // Package-manager staging artifacts. `dpkg` unpacked 70 `.dpkg-new`
    // files across 20 directories inside one 60-second window on a real
    // host — measured by replaying the fleet's own history through this
    // rule, which is the only way it would have been found before an
    // operator saw "possible ransomware" during an `apt upgrade`.
    "dpkg-new",
    "dpkg-old",
    "dpkg-tmp",
    "dpkg-dist",
    "ucf-new",
    "ucf-old",
    "ucf-dist",
    "rpmnew",
    "rpmsave",
    "rpmorig",
];

/// Package-management tools, which legitimately fan one filename out
/// across the filesystem.
///
/// Paths, not names, and only honoured for a binary a package vouches
/// for — the same rule the file-watch exemptions follow, for the same
/// reason: `comm` is 16 bytes any process can set, so a name-based
/// allowlist would be an instruction for evading this.
///
/// Deliberately **not** "any packaged binary". `cp` is packaged and
/// intact, and `cp` in a loop is a perfectly good way to drop a ransom
/// note in every directory. The exemption is for the four tools measured
/// doing this on a real fleet, not for the property of being packaged.
const PACKAGE_TOOLS: &[&str] = &[
    "/usr/bin/dpkg",
    "/usr/bin/mandb",
    "/usr/bin/apt-key",
    "/usr/bin/unsquashfs",
];

/// Is this writer one of the package tools that does this legitimately?
#[must_use]
pub fn writer_is_package_tool(
    exe: Option<&str>,
    provenance: crate::provenance::Provenance,
) -> bool {
    let Some(exe) = exe else {
        // Fails closed: an unresolvable writer is not exempt.
        return false;
    };
    provenance == crate::provenance::Provenance::PackagedIntact && PACKAGE_TOOLS.contains(&exe)
}

/// One filename written into many directories across the filesystem.
///
/// The shape of a ransom note. It is the half of an encryption sweep the
/// attacker cannot leave out — the whole purpose is to be found — and it
/// does not depend on renaming, on file contents, or on entropy, so it
/// sees the in-place families the sweep rule above cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteFanout {
    pub pid: u32,
    /// The filename that repeated.
    pub name: String,
    /// How many distinct directories it landed in.
    pub dirs: usize,
    /// The deepest directory all of them share.
    pub common_ancestor: String,
    pub samples: Vec<String>,
}

/// What the tracker found, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImpactFinding {
    /// Many files renamed into one unusual extension.
    Sweep(Box<MassWriteBurst>),
    /// One filename dropped across the filesystem.
    Note(Box<NoteFanout>),
}

impl ImpactFinding {
    /// The encryption sweep, if that is what this is.
    #[must_use]
    pub fn as_sweep(&self) -> Option<&MassWriteBurst> {
        match self {
            Self::Sweep(b) => Some(b),
            Self::Note(_) => None,
        }
    }

    /// The note fan-out, if that is what this is.
    #[must_use]
    pub fn as_note(&self) -> Option<&NoteFanout> {
        match self {
            Self::Note(n) => Some(n),
            Self::Sweep(_) => None,
        }
    }
}

/// A run of writes that looks like encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MassWriteBurst {
    pub pid: u32,
    /// Distinct files written in the window.
    pub files: usize,
    /// Distinct parent directories touched.
    pub dirs: usize,
    /// The extension most of them share.
    pub extension: String,
    /// How many of the distinct files carried it.
    pub extension_files: usize,
    /// A few example paths, for the alert.
    pub samples: Vec<String>,
}

/// Directories retained per filename. Six is the reporting threshold, so
/// a handful more is enough to decide and to name the shared ancestor;
/// past that the answer cannot change and the strings are dropped.
const MAX_DIRS_PER_NAME: usize = 16;
/// Distinct filenames tracked per process per window. Bounds a process
/// that writes a great many differently-named files.
const MAX_NAMES: usize = 256;

/// Where one filename has been seen.
#[derive(Debug, Default)]
struct NameWatch {
    dirs: Vec<Box<str>>,
    samples: Vec<String>,
}

#[derive(Debug)]
struct Window {
    started: Instant,
    paths: HashSet<u64>,
    dirs: HashSet<u64>,
    extensions: HashMap<Box<str>, usize>,
    names: HashMap<Box<str>, NameWatch>,
    samples: Vec<String>,
    reported: bool,
    note_reported: bool,
}

impl Window {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            paths: HashSet::new(),
            dirs: HashSet::new(),
            extensions: HashMap::new(),
            names: HashMap::new(),
            samples: Vec::new(),
            reported: false,
            note_reported: false,
        }
    }
}

/// Pseudo-filesystems, which are not where anybody's documents live.
///
/// `systemd` writes the same cgroup control filenames into hundreds of
/// directories under `/sys` as a matter of routine; so does anything
/// walking `/proc`. Excluding them costs no coverage — ransomware has no
/// reason to drop a note in `/proc` — and removes the largest source of
/// noise measured on a real fleet.
const PSEUDO_FS: &[&str] = &["/proc/", "/sys/", "/dev/", "/run/"];

/// How many leading path components every directory shares.
///
/// The discriminator that makes this rule usable. A build tree fans one
/// filename across hundreds of directories that all sit under one deep
/// root — `rustc` wrote `tmp.a` into 9,497 of them on the machine this
/// was measured on, every one under the same `target/` directory, a
/// shared depth of four. A ransom note spreads across a user's home or
/// across unrelated data roots, which meet much higher up.
///
/// Measured against 170,963 real writes: at six directories and a shared
/// depth of three or less, the only hits on an ordinary fleet were four
/// package-management tools. At depth four, the build trees arrive.
fn common_depth(dirs: &[Box<str>]) -> usize {
    let mut parts = dirs.iter().map(|d| d.trim_matches('/').split('/'));
    let Some(first) = parts.next() else {
        return 0;
    };
    let first: Vec<&str> = first.collect();
    let mut depth = first.len();
    for other in dirs.iter().skip(1) {
        let shared = first
            .iter()
            .zip(other.trim_matches('/').split('/'))
            .take_while(|(a, b)| **a == *b)
            .count();
        depth = depth.min(shared);
    }
    depth
}

/// Watches for one process encrypting a lot of files.
#[derive(Debug)]
pub struct MassWriteTracker {
    inner: Mutex<HashMap<u32, Window>>,
    window: Duration,
    min_files: usize,
    min_dirs: usize,
    /// Fraction of the distinct files that must share the extension.
    min_share: f32,
    max_tracked: usize,
    /// Directories one filename must reach to be a fan-out.
    min_note_dirs: usize,
    /// How shallow their shared ancestor must be. See [`common_depth`].
    max_note_depth: usize,
}

impl MassWriteTracker {
    #[must_use]
    pub fn new(window: Duration, min_files: usize, min_dirs: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window,
            min_files: min_files.max(2),
            min_dirs: min_dirs.max(1),
            min_share: 0.7,
            max_tracked: 512,
            // Both measured, not chosen: see `common_depth`.
            min_note_dirs: 6,
            max_note_depth: 3,
        }
    }

    /// Record a write-intent open, and report a burst if this completes
    /// one.
    ///
    /// Reports **once** per window per process: the point is to say "this
    /// is happening", not to narrate every file as it goes.
    pub fn observe(&self, pid: u32, path: &str, now: Instant) -> Option<ImpactFinding> {
        if !path.starts_with('/') {
            return None;
        }
        let mut guard = self.inner.lock().ok()?;
        if guard.len() >= self.max_tracked && !guard.contains_key(&pid) {
            guard.clear();
        }
        let w = guard.entry(pid).or_insert_with(|| Window::new(now));
        // Tumbling rather than sliding: a sliding window means storing a
        // timestamp per path, and this runs on every write on the host.
        // The cost is that a burst straddling a boundary is split, which
        // delays detection by at most one window.
        if now.duration_since(w.started) > self.window {
            *w = Window::new(now);
        }
        if w.reported && w.note_reported {
            return None;
        }

        let (dir, file) = path.rsplit_once('/')?;
        if !w.paths.insert(hash(path)) {
            return None;
        }
        w.dirs.insert(hash(dir));

        // The note fan-out: this filename, in how many places?
        if !w.note_reported
            && !file.is_empty()
            && !PSEUDO_FS.iter().any(|pre| path.starts_with(pre))
        {
            // Track a new filename only while there is room; an
            // already-tracked one always continues.
            let room = w.names.len() < MAX_NAMES || w.names.contains_key(file);
            if let Some(watch) = room.then(|| w.names.entry(file.into()).or_default()) {
                let dir_owned: Box<str> = dir.into();
                if !watch.dirs.contains(&dir_owned) {
                    if watch.dirs.len() < MAX_DIRS_PER_NAME {
                        watch.dirs.push(dir_owned);
                    }
                    if watch.samples.len() < 3 {
                        watch.samples.push(path.to_string());
                    }
                }
                if watch.dirs.len() >= self.min_note_dirs {
                    let depth = common_depth(&watch.dirs);
                    if depth <= self.max_note_depth {
                        let ancestor = watch.dirs[0].trim_matches('/').split('/').take(depth).fold(
                            String::new(),
                            |mut acc, c| {
                                acc.push('/');
                                acc.push_str(c);
                                acc
                            },
                        );
                        let finding = NoteFanout {
                            pid,
                            name: file.to_string(),
                            dirs: watch.dirs.len(),
                            common_ancestor: if ancestor.is_empty() {
                                "/".to_string()
                            } else {
                                ancestor
                            },
                            samples: watch.samples.clone(),
                        };
                        w.note_reported = true;
                        return Some(ImpactFinding::Note(Box::new(finding)));
                    }
                }
            }
        }

        if w.reported {
            return None;
        }
        if let Some(ext) = final_extension(file) {
            *w.extensions.entry(ext.into()).or_insert(0) += 1;
        }
        if w.samples.len() < 5 {
            w.samples.push(path.to_string());
        }

        if w.paths.len() < self.min_files || w.dirs.len() < self.min_dirs {
            return None;
        }
        let (ext, count) = w.extensions.iter().max_by_key(|(_, n)| **n)?;
        #[allow(clippy::cast_precision_loss)]
        let share = *count as f32 / w.paths.len() as f32;
        if share < self.min_share || is_common(ext) {
            return None;
        }
        w.reported = true;
        Some(ImpactFinding::Sweep(Box::new(MassWriteBurst {
            pid,
            files: w.paths.len(),
            dirs: w.dirs.len(),
            extension: ext.to_string(),
            extension_files: *count,
            samples: w.samples.clone(),
        })))
    }

    /// Forget a process that has exited.
    pub fn forget(&self, pid: u32) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(&pid);
        }
    }
}

fn hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// The last extension of a filename, lowercased.
///
/// `None` for a dotfile with no extension (`.bashrc`), for a name with
/// no dot, and for anything implausibly long — an "extension" of 40
/// characters is not one, and treating it as one would let a single
/// weird filename define the dominant extension.
#[must_use]
pub fn final_extension(file: &str) -> Option<String> {
    let (stem, ext) = file.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() || ext.len() > 16 {
        return None;
    }
    if !ext
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

#[must_use]
pub fn is_common(ext: &str) -> bool {
    COMMON_EXTENSIONS.contains(&ext)
}

/// The rule id a mass-write burst is reported under.
pub const RULE_ID: &str = "impact.mass_write_new_extension";

/// The rule id a ransom-note fan-out is reported under.
pub const NOTE_RULE_ID: &str = "impact.ransom_note_fanout";

/// Every rule id this module can produce.
#[must_use]
pub const fn rule_ids() -> &'static [&'static str] {
    &[RULE_ID, NOTE_RULE_ID]
}

/// Operator-facing text for a burst.
#[must_use]
pub fn rationale(b: &MassWriteBurst) -> String {
    format!(
        "possible ransomware: pid {} wrote {} distinct files across {} directories, and {} of \
         them end in `.{}` — an extension normal software does not produce in bulk. Renaming \
         what it encrypts is what most families do, so this is the shape of an encryption \
         sweep rather than a build or an unpack (examples: {}). Note the sensor sees write \
         intent only, not renames or contents, so a family that encrypts in place without \
         changing the name would not appear here",
        b.pid,
        b.files,
        b.dirs,
        b.extension_files,
        b.extension,
        b.samples.join(", ")
    )
}

/// Operator-facing text for a note fan-out.
#[must_use]
pub fn note_rationale(n: &NoteFanout) -> String {
    format!(
        "possible ransomware: pid {} wrote a file named `{}` into {} different directories \
         under {}, which is the shape of a ransom note rather than of any one program's \
         output — a build or an unpack repeats a filename inside its own tree, not across \
         unrelated ones (examples: {}). This is the half of an encryption sweep that cannot \
         be left out, since the note exists to be found, and it does not depend on the \
         files being renamed — so it sees the families that encrypt in place, which the \
         extension rule cannot",
        n.pid,
        n.name,
        n.dirs,
        n.common_ancestor,
        n.samples.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> MassWriteTracker {
        MassWriteTracker::new(Duration::from_mins(1), 50, 5)
    }

    fn sweep(t: &MassWriteTracker, ext: &str, files: usize, dirs: usize) -> Option<MassWriteBurst> {
        let now = Instant::now();
        let mut last = None;
        for i in 0..files {
            let path = format!("/home/j/dir{}/file{i}.docx.{ext}", i % dirs);
            last = t
                .observe(4242, &path, now)
                .and_then(|f| f.as_sweep().cloned())
                .or(last);
        }
        last
    }

    #[test]
    fn an_encryption_sweep_is_caught() {
        let t = tracker();
        let b = sweep(&t, "locked", 100, 20).expect("burst");
        assert_eq!(b.extension, "locked");
        assert!(b.files >= 50 && b.dirs >= 5);
        assert!(rationale(&b).contains("possible ransomware"));
    }

    /// The condition that makes the rule usable. An unpacked source
    /// tree writes thousands of files across hundreds of directories
    /// and must not alert.
    #[test]
    fn unpacking_a_source_tree_is_not_a_finding() {
        let t = tracker();
        assert!(sweep(&t, "rs", 500, 50).is_none());
        let t = tracker();
        assert!(sweep(&t, "png", 500, 50).is_none());
    }

    /// A build writes a lot into few directories.
    #[test]
    fn a_build_writing_into_one_tree_is_not_a_finding() {
        let t = tracker();
        let now = Instant::now();
        let mut hit = None;
        for i in 0..500 {
            let p = format!("/src/target/debug/obj{i}.weird");
            hit = t
                .observe(4242, &p, now)
                .and_then(|f| f.as_sweep().cloned())
                .or(hit);
        }
        assert!(hit.is_none(), "one directory must never trip this");
    }

    /// Volume alone is not the detection.
    #[test]
    fn rewriting_one_file_repeatedly_is_not_a_finding() {
        let t = tracker();
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(t.observe(4242, "/var/log/app.locked", now).is_none());
        }
    }

    /// Mixed extensions mean something other than an encryption sweep.
    #[test]
    fn a_mixed_workload_does_not_reach_the_share_threshold() {
        let t = tracker();
        let now = Instant::now();
        let mut hit = None;
        for i in 0..300 {
            let ext = ["locked", "aaa", "bbb", "ccc"][i % 4];
            let p = format!("/home/j/d{}/f{i}.{ext}", i % 20);
            hit = t
                .observe(4242, &p, now)
                .and_then(|f| f.as_sweep().cloned())
                .or(hit);
        }
        assert!(hit.is_none(), "no extension dominates, so nothing fires");
    }

    #[test]
    fn it_reports_once_not_once_per_file() {
        let t = tracker();
        let now = Instant::now();
        let mut hits = 0;
        for i in 0..400 {
            let p = format!("/home/j/d{}/f{i}.locked", i % 20);
            if t.observe(4242, &p, now).is_some() {
                hits += 1;
            }
        }
        assert_eq!(hits, 1, "one alert per window, not one per file");
    }

    #[test]
    fn different_processes_do_not_pool() {
        let t = tracker();
        let now = Instant::now();
        let mut hit = None;
        for i in 0..400 {
            let p = format!("/home/j/d{}/f{i}.locked", i % 20);
            hit = t
                .observe(u32::try_from(i).unwrap(), &p, now)
                .and_then(|f| f.as_sweep().cloned())
                .or(hit);
        }
        assert!(hit.is_none(), "one file each from 400 pids is not a sweep");
    }

    #[test]
    fn relative_paths_are_ignored() {
        let t = tracker();
        assert!(t.observe(1, "relative/f.locked", Instant::now()).is_none());
    }

    #[test]
    fn extensions_are_parsed_the_way_the_rule_needs() {
        assert_eq!(
            final_extension("report.docx.locked").as_deref(),
            Some("locked")
        );
        assert_eq!(final_extension("archive.tar.gz").as_deref(), Some("gz"));
        // A dotfile has no extension; treating `.bashrc` as one would
        // make every home directory look uniform.
        assert_eq!(final_extension(".bashrc"), None);
        assert_eq!(final_extension("noext"), None);
        // Absurdly long "extensions" are not extensions — one weird
        // filename must not get to define the dominant one.
        assert_eq!(final_extension(&format!("f.{}", "x".repeat(40))), None);
    }

    #[test]
    fn the_common_list_covers_what_builds_and_unpacks_produce() {
        for e in ["rs", "o", "png", "gz", "json", "pyc", "so", "docx"] {
            assert!(is_common(e), "{e} must be treated as ordinary");
        }
        for e in ["locked", "encrypted", "crypt", "wnry"] {
            assert!(!is_common(e), "{e} must not be");
        }
    }

    // -- the note fan-out ------------------------------------------

    fn note(t: &MassWriteTracker, name: &str, dirs: &[&str]) -> Option<NoteFanout> {
        let now = Instant::now();
        let mut last = None;
        for d in dirs {
            last = t
                .observe(4242, &format!("{d}/{name}"), now)
                .and_then(|f| f.as_note().cloned())
                .or(last);
        }
        last
    }

    /// The shape this exists for: one filename, across a user's data.
    #[test]
    fn a_note_dropped_across_a_home_directory_is_a_finding() {
        let t = tracker();
        let hit = note(
            &t,
            "READ-ME-TO-DECRYPT.txt",
            &[
                "/home/j/Documents",
                "/home/j/Pictures",
                "/home/j/Desktop",
                "/home/j/Music",
                "/home/j/Videos",
                "/home/j/Downloads",
            ],
        )
        .expect("six directories under one home is a fan-out");
        assert_eq!(hit.name, "READ-ME-TO-DECRYPT.txt");
        assert_eq!(hit.dirs, 6);
        assert_eq!(hit.common_ancestor, "/home/j");
    }

    /// It must not depend on renaming — that is the whole point, and the
    /// gap in the extension rule it exists to cover.
    #[test]
    fn it_fires_although_nothing_was_renamed() {
        let t = tracker();
        // Files encrypted in place, keeping their names: invisible to
        // the extension rule by construction.
        let now = Instant::now();
        for i in 0..40 {
            assert!(
                t.observe(4242, &format!("/home/j/d{}/report{i}.docx", i % 8), now)
                    .is_none(),
                "in-place encryption alone is not visible here"
            );
        }
        // The note is what gives it away.
        assert!(
            note(
                &t,
                "HOW_TO_RECOVER.txt",
                &[
                    "/home/j/d0",
                    "/home/j/d1",
                    "/home/j/d2",
                    "/home/j/d3",
                    "/home/j/d4",
                    "/home/j/d5",
                ]
            )
            .is_some()
        );
    }

    /// A build repeats filenames constantly — inside one tree.
    ///
    /// `rustc` wrote `tmp.a` into 9,497 directories on the machine this
    /// was measured on. Every one sat under the same `target/`, and that
    /// shared depth is the only thing separating it from a note.
    #[test]
    fn a_build_repeating_a_filename_inside_its_own_tree_is_not_a_finding() {
        let t = tracker();
        let dirs: Vec<String> = (0..12)
            .map(|i| format!("/home/j/code/proj/target/debug/build/crate{i}"))
            .collect();
        let refs: Vec<&str> = dirs.iter().map(String::as_str).collect();
        assert!(
            note(&t, "tmp.a", &refs).is_none(),
            "one deep tree is a build, not a sweep"
        );
    }

    /// Pseudo-filesystems are not where documents live, and `systemd`
    /// writes the same cgroup filenames into hundreds of directories.
    #[test]
    fn cgroup_writes_are_not_a_finding() {
        let t = tracker();
        let dirs: Vec<String> = (0..12)
            .map(|i| format!("/sys/fs/cgroup/system.slice/unit{i}.service"))
            .collect();
        let refs: Vec<&str> = dirs.iter().map(String::as_str).collect();
        assert!(note(&t, "memory.max", &refs).is_none());
    }

    /// One filename in one place, however many times, is nothing.
    #[test]
    fn the_same_file_rewritten_is_not_a_fan_out() {
        let t = tracker();
        let now = Instant::now();
        for _ in 0..50 {
            assert!(t.observe(4242, "/home/j/notes.txt", now).is_none());
        }
    }

    #[test]
    fn it_reports_once_per_window_not_once_per_directory() {
        let t = tracker();
        let now = Instant::now();
        let mut fired = 0;
        for i in 0..30 {
            if t.observe(4242, &format!("/srv/data{i}/README.txt"), now)
                .and_then(|f| f.as_note().cloned())
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(fired, 1, "one finding, not one per directory");
    }

    /// The exemption is four measured tools, and only when a package
    /// vouches for the binary — not the property of being packaged.
    #[test]
    fn package_tools_are_exempt_but_only_the_measured_ones() {
        use crate::provenance::Provenance;
        assert!(writer_is_package_tool(
            Some("/usr/bin/dpkg"),
            Provenance::PackagedIntact
        ));
        // A tampered dpkg is not dpkg.
        assert!(!writer_is_package_tool(
            Some("/usr/bin/dpkg"),
            Provenance::PackagedModified
        ));
        // `cp` is packaged and intact, and `cp` in a loop drops notes
        // perfectly well.
        assert!(!writer_is_package_tool(
            Some("/usr/bin/cp"),
            Provenance::PackagedIntact
        ));
        // Fails closed on a writer we could not resolve.
        assert!(!writer_is_package_tool(None, Provenance::PackagedIntact));
    }

    #[test]
    fn the_shared_ancestor_is_reported_for_the_operator() {
        let t = tracker();
        let hit = note(
            &t,
            "DECRYPT.txt",
            &["/srv/a", "/srv/b", "/srv/c", "/srv/d", "/srv/e", "/srv/f"],
        )
        .expect("fan-out");
        assert_eq!(hit.common_ancestor, "/srv");
        assert!(!hit.samples.is_empty(), "the alert needs examples");
    }

    #[test]
    fn tracking_is_bounded() {
        let t = tracker();
        let now = Instant::now();
        for pid in 0..5000 {
            t.observe(pid, "/a/b/c.locked", now);
        }
        assert!(t.inner.lock().unwrap().len() <= 512);
    }
}
