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
//! - **In-place encryption that keeps the filename is invisible.** Some
//!   families do exactly that. This detection would not fire, and the
//!   ATT&CK map says so rather than claiming the technique is covered.
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
];

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

#[derive(Debug)]
struct Window {
    started: Instant,
    paths: HashSet<u64>,
    dirs: HashSet<u64>,
    extensions: HashMap<Box<str>, usize>,
    samples: Vec<String>,
    reported: bool,
}

impl Window {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            paths: HashSet::new(),
            dirs: HashSet::new(),
            extensions: HashMap::new(),
            samples: Vec::new(),
            reported: false,
        }
    }
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
        }
    }

    /// Record a write-intent open, and report a burst if this completes
    /// one.
    ///
    /// Reports **once** per window per process: the point is to say "this
    /// is happening", not to narrate every file as it goes.
    pub fn observe(&self, pid: u32, path: &str, now: Instant) -> Option<MassWriteBurst> {
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
        if w.reported {
            return None;
        }

        let (dir, file) = path.rsplit_once('/')?;
        if !w.paths.insert(hash(path)) {
            return None;
        }
        w.dirs.insert(hash(dir));
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
        Some(MassWriteBurst {
            pid,
            files: w.paths.len(),
            dirs: w.dirs.len(),
            extension: ext.to_string(),
            extension_files: *count,
            samples: w.samples.clone(),
        })
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

/// Every rule id this module can produce.
#[must_use]
pub const fn rule_ids() -> &'static [&'static str] {
    &[RULE_ID]
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
            last = t.observe(4242, &path, now).or(last);
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
            hit = t.observe(4242, &p, now).or(hit);
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
            hit = t.observe(4242, &p, now).or(hit);
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
            hit = t.observe(u32::try_from(i).unwrap(), &p, now).or(hit);
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
