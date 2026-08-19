//! Git stamping for build scripts.
//!
//! Called from each binary crate's `build.rs`, so the three shipped
//! binaries report the commit they were built from rather than a crate
//! version that has read `0.0.1` for months.
//!
//! A static version cannot answer the only question anyone asks it —
//! *is this the binary I just built?* — and answering it otherwise meant
//! grepping deployed binaries for a string from the change.
//!
//! Two rules this must not break:
//!
//! - **Never fail the build.** A release tarball or container with no
//!   `.git` is legitimate. It reports `unknown` and compiles.
//! - **Never claim a commit it is not.** Uncommitted changes get a
//!   `-dirty` suffix. A version naming a commit whose contents it does
//!   not match is worse than one admitting it does not know, because it
//!   sends whoever is debugging to the wrong source.

use std::process::Command;

/// Emit `BOWERY_GIT_COMMIT` for the calling crate, and the
/// `rerun-if-changed` lines that keep it from going stale.
///
/// # Panics
///
/// Never. Every git failure degrades to `unknown`.
pub fn emit() {
    // HEAD changes on checkout; the ref it names changes on commit.
    // Watching only one of them lets an incremental build keep a stale
    // stamp, which is the failure mode that makes the whole field
    // untrustworthy.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    if let Some(head) = git(&["rev-parse", "--symbolic-full-name", "HEAD"]) {
        println!("cargo:rerun-if-changed=../../.git/{head}");
    }

    let commit = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".into());
    // `--porcelain` is empty exactly when the tree is clean. git being
    // absent is not cleanliness and not dirtiness, and `None` covers
    // both without adding a suffix that would be a lie either way.
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|s| !s.trim().is_empty());
    let suffix = if dirty { "-dirty" } else { "" };

    println!("cargo:rustc-env=BOWERY_GIT_COMMIT={commit}{suffix}");
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}
