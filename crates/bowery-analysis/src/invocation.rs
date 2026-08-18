//! What a program was invoked *as*, which is not where it lives.
//!
//! `/proc/<pid>/exe` resolves symlinks, so the path the pipeline hands a
//! rule is the implementation rather than the name anyone typed:
//!
//! | typed | `/proc/<pid>/exe` |
//! | --- | --- |
//! | `iptables` | `/usr/sbin/xtables-nft-multi` |
//! | `nc` | `/usr/bin/nc.openbsd` |
//! | `python3` | `/usr/bin/python3.12` |
//! | `sh` | `/usr/bin/dash` |
//!
//! Every rule that matches a program by name has to reckon with that,
//! and three have now failed to. The versioned-interpreter case made
//! `nginx` spawning python invisible on every current Debian; the
//! alternatives case made a firewall flush invisible the same way, in a
//! rule written *after* the first was fixed. `sh` resolving to `dash`
//! only worked because `dash` happened to be in the list under its own
//! name — the same mechanism, opposite luck.
//!
//! # argv[0] is the other half of the answer
//!
//! A multi-call binary dispatches on `argv[0]`: `xtables-nft-multi` *is*
//! `iptables`, `ip6tables` and `arptables` depending on how it was
//! called, and busybox is the same idea. So `argv[0]` is often the only
//! place the tool's identity survives.
//!
//! It is also attacker-controlled, which decides how it must be used.
//! Matching on `argv[0]` **in addition to** the resolved path can only
//! make a rule fire more often, never less: someone lying about
//! `argv[0]` produces a false positive, while someone lying about it to
//! *hide* is still caught by the resolved path. Matching on `argv[0]`
//! *instead* would be an evasion primitive. Both, always.

/// The names a program may reasonably be known by, most specific first.
///
/// Returns the basename of `argv[0]` and the basename of the resolved
/// executable path, deduplicated. Either may be what a rule's list
/// contains, and a rule should match if *any* of them does — see the
/// module docs for why this direction is the safe one.
#[must_use]
pub fn names<'a>(exe_path: &'a str, args: &'a [String]) -> Vec<&'a str> {
    let mut out = Vec::with_capacity(2);
    if let Some(argv0) = args.first() {
        let base = base_name(argv0);
        // A shell may pass a full path, or `-bash` for a login shell;
        // neither is a useful name, and an empty one is no name at all.
        if !base.is_empty() && !base.starts_with('-') {
            out.push(base);
        }
    }
    let exe = base_name(exe_path);
    if !exe.is_empty() && !out.contains(&exe) {
        out.push(exe);
    }
    out
}

/// The last path component.
#[must_use]
pub fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    /// The case that broke the firewall rule: an alternatives symlink to
    /// a multi-call binary, where `argv[0]` is the only identity left.
    #[test]
    fn a_multi_call_binary_is_known_by_the_name_it_was_called_with() {
        let argv = args(&["iptables", "-F"]);
        let n = names("/usr/sbin/xtables-nft-multi", &argv);
        assert!(n.contains(&"iptables"), "{n:?}");
        assert!(n.contains(&"xtables-nft-multi"), "{n:?}");
    }

    /// And the case that broke the interpreter rule.
    #[test]
    fn a_versioned_binary_offers_both_spellings() {
        let argv = args(&["python3", "-c", "pass"]);
        let n = names("/usr/bin/python3.12", &argv);
        assert_eq!(n, vec!["python3", "python3.12"]);
    }

    #[test]
    fn an_ordinary_program_yields_one_name() {
        let argv = args(&["curl", "-s"]);
        assert_eq!(names("/usr/bin/curl", &argv), vec!["curl"]);
        let argv = args(&["/usr/bin/curl"]);
        assert_eq!(names("/usr/bin/curl", &argv), vec!["curl"]);
    }

    /// Without argv the resolved path is all there is.
    #[test]
    fn no_arguments_still_yields_the_executable() {
        assert_eq!(names("/usr/bin/curl", &[]), vec!["curl"]);
    }

    /// A login shell's `-bash` is a convention, not a name.
    #[test]
    fn a_login_shell_marker_is_not_treated_as_a_name() {
        let argv = args(&["-bash"]);
        assert_eq!(names("/usr/bin/bash", &argv), vec!["bash"]);
    }

    #[test]
    fn a_bare_name_is_its_own_basename() {
        assert_eq!(base_name("iptables"), "iptables");
        assert_eq!(base_name("/usr/sbin/iptables"), "iptables");
        assert_eq!(base_name(""), "");
    }
}
