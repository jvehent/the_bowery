//! What an operator judged benign, and what that does to a score.
//!
//! The pure half of alert silencing: matching and weighting, with no
//! signing, no storage and no clock. Everything here is a function of its
//! arguments, because this is the code that decides whether a finding
//! reaches a human and it should be possible to read all of it at once.
//!
//! # This is the one thing here that fails toward silence
//!
//! Every other detection in this agent errs toward noise — an unresolved
//! exe earns no exemption, a poisoned lock reports rather than drops, a
//! peer that cannot answer is not evidence. This module is the exception
//! by construction: its whole job is to stop alerts. So the safety
//! properties are inverted, and they are tested rather than asserted:
//!
//! - **A spec that constrains nothing matches nothing.** An empty
//!   `SilenceSpec` is not a fleet-wide kill switch; it is inert. That is
//!   the single most important line in the file, because every other
//!   guard is upstream of it and upstream guards get bypassed.
//! - **An expired silence matches nothing**, with no grace.
//! - **Wildcards are opt-in per field**, never a default.
//!
//! # Why a hash and not a name
//!
//! A silence names a binary by SHA-256. `comm` is sixteen bytes any
//! process sets with `prctl`, and a path is whatever an attacker can
//! write to — so a silence keyed on either would be an instruction for
//! evading the detection it covers. Keyed on the hash, a silence for
//! `git-remote-http` reading `~/.netrc` stops covering it the moment the
//! binary changes, which is exactly when it should.

use std::collections::HashMap;

/// The alert being judged, reduced to what a silence can match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertSubject<'a> {
    pub rule_id: &'a str,
    /// Lowercase hex, or empty when the agent could not hash the binary.
    pub exe_sha256_hex: &'a str,
    pub exe_path: &'a str,
    /// Lowercase hex fingerprint of the host that raised it.
    pub host_fp_hex: &'a str,
}

/// Which alerts a silence covers.
///
/// An **empty field is a wildcard**, and a spec with every field empty
/// covers nothing at all — see [`SilenceSpec::constrains`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SilenceSpec {
    pub rule_id: String,
    pub exe_sha256_hex: String,
    pub exe_path: String,
    /// Empty means fleet-wide; set means only that host honours it.
    pub host_fp_hex: String,
}

impl SilenceSpec {
    /// How many fields this pins down. Zero means it covers nothing.
    #[must_use]
    pub fn constrains(&self) -> usize {
        [
            &self.rule_id,
            &self.exe_sha256_hex,
            &self.exe_path,
            &self.host_fp_hex,
        ]
        .iter()
        .filter(|f| !f.is_empty())
        .count()
    }

    /// Does this spec name a specific binary?
    ///
    /// The CLI refuses to sign a spec where this is false unless the
    /// operator passes `--any-binary`, because a silence that does not
    /// name a binary is inherited by whatever an attacker puts at the
    /// path it does name.
    #[must_use]
    pub fn constrains_binary(&self) -> bool {
        !self.exe_sha256_hex.is_empty()
    }

    /// This spec's content id: `sil-` plus 16 bytes of SHA-256 over the
    /// fields, length-prefixed.
    ///
    /// Derived rather than chosen, so the same judgement issued twice
    /// carries the same id and replaces itself instead of stacking a
    /// second copy, and so two different specs cannot be made to collide
    /// by naming them alike.
    ///
    /// Length-prefixed for the same reason the signing input is: without
    /// it, a rule of `a` with a path of `bc` would hash identically to a
    /// rule of `ab` with a path of `c`, and two unrelated silences would
    /// share an id.
    #[must_use]
    pub fn id(&self, cluster_id: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for field in [
            cluster_id,
            self.rule_id.as_str(),
            self.exe_sha256_hex.as_str(),
            self.exe_path.as_str(),
            self.host_fp_hex.as_str(),
        ] {
            h.update(u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
            h.update(field.as_bytes());
        }
        let digest = h.finalize();
        let mut out = String::with_capacity(4 + 32);
        out.push_str("sil-");
        for b in &digest[..16] {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    /// Does this cover `subject`?
    ///
    /// A spec that constrains nothing matches nothing. That is not a
    /// degenerate case to be tidy about — it is the difference between
    /// "a field was left blank" and "every alert on this fleet stops".
    #[must_use]
    pub fn matches(&self, subject: &AlertSubject<'_>) -> bool {
        if self.constrains() == 0 {
            return false;
        }
        field_matches(&self.rule_id, subject.rule_id)
            && field_matches(&self.exe_sha256_hex, subject.exe_sha256_hex)
            && field_matches(&self.exe_path, subject.exe_path)
            && field_matches(&self.host_fp_hex, subject.host_fp_hex)
    }
}

/// An empty pattern is a wildcard; anything else must match exactly.
///
/// Deliberately not a prefix, glob or regex. A pattern language is a
/// place for a silence to cover more than its author read, and the
/// author is signing it.
fn field_matches(pattern: &str, value: &str) -> bool {
    pattern.is_empty() || pattern == value
}

/// One operator judgement.
#[derive(Debug, Clone, PartialEq)]
pub struct Silence {
    /// Stable content id over the spec, so re-issuing the same judgement
    /// replaces it rather than stacking another.
    pub id: String,
    pub spec: SilenceSpec,
    /// `0.0` silences; `1.0` changes no score and only counts matches.
    pub weight: f32,
    pub reason: String,
    pub issued_unix_ms: u64,
    /// Mandatory upstream. An unbounded silence is a permanent blind
    /// spot, so this type has no way to express "never expires".
    pub expires_unix_ms: u64,
}

impl Silence {
    /// Is this still in force at `now_unix_ms`?
    #[must_use]
    pub fn is_live(&self, now_unix_ms: u64) -> bool {
        now_unix_ms < self.expires_unix_ms
    }

    /// The suspicion this leaves behind.
    #[must_use]
    pub fn apply(&self, suspicion: f32) -> f32 {
        (suspicion * self.weight.clamp(0.0, 1.0)).clamp(0.0, 1.0)
    }
}

/// What the silence set had to say about an alert.
#[derive(Debug, Clone, PartialEq)]
pub enum SilenceDecision {
    /// Nothing matched. The alert keeps its score.
    Unaffected,
    /// A silence applied. The caller compares `to` against its own alert
    /// threshold — the threshold lives with the inbox, not here.
    Damped {
        silence_id: String,
        reason: String,
        from: f32,
        to: f32,
    },
}

/// The silences an agent currently honours.
#[derive(Debug, Default)]
pub struct SilenceSet {
    by_id: HashMap<String, Silence>,
}

impl SilenceSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a silence.
    ///
    /// Keyed on `id`, and a re-issue only wins if it is *newer*: gossip
    /// and multi-hop propagation both redeliver, and an older copy
    /// arriving late must not undo a revocation.
    pub fn insert(&mut self, silence: Silence) {
        match self.by_id.get(&silence.id) {
            Some(existing) if existing.issued_unix_ms > silence.issued_unix_ms => {}
            _ => {
                self.by_id.insert(silence.id.clone(), silence);
            }
        }
    }

    /// Drop everything that has expired. Returns how many went.
    pub fn sweep(&mut self, now_unix_ms: u64) -> usize {
        let before = self.by_id.len();
        self.by_id.retain(|_, s| s.is_live(now_unix_ms));
        before - self.by_id.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Silence> {
        self.by_id.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Silence> {
        self.by_id.values()
    }

    /// The silence that governs `subject`, if any.
    ///
    /// **Most specific wins**, ties broken by the most recently issued.
    /// Two overlapping silences are two operator judgements, and the
    /// narrower one is the more considered: an operator who writes a
    /// broad rule and then a narrow exception means the exception.
    /// Taking the lowest weight instead would make a broad `0.0` swallow
    /// every later refinement, and taking the highest would make a stale
    /// `1.0` quietly undo a deliberate silence.
    #[must_use]
    pub fn governing(&self, subject: &AlertSubject<'_>, now_unix_ms: u64) -> Option<&Silence> {
        self.by_id
            .values()
            .filter(|s| s.is_live(now_unix_ms) && s.spec.matches(subject))
            .max_by(|a, b| {
                a.spec
                    .constrains()
                    .cmp(&b.spec.constrains())
                    .then(a.issued_unix_ms.cmp(&b.issued_unix_ms))
            })
    }

    /// Decide what happens to an alert.
    #[must_use]
    pub fn decide(
        &self,
        subject: &AlertSubject<'_>,
        suspicion: f32,
        now_unix_ms: u64,
    ) -> SilenceDecision {
        match self.governing(subject, now_unix_ms) {
            None => SilenceDecision::Unaffected,
            Some(s) => SilenceDecision::Damped {
                silence_id: s.id.clone(),
                reason: s.reason.clone(),
                from: suspicion,
                to: s.apply(suspicion),
            },
        }
    }
}

/// The note appended to an alert a silence damped but did not suppress.
///
/// An alert that arrives at 0.4 because a silence took it down from 0.95
/// reads very differently from one that was always 0.4, and an operator
/// has to be able to tell which they are looking at.
#[must_use]
pub fn damped_note(silence_id: &str, reason: &str, from: f32, to: f32) -> String {
    // `chars`, not a byte slice: ids are hex today, and a byte index into
    // a string that one day is not would panic on the alert path.
    //
    // Sixteen characters, so the `sil-` prefix still leaves twelve hex
    // digits to tell two silences apart. The full id is in
    // `bowery_silences`; this is the version a human reads in a
    // rationale.
    let short: String = silence_id.chars().take(16).collect();
    format!(" [scored {from:.2}, reduced to {to:.2} by silence {short} — \"{reason}\"]")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(rule: &str, sha: &str, path: &str, host: &str) -> SilenceSpec {
        SilenceSpec {
            rule_id: rule.into(),
            exe_sha256_hex: sha.into(),
            exe_path: path.into(),
            host_fp_hex: host.into(),
        }
    }

    fn silence(id: &str, spec: SilenceSpec, weight: f32) -> Silence {
        Silence {
            id: id.into(),
            spec,
            weight,
            reason: "benign".into(),
            issued_unix_ms: 1_000,
            expires_unix_ms: 100_000,
        }
    }

    fn subject<'a>() -> AlertSubject<'a> {
        AlertSubject {
            rule_id: "cred.read_netrc",
            exe_sha256_hex: "8353a512",
            exe_path: "/home/j/.netrc",
            host_fp_hex: "aabb",
        }
    }

    // -- the safety properties ------------------------------------------

    /// The most important line in the module. A spec with nothing filled
    /// in is inert, not universal — otherwise a dropped field or a
    /// default-constructed record silences an entire fleet.
    #[test]
    fn a_spec_that_constrains_nothing_matches_nothing() {
        assert!(!SilenceSpec::default().matches(&subject()));
        assert_eq!(SilenceSpec::default().constrains(), 0);

        let mut set = SilenceSet::new();
        set.insert(silence("s1", SilenceSpec::default(), 0.0));
        assert_eq!(
            set.decide(&subject(), 0.9, 5_000),
            SilenceDecision::Unaffected
        );
    }

    #[test]
    fn an_expired_silence_matches_nothing() {
        let mut set = SilenceSet::new();
        let mut s = silence(
            "s1",
            spec("cred.read_netrc", "8353a512", "/home/j/.netrc", ""),
            0.0,
        );
        s.expires_unix_ms = 2_000;
        set.insert(s);
        // Live before, gone after — no grace period.
        assert!(matches!(
            set.decide(&subject(), 0.9, 1_999),
            SilenceDecision::Damped { .. }
        ));
        assert_eq!(
            set.decide(&subject(), 0.9, 2_000),
            SilenceDecision::Unaffected
        );
        assert_eq!(
            set.decide(&subject(), 0.9, 9_999),
            SilenceDecision::Unaffected
        );
    }

    /// The hash is what stops a silence covering a replaced binary.
    #[test]
    fn a_different_binary_at_the_same_path_is_not_covered() {
        let mut set = SilenceSet::new();
        set.insert(silence(
            "s1",
            spec("cred.read_netrc", "8353a512", "/home/j/.netrc", ""),
            0.0,
        ));
        let trojan = AlertSubject {
            exe_sha256_hex: "deadbeef",
            ..subject()
        };
        assert_eq!(set.decide(&trojan, 0.9, 5_000), SilenceDecision::Unaffected);
    }

    /// The same judgement must land on the same id, or re-issuing it
    /// stacks a second silence instead of replacing the first.
    #[test]
    fn the_id_is_derived_from_the_spec_and_is_stable() {
        let a = spec("cred.read_netrc", "8353a512", "/home/j/.netrc", "");
        let b = spec("cred.read_netrc", "8353a512", "/home/j/.netrc", "");
        assert_eq!(a.id("prod"), b.id("prod"));
        assert!(a.id("prod").starts_with("sil-"));
        // A different cluster is a different silence.
        assert_ne!(a.id("prod"), a.id("staging"));
        // So is a different spec.
        assert_ne!(
            a.id("prod"),
            spec("cred.read_netrc", "8353a512", "", "").id("prod")
        );
    }

    /// Without length prefixes, `("a", "bc")` and `("ab", "c")` would
    /// hash alike and two unrelated silences would share an id.
    #[test]
    fn field_boundaries_cannot_be_shifted_to_collide() {
        assert_ne!(
            spec("a", "bc", "", "").id("c"),
            spec("ab", "c", "", "").id("c")
        );
    }

    #[test]
    fn a_spec_without_a_hash_says_so() {
        assert!(spec("r", "abc", "", "").constrains_binary());
        assert!(!spec("r", "", "/p", "").constrains_binary());
    }

    // -- matching --------------------------------------------------------

    #[test]
    fn the_full_triple_matches_exactly_what_it_names() {
        let s = spec("cred.read_netrc", "8353a512", "/home/j/.netrc", "");
        assert!(s.matches(&subject()));
        for wrong in [
            AlertSubject {
                rule_id: "cred.read_aws",
                ..subject()
            },
            AlertSubject {
                exe_path: "/home/other/.netrc",
                ..subject()
            },
            AlertSubject {
                exe_sha256_hex: "ffff",
                ..subject()
            },
        ] {
            assert!(!s.matches(&wrong), "{wrong:?}");
        }
    }

    #[test]
    fn an_empty_field_is_a_wildcard_for_that_field_only() {
        // "this binary doing this is fine anywhere"
        let any_path = spec("cred.read_netrc", "8353a512", "", "");
        assert!(any_path.matches(&subject()));
        assert!(any_path.matches(&AlertSubject {
            exe_path: "/home/someone-else/.netrc",
            ..subject()
        }));
        // ...but still only that rule.
        assert!(!any_path.matches(&AlertSubject {
            rule_id: "cred.read_aws",
            ..subject()
        }));
    }

    #[test]
    fn a_host_scoped_silence_covers_only_that_host() {
        let scoped = spec("cred.read_netrc", "8353a512", "/home/j/.netrc", "aabb");
        assert!(scoped.matches(&subject()));
        assert!(!scoped.matches(&AlertSubject {
            host_fp_hex: "ccdd",
            ..subject()
        }));
    }

    #[test]
    fn a_fleet_wide_silence_covers_every_host() {
        let fleet = spec("cred.read_netrc", "8353a512", "/home/j/.netrc", "");
        assert!(fleet.matches(&subject()));
        assert!(fleet.matches(&AlertSubject {
            host_fp_hex: "ccdd",
            ..subject()
        }));
    }

    // -- weighting -------------------------------------------------------

    #[test]
    fn weight_zero_silences_and_weight_one_changes_nothing() {
        assert!((silence("s", SilenceSpec::default(), 0.0).apply(0.95) - 0.0).abs() < f32::EPSILON);
        assert!((silence("s", SilenceSpec::default(), 1.0).apply(0.95) - 0.95).abs() < 1e-6);
    }

    #[test]
    fn a_partial_weight_damps_proportionally() {
        let got = silence("s", SilenceSpec::default(), 0.3).apply(0.95);
        assert!((got - 0.285).abs() < 1e-6, "{got}");
    }

    /// A malformed weight must not raise a score. Damping is the only
    /// thing this may do.
    #[test]
    fn an_out_of_range_weight_cannot_amplify() {
        assert!(silence("s", SilenceSpec::default(), 5.0).apply(0.5) <= 1.0);
        assert!((silence("s", SilenceSpec::default(), 5.0).apply(0.5) - 0.5).abs() < 1e-6);
        assert!(silence("s", SilenceSpec::default(), -2.0).apply(0.5) >= 0.0);
    }

    // -- precedence ------------------------------------------------------

    /// An operator who writes a broad rule and then a narrow one means
    /// the narrow one.
    #[test]
    fn the_most_specific_silence_governs() {
        let mut set = SilenceSet::new();
        set.insert(silence("broad", spec("cred.read_netrc", "", "", ""), 0.0));
        set.insert(silence(
            "narrow",
            spec("cred.read_netrc", "8353a512", "/home/j/.netrc", ""),
            0.5,
        ));
        let governing = set.governing(&subject(), 5_000).expect("one matches");
        assert_eq!(governing.id, "narrow");
    }

    #[test]
    fn equally_specific_silences_are_broken_by_recency() {
        let mut set = SilenceSet::new();
        let mut older = silence("older", spec("cred.read_netrc", "8353a512", "", ""), 0.0);
        older.issued_unix_ms = 1_000;
        let mut newer = silence("newer", spec("cred.read_netrc", "8353a512", "", ""), 0.5);
        newer.issued_unix_ms = 2_000;
        set.insert(older);
        set.insert(newer);
        assert_eq!(set.governing(&subject(), 5_000).unwrap().id, "newer");
    }

    // -- the set ---------------------------------------------------------

    /// Propagation redelivers. An older copy arriving late must not undo
    /// a revocation issued after it.
    #[test]
    fn a_stale_reissue_does_not_replace_a_newer_one() {
        let mut set = SilenceSet::new();
        let mut newer = silence("s", spec("r", "abc", "", ""), 1.0);
        newer.issued_unix_ms = 5_000;
        set.insert(newer);
        let mut stale = silence("s", spec("r", "abc", "", ""), 0.0);
        stale.issued_unix_ms = 1_000;
        set.insert(stale);
        assert!((set.get("s").unwrap().weight - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn reissuing_with_a_newer_stamp_replaces() {
        let mut set = SilenceSet::new();
        set.insert(silence("s", spec("r", "abc", "", ""), 0.0));
        let mut revoked = silence("s", spec("r", "abc", "", ""), 1.0);
        revoked.issued_unix_ms = 9_000;
        set.insert(revoked);
        assert!((set.get("s").unwrap().weight - 1.0).abs() < f32::EPSILON);
        assert_eq!(set.len(), 1, "a re-issue replaces rather than stacks");
    }

    #[test]
    fn sweeping_drops_only_what_expired() {
        let mut set = SilenceSet::new();
        let mut short = silence("short", spec("r", "abc", "", ""), 0.0);
        short.expires_unix_ms = 2_000;
        set.insert(short);
        set.insert(silence("long", spec("r2", "def", "", ""), 0.0));
        assert_eq!(set.sweep(5_000), 1);
        assert_eq!(set.len(), 1);
        assert!(set.get("long").is_some());
    }

    #[test]
    fn an_empty_set_affects_nothing() {
        let set = SilenceSet::new();
        assert!(set.is_empty());
        assert_eq!(set.decide(&subject(), 0.9, 1), SilenceDecision::Unaffected);
    }

    #[test]
    fn the_decision_carries_what_an_operator_needs_to_understand_it() {
        let mut set = SilenceSet::new();
        set.insert(silence(
            "sil-abc123",
            spec("cred.read_netrc", "8353a512", "/home/j/.netrc", ""),
            0.3,
        ));
        match set.decide(&subject(), 0.9, 5_000) {
            SilenceDecision::Damped {
                silence_id,
                reason,
                from,
                to,
            } => {
                assert_eq!(silence_id, "sil-abc123");
                assert_eq!(reason, "benign");
                assert!((from - 0.9).abs() < f32::EPSILON);
                assert!((to - 0.27).abs() < 1e-6);
            }
            SilenceDecision::Unaffected => panic!("should have matched"),
        }
    }

    #[test]
    fn the_damped_note_says_both_numbers_and_why() {
        let full = "sil-0123456789abcdef0123456789abcdef";
        let note = damped_note(full, "git reads its own netrc", 0.95, 0.285);
        // Both numbers, because "arrived at 0.28" and "was 0.95 and got
        // damped to 0.28" are different facts about the same alert.
        assert!(note.contains("0.95"), "{note}");
        assert!(note.contains("0.28"), "{note}");
        assert!(note.contains("git reads its own netrc"), "{note}");
        // Enough of the id to find it, and not so much that a rationale
        // becomes a hash dump.
        assert!(note.contains("sil-0123456789ab"), "{note}");
        assert!(
            !note.contains(full),
            "the note should abbreviate the id, not restate it: {note}"
        );
    }

    /// An alert whose binary could not be hashed must not be swept up by
    /// a silence that names a hash — an empty subject field is missing
    /// information, not a match.
    #[test]
    fn an_unhashed_alert_is_not_covered_by_a_hash_specific_silence() {
        let mut set = SilenceSet::new();
        set.insert(silence(
            "s",
            spec("cred.read_netrc", "8353a512", "/home/j/.netrc", ""),
            0.0,
        ));
        let unhashed = AlertSubject {
            exe_sha256_hex: "",
            ..subject()
        };
        assert_eq!(
            set.decide(&unhashed, 0.9, 5_000),
            SilenceDecision::Unaffected
        );
    }
}
