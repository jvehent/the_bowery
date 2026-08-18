//! Kernel module loading.
//!
//! `T1547.006` was the last technique on the coverage map at `none`, and
//! it is the one that invalidates the others: a module runs in kernel
//! context and can hide processes, files and sockets from every probe
//! this agent has — including the probe that would have reported it.
//! Only the load itself is observable.
//!
//! # Why the taint flags are the whole rule
//!
//! Elsewhere in this agent a single kernel-provided fact is never enough
//! and the finding needs a conjunction. Here it genuinely is enough,
//! because the kernel has already done the judging: it marks a module
//! out-of-tree or unsigned when its own signing chain does not vouch for
//! it. A stock host loads modules constantly — at boot, on hotplug, the
//! first time a filesystem is mounted — and every one of them is in-tree
//! and signed. One that is neither is a categorically different event,
//! not a matter of degree.
//!
//! # What it cannot see
//!
//! **A signed malicious module.** An attacker with a trusted signing key,
//! or on a host with Secure Boot disabled and signature enforcement off,
//! produces no taint and no finding.
//!
//! **Anything after the fact.** This fires at load. A module already
//! resident when the agent started is invisible, and one that hides
//! itself from `/proc/modules` stays hidden — which is exactly why the
//! detection is at load time rather than by polling.

/// The rule id an untrusted module load is reported under.
pub const RULE_ID: &str = "persist.kernel_module_untrusted";

/// Every rule id this module can produce.
#[must_use]
pub const fn rule_ids() -> &'static [&'static str] {
    &[RULE_ID]
}
