//! Built-in watch sets for file writes.
//!
//! The kernel sensor reports every write-intent open. This decides which
//! of them are worth an operator's attention.
//!
//! # Why these are built in rather than configured
//!
//! The agent already has operator-configurable file watches, and they
//! covered nothing by default — an operator had to know in advance which
//! paths matter. That is backwards for the paths below: `/etc/ld.so.preload`
//! and `~/.ssh/authorized_keys` are how Linux hosts get persisted on,
//! and every deployment wants them watched. Configuration is for the
//! paths that are specific to *your* estate.
//!
//! # Matching, and what it deliberately misses
//!
//! **Absolute paths only.** `openat` resolves relative paths against a
//! dirfd that a kernel probe cannot follow, so a relative path is
//! recorded but never matched. Resolving it wrongly would be worse than
//! not matching: it would attribute a write to a file nobody touched.
//! [`is_matchable`] makes the gap countable rather than silent.
//!
//! **No suppression by process name.** A package upgrade writes systemd
//! units, and it is tempting to ignore writes from `dpkg` or `apt`. We
//! don't, for one reason: `comm` is attacker-controlled — it is 16 bytes
//! any process can set with `prctl` — so a suppression list keyed on it
//! is an instruction for how to evade the rule. The process name is
//! reported so a human can judge, never used to silence.
//!
//! That means routine package operations will produce hits. The
//! rationale says so, and the fix is fleet corroboration (a write every
//! host makes at the same moment is an upgrade) rather than a bypass
//! anyone can spell.

/// What a matched write is evidence of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileWatchCategory {
    /// Survives a reboot, or re-executes on a schedule or a login.
    Persistence,
    /// Grants or widens privilege.
    PrivilegeEscalation,
    /// Secrets, or the files that guard them.
    Credential,
    /// Blinds or rewrites the record.
    DefenseEvasion,
}

impl FileWatchCategory {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Persistence => "persistence",
            Self::PrivilegeEscalation => "privilege-escalation",
            Self::Credential => "credential-access",
            Self::DefenseEvasion => "defense-evasion",
        }
    }
}

/// A matched write.
#[derive(Debug, Clone, PartialEq)]
pub struct FileWatchHit {
    pub rule_id: &'static str,
    pub category: FileWatchCategory,
    /// What this path is for, in an operator's words — the alert has to
    /// explain itself to someone woken at 03:00 who does not know why
    /// `/etc/ld.so.preload` matters.
    pub why: &'static str,
    /// `[0,1]`, fed straight into the alert's suspicion.
    pub severity: f32,
    /// Absolute exe paths that read this file **as their job**.
    ///
    /// Empty means no reader is sanctioned: every access is a finding.
    /// Consult it through [`reader_is_sanctioned`] rather than directly —
    /// membership alone is not enough, and treating it as an allowlist of
    /// names is the mistake the function exists to prevent.
    pub sanctioned_readers: &'static [&'static str],
}

/// How a rule matches a path.
#[derive(Debug, Clone, Copy)]
enum Match {
    /// Path starts with this. Directory rules end in `/` so
    /// `/etc/cron.daily` cannot be matched by `/etc/crontabs-mine`.
    Prefix(&'static str),
    /// Path is exactly this.
    Exact(&'static str),
    /// Path ends with this — the only way to catch a file in *any*
    /// user's home without enumerating homes.
    Suffix(&'static str),
}

struct Rule {
    id: &'static str,
    m: Match,
    category: FileWatchCategory,
    why: &'static str,
    severity: f32,
    /// See [`FileWatchHit::sanctioned_readers`]. Defaults to `NOBODY` for
    /// write rules: nothing has a *job* that requires writing
    /// `/etc/ld.so.preload`.
    readers: &'static [&'static str],
}

/// No reader of this path is sanctioned; every access is a finding.
const NOBODY: &[&str] = &[];

// ---------------------------------------------------------------------------
// Sanctioned readers
//
// Paths, not names. `comm` is 16 bytes any process sets with `prctl`, so
// an allowlist of names would be an evasion primitive: name your implant
// `sshd` and read every key on the box in silence. These are resolved
// from `/proc/<pid>/exe` and are only honoured for a binary a package
// vouches for — see `reader_is_sanctioned`.
//
// Both `/bin/...` and `/usr/bin/...` spellings appear because a
// non-merged-usr host resolves to the former. Listing a path that does
// not exist on a given host costs nothing.
// ---------------------------------------------------------------------------

/// Everything that legitimately reads the password databases.
///
/// `sshd-session` and `sshd-auth` are OpenSSH 9.8+, which split the
/// per-connection work out of `sshd`. Debian 13 ships them and Debian 12
/// does not — omitting them would have left the newer hosts alerting on
/// every login while the older ones went quiet, which reads as a
/// detection working until you notice which hosts are silent.
const PASSWORD_TOOLS: &[&str] = &[
    "/usr/sbin/sshd",
    "/usr/lib/openssh/sshd-session",
    "/usr/lib/openssh/sshd-auth",
    "/usr/sbin/unix_chkpwd",
    "/usr/bin/unix_chkpwd",
    "/usr/sbin/unix_update",
    "/bin/su",
    "/usr/bin/su",
    "/bin/login",
    "/usr/bin/login",
    "/usr/bin/passwd",
    "/usr/bin/sudo",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/sbin/chpasswd",
    "/usr/sbin/usermod",
    "/usr/sbin/useradd",
    "/usr/sbin/userdel",
    "/usr/sbin/groupadd",
    "/usr/sbin/groupdel",
    "/usr/sbin/vipw",
    "/usr/sbin/pwck",
    "/usr/sbin/grpck",
    "/usr/sbin/cron",
    "/usr/bin/systemd-sysusers",
    "/usr/lib/systemd/systemd-sysusers",
    // pid 1 itself. It resolves `User=` for every unit it starts, so on
    // a host with any such unit it reads the password databases at boot
    // and on every restart. Caught on legolas an hour after the first
    // pass shipped.
    "/usr/lib/systemd/systemd",
    "/lib/systemd/systemd",
    "/usr/sbin/lightdm",
    "/usr/sbin/gdm3",
    // The display manager's per-session auth helper, which is what
    // actually runs PAM for a graphical login — `gdm3` itself does not
    // read the password databases, this does. Caught on a desktop host;
    // a headless fleet would never have shown it.
    "/usr/libexec/gdm-session-worker",
    "/usr/lib/gdm3/gdm-session-worker",
    "/usr/libexec/lightdm-session",
    "/usr/lib/lightdm/lightdm-session",
    "/usr/bin/polkit-agent-helper-1",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    // Found by reading the fleet's inbox rather than by reasoning about
    // it: `accounts-daemon` was the third-largest source of
    // `/etc/shadow` alerts on a live host and had been missed. It is
    // what backs org.freedesktop.Accounts, so it reads the password
    // databases on every desktop and on anything running polkit.
    // Ubuntu ships it under libexec, Debian under lib/accountsservice.
    "/usr/libexec/accounts-daemon",
    "/usr/lib/accountsservice/accounts-daemon",
    "/usr/sbin/accounts-daemon",
    "/usr/lib/polkit-1/polkitd",
    "/usr/libexec/polkitd",
];

/// The SSH daemon, which reads host keys at startup and
/// `authorized_keys` on every connection. That is the entire job.
const SSH_DAEMON: &[&str] = &[
    "/usr/sbin/sshd",
    "/usr/lib/openssh/sshd-session",
    "/usr/lib/openssh/sshd-auth",
    "/usr/bin/ssh-keygen", // regenerates and fingerprints host keys
];

/// SSH client-side tools, which read *user* private keys to authenticate.
const SSH_CLIENT: &[&str] = &[
    "/usr/bin/ssh",
    "/usr/bin/ssh-add",
    "/usr/bin/ssh-keygen",
    "/usr/bin/ssh-copy-id",
    "/usr/bin/scp",
    "/usr/bin/sftp",
    "/usr/sbin/sshd",
    "/usr/lib/openssh/sshd-session",
];

/// `sudo` reading its own policy is what `sudo` is.
const SUDO_TOOLS: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/sbin/visudo",
    "/usr/bin/sudoedit",
    "/usr/bin/sudoreplay",
];

/// Git reaching for the credentials it was configured to use.
///
/// `git-remote-http` links libcurl, which reads `~/.netrc` as a
/// documented part of authenticating a fetch or push — so an ordinary
/// `git pull` over https raised a credential-access alert on this fleet.
/// One path covers https, ftp and ftps too: those are symlinks to
/// `git-remote-http`, and `/proc/<pid>/exe` reports the resolved target.
///
/// Deliberately just the one binary. `git-credential-store` reading
/// `.git-credentials` is arguably as legitimate, but that file holds
/// long-lived tokens with write access to source and has raised nothing
/// here — an exemption granted without a false positive to justify it is
/// detection given away for free.
const GIT_TOOLS: &[&str] = &["/usr/lib/git-core/git-remote-http"];

/// GnuPG reading its own keyring.
const GPG_TOOLS: &[&str] = &[
    "/usr/bin/gpg",
    "/usr/bin/gpg2",
    "/usr/bin/gpg-agent",
    "/usr/lib/gnupg/gpg-agent",
    "/usr/bin/gpgconf",
    "/usr/bin/gpgsm",
    "/usr/bin/dirmngr",
];

/// Is this read the sanctioned one?
///
/// Two conditions, and **both** are required:
///
/// 1. The reader's resolved exe path is one the rule names.
/// 2. Package provenance vouches for that binary — it is owned by an
///    installed package and its contents still match what the package
///    put there.
///
/// The second condition is what makes the first safe. On its own, a list
/// of paths is defeated by writing to one of them; a list of *names*
/// would be worse still, defeated by `prctl(PR_SET_NAME)`. Requiring
/// [`Provenance::PackagedIntact`] means the exemption covers the
/// distribution's `sshd` and nothing that merely resembles it — a
/// trojanised `/usr/sbin/sshd` reads every host key and is **not**
/// exempt, which is the case that matters most.
///
/// `exe` is `None` when `/proc/<pid>/exe` could not be read, which is
/// usually a process that exited between the open and the lookup. That
/// **is not** an exemption: the sanctioned path has to be demonstrated,
/// not assumed, and a detection that goes quiet whenever it cannot look
/// is one an attacker only has to outrun.
#[must_use]
pub fn reader_is_sanctioned(
    hit: &FileWatchHit,
    exe: Option<&str>,
    provenance: crate::provenance::Provenance,
) -> bool {
    let Some(exe) = exe else {
        return false;
    };
    if provenance != crate::provenance::Provenance::PackagedIntact {
        return false;
    }
    hit.sanctioned_readers.contains(&exe)
}

/// The suffixes the kernel probe ships a *read* for.
///
/// Mirrors `is_secret_path` in `bowery-ebpf`, which is the authority.
/// Duplicated because the two crates build for different targets and
/// cannot share a constant; kept honest by
/// [`tests::every_read_rule_is_reachable_through_the_kernel_filter`],
/// which compares them.
///
/// The comparison is not academic. Reads are the *filtered* direction —
/// writes ship unconditionally, but a read is dropped in the kernel
/// unless its path ends with one of these. Three read rules were correct,
/// registered, on the ATT&CK map, counted in `bowery_detections`, and
/// could never fire, because nothing had ever put the two lists side by
/// side: `~/.kube/config` (the kernel looked for `/kubeconfig`),
/// `master.key` (the kernel's `_key` has an underscore), and every
/// drop-in under `/etc/sudoers.d/`.
const KERNEL_SECRET_SUFFIXES: &[&str] = &[
    "/shadow",
    "/gshadow",
    "/opasswd",
    "/sudoers",
    "/id_rsa",
    "/id_dsa",
    "/id_ecdsa",
    "/id_ed25519",
    "_key",
    "/authorized_keys",
    "/credentials",
    "/kubeconfig",
    "/.kube/config",
    "/master.key",
    "/.netrc",
    "/.pgpass",
    "/.my.cnf",
    "/.git-credentials",
    "/.htpasswd",
    "/.dockercfg",
    "/secring.gpg",
];

/// A path each read rule is meant to fire on, as a real host spells it.
///
/// Serves two purposes, which is why it is written out rather than
/// generated. As a test fixture it proves each rule is reachable — a
/// synthesised path cannot do that, because a prefix rule like
/// `/etc/ssh/ssh_host_` names a *stem* and the file that matters is
/// `ssh_host_ed25519_key`. As a fixture for the detection prover it is
/// the list of reads to perform on a live host to make each rule fire.
///
/// Every read rule must appear here; a test enforces it, so a new rule
/// arrives with the evidence that it can fire.
pub const READ_RULE_EXAMPLES: &[(&str, &str)] = &[
    ("cred.read_shadow", "/etc/shadow"),
    ("cred.read_gshadow", "/etc/gshadow"),
    ("cred.read_opasswd", "/etc/security/opasswd"),
    ("cred.read_ssh_host_key", "/etc/ssh/ssh_host_ed25519_key"),
    ("cred.read_ssh_private_key", "/home/someone/.ssh/id_rsa"),
    (
        "cred.read_authorized_keys",
        "/home/someone/.ssh/authorized_keys",
    ),
    ("cred.read_aws", "/home/someone/.aws/credentials"),
    ("cred.read_kube", "/home/someone/.kube/config"),
    ("cred.read_netrc", "/home/someone/.netrc"),
    ("cred.read_pgpass", "/home/someone/.pgpass"),
    ("cred.read_mysql", "/home/someone/.my.cnf"),
    ("cred.read_git", "/home/someone/.git-credentials"),
    ("cred.read_docker", "/home/someone/.dockercfg"),
    ("cred.read_gnupg", "/home/someone/.gnupg/secring.gpg"),
    ("cred.read_rails_master_key", "/srv/app/config/master.key"),
    ("cred.read_htpasswd", "/var/www/.htpasswd"),
    ("recon.read_sudoers", "/etc/sudoers"),
];

/// Would the kernel probe ship a read of this path to userspace?
#[must_use]
pub fn kernel_ships_read(path: &str) -> bool {
    KERNEL_SECRET_SUFFIXES.iter().any(|s| path.ends_with(s))
}

/// The watch set.
///
/// Ordered most-specific first: `/etc/ld.so.preload` before any broader
/// `/etc/` rule, so the reported reason is the sharpest one that applies.
const RULES: &[Rule] = &[
    // -- persistence: execution that outlives a session -----------------
    Rule {
        id: "evade.watchdog_disarm",
        m: Match::Prefix("/dev/watchdog"),
        category: FileWatchCategory::DefenseEvasion,
        why: "the hardware watchdog was opened for write. A watchdog reboots a board that \
              stops petting it, so malware that wants to survive opens it and either keeps \
              it fed or disables it outright — this is what the Mirai family does on the \
              devices it takes, and it is how a compromised board stops recovering on its \
              own. Almost nothing else opens it: systemd and a watchdog daemon, and they \
              do it once at boot",
        severity: 0.8,
        readers: NOBODY,
    },
    Rule {
        id: "persist.ld_preload",
        m: Match::Exact("/etc/ld.so.preload"),
        category: FileWatchCategory::Persistence,
        why: "every dynamically linked process on the host loads what this file names, \
              before main() runs. Writing it is a whole-system code-injection primitive \
              and has almost no legitimate use",
        severity: 0.97,
        readers: NOBODY,
    },
    Rule {
        id: "persist.systemd_unit",
        m: Match::Prefix("/etc/systemd/system/"),
        category: FileWatchCategory::Persistence,
        why: "systemd units start at boot and can restart themselves. Also written by \
              package installs, so check the process and whether peers saw the same write",
        severity: 0.85,
        readers: NOBODY,
    },
    Rule {
        id: "persist.systemd_unit_lib",
        m: Match::Prefix("/usr/lib/systemd/system/"),
        category: FileWatchCategory::Persistence,
        why: "distribution-owned systemd unit directory; normally only a package manager \
              writes here",
        severity: 0.85,
        readers: NOBODY,
    },
    Rule {
        id: "persist.cron",
        m: Match::Prefix("/etc/cron"),
        category: FileWatchCategory::Persistence,
        why: "cron re-executes on a schedule, which is the cheapest durable foothold there is",
        severity: 0.9,
        readers: NOBODY,
    },
    Rule {
        id: "persist.authorized_keys",
        m: Match::Suffix("/.ssh/authorized_keys"),
        category: FileWatchCategory::Persistence,
        why: "appending a public key here grants permanent passwordless login as that user, \
              and survives password changes",
        severity: 0.95,
        readers: NOBODY,
    },
    Rule {
        id: "persist.pam",
        m: Match::Prefix("/etc/pam.d/"),
        category: FileWatchCategory::Persistence,
        why: "PAM decides how every authentication on the host succeeds; a module added \
              here can harvest or bypass credentials",
        severity: 0.93,
        readers: NOBODY,
    },
    Rule {
        id: "persist.udev",
        m: Match::Prefix("/etc/udev/rules.d/"),
        category: FileWatchCategory::Persistence,
        why: "udev rules can run programs on device events, which is execution that no \
              service list shows",
        severity: 0.8,
        readers: NOBODY,
    },
    Rule {
        id: "persist.shell_profile",
        m: Match::Prefix("/etc/profile.d/"),
        category: FileWatchCategory::Persistence,
        why: "sourced by every interactive login shell on the host",
        severity: 0.8,
        readers: NOBODY,
    },
    Rule {
        id: "persist.user_rc",
        m: Match::Suffix("/.bashrc"),
        category: FileWatchCategory::Persistence,
        why: "sourced by every interactive shell that user opens, so a line here \
              re-executes on each login and survives reboots",
        severity: 0.7,
        readers: NOBODY,
    },
    Rule {
        id: "persist.user_profile",
        m: Match::Suffix("/.bash_profile"),
        category: FileWatchCategory::Persistence,
        why: "sourced by that user's login shells; a common place to hide \
              re-execution that no service manager lists",
        severity: 0.7,
        readers: NOBODY,
    },
    // -- privilege escalation -------------------------------------------
    Rule {
        id: "privesc.sudoers",
        m: Match::Prefix("/etc/sudoers"),
        category: FileWatchCategory::PrivilegeEscalation,
        why: "defines who may become root and with what password prompt; a single line \
              here is a permanent privilege grant",
        severity: 0.95,
        readers: NOBODY,
    },
    // -- credential access ----------------------------------------------
    Rule {
        id: "cred.shadow",
        m: Match::Exact("/etc/shadow"),
        category: FileWatchCategory::Credential,
        why: "the password hash database. A write is either a password change or an \
              account being added or backdoored",
        severity: 0.9,
        readers: NOBODY,
    },
    Rule {
        id: "cred.passwd",
        m: Match::Exact("/etc/passwd"),
        category: FileWatchCategory::Credential,
        why: "account database; a new uid-0 entry here is a classic backdoor",
        severity: 0.88,
        readers: NOBODY,
    },
    Rule {
        id: "cred.ssh_private_key",
        m: Match::Suffix("/.ssh/id_rsa"),
        category: FileWatchCategory::Credential,
        why: "an SSH private key being written — key replacement, or a stolen key being \
              staged for use",
        severity: 0.85,
        readers: NOBODY,
    },
    // -- defense evasion -------------------------------------------------
    Rule {
        id: "defense_evasion.proc_mem_write",
        // Suffix rather than prefix: `/proc/` is far too broad, and the
        // pid in the middle cannot be expressed by the matcher. Very
        // little else on a Linux host is named `mem` at the end of a
        // path, and the write-intent filter narrows it further — reading
        // /proc/<pid>/mem is a debugger's business, writing it is
        // somebody putting code into a process.
        m: Match::Suffix("/mem"),
        category: FileWatchCategory::DefenseEvasion,
        why: "a process's memory was opened for writing through /proc. This is process \
              injection by the other door: code written here inherits the identity of \
              the process it lands in, so every provenance and lineage check keeps \
              vouching for that process afterwards",
        severity: 0.92,
        readers: NOBODY,
    },
    Rule {
        id: "evade.auth_log",
        m: Match::Prefix("/var/log/auth"),
        category: FileWatchCategory::DefenseEvasion,
        why: "the authentication log. Writes from anything but the logging daemon suggest \
              the record of a login is being edited",
        severity: 0.85,
        readers: NOBODY,
    },
    Rule {
        id: "evade.wtmp",
        m: Match::Prefix("/var/log/wtmp"),
        category: FileWatchCategory::DefenseEvasion,
        why: "login history; truncating it is how a session is removed from `last`",
        severity: 0.85,
        readers: NOBODY,
    },
];

/// Rules for *reads* of files that hold secrets.
///
/// The kernel ships only opens whose basename looks like a credential
/// (`shadow`, `id_*`, `credentials`, `.pgpass`, …), which is
/// deliberately permissive — it costs one ring slot to be wrong there,
/// and an operator's attention to be wrong here. These rules see the
/// whole path and decide what actually warrants an alert.
///
/// Reads are noisier than writes by nature: `sshd` reads host keys at
/// every startup, `sudo` reads `/etc/sudoers` on every invocation. The
/// severities below reflect that — a host key read is ordinary, and an
/// `/etc/shadow` read by something that is not a password tool is not.
const READ_RULES: &[Rule] = &[
    Rule {
        id: "cred.read_shadow",
        m: Match::Prefix("/etc/shadow"),
        category: FileWatchCategory::Credential,
        why: "the password hash database was read. Legitimate for `su`, `sudo`, `login` \
              and PAM; from anything else this is credential theft, and the hashes are \
              offline-crackable once taken",
        severity: 0.9,
        readers: PASSWORD_TOOLS,
    },
    Rule {
        id: "cred.read_gshadow",
        m: Match::Prefix("/etc/gshadow"),
        category: FileWatchCategory::Credential,
        why: "the group password database was read — the same exposure as /etc/shadow, \
              and rarer to touch legitimately",
        severity: 0.88,
        readers: PASSWORD_TOOLS,
    },
    Rule {
        id: "cred.read_opasswd",
        m: Match::Exact("/etc/security/opasswd"),
        category: FileWatchCategory::Credential,
        why: "PAM's password-history file, which holds previous password hashes for \
              every user — a bonus for anyone cracking the current ones",
        severity: 0.9,
        readers: PASSWORD_TOOLS,
    },
    Rule {
        id: "cred.read_ssh_host_key",
        m: Match::Prefix("/etc/ssh/ssh_host_"),
        category: FileWatchCategory::Credential,
        why: "an SSH host private key was read. sshd does this at startup; anything \
              else can impersonate this host to every client that trusts it",
        severity: 0.85,
        readers: SSH_DAEMON,
    },
    Rule {
        id: "cred.read_ssh_private_key",
        m: Match::Suffix("/.ssh/id_rsa"),
        category: FileWatchCategory::Credential,
        why: "an SSH private key was read — the credential that opens every host this \
              key is authorised on",
        severity: 0.9,
        readers: SSH_CLIENT,
    },
    Rule {
        id: "cred.read_aws",
        m: Match::Suffix("/.aws/credentials"),
        category: FileWatchCategory::Credential,
        why: "AWS access keys were read; these usually carry far more authority than \
              the host they were stored on",
        severity: 0.9,
        readers: NOBODY,
    },
    Rule {
        id: "cred.read_kube",
        m: Match::Suffix("/.kube/config"),
        category: FileWatchCategory::Credential,
        why: "kubeconfig was read, which typically grants control of a whole cluster",
        severity: 0.88,
        readers: NOBODY,
    },
    Rule {
        id: "cred.read_netrc",
        m: Match::Suffix("/.netrc"),
        category: FileWatchCategory::Credential,
        why: "a .netrc was read; it stores passwords in plain text for every host \
              listed in it",
        severity: 0.85,
        readers: GIT_TOOLS,
    },
    Rule {
        id: "cred.read_pgpass",
        m: Match::Suffix("/.pgpass"),
        category: FileWatchCategory::Credential,
        why: "PostgreSQL passwords were read, in plain text",
        severity: 0.85,
        readers: NOBODY,
    },
    Rule {
        id: "cred.read_mysql",
        m: Match::Suffix("/.my.cnf"),
        category: FileWatchCategory::Credential,
        why: "MySQL client credentials were read, in plain text",
        severity: 0.85,
        readers: NOBODY,
    },
    Rule {
        id: "cred.read_git",
        m: Match::Suffix("/.git-credentials"),
        category: FileWatchCategory::Credential,
        why: "stored Git credentials were read; these are often long-lived tokens with \
              write access to source",
        severity: 0.85,
        readers: NOBODY,
    },
    Rule {
        id: "cred.read_docker",
        m: Match::Suffix("/.dockercfg"),
        category: FileWatchCategory::Credential,
        why: "container registry credentials were read, which can allow poisoning the \
              images this estate deploys",
        severity: 0.85,
        readers: NOBODY,
    },
    Rule {
        id: "cred.read_gnupg",
        m: Match::Suffix("/secring.gpg"),
        category: FileWatchCategory::Credential,
        why: "a GnuPG secret keyring was read — signing and decryption authority for \
              whoever holds it",
        severity: 0.88,
        readers: GPG_TOOLS,
    },
    Rule {
        id: "cred.read_rails_master_key",
        m: Match::Suffix("/master.key"),
        category: FileWatchCategory::Credential,
        why: "an application master key was read, which decrypts that application's \
              stored secrets wholesale",
        severity: 0.85,
        readers: NOBODY,
    },
    Rule {
        id: "cred.read_htpasswd",
        m: Match::Suffix("/.htpasswd"),
        category: FileWatchCategory::Credential,
        why: "an HTTP basic-auth password file was read; the hashes in it are \
              offline-crackable and often reused elsewhere",
        severity: 0.8,
        readers: NOBODY,
    },
    Rule {
        id: "recon.read_sudoers",
        m: Match::Prefix("/etc/sudoers"),
        category: FileWatchCategory::PrivilegeEscalation,
        why: "the sudo policy was read — routine for `sudo` itself, and otherwise the \
              standard first step in working out how to become root here (reads of drop-ins under /etc/sudoers.d/ are \
              *not* seen: the kernel ships a read only when the path ends in a known \
              suffix, and drop-in names are arbitrary — writes to them are seen)",
        severity: 0.7,
        readers: SUDO_TOOLS,
    },
    Rule {
        id: "cred.read_authorized_keys",
        m: Match::Suffix("/.ssh/authorized_keys"),
        category: FileWatchCategory::Credential,
        why: "the list of keys permitted to log in as this user was read; sshd does \
              this on every connection, anything else is enumerating access",
        severity: 0.6,
        readers: SSH_DAEMON,
    },
];

/// Classify a **read** of a sensitive-looking path.
///
/// Separate from [`classify`] because the same path means different
/// things read and written: reading `/etc/shadow` is credential theft,
/// writing it is an account change.
#[must_use]
pub fn classify_read(path: &str) -> Option<FileWatchHit> {
    if !is_matchable(path) {
        return None;
    }
    READ_RULES
        .iter()
        .find(|r| match r.m {
            Match::Prefix(p) => path.starts_with(p),
            Match::Exact(p) => path == p,
            Match::Suffix(p) => path.ends_with(p),
        })
        .map(|r| FileWatchHit {
            rule_id: r.id,
            category: r.category,
            why: r.why,
            severity: r.severity,
            sanctioned_readers: r.readers,
        })
}

/// Every file-watch rule id, writes then reads.
///
/// Exists so the ATT&CK coverage map can be checked against the code
/// rather than trusted. See [`crate::attack`].
#[must_use]
pub fn rule_ids() -> Vec<&'static str> {
    RULES
        .iter()
        .chain(READ_RULES.iter())
        .map(|r| r.id)
        .collect()
}

/// Can this path be matched at all?
///
/// Only absolute paths. A relative one came from an `openat` against a
/// dirfd the probe could not resolve, and guessing would attribute a
/// write to a file nobody touched.
#[must_use]
pub fn is_matchable(path: &str) -> bool {
    path.starts_with('/')
}

/// Classify a write. `None` means nothing in the watch set applies.
#[must_use]
pub fn classify(path: &str) -> Option<FileWatchHit> {
    if !is_matchable(path) {
        return None;
    }
    RULES
        .iter()
        .find(|r| match r.m {
            Match::Prefix(p) => path.starts_with(p),
            Match::Exact(p) => path == p,
            Match::Suffix(p) => path.ends_with(p),
        })
        .map(|r| FileWatchHit {
            rule_id: r.id,
            category: r.category,
            why: r.why,
            severity: r.severity,
            sanctioned_readers: r.readers,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::Provenance;

    /// The alert that made this necessary.
    ///
    /// The live fleet produced 63 alerts in 24 minutes; 61 were `sshd`
    /// and `unix_chkpwd` doing their job. The rule text already *said*
    /// "sshd does this at startup" and alerted anyway.
    #[test]
    fn the_distributions_sshd_reading_a_host_key_is_not_a_finding() {
        let hit = classify_read("/etc/ssh/ssh_host_rsa_key").expect("rule matches");
        assert!(reader_is_sanctioned(
            &hit,
            Some("/usr/sbin/sshd"),
            Provenance::PackagedIntact
        ));
    }

    /// OpenSSH 9.8+ splits per-connection work into `sshd-session`.
    /// Debian 13 ships it, Debian 12 does not — miss it and the newer
    /// hosts alert on every login while the older ones stay quiet, which
    /// looks like a working detection until you notice which hosts are
    /// silent.
    #[test]
    fn the_split_sshd_helpers_are_sanctioned_too() {
        let hit = classify_read("/etc/shadow").expect("rule matches");
        for exe in [
            "/usr/lib/openssh/sshd-session",
            "/usr/lib/openssh/sshd-auth",
        ] {
            assert!(
                reader_is_sanctioned(&hit, Some(exe), Provenance::PackagedIntact),
                "{exe} must be sanctioned"
            );
        }
    }

    /// The whole point of anchoring on provenance.
    #[test]
    fn a_trojanised_sshd_is_not_sanctioned() {
        let hit = classify_read("/etc/ssh/ssh_host_rsa_key").expect("rule matches");
        for p in [
            Provenance::PackagedModified,
            Provenance::Unpackaged,
            Provenance::Unknown,
        ] {
            assert!(
                !reader_is_sanctioned(&hit, Some("/usr/sbin/sshd"), p),
                "a binary at the right path but {p:?} must still alert"
            );
        }
    }

    /// A binary somewhere else is not `sshd` no matter what it is
    /// called. `comm` never reaches this function precisely because it
    /// is 16 bytes any process sets with `prctl` — an allowlist keyed on
    /// it would be an instruction for reading every key on the box in
    /// silence.
    #[test]
    fn an_impostor_elsewhere_on_disk_is_not_sanctioned() {
        let hit = classify_read("/etc/shadow").expect("rule matches");
        assert!(!reader_is_sanctioned(
            &hit,
            Some("/tmp/sshd"),
            Provenance::PackagedIntact
        ));
    }

    /// The exemption is per rule, not per binary. `sshd` has a job that
    /// requires host keys; it has none that requires cloud credentials.
    #[test]
    fn a_sanctioned_reader_is_only_sanctioned_for_its_own_paths() {
        let aws = classify_read("/home/julien/.aws/credentials").expect("rule matches");
        assert!(!reader_is_sanctioned(
            &aws,
            Some("/usr/sbin/sshd"),
            Provenance::PackagedIntact
        ));
    }

    /// Fails **closed**, unlike the uid-transition rule.
    ///
    /// There, an unreadable parent reports nothing, because a transition
    /// cannot be established. Here the default is the opposite: the
    /// exemption must be earned. A detection that goes quiet whenever it
    /// cannot look is one an attacker only has to outrun — exit fast
    /// enough and `/proc/<pid>/exe` is gone.
    #[test]
    fn an_unreadable_exe_earns_no_exemption() {
        let hit = classify_read("/etc/shadow").expect("rule matches");
        assert!(!reader_is_sanctioned(
            &hit,
            None,
            Provenance::PackagedIntact
        ));
    }

    /// Nothing has a *job* that requires writing these.
    #[test]
    fn no_writer_is_ever_sanctioned() {
        for path in ["/etc/ld.so.preload", "/etc/sudoers", "/etc/shadow"] {
            let hit = classify(path).expect("rule matches");
            assert!(
                hit.sanctioned_readers.is_empty(),
                "{path} must have no sanctioned writer"
            );
            assert!(!reader_is_sanctioned(
                &hit,
                Some("/usr/bin/dpkg"),
                Provenance::PackagedIntact
            ));
        }
    }

    /// Secrets that belong to a person, not to a daemon, keep no
    /// exemption: there is no packaged binary whose job is reading your
    /// AWS keys.
    ///
    /// `.netrc` is the exception and is absent from this list on purpose
    /// — libcurl reads it to authenticate an ordinary `git` fetch, which
    /// this fleet raised as a credential-access alert. The rule for
    /// telling the two apart is whether a packaged binary reads the file
    /// as its documented job, not whether the file belongs to a person.
    #[test]
    fn user_secrets_have_no_sanctioned_reader() {
        for path in [
            "/home/j/.aws/credentials",
            "/home/j/.kube/config",
            "/home/j/.pgpass",
            "/home/j/.git-credentials",
        ] {
            let hit = classify_read(path).expect("rule matches");
            assert!(
                hit.sanctioned_readers.is_empty(),
                "{path} must have no sanctioned reader"
            );
        }
    }

    /// `git` fetching over https reads `~/.netrc` through libcurl. That
    /// raised a credential-access alert on a live fleet for what is an
    /// ordinary `git pull`.
    #[test]
    fn git_reading_a_netrc_to_authenticate_a_fetch_is_sanctioned() {
        let hit = classify_read("/home/julien/.netrc").expect("rule matches");
        assert!(reader_is_sanctioned(
            &hit,
            Some("/usr/lib/git-core/git-remote-http"),
            crate::provenance::Provenance::PackagedIntact,
        ));
        // The exemption is the packaged binary, not the name. A copy
        // that a package does not vouch for reads as what it is.
        assert!(!reader_is_sanctioned(
            &hit,
            Some("/usr/lib/git-core/git-remote-http"),
            crate::provenance::Provenance::PackagedModified,
        ));
        assert!(!reader_is_sanctioned(
            &hit,
            Some("/tmp/git-remote-http"),
            crate::provenance::Provenance::PackagedIntact,
        ));
        // And it does not extend to the neighbouring credential file,
        // which holds tokens rather than a fetch password.
        let git_creds = classify_read("/home/julien/.git-credentials").expect("rule matches");
        assert!(!reader_is_sanctioned(
            &git_creds,
            Some("/usr/lib/git-core/git-remote-http"),
            crate::provenance::Provenance::PackagedIntact,
        ));
    }

    /// A read rule the kernel never ships a read for cannot fire.
    ///
    /// Reads are the filtered direction: writes reach userspace
    /// unconditionally, but a read is dropped in the probe unless its
    /// path ends with one of `is_secret_path`'s suffixes. A rule can
    /// therefore be correct, registered, mapped to a technique and
    /// counted, and still be unreachable — which three of them were,
    /// because nothing compared the two lists.
    ///
    /// If this fails, the fix is in `bowery-ebpf`'s `is_secret_path`
    /// first and in [`KERNEL_SECRET_SUFFIXES`] second. Changing only the
    /// mirror makes the test pass and leaves the rule as dead as it was.
    #[test]
    fn every_read_rule_is_reachable_through_the_kernel_filter() {
        for (id, example) in READ_RULE_EXAMPLES {
            assert!(
                kernel_ships_read(example),
                "{id}: the kernel drops reads of `{example}`, so the rule can never fire"
            );
            assert_eq!(
                classify_read(example).map(|h| h.rule_id),
                Some(*id),
                "`{example}` is meant to be {id}"
            );
        }

        // And no read rule may sit outside that list, or it arrives with
        // no evidence that it can fire at all.
        for rule in READ_RULES {
            assert!(
                READ_RULE_EXAMPLES.iter().any(|(id, _)| *id == rule.id),
                "{} has no example path — add one, and check the kernel ships it",
                rule.id
            );
        }
    }

    /// A prefix rule for reads only ever sees the file it names.
    ///
    /// `recon.read_sudoers` is spelled as a prefix, which suggests it
    /// covers `/etc/sudoers.d/` too. It does not: drop-in filenames are
    /// arbitrary, the kernel matcher is suffix-only — a basename scan is
    /// what the verifier rejected — and so no suffix can catch them.
    /// Writes to those paths *are* seen, because writes are unfiltered.
    /// Pinned so the limit is a stated fact rather than a surprise.
    #[test]
    fn sudoers_drop_ins_are_visible_as_writes_but_not_as_reads() {
        assert!(kernel_ships_read("/etc/sudoers"));
        assert!(
            !kernel_ships_read("/etc/sudoers.d/90-cloud-init-users"),
            "if this starts passing, the drop-in gap has closed and the \
             rule text should stop disclaiming it"
        );
        // The write path has no such filter.
        assert_eq!(
            classify("/etc/sudoers.d/90-cloud-init-users").map(|h| h.rule_id),
            Some("privesc.sudoers"),
        );
    }

    /// The watchdog is how an IoT implant stops a board recovering on
    /// its own, and it is a write-intent open, so the sensor already
    /// delivers it — this rule is the whole change.
    #[test]
    fn opening_the_watchdog_for_write_is_a_finding() {
        for path in ["/dev/watchdog", "/dev/watchdog0", "/dev/watchdog1"] {
            assert_eq!(
                classify(path).map(|h| h.rule_id),
                Some("evade.watchdog_disarm"),
                "{path}"
            );
        }
        // Not every /dev node, and not a lookalike elsewhere.
        assert_eq!(classify("/dev/null"), None);
        assert_eq!(classify("/home/j/watchdog"), None);
        // The prover names a path that does not exist, because opening
        // the real device arms the timer and closing it can reboot the
        // board. It has to still classify.
        assert_eq!(
            classify("/dev/watchdog-bowery-prove-nosuch").map(|h| h.rule_id),
            Some("evade.watchdog_disarm")
        );
    }

    /// Every sanctioned path must be absolute, or it can never match a
    /// resolved `/proc/<pid>/exe` and the exemption is silently dead.
    #[test]
    fn sanctioned_reader_paths_are_absolute() {
        for r in RULES.iter().chain(READ_RULES.iter()) {
            for exe in r.readers {
                assert!(exe.starts_with('/'), "{} lists a relative {exe}", r.id);
            }
        }
    }

    #[test]
    fn catches_the_classic_persistence_paths() {
        for (path, id) in [
            ("/etc/ld.so.preload", "persist.ld_preload"),
            ("/etc/systemd/system/evil.service", "persist.systemd_unit"),
            ("/etc/cron.d/backdoor", "persist.cron"),
            ("/etc/crontab", "persist.cron"),
            ("/root/.ssh/authorized_keys", "persist.authorized_keys"),
            (
                "/home/julien/.ssh/authorized_keys",
                "persist.authorized_keys",
            ),
            ("/etc/pam.d/sshd", "persist.pam"),
            ("/etc/sudoers.d/oops", "privesc.sudoers"),
            ("/etc/shadow", "cred.shadow"),
            ("/var/log/auth.log", "evade.auth_log"),
        ] {
            let hit = classify(path).unwrap_or_else(|| panic!("{path} should match"));
            assert_eq!(hit.rule_id, id, "{path}");
        }
    }

    #[test]
    fn suffix_rules_catch_any_users_home() {
        // The only way to watch every home without enumerating them.
        assert!(classify("/home/alice/.ssh/authorized_keys").is_some());
        assert!(classify("/var/lib/postgres/.ssh/authorized_keys").is_some());
    }

    #[test]
    fn ordinary_writes_do_not_match() {
        for path in [
            "/tmp/build-output.o",
            "/var/lib/bowery/events.db",
            "/home/julien/notes.md",
            "/proc/self/oom_score_adj",
        ] {
            assert!(classify(path).is_none(), "{path} should not match");
        }
    }

    #[test]
    fn a_directory_rule_cannot_be_matched_by_a_similar_name() {
        // `/etc/systemd/system/` ends in a slash on purpose. Without it,
        // `/etc/systemd/system-evil` would match the unit rule.
        let hit = classify("/etc/systemd/system-not-a-unit-dir/x");
        assert!(hit.is_none(), "got {hit:?}");
    }

    #[test]
    fn relative_paths_never_match() {
        // They come from an openat against a dirfd the kernel probe
        // cannot resolve. Matching one would attribute a write to a file
        // nobody touched.
        assert!(!is_matchable("etc/shadow"));
        assert!(classify("etc/shadow").is_none());
        assert!(classify("../../etc/ld.so.preload").is_none());
    }

    #[test]
    fn the_most_specific_rule_wins() {
        // /etc/ld.so.preload must not be reported as some generic /etc
        // rule; the operator needs the sharpest reason.
        assert_eq!(
            classify("/etc/ld.so.preload").unwrap().rule_id,
            "persist.ld_preload"
        );
    }

    #[test]
    fn credential_reads_are_caught_across_a_broad_set() {
        for (path, id) in [
            ("/etc/shadow", "cred.read_shadow"),
            ("/etc/gshadow", "cred.read_gshadow"),
            ("/etc/security/opasswd", "cred.read_opasswd"),
            ("/etc/ssh/ssh_host_ed25519_key", "cred.read_ssh_host_key"),
            ("/home/julien/.ssh/id_rsa", "cred.read_ssh_private_key"),
            ("/root/.aws/credentials", "cred.read_aws"),
            ("/home/deploy/.kube/config", "cred.read_kube"),
            ("/home/ci/.netrc", "cred.read_netrc"),
            ("/var/lib/postgresql/.pgpass", "cred.read_pgpass"),
            ("/root/.my.cnf", "cred.read_mysql"),
            ("/home/dev/.git-credentials", "cred.read_git"),
            ("/root/.dockercfg", "cred.read_docker"),
            ("/home/a/.gnupg/secring.gpg", "cred.read_gnupg"),
            ("/srv/app/config/master.key", "cred.read_rails_master_key"),
            ("/etc/sudoers", "recon.read_sudoers"),
        ] {
            let hit = classify_read(path).unwrap_or_else(|| panic!("{path} should match"));
            assert_eq!(hit.rule_id, id, "{path}");
        }
    }

    #[test]
    fn reading_and_writing_the_same_path_are_different_findings() {
        // Reading /etc/shadow is credential theft; writing it is an
        // account change. Same path, different rule, different wording.
        let read = classify_read("/etc/shadow").unwrap();
        let write = classify("/etc/shadow").unwrap();
        assert_ne!(read.rule_id, write.rule_id);
        assert!(read.why.contains("read"));
    }

    #[test]
    fn ordinary_reads_do_not_match() {
        for path in [
            "/etc/passwd",
            "/etc/hosts",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/home/julien/.ssh/known_hosts",
            "/home/julien/notes.md",
        ] {
            assert!(classify_read(path).is_none(), "{path} should not match");
        }
    }

    #[test]
    fn routine_reads_rank_below_theft() {
        // sshd reads authorized_keys on every connection and sudo reads
        // the policy on every invocation. Both are worth recording and
        // neither should outrank an /etc/shadow read.
        let shadow = classify_read("/etc/shadow").unwrap();
        for routine in ["/home/x/.ssh/authorized_keys", "/etc/sudoers"] {
            let hit = classify_read(routine).unwrap();
            assert!(
                hit.severity < shadow.severity,
                "{routine} must rank below an /etc/shadow read"
            );
        }
    }

    #[test]
    fn read_rules_explain_themselves_too() {
        for r in READ_RULES {
            assert!(r.why.len() > 40, "{} needs a real explanation", r.id);
            assert!((0.0..=1.0).contains(&r.severity));
        }
        let mut ids: Vec<&str> = READ_RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(n, ids.len(), "duplicate read rule id");
    }

    #[test]
    fn every_rule_has_a_usable_severity_and_explanation() {
        for r in RULES {
            assert!(
                (0.0..=1.0).contains(&r.severity),
                "{} severity out of range",
                r.id
            );
            // The alert has to explain itself to someone who does not
            // already know why the path matters.
            assert!(r.why.len() > 40, "{} needs a real explanation", r.id);
            assert!(r.id.contains('.'), "{} should be namespaced", r.id);
        }
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate rule id");
    }
}
