# ATT&CK coverage

<!-- GENERATED FILE — do not edit by hand.
     Source: crates/bowery-analysis/src/attack.rs
     Regenerate: BOWERY_UPDATE_DOCS=1 cargo test -p bowery-analysis -->

What The Bowery's agents actually detect, mapped to MITRE ATT&CK, and — more
usefully — what they do not.

There is no "full" grade. No host sensor covers a technique completely: there
is always a variant, a bypass, or a code path nobody thought of, and a map that
claims completeness invites an operator to stop looking. The grades answer a
narrower question: *if this technique were used on this host, how likely is it
that something fires?*

- **good** — the mainstream variants fire.
- **partial** — one narrow variant fires; the common forms do not.
- **none** — nothing fires. Listed anyway; the gaps are the useful half.

Today: **12 good, 14 partial, 2 uncovered** across 28 techniques.

## Execution

### T1059.004 — Command and Scripting Interpreter: Unix Shell

**Coverage: partial**

Rules: `lineage.service_spawned_shell`, `lineage.service_spawned_interpreter`

Gap: only fires when a network service or scheduler is the parent. A shell started
from an interactive login looks exactly like a person working.

### T1204.002 — User Execution: Malicious File

**Coverage: partial**

Rules: `baseline.rarity`, `yara.match`

Gap: rests on the binary being rare for this host or matching a YARA rule. A
malicious file that is neither is executed silently.

## Persistence

### T1543.002 — Create or Modify System Process: systemd Service

**Coverage: good**

Rules: `persist.systemd_unit`, `persist.systemd_unit_lib`

Gap: user units under `~/.config/systemd` are not watched, and a unit created before
the agent started is never seen — there is no boot-time sweep.

### T1053.003 — Scheduled Task/Job: Cron

**Coverage: good**

Rules: `persist.cron`, `lineage.scheduled_downloader`

Gap: `at` jobs and systemd timers are not watched.

### T1098.004 — Account Manipulation: SSH Authorized Keys

**Coverage: good**

Rules: `persist.authorized_keys`, `cred.read_authorized_keys`

Gap: a key added through a non-default `AuthorizedKeysFile` path is missed.

### T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification

**Coverage: good**

Rules: `persist.shell_profile`, `persist.user_rc`, `persist.user_profile`

Gap: covers the standard rc and profile files; an exotic shell's own configuration
is not enumerated.

### T1547.006 — Boot or Logon Autostart Execution: Kernel Modules

**Coverage: partial**

Rules: `persist.kernel_module_untrusted`

Gap: reports a module the kernel itself declines to vouch for — out-of-tree or
unsigned — at the moment it loads, which is the only moment anything here can be
trusted about it. A module signed with a key the host accepts, or any module at all
where signature enforcement is off, produces no taint and no finding. Nothing
already resident when the agent started is visible, and a module that hides itself
stays hidden — which is why this fires at load rather than by polling.

### T1546 — Event Triggered Execution (udev rules)

**Coverage: partial**

Rules: `persist.udev`

Gap: watches udev rule directories only. The wider technique — inotify hooks,
message-bus triggers, anything else that runs code on an event — is not covered.

### T1556.003 — Modify Authentication Process: Pluggable Authentication Modules

**Coverage: good**

Rules: `persist.pam`

Gap: watches the configuration; a replaced PAM `.so` is caught only if it lands
under a watched path.

## Privilege Escalation

### T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

**Coverage: good**

Rules: `privesc.sudoers`, `recon.read_sudoers`

Gap: a rule added by a package's own postinst is indistinguishable from one an
attacker added.

### T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid

**Coverage: good**

Rules: `privesc.setid_unpackaged`, `privesc.setid_packaged_modified`, `privesc.setid_unknown_provenance`, `privesc.uid_transition_untrusted_setuid`

Gap: the set-id bit is read at exec time, so a binary that is made setuid and never
run again is not reported until it runs. There is no filesystem sweep.

### T1068 — Exploitation for Privilege Escalation

**Coverage: partial**

Rules: `privesc.uid_transition_no_helper`

Gap: catches the *result* — a process running as root whose parent was not — not the
exploit. An exploit that stays inside one process, never execs, and does its work
in-memory produces no transition to see.

## Defense Evasion

### T1070.002 — Indicator Removal: Clear Linux or Mac System Logs

**Coverage: good**

Rules: `evade.auth_log`, `evade.wtmp`

Gap: journald's binary logs are not watched, and on a systemd host that is where the
evidence actually lives.

### T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking

**Coverage: good**

Rules: `persist.ld_preload`

Gap: `/etc/ld.so.preload` is watched; the `LD_PRELOAD` *environment variable* is
not, because the exec sensor does not capture the environment.

### T1562.001 — Impair Defenses: Disable or Modify Tools

**Coverage: partial**

Rules: `probe.sensor_blind`, `peer.silent`

Gap: the agent reports its own blindness, and its neighbours now report it going
silent altogether — a host cannot witness its own death. What remains uncovered is
the quieter attack: an agent left running but tampered with, which still gossips and
so still looks alive to every peer watching for silence.

## Credential Access

### T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow

**Coverage: good**

Rules: `cred.read_shadow`, `cred.read_gshadow`, `cred.read_opasswd`, `cred.shadow`, `cred.passwd`

Gap: the sanctioned readers (a packaged, unmodified `sshd`, `su`, `login`, PAM) are
exempt, so a compromise *of one of those binaries* that leaves the package hash
intact — an injected library, a hijacked child process — reads shadow without a
finding.

### T1552.001 — Unsecured Credentials: Credentials In Files

**Coverage: good**

Rules: `cred.read_aws`, `cred.read_kube`, `cred.read_netrc`, `cred.read_pgpass`, `cred.read_mysql`, `cred.read_git`, `cred.read_docker`, `cred.read_rails_master_key`, `cred.read_htpasswd`

Gap: a known list of well-known credential paths. Application-specific secret files
nobody enumerated are not watched, and neither is a `.env`. No reader is sanctioned
for these, so every access is a finding.

### T1552.004 — Unsecured Credentials: Private Keys

**Coverage: good**

Rules: `cred.read_ssh_private_key`, `cred.read_ssh_host_key`, `cred.read_gnupg`, `cred.ssh_private_key`

Gap: keys stored outside `~/.ssh` and `/etc/ssh` are missed.

## Discovery

### T1087 — Account Discovery

**Coverage: partial**

Rules: `discovery.recon_burst`

Gap: needs a *burst* — several different recon commands from one parent. A patient
attacker running one command a minute never trips it, and reading `/etc/passwd`
directly instead of running `getent` is a credential-access hit rather than a
discovery one.

### T1082 — System Information Discovery

**Coverage: partial**

Rules: `discovery.recon_burst`

Gap: same burst requirement. Reading `/proc` and `/sys` directly, which is what a
compiled implant does, executes nothing and so is not seen.

### T1049 — System Network Connections Discovery

**Coverage: partial**

Rules: `discovery.recon_burst`

Gap: same burst requirement.

## Lateral Movement

### T1021.004 — Remote Services: SSH

**Coverage: partial**

Rules: `corroborate.net_inbound_connect`

Gap: the whisper network can ask the other end 'did you connect to me?', which is
the strongest signal here — but it only covers hosts that are *in* the mesh. A
connection from anywhere else cannot be corroborated.

## Command and Control

### T1105 — Ingress Tool Transfer

**Coverage: partial**

Rules: `lineage.service_spawned_downloader`, `lineage.scheduled_downloader`

Gap: fires on a downloader started by a service or scheduler. A downloader run from
a shell, or a transfer done in-process by an implant, is not seen.

### T1071.001 — Application Layer Protocol: Web Protocols

**Coverage: partial**

Rules: `c2.beacon_new_destination`

Gap: catches a timer to a destination this host has not known long — periodicity
alone would fire on NTP, package mirrors and every monitoring agent, so novelty is
what makes it readable. A jittered beacon, which is what any serious implant uses,
is indistinguishable from ordinary traffic by this measure; so is one multiplexed
onto an existing TLS session, since the sensor sees connection setup and not
messages; and a beacon slower than a few hours outruns the measurement window.

## Defense Evasion

### T1055 — Process Injection

**Coverage: partial**

Rules: `defense_evasion.ptrace_inject`

Gap: watches the `ptrace` requests that write to or seize a process, exempting
packaged debuggers. Two other doors reach the same place and neither is watched:
`process_vm_writev`, and writing `/proc/<pid>/mem` directly. And an attacker who
runs the distribution's own `gdb` is exempted by the very rule that makes this
usable — the same boundary the privilege-transition exemption has with `sudo`.

## Initial Access

### T1078 — Valid Accounts

**Coverage: none**

No rule fires.

Gap: an attacker using credentials that work looks exactly like the person those
credentials belong to. Nothing here models who *should* be logging in, from where,
or when, so a stolen key or password produces no signal at all. This is the single
largest gap on the map and it is not closeable with host telemetry alone.

## Command and Control

### T1572 — Protocol Tunneling

**Coverage: none**

No rule fires.

Gap: connections are recorded with addresses and ports and nothing inspects what
travels over them. SSH port-forwarding, DNS tunnelling and traffic wrapped in TLS on
a normal-looking port are all indistinguishable from the legitimate use of the same
protocols.

## Impact

### T1486 — Data Encrypted for Impact

**Coverage: partial**

Rules: `impact.mass_write_new_extension`

Gap: needs the sweep to *rename* what it encrypts, which most families do but not
all — in-place encryption that keeps the filename is invisible here. The sensor
reports write intent only: no renames, no unlinks, no contents, so there is no
entropy check and a family that writes everything as a common extension evades the
test that makes the rule usable at all.

## Rules that are not table entries

These fire from subsystems rather than from a rule table, so they have no
entry in the analyzer's rule lists:

- `baseline.rarity`
- `yara.match`
- `probe.sensor_blind`
- `peer.silent`
- `corroborate.net_inbound_connect`
- `corroborate.file_access`
