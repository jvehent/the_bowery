#!/usr/bin/env bash
# install-agent.sh — install the Bowery agent on a remote node from a
# staged tarball (produced by package-agent.sh). Idempotent; safe to
# re-run for upgrades. Mirrors the .deb maintainer scripts but works
# on any systemd distro and any arch (it just installs the files it's
# shipped with).
#
# Run ON the target node as root:
#   sudo ./install-agent.sh --operator-pubkey <b64> [options]
#
# Options:
#   --operator-pubkey <b64>   Operator verifying key allowed to query
#                             this node (from `bowery key info` on your
#                             laptop). Required to actually use the node.
#   --whisper-bind <addr>     Operator-facing QUIC bind. Default
#                             0.0.0.0:9902. Use a 100.x tailnet IP for
#                             least exposure (see README on the ordering
#                             caveat).
#   --mesh-listen <addr>      Chitchat bind. Default 0.0.0.0:9901.
#   --cluster-id <name>       Mesh cluster id. Default bowery-tailnet.
#   --start                   Enable + start the service now. Implied
#                             when --operator-pubkey is a real key.
#   --no-start                Install only; don't enable/start.
#   --strict-syscalls         Skip the syscall-filter drop-in. By default a
#                             drop-in re-allows the @chown family, which the
#                             root agent needs (SQLite fchown()s its WAL/SHM
#                             as root) — without it the agent is SIGSYS-killed
#                             at startup (status=31/SYS). Use --strict-syscalls
#                             only if your unit already allows @chown.
#   -h, --help                This help.

set -euo pipefail

WHISPER_BIND="0.0.0.0:9902"
MESH_LISTEN="0.0.0.0:9901"
CLUSTER_ID="bowery-tailnet"
OPERATOR_PUBKEY=""
DO_START="auto"
STRICT_SYSCALLS="no"

die() { echo "error: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --operator-pubkey) OPERATOR_PUBKEY="${2:?}"; shift 2 ;;
        --whisper-bind)    WHISPER_BIND="${2:?}";    shift 2 ;;
        --mesh-listen)     MESH_LISTEN="${2:?}";     shift 2 ;;
        --cluster-id)      CLUSTER_ID="${2:?}";      shift 2 ;;
        --start)           DO_START="yes";           shift ;;
        --no-start)        DO_START="no";            shift ;;
        --strict-syscalls) STRICT_SYSCALLS="yes";    shift ;;
        -h|--help)         sed -n '2,34p' "$0";      exit 0 ;;
        *) die "unknown flag: $1 (see --help)" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SRC/bowery-agent"
SVC="$SRC/bowery-agent.service"
SLICE="$SRC/bowery.slice"
CFG_TEMPLATE="$SRC/agent.toml"
DROPIN="$SRC/10-remote-node.conf"

for f in "$BIN" "$SVC" "$SLICE" "$CFG_TEMPLATE" "$DROPIN"; do
    [[ -f "$f" ]] || die "missing bundled file: $f (extract the full tarball first)"
done

# Sanity: refuse to install an x86_64 binary on an arm host, etc.
if command -v file >/dev/null 2>&1; then
    host_arch="$(uname -m)"
    bin_desc="$(file -b "$BIN" || true)"
    case "$host_arch:$bin_desc" in
        aarch64:*x86-64*|arm*:*x86-64*|x86_64:*aarch64*)
            die "binary arch mismatch: host is $host_arch but $BIN is: $bin_desc
       rebuild for the right target (see package-agent.sh)" ;;
    esac
fi

echo "==> creating bowery system user + directories"
getent group bowery >/dev/null 2>&1 || groupadd --system bowery
getent passwd bowery >/dev/null 2>&1 || \
    useradd --system --gid bowery --home-dir /var/lib/bowery \
            --no-create-home --shell /usr/sbin/nologin \
            --comment "Bowery agent" bowery
install -d -m 0750 -o bowery -g bowery /var/lib/bowery
install -d -m 0750 -o bowery -g bowery /var/log/bowery
install -d -m 0755 /etc/bowery

echo "==> installing binary + unit"
install -m 0755 "$BIN"   /usr/bin/bowery-agent
install -m 0644 "$SVC"   /lib/systemd/system/bowery-agent.service
install -m 0644 "$SLICE" /lib/systemd/system/bowery.slice

# Operator CLI, if the package bundled it. Handy on the node itself for
# `bowery key info` (to read the node's fingerprint + pubkey) and
# `bowery doctor`. Optional — the agent works without it.
CLI="$SRC/bowery"
if [[ -f "$CLI" ]]; then
    echo "==> installing bowery CLI"
    install -m 0755 "$CLI" /usr/bin/bowery
fi

# Remote-node drop-in: re-allows the @chown syscall family, which the
# root agent needs (SQLite fchown()s its WAL/SHM as root). Without it
# the strict fleet-unit filter SIGSYS-kills the agent at baseline init.
# All other sandbox controls stay in force. Skip with --strict-syscalls.
if [[ "$STRICT_SYSCALLS" == "yes" ]]; then
    echo "==> --strict-syscalls: NOT installing the @chown syscall drop-in"
    echo "    (if the agent SIGSYS-dies with status=31/SYS, remove --strict-syscalls)"
    rm -f /etc/systemd/system/bowery-agent.service.d/10-remote-node.conf 2>/dev/null || true
else
    echo "==> installing remote-node drop-in (re-allows @chown syscalls)"
    install -d -m 0755 /etc/systemd/system/bowery-agent.service.d
    install -m 0644 "$DROPIN" /etc/systemd/system/bowery-agent.service.d/10-remote-node.conf
fi

CFG=/etc/bowery/agent.toml
if [[ -f "$CFG" ]]; then
    echo "==> keeping existing $CFG (not overwritten)"
    echo "    to re-generate, remove it and re-run this installer"
else
    echo "==> writing $CFG"
    [[ -n "$OPERATOR_PUBKEY" ]] || \
        echo "    WARNING: no --operator-pubkey given; the node will accept" \
             "no operator until you edit $CFG"
    op="${OPERATOR_PUBKEY:-PASTE_OPERATOR_PUBKEY_B64_HERE}"
    sed -e "s|@@WHISPER_BIND@@|$WHISPER_BIND|" \
        -e "s|@@MESH_LISTEN@@|$MESH_LISTEN|" \
        -e "s|@@CLUSTER_ID@@|$CLUSTER_ID|" \
        -e "s|@@OPERATOR_PUBKEY@@|$op|" \
        "$CFG_TEMPLATE" > "$CFG"
    chmod 0644 "$CFG"
fi

systemctl daemon-reload

# Decide whether to start. Real key present → start unless told not to.
have_real_key="no"
if grep -q 'PASTE_OPERATOR_PUBKEY_B64_HERE' "$CFG"; then have_real_key="no"; else have_real_key="yes"; fi
case "$DO_START" in
    yes) start_now="yes" ;;
    no)  start_now="no" ;;
    auto) start_now="$have_real_key" ;;
esac

if [[ "$start_now" == "yes" ]]; then
    echo "==> enabling + starting bowery-agent"
    systemctl enable --now bowery-agent.service
    sleep 1
    systemctl --no-pager --lines=8 status bowery-agent.service || true
else
    echo "==> installed but NOT started (no operator key yet)."
    echo "    1. edit $CFG → set [operators] pubkeys_b64"
    echo "    2. systemctl enable --now bowery-agent"
fi

echo
echo "Node identity — pass these to the operator laptop as --agent-fp / --agent-pubkey-b64:"
KEYFILE=/var/lib/bowery/identity.key
if [[ -f "$KEYFILE" ]]; then
    # We are root here, and the key is root-owned 0600 (the service runs
    # as root), so read it directly — no `sudo -u bowery`.
    if command -v bowery >/dev/null 2>&1; then
        bowery key info "$KEYFILE" || true
    else
        echo "  install the 'bowery' CLI on this node, then:"
        echo "     sudo bowery key info $KEYFILE"
        echo "  (fingerprint alone is also in: journalctl -u bowery-agent | grep fingerprint)"
    fi
else
    echo "  identity key not generated yet — created on first start."
    echo "  after starting:  sudo bowery key info $KEYFILE   (or grep the journal for the fp)"
fi
