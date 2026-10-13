#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# deenroll-node-local — LOGICAL wipe: return this node to "never met the
# fleet", without reflashing (onboarding test plan, Test 1; doubles as the
# uninstall story). Run ON the node, as the human, with sudo:
#
#     sudo bash deenroll-node-local.sh [--keep-tailscale]
#
# Removes everything PAI AUTHORED; leaves OS PACKAGES alone. "OS packages"
# = what prep installed via the system package manager and a real machine
# might have wanted regardless: docker, the NVIDIA container toolkit,
# curl/gnupg/rsync/ca-certificates, and the tailscale BINARY (this logs it
# out, does not uninstall it). Everything PAI wrote — agent, gate, /etc/noo,
# accounts, units, keys — is removed. Data root is kept unless --purge-data.
# THE CONTROLLER-SIDE half (tailscale admin device
# delete, cluster DB row, inventory line) is separate and listed at the end.
#
# CI GUARD: host8 hosts the GitHub Actions runners. This script refuses to
# touch /opt/actions-runner*, the noo-ci account, or the buildx builder —
# they are CI infrastructure, not fleet enrollment state.
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
KEEP_TS=0
FROM_GATE=0
PURGE_DATA=0
PURGE_TS=0
for a in "$@"; do
    case "$a" in
        --keep-tailscale) KEEP_TS=1 ;;
        # Invoked by noo-apply's teardown kind: no human present, no SUDO_USER.
        # Resolve the account to clean from the prep marker instead.
        --from-gate) FROM_GATE=1 ;;
        # Also delete the data root (models, HF cache, ollama). OFF by
        # default — data is the one thing worth keeping across a rebirth,
        # and re-downloading models is slow. Opt in explicitly.
        --purge-data) PURGE_DATA=1 ;;
        # Also UNINSTALL tailscale — but only if PAI installed it (marker).
        # The one OS package worth fully removing: onboarding-specific,
        # rarely a shared dependency. docker/nvidia are deliberately NOT
        # removed — commonly pre-existing, high blast radius.
        --purge-tailscale) PURGE_TS=1 ;;
    esac
done
if [ "$FROM_GATE" = 1 ] && [ -z "${SUDO_USER:-}" ]; then
    SUDO_USER="$(grep -E '^ENROLL_USER=' /etc/noo/host-prepped 2>/dev/null | cut -d= -f2- || true)"
    export SUDO_USER
fi
say() { printf 'deenroll: %s\n' "$*"; }

# ── agent + containers ─────────────────────────────────────────────────────
systemctl disable --now noo-node-agent 2>/dev/null && say "agent stopped+disabled" || true
rm -f /etc/systemd/system/noo-node-agent.service /etc/noo-node-agent.env \
      /etc/noo-node-agent.env.container-backup /usr/local/bin/noo-node-agent
systemctl disable --now noo-hostd 2>/dev/null || true
rm -f /usr/local/bin/noo-hostd /etc/systemd/system/noo-hostd.service
systemctl daemon-reload
docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^noo-' | xargs -r docker rm -f 2>/dev/null || true
say "agent, hostd, noo-* containers removed"

# ── the gate + grants ──────────────────────────────────────────────────────
rm -f /usr/local/bin/noo-gate /usr/local/bin/noo-apply
rm -f /etc/sudoers.d/noo-cluster /etc/sudoers.d/noo-node-maintenance /etc/sudoers.d/noo-apply
say "gate + sudoers grants removed"

# ── trust + state ──────────────────────────────────────────────────────────
# Capture the data root BEFORE /etc/noo goes away — the old order read the
# prep marker AFTER deleting it, so --purge-data silently purged nothing
#. Exported for the data section below.
DATA_ROOT_EARLY="$(grep -E '^NOO_DATA_ROOT=' /etc/noo/host-prepped 2>/dev/null | cut -d= -f2- || true)"
# Read the tailscale-ownership marker EARLY too (finding #96 — the same
# read-after-delete class as the data-root: the tailnet section read this
# from /etc/noo AFTER the walk deleted it, so --purge-tailscale could never
# actually uninstall, silently).
TS_OURS_EARLY="$(grep -E '^INSTALLED_TAILSCALE=' /etc/noo/host-prepped 2>/dev/null | cut -d= -f2- || echo 0)"
# The pull loop: prep-host arms noo-fetch.{service,timer};
# the old deenroll predated them, so a torn-down box kept polling the
# gateway every 60s forever, across reboots.
systemctl disable --now noo-fetch.timer 2>/dev/null || true
systemctl stop noo-fetch.service 2>/dev/null || true
rm -f /etc/systemd/system/noo-fetch.service /etc/systemd/system/noo-fetch.timer       /usr/local/bin/noo-fetch
systemctl daemon-reload
say "noo-fetch loop disarmed + removed"
rm -rf /etc/noo /var/lib/noo-node-agent
say "/etc/noo (PKI, marker, birth key) + agent state removed"

# ── the pinned controller key ──────────────────────────────────────────────
U="${SUDO_USER:-}"
if [ -n "$U" ]; then
    AK="$(getent passwd "$U" | cut -d: -f6)/.ssh/authorized_keys"
    if [ -f "$AK" ]; then
        # Remove ONLY the controller's key — precisely, by its KEY BODY, never
        # by comment. Matching on comments (pai-assistant@, ServerFleet, …)
        # was a serious bug: those overlap with the OPERATOR's own keys, so a
        # teardown deleted the human's personal fleet-key access to the box
        # (found live 2026-08-19). The pinned line carries the controller key;
        # extract its body and drop any line bearing that exact key (the pin,
        # plus a bare duplicate if enrolment ran unpinned). All other keys —
        # the operator's — are untouched.
        TMP="$(mktemp)"
        PIN="$(grep 'command="/usr/local/bin/noo-gate"' "$AK" | head -1 || true)"
        CTRL_BODY="$(printf '%s' "$PIN" | grep -oE '(ssh-[a-z0-9-]+|ecdsa-sha2[^ ]*) [A-Za-z0-9+/=]+' | awk '{print $2}' | head -1)"
        if [ -n "$CTRL_BODY" ]; then
            grep -vF "$CTRL_BODY" "$AK" > "$TMP" || true
        else
            # No pinned line to learn the body from (legacy bare enrolment):
            # remove only pinned lines, if any. Never guess by comment.
            grep -vE 'command="/usr/local/bin/noo-gate"' "$AK" > "$TMP" || true
        fi
        chown "$U:$(id -gn "$U")" "$TMP" && chmod 600 "$TMP" && mv "$TMP" "$AK"
        say "controller key removed from $U's authorized_keys (by key body — operator keys untouched)"
    fi
fi

# ── service account ────────────────────────────────────────────────────────
# NEVER touch noo-ci (CI) — only the fleet's agent account.
id -u noo-agent >/dev/null 2>&1 && userdel noo-agent 2>/dev/null && say "noo-agent account removed" || true

# On a gate-initiated teardown the applier + gate are being removed with
# everything else; clean up this script's installed copy last.
[ "$FROM_GATE" = 1 ] && rm -f /usr/local/bin/noo-deenroll

# ── data (asked, not assumed) ──────────────────────────────────────────────
# Data root: read the ACTUAL path from the prep marker — never a default,
# because a purge of a guessed path deletes someone else's data. Purge only
# when asked, and only a root the marker names.
DATA_ROOT="${DATA_ROOT_EARLY:-}"
if [ "$PURGE_DATA" = 1 ]; then
    if [ -z "$DATA_ROOT" ]; then
        say "NOTE: --purge-data skipped: /etc/noo/host-prepped names no data root, and a guessed one is never deleted"
    elif [ -d "$DATA_ROOT" ]; then rm -rf "$DATA_ROOT" && say "data root $DATA_ROOT PURGED (--purge-data)"; fi
elif [ -n "$DATA_ROOT" ] && [ -d "$DATA_ROOT" ]; then
    say "NOTE: data root $DATA_ROOT left in place (models/caches). Re-run with"
    say "      --purge-data, or teardown-node --purge-data, for a cold node."
fi

# ── tailnet ────────────────────────────────────────────────────────────────
if [ "$KEEP_TS" = 0 ] && command -v tailscale >/dev/null 2>&1; then
    tailscale logout 2>/dev/null && say "tailscale logged out" || true
    TS_OURS="${TS_OURS_EARLY:-0}"
    # Logout leaves profile crumbs in /var/lib/tailscale, and crumbs breed
    # the <name>-1, -2 ghost registrations on the next enroll (finding
    # #95). When PAI installed tailscale, its state exists only for the
    # fleet — reset it fully. A pre-existing tailscale is not ours to
    # wipe: leave the note instead.
    if [ "$TS_OURS" = 1 ] && command -v systemctl >/dev/null 2>&1; then
        systemctl stop tailscaled 2>/dev/null || true
        rm -rf /var/lib/tailscale
        systemctl start tailscaled 2>/dev/null || true
        say "tailscale state reset (PAI installed it — factory-fresh for the next join)"
    elif [ "$TS_OURS" != 1 ]; then
        say "tailscale state kept (pre-existing install). For factory-fresh:"
        say "  sudo systemctl stop tailscaled && sudo rm -rf /var/lib/tailscale && sudo systemctl start tailscaled"
        say "  (server-side device records are separate — delete old entries in the tailnet console)"
    fi
    # Uninstall ONLY if PAI installed it (marker) AND asked — never remove a
    # tailscale the machine had before onboarding.
    if [ "$PURGE_TS" = 1 ] && [ "$TS_OURS" = 1 ]; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq tailscale >/dev/null 2>&1                 && rm -f /etc/apt/sources.list.d/tailscale.list                 && say "tailscale UNINSTALLED (PAI installed it; --purge-tailscale)"
        fi
    elif [ "$PURGE_TS" = 1 ]; then
        say "tailscale kept: marker says PAI did not install it (pre-existing) — not ours to remove"
    fi
else
    say "tailscale left connected (--keep-tailscale)"
fi

say "done — this machine no longer knows the fleet."
say ""
say "CONTROLLER side: if this node was removed with 'noo cluster teardown-node'"
say "(or a controller offboard), the controller already cleaned up — nothing to do."
say "Only if the controller never ran teardown for this node (orphan recovery):"
say "  1. noo cluster forget <name>       # node row + mesh entry"
say "  2. tailscale admin: delete this device (frees the name + IP)"
say "  3. pki/nodes/<name>/ on the controller: delete so certs re-issue fresh"
