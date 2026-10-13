#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# teardown-controller-local — return a CONTROLLER box to blank. The symmetric
# twin of deenroll-node-local.sh, for the controller half of the fleet.
#
#     sudo bash teardown-controller-local.sh [--purge-data] [--purge-tailscale] [--factory] [-y]
#
# TWO GRANULARITIES, on purpose:
#   * For ITERATING a test (stand a fresh controller, tear down, repeat) you
#     usually do NOT want this — `noo stack clean --deep -y` returns the box
#     to a re-onboardable state while KEEPING docker, tailscale, and the
#     checkout, so the next `noo onboard` is fast. Use that in a loop.
#   * This script is the FULL teardown to blank: the stack AND everything the
#     controller install laid down beyond it — the on-box node-agent/gate/
#     hostd (the controller is also a node), the PKI, secrets, the pinned
#     key, and (opt-in) data + tailscale. Use it when you are DONE with a box.
#
# Runs `noo stack clean --deep -y` for the stack/volumes/secrets/PKI-untrust,
# then removes the §7b node-plane artifacts clean predates. NEVER removes the
# repo checkout or the age key backup — those are yours.
set -u
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }

PURGE_DATA=0; PURGE_TS=0; YES=0
for a in "$@"; do case "$a" in
    --purge-data) PURGE_DATA=1 ;;
    --purge-tailscale) PURGE_TS=1 ;;
    --factory) PURGE_DATA=1; PURGE_TS=1 ;;
    -y|--yes) YES=1 ;;
esac; done
say() { printf 'teardown-controller: %s\n' "$*"; }

REPO_USER="${SUDO_USER:-$(logname 2>/dev/null || echo '')}"
REPO_HOME="$(getent passwd "$REPO_USER" 2>/dev/null | cut -d: -f6)"

if [ "$YES" = 0 ]; then
    echo "This tears the controller down to BLANK: stack, volumes, secrets, PKI,"
    echo "the on-box agent/gate/hostd — and DELETES all graph/memory data."
    printf "Type 'teardown' to confirm: "; read -r c
    [ "$c" = teardown ] || { echo "aborted"; exit 1; }
fi

# ── 1. The stack + data + secrets + PKI (existing deep clean) ───────────────
if [ -n "$REPO_USER" ] && [ -d "$REPO_HOME/pai-assistant" ]; then
    say "running: noo stack clean --deep -y"
    runuser -u "$REPO_USER" -- sh -c 'cd ~/pai-assistant && noo stack clean --deep -y' || \
        say "WARNING: deep clean returned nonzero — continuing with the node-plane teardown"
else
    say "WARNING: no ~/pai-assistant checkout for '$REPO_USER' — skipping deep clean; remove the stack manually"
fi

# ── 2. The on-box node plane (§7b — clean --deep predates this) ─────────────
systemctl disable --now noo-node-agent 2>/dev/null || true
systemctl disable --now noo-hostd 2>/dev/null || true
rm -f /etc/systemd/system/noo-node-agent.service /etc/systemd/system/noo-hostd.service \
      /usr/local/bin/noo-node-agent /usr/local/bin/noo-hostd \
      /usr/local/bin/noo-gate /usr/local/bin/noo-apply /usr/local/bin/noo-deenroll \
      /etc/noo-node-agent.env /etc/noo-node-agent.env.container-backup
systemctl daemon-reload 2>/dev/null || true
rm -f /etc/sudoers.d/noo-cluster /etc/sudoers.d/noo-node-maintenance /etc/sudoers.d/noo-apply
rm -rf /etc/noo /var/lib/noo-node-agent /var/lib/noo-hostd
id -u noo-agent >/dev/null 2>&1 && userdel noo-agent 2>/dev/null || true
say "on-box node plane removed (agent, hostd, gate, /etc/noo, grants, noo-agent)"

# The controller-as-node may have carried a pinned key too (self-enrolled).
if [ -n "$REPO_HOME" ] && [ -f "$REPO_HOME/.ssh/authorized_keys" ]; then
    TMP="$(mktemp)"
    grep -vE 'command="/usr/local/bin/noo-gate"' "$REPO_HOME/.ssh/authorized_keys" > "$TMP" || true
    chown "$REPO_USER:$(id -gn "$REPO_USER")" "$TMP"; chmod 600 "$TMP"; mv "$TMP" "$REPO_HOME/.ssh/authorized_keys"
    say "noo-gate pin removed from $REPO_USER's authorized_keys"
fi

# ── 3. data (opt-in) ───────────────────────────────────────────────────────
# The data root is the one this install recorded (prep marker, else the
# install's .env) — never a default: purging a guessed path deletes data
# that is not this install's.
CTRL_DATA_ROOT="$(grep -E '^NOO_DATA_ROOT=' /etc/noo/host-prepped 2>/dev/null | cut -d= -f2- || true)"
[ -n "$CTRL_DATA_ROOT" ] || CTRL_DATA_ROOT="$(grep -E '^NOO_DATA_ROOT=' "$REPO_HOME/.noo/.env" "$REPO_HOME/pai-assistant/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d ' "' || true)"
if [ "$PURGE_DATA" = 1 ]; then
    if [ -z "$CTRL_DATA_ROOT" ]; then
        say "NOTE: no recorded data root (prep marker or .env) — data left in place; delete it by hand if intended"
    fi
    for d in ${CTRL_DATA_ROOT:+"$CTRL_DATA_ROOT"} "$REPO_HOME/pai-assistant/pki"; do
        [ -e "$d" ] && rm -rf "$d" && say "purged $d"
    done
else
    say "NOTE: the data root${CTRL_DATA_ROOT:+ ($CTRL_DATA_ROOT)} and the home PKI left in place (--purge-data / --factory to remove)"
fi

# ── 4. tailscale (opt-in; controllers usually installed it themselves) ──────
if [ "$PURGE_TS" = 1 ] && command -v tailscale >/dev/null 2>&1; then
    tailscale logout 2>/dev/null || true
    command -v apt-get >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq tailscale >/dev/null 2>&1 \
        && say "tailscale logged out + uninstalled"
elif command -v tailscale >/dev/null 2>&1; then
    say "tailscale left connected (--purge-tailscale / --factory to remove)"
fi

say "done. LEFT ALONE (yours): the ~/pai-assistant checkout and the age key backup."
say "Re-stand a controller with: cd ~/pai-assistant && noo onboard && noo stack start"
