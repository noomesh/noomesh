#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# i1160 risk 5 against a REAL systemd + logind (the runner is PID 1 systemd):
# the controller's noo-hostd is a systemd USER unit (WantedBy=default.target),
# which starts at boot only when its user lingers. A runner cannot reboot, but
# "the user manager is up with no login" is exactly what a boot gives a
# lingering user, so this proves the mechanism onboard relies on:
#
#   1. a fresh user, never logged in, with a trivial user unit enabled under
#      default.target: no user manager, the unit is not running, and
#      `loginctl show-user` answers the "not logged in or lingering" error
#      noo-cli's parse_linger reads as off;
#   2. `loginctl enable-linger <user>` (what onboard runs, through sudo): the
#      user manager (user@<uid>.service) is active and the unit runs, with no
#      session, and `loginctl show-user -p Linger` answers `Linger=yes`;
#   3. `loginctl disable-linger <user>`: the manager and the unit stop.
#
# CI ONLY: it creates a user. Run as: sudo bash tests/ci/hostd-linger-systemd.sh
set -u
U=noo-linger-ci
UNIT=noo-ci-hostd.service
FAILS=0

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
# wait_for SECS CMD...: CMD succeeds within SECS seconds.
wait_for() {
    local n="$1"; shift
    while [ "$n" -gt 0 ]; do
        "$@" && return 0
        sleep 1; n=$((n - 1))
    done
    return 1
}

[ "${GITHUB_ACTIONS:-}" = true ] || [ "${NOO_CI_LINGER_ALLOW_LOCAL:-}" = 1 ] \
    || { echo "refusing: this is a CI-only script (it creates a user)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ "$(ps -o comm= -p 1)" = systemd ] || { echo "PID 1 is not systemd"; exit 2; }
systemctl --version | head -1

id "$U" >/dev/null 2>&1 || useradd -m -s /bin/bash "$U" || exit 2
UID_="$(id -u "$U")"
HOME_="$(getent passwd "$U" | cut -d: -f6)"
# Runner traps: a masked unit (a link to /dev/null) loads as "masked" and
# never starts, and without logind nothing acts on linger. Say so instead of
# failing later as "the manager never became active".
ls_="$(systemctl show -p LoadState --value "user@$UID_.service" 2>/dev/null)"
[ "$ls_" != masked ] || { echo "user@$UID_.service is masked on this runner"; exit 2; }
systemctl is-active --quiet systemd-logind.service || { echo "systemd-logind is not active"; exit 2; }
cleanup() {
    loginctl disable-linger "$U" 2>/dev/null || true
    systemctl stop "user@$UID_.service" 2>/dev/null || true
}
trap cleanup EXIT

# The unit, enabled the way `systemctl --user enable` would (that needs the
# user manager, which must not exist yet): the default.target.wants link.
mkdir -p "$HOME_/.config/systemd/user/default.target.wants"
cat > "$HOME_/.config/systemd/user/$UNIT" <<'EOF'
[Unit]
Description=noomesh CI stand-in for the controller's noo-hostd user unit

[Service]
ExecStart=/bin/sleep infinity

[Install]
WantedBy=default.target
EOF
ln -sf "../$UNIT" "$HOME_/.config/systemd/user/default.target.wants/$UNIT"
chown -R "$U:$U" "$HOME_/.config"

manager_active() { systemctl is-active --quiet "user@$UID_.service"; }
manager_inactive() { ! manager_active; }
unit_active() {
    sudo -u "$U" env XDG_RUNTIME_DIR="/run/user/$UID_" systemctl --user is-active --quiet "$UNIT" 2>/dev/null
}
unit_process() { pgrep -u "$U" -x sleep >/dev/null; }
no_unit_process() { ! unit_process; }
no_session() { [ -z "$(loginctl list-sessions --no-legend 2>/dev/null | awk -v u="$U" '$3 == u')" ]; }

# ── 1. linger off, never logged in ──────────────────────────────────────────
loginctl disable-linger "$U" 2>/dev/null || true
wait_for 30 manager_inactive || true
if manager_inactive; then pass "linger off: no user manager"; else fail "linger off: user@$UID_.service is active"; fi
if no_unit_process; then pass "linger off: the user unit is not running"; else fail "linger off: the unit's process runs"; fi
err="$(loginctl show-user "$U" -p Linger 2>&1 >/dev/null)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$err" | grep -q "not logged in or lingering"; then
    pass "linger off: loginctl answers the error parse_linger reads as off ($err)"
else
    fail "linger off: loginctl show-user exit $rc, stderr: $err"
fi

# ── 2. enable linger, as onboard does ───────────────────────────────────────
loginctl enable-linger "$U" || fail "loginctl enable-linger $U failed"
if wait_for 60 manager_active; then pass "linger on: user@$UID_.service is active"; else fail "linger on: user@$UID_.service never became active"; fi
if wait_for 30 unit_active; then pass "linger on: $UNIT (WantedBy=default.target) runs"; else fail "linger on: $UNIT is not active"; fi
if no_session; then pass "linger on: with no login session for $U"; else fail "linger on: $U has a session"; fi
out="$(loginctl show-user "$U" -p Linger 2>&1)"
if [ "$out" = "Linger=yes" ]; then pass "linger on: loginctl answers Linger=yes"; else fail "linger on: loginctl answered: $out"; fi

# ── 3. disable linger again ─────────────────────────────────────────────────
loginctl disable-linger "$U" || fail "loginctl disable-linger $U failed"
if wait_for 60 manager_inactive; then pass "linger off again: user@$UID_.service stopped"; else fail "linger off again: user@$UID_.service still active"; fi
if wait_for 30 no_unit_process; then pass "linger off again: the unit's process is gone"; else fail "linger off again: the unit's process still runs"; fi

echo "hostd-linger-systemd: $FAILS failure(s)"
[ "$FAILS" -eq 0 ]
