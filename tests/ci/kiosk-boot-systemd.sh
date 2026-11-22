#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# A dedicated kiosk seat against a REAL systemd (the runner is PID 1 systemd),
# i1153: a seat that stayed black after a reboot because kiosk.service's start
# job queued behind plymouth-quit-wait.service, which nobody released.
#
# It installs the kiosk.service `noo kiosk setup --mode dedicated` RENDERS (its
# --dry-run --json output), with only ExecStart swapped for a sleeping stub
# (there is no display), plus a fake plymouth-quit-wait.service that never
# returns and a plymouth-quit.service that never runs: the incident's state.
# Then:
#   1. this release's unit becomes active with the wait still running;
#   2. the OLD ordering (After=plymouth-quit-wait.service) stays queued,
#      bounded by this script's own timeout, and `noo kiosk status --json`
#      names the job and what it waits behind;
#   3. releasing the wait starts the old unit (it was the wait, nothing else).
#
# What it cannot show: a boot transaction (a display manager's Conflicts=
# dropping plymouth-quit at boot) and a real plymouthd handing the screen
# over. Those need a VM boot.
#
# CI ONLY: it adds a kiosk user and units under /etc/systemd/system.
# Run as: sudo -E bash tests/ci/kiosk-boot-systemd.sh <path to noo>
set -u
NOO="${1:?usage: kiosk-boot-systemd.sh <path to noo>}"
UNITS=/etc/systemd/system
FLAG=/run/fake-plymouthd-gone
FAILS=0

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
check() { # check DESC CMD...
    local d="$1"; shift
    if "$@"; then pass "$d"; else fail "$d"; fi
}
prop() { systemctl show -p "$1" --value kiosk.service; }
# wait_active SECS: true once kiosk.service is active.
wait_active() {
    local i=0
    while [ "$i" -lt "$1" ]; do
        [ "$(prop ActiveState)" = active ] && return 0
        i=$((i + 1)); sleep 1
    done
    return 1
}
status_json() { "$NOO" --json kiosk status; }
jget() { python3 -c 'import json,sys; v=json.load(sys.stdin).get(sys.argv[1]); print("" if v is None else str(v).lower() if isinstance(v,bool) else v)' "$1"; }

[ "${GITHUB_ACTIONS:-}" = true ] || { echo "refusing: CI-only (it adds a kiosk user and units)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }

work=$(mktemp -d)
"$NOO" --json kiosk setup --mode dedicated --url https://ctrl.tail0000.ts.net --dry-run > "$work/dry.json" \
    || { echo "FAIL  noo kiosk setup --dry-run"; exit 1; }
python3 - "$work" <<'PY'
import json, sys, pathlib
work = pathlib.Path(sys.argv[1])
files = {pathlib.Path(f["path"]).name: f["content"] for f in json.loads((work / "dry.json").read_text())["files"]}
for n in ("kiosk.service", "kiosk-serve.service"):
    (work / n).write_text(files[n])
PY
stub() { sed 's|^ExecStart=.*|ExecStart=/bin/sleep infinity|' "$1"; }
echo "--- the rendered kiosk.service [Unit]"
sed -n '/^\[Unit\]/,/^\[Service\]/p' "$work/kiosk.service"

id -u kiosk >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin kiosk
printf 'NOO_KIOSK_USER=kiosk\nNOO_KIOSK_MODE=dedicated\nNOO_KIOSK_VT=1\n' > /etc/default/kiosk
stub "$work/kiosk-serve.service" > "$UNITS/kiosk-serve.service"
stub "$work/kiosk.service" > "$work/kiosk.new"
if [ ! -e /dev/tty1 ]; then
    echo "NOTE  no /dev/tty1 on this runner: the TTY lines are dropped (the ordering is what is tested)"
    sed -i '/^TTY\|^StandardInput=tty\|^Utmp/d' "$work/kiosk.new"
fi
# The OLD ordering: the same unit with the 0.6.29 After= line and without
# the display-manager plymouth lines.
sed -e 's|^After=systemd-user-sessions.service network-online.target kiosk-serve.service$|After=systemd-user-sessions.service network-online.target plymouth-quit-wait.service kiosk-serve.service|' \
    -e '/^Conflicts=plymouth-quit.service$/d' -e '/^After=plymouth-quit.service /d' \
    -e '/^OnFailure=plymouth-quit.service$/d' -e '/^ExecStartPre=.*plymouth/d' "$work/kiosk.new" > "$work/kiosk.old"
check "the rendered dedicated unit does not wait on plymouth-quit-wait" \
    sh -c "! grep -q '^After=.*plymouth-quit-wait' '$work/kiosk.new'"
check "the old unit does" grep -q '^After=.*plymouth-quit-wait' "$work/kiosk.old"

# The incident's plymouth: the wait returns only when plymouthd is gone
# (here: the flag), and plymouth-quit never runs.
rm -f "$FLAG"
# A runner image may MASK the plymouth units (a symlink to /dev/null): a
# write through that link lands in /dev/null and no fake unit exists.
systemctl unmask plymouth-quit-wait.service plymouth-quit.service >/dev/null 2>&1 || true
rm -f "$UNITS/plymouth-quit-wait.service" "$UNITS/plymouth-quit.service"
cat > "$UNITS/plymouth-quit-wait.service" <<EOF
[Unit]
Description=fake: hold until something quits plymouth (never, here)
[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutSec=0
ExecStart=/bin/sh -c 'while [ ! -e $FLAG ]; do sleep 1; done'
EOF
cat > "$UNITS/plymouth-quit.service" <<EOF
[Unit]
Description=fake: quit plymouth (never started: the boot transaction dropped it)
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/touch $FLAG
EOF
cp "$work/kiosk.new" "$UNITS/kiosk.service"
systemctl daemon-reload
systemctl start --no-block plymouth-quit-wait.service
sleep 2
check "plymouth-quit-wait is running and never returns" \
    test "$(systemctl show -p ActiveState --value plymouth-quit-wait.service)" = activating
[ "$(systemctl show -p ActiveState --value plymouth-quit-wait.service)" = activating ] || {
    ls -l "$UNITS/plymouth-quit-wait.service"; systemctl status --no-pager plymouth-quit-wait.service 2>&1 | head -12; }

# 1. This release's unit.
systemctl start --no-block kiosk.service
if wait_active 30; then pass "this release's unit is active with plymouth-quit-wait still running"; else
    fail "this release's unit did not become active within 30 s"; systemctl status kiosk.service --no-pager || true
    journalctl -u kiosk.service -n 30 --no-pager || true; systemctl list-jobs --no-pager || true
fi
check "nobody quit plymouth (the wait is still running)" \
    test "$(systemctl show -p ActiveState --value plymouth-quit-wait.service)" = activating
check "plymouth-quit never ran" test ! -e "$FLAG"
check "no job left for kiosk.service" test -z "$(prop Job)"
s=$(status_json)
check "kiosk status: active, no queued job" \
    test "$(echo "$s" | jget kiosk_service)/$(echo "$s" | jget kiosk_job_queued)" = "active/false"
systemctl stop kiosk.service

# 2. The old ordering: queued behind the wait, bounded here by timeout(1).
cp "$work/kiosk.old" "$UNITS/kiosk.service"
systemctl daemon-reload
timeout 20 systemctl start kiosk.service; rc=$?
check "the old unit's start hangs (timeout after 20 s, rc 124; got $rc)" test "$rc" = 124
check "its job is still queued (Job=$(prop Job))" test -n "$(prop Job)"
check "and it is inactive" test "$(prop ActiveState)" = inactive
systemctl list-jobs --no-pager || true
s=$(status_json)
echo "$s" | python3 -m json.tool | grep -E '"kiosk_(service|job_)' || true
check "kiosk status says a start job is queued" test "$(echo "$s" | jget kiosk_job_queued)" = true
check "and names plymouth-quit-wait.service" \
    test "$(echo "$s" | jget kiosk_job_blocked_by)" = plymouth-quit-wait.service

# 3. Releasing the wait (what `sudo plymouth quit` did on the seat).
touch "$FLAG"
if wait_active 30; then pass "the old unit starts once the wait is released"; else fail "the old unit did not start after the release"; fi

systemctl stop kiosk.service kiosk-serve.service plymouth-quit-wait.service || true
echo
if [ "$FAILS" -gt 0 ]; then echo "$FAILS check(s) failed"; exit 1; fi
echo "all checks passed"
