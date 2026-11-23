#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# Enforcement step 1 against a REAL systemd (the runner is PID 1 systemd):
# the applier's harness_egress block (lifted out of scripts/noo-apply.sh and
# run as root with the real paths) renders the hold, and a harness-like unit
# proves, from inside the hold, that loopback and private addresses connect,
# a public one is denied (EPERM), an internet name cannot be looked up (and
# the question never leaves the box: tcpdump on port 53 stays empty of it),
# and the rendered controller name resolves. Then the node agent's real
# reader judges the live unit, and the fail-safe is exercised: a controller
# that the hold would cut off is NOT held.
#
# No real controller, no secrets. The only network touched: a lookup of
# example.com (which must not leave) and a connect to 1.1.1.1 (denied).
# CI ONLY: it writes /etc/hosts, /etc/noo-harness.env and a noo-harness unit.
# Run as: sudo -E bash tests/ci/harness-egress-systemd.sh
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APPLY="$REPO/scripts/noo-apply.sh"
PORT_HTTP=18443
PORT_NATS=14222
UNIT=/etc/systemd/system/noo-harness.service
DROPIN=/etc/systemd/system/noo-harness.service.d/50-noomesh-egress.conf
PROBE=/usr/local/libexec/noo-ci-harness-probe
RESULT=/run/noo-harness/ci-result.txt
FAILS=0
PIDS=""

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
check() { # check DESC CMD...
    local d="$1"; shift
    if "$@"; then pass "$d"; else fail "$d"; fi
}

# This script rewrites /etc on the machine it runs on: only a CI runner.
[ "${GITHUB_ACTIONS:-}" = true ] || [ "${NOO_CI_EGRESS_ALLOW_LOCAL:-}" = 1 ] \
    || { echo "refusing: this is a CI-only script (it edits /etc/hosts and installs a noo-harness unit)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ "$(ps -o comm= -p 1)" = systemd ] || { echo "PID 1 is not systemd"; exit 2; }
WORK="$(mktemp -d /tmp/noo-egress-ci.XXXXXX)" || exit 2
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    systemctl stop noo-harness 2>/dev/null || true
}
trap cleanup EXIT
systemctl --version | head -1
echo "resolv.conf at start: $(ls -l /etc/resolv.conf | awk '{print $1, $9, $10, $11}')"

# ── a. the fake controller ──────────────────────────────────────────────────
PRIV="$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
[ -n "$PRIV" ] || { echo "no IPv4 address for the runner"; exit 2; }
echo "runner address: $PRIV"
(cd "$WORK" && exec python3 -m http.server "$PORT_HTTP" --bind 0.0.0.0 >/dev/null 2>&1) &
PIDS="$PIDS $!"
python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $PORT_NATS)); s.listen(16)
while True:
    c, _ = s.accept(); c.close()
" &
PIDS="$PIDS $!"
sleep 1
echo "$PRIV noo-ci-controller" >> /etc/hosts
printf 'NODE_ID=ci\nNOO_GATEWAY_URL=https://noo-ci-controller:%s\nNATS_URL=nats://noo-ci-controller:%s\n' \
    "$PORT_HTTP" "$PORT_NATS" > /etc/noo-harness.env
chmod 600 /etc/noo-harness.env

# ── b. the harness-like unit ────────────────────────────────────────────────
install -d -m 755 /usr/local/libexec
cat > "$PROBE" <<PROBE_EOF
#!/bin/bash
R=/run/noo-harness
if [ ! -d "\$R" ]; then sleep infinity; fi
out="\$R/ci-result.txt.tmp"; : > "\$out"
try() { timeout 5 bash -c 'exec 3<>/dev/tcp/\$0/\$1' "\$1" "\$2" 2>&1; }
if o=\$(try 127.0.0.1 $PORT_HTTP); then echo "loopback ok" >> "\$out"; else echo "loopback FAILED \$o" >> "\$out"; fi
if o=\$(try $PRIV $PORT_HTTP); then echo "private ok" >> "\$out"; else echo "private FAILED \$o" >> "\$out"; fi
# A dropped SYN surfaces as EPERM or a timeout (real systemd 249/255: a
# timeout); connecting at all is the leak. The host-side control below proves
# the runner itself reaches this address.
if o=\$(try 1.1.1.1 443); then echo "public CONNECTED" >> "\$out"; else echo "public BLOCKED" >> "\$out"; fi
# The loopback canary (127.0.0.2:9, outside the allowlist, nothing listening):
# unrestricted, the kernel refuses at once; held, the SYN is dropped.
cr=other
if o=\$(try 127.0.0.2 9); then echo "loopback2 CONNECTED" >> "\$out"; cr=connected
else
    case "\$o" in *"Connection refused"*) echo "loopback2 REFUSED" >> "\$out"; cr=refused ;; *) echo "loopback2 BLOCKED" >> "\$out"; cr=timeout ;; esac
fi
lk=failed
if getent hosts example.com >/dev/null 2>&1; then echo "canary RESOLVED" >> "\$out"; lk=resolved; else echo "canary FAILED" >> "\$out"; fi
if getent hosts noo-ci-controller >/dev/null 2>&1; then echo "rendered RESOLVED" >> "\$out"; else echo "rendered FAILED" >> "\$out"; fi
enf=false; if [ "\$lk" = failed ] && [ "\$cr" = timeout ]; then enf=true; fi
st=\$(date +%s)
rec() {
    rh=false; [ "\$(grep -m1 '^nameserver' /etc/resolv.conf 2>/dev/null)" = "nameserver 192.0.2.53" ] && rh=true
    printf '{"version":1,"pid":%s,"started_at":%s,"checked_at":%s,"resolv_held":%s,"lookup":{"name":"example.com","result":"%s"},"connect":{"addr":"127.0.0.2:9","result":"%s"},"enforced":%s}\n' \
        "\$\$" "\$st" "\$(date +%s)" "\$rh" "\$lk" "\$cr" "\$enf" > "\$R/egress.json.tmp" \
        && chmod 644 "\$R/egress.json.tmp" && mv -f "\$R/egress.json.tmp" "\$R/egress.json"
}
rec
echo done >> "\$out"
mv "\$out" "$RESULT"
while :; do sleep 2; rec; done
PROBE_EOF
chmod 755 "$PROBE"
cat > "$UNIT" <<UNIT_EOF
[Unit]
Description=noo-harness CI stand-in
[Service]
Type=simple
User=nobody
ExecStart=$PROBE
UNIT_EOF
systemctl daemon-reload

# ── c. the applier's block, real paths ──────────────────────────────────────
run_block() { # [APPLY_FILE]: this tree's applier, or another release's
    local src="${1:-$APPLY}"
    {
        echo 'set -eu'
        sed -n '/^# BEGIN config_unchanged$/,/^# END config_unchanged$/p' "$src"
        sed -n '/^# BEGIN harness_egress$/,/^# END harness_egress$/p' "$src"
        echo 'applied=""; need_harness_restart=0; need_daemon_reload=0'
        echo 'harness_egress_apply'
        # The applier's own restart of a running harness (absent from a
        # release older than this block: the caller restarts for it).
        sed -n '/^# BEGIN harness_restart/,/^# END harness_restart$/p' "$src"
        echo 'echo "APPLIED=$applied"; echo "RESTART=$need_harness_restart"'
    } > "$WORK/block.sh"
    bash "$WORK/block.sh"
}

# ── c0. the upgrade: the previous release's hold first ─────────────────────
# A node rolled from the previous release has that release's drop-in and a
# harness running under it. The new block must replace it in one apply and
# ask for one harness restart, after which the unit runs under the new hold.
# PREV_STACK_TAG is the release this one upgrades from.
PREV_STACK_TAG="${PREV_STACK_TAG:-stack-v0.6.29}"
OLD_APPLY="$WORK/prev-noo-apply.sh"
OLD_PID=""
if git -c safe.directory="$REPO" -C "$REPO" fetch -q --depth=1 origin "refs/tags/$PREV_STACK_TAG:refs/tags/$PREV_STACK_TAG" 2>"$WORK/fetch.err" \
    && git -c safe.directory="$REPO" -C "$REPO" show "$PREV_STACK_TAG:scripts/noo-apply.sh" > "$OLD_APPLY" && [ -s "$OLD_APPLY" ]; then
    OUT0="$(run_block "$OLD_APPLY" 2>"$WORK/block0.err")"
    echo "$OUT0"
    check "upgrade: the previous release ($PREV_STACK_TAG) installs its hold" grep -q 'harness-egress=enforced' <<<"$OUT0"
    systemctl daemon-reload
    systemctl restart noo-harness
    sleep 2
    OLD_PID="$(systemctl show -p MainPID --value noo-harness)"
    check "upgrade: the harness runs under the previous release's hold" test -n "$OLD_PID" -a "$OLD_PID" != 0
else
    cat "$WORK/fetch.err"
    fail "upgrade: could not read the previous release's applier ($PREV_STACK_TAG)"
fi

tcpdump -i any -nn -l 'port 53' > "$WORK/dns.txt" 2>&1 &
TCPDUMP=$!
PIDS="$PIDS $TCPDUMP"
sleep 2
rm -f "$RESULT"
OUT="$(run_block 2>"$WORK/block.err")"
echo "$OUT"
cat "$WORK/block.err"
check "applied tag says harness-egress=enforced" grep -q 'harness-egress=enforced' <<<"$OUT"
check "the drop-in exists" test -f "$DROPIN"
check "harness-net files exist" test -f /etc/noo/harness-net/resolv.conf -a -f /etc/noo/harness-net/hosts -a -f /etc/noo/harness-net/nsswitch.conf
check "the hosts file names the controller" grep -q 'noo-ci-controller' /etc/noo/harness-net/hosts
check "upgrade: the new block re-rendered the hold and asks for one harness restart" grep -qx 'RESTART=1' <<<"$OUT"
# The restart is the applier's own (its harness_restart block), not this script's.
check "upgrade: the applier itself restarted the harness" grep -q '^APPLIED=.*(harness restarted)' <<<"$OUT"
sleep 2
NEW_PID="$(systemctl show -p MainPID --value noo-harness)"
LIVE_ALLOW="$(systemctl show -p IPAddressAllow --value noo-harness)"
LIVE_WIDE="$(for a in $LIVE_ALLOW; do case $a in */32|*/128) ;; *) echo "$a" ;; esac; done)"
check "upgrade: after the restart a new harness process runs" test -n "$NEW_PID" -a "$NEW_PID" != 0 -a "$NEW_PID" != "$OLD_PID"
check "upgrade: the running unit allows single hosts only" test -n "$LIVE_ALLOW" -a -z "$LIVE_WIDE"
# Exactly loopback (v4 and v6) and the controller: no other address, single or not.
WANT_ALLOW="$(printf '%s\n' 127.0.0.1/32 ::1/128 "$PRIV/32" | sort | tr '\n' ' ')"
GOT_ALLOW="$(for a in $LIVE_ALLOW; do echo "$a"; done | sort | tr '\n' ' ')"
echo "allow: want [$WANT_ALLOW] got [$GOT_ALLOW]"
check "upgrade: the running unit allows exactly loopback and the controller" test -n "$LIVE_ALLOW" -a "$GOT_ALLOW" = "$WANT_ALLOW"
check "upgrade: the running unit carries the hold flag" bash -c "systemctl show -p Environment --value noo-harness | tr ' ' '\\n' | grep -qx NOO_HARNESS_EGRESS_HOLD=1"

# ── d/e. what the unit saw ──────────────────────────────────────────────────
for _ in $(seq 1 30); do [ -f "$RESULT" ] && break; sleep 1; done
sleep 2
kill "$TCPDUMP" 2>/dev/null || true
echo "--- ci-result"
cat "$RESULT" 2>&1 || true
echo "--- dns capture"
cat "$WORK/dns.txt"
check "unit wrote its result" test -f "$RESULT"
# Control: the runner itself reaches the public address, so the unit's failure
# to is the hold, not the network.
check "control: the host (outside the unit) reaches 1.1.1.1:443" timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'
for want in "loopback ok" "private ok" "public BLOCKED" "loopback2 BLOCKED" "canary FAILED" "rendered RESOLVED" "done"; do
    check "unit saw: $want" grep -qx "$want" "$RESULT"
done
check "no DNS packet mentions example.com" bash -c "! grep -qi example.com '$WORK/dns.txt'"
check "no query went to the resolv.conf address" bash -c "! grep -q '192.0.2.53' '$WORK/dns.txt'"
check "egress.json says enforced" grep -q '"enforced":true' /run/noo-harness/egress.json
echo "--- systemctl show"
systemctl show noo-harness -p MainPID -p IPAddressDeny -p IPAddressAllow -p BindReadOnlyPaths -p InaccessiblePaths
systemctl --version | head -1
check "unit property IPAddressDeny is set" bash -c "systemctl show noo-harness -p IPAddressDeny --value | grep -q ."

# Why a deny would not be enforced: systemd's own word and the kernel's state.
echo "--- enforcement diagnostics"
echo "kernel $(uname -r); cgroup fs: $(stat -fc %T /sys/fs/cgroup)"
tr ' ' '\n' < /proc/cmdline | grep -iE 'cgroup|systemd|bpf|lockdown' || echo "(no cgroup/bpf/lockdown switches on the kernel command line)"
cat /sys/kernel/security/lockdown 2>/dev/null || true
systemctl show noo-harness -p IPAccounting -p IPIngressBytes -p IPEgressBytes -p ControlGroup
# systemd's own word only (the Azure agent's "Firewall" lines are not systemd's).
journalctl -b _PID=1 --no-pager -o cat 2>/dev/null | grep -iE 'bpf|firewall|IPAddress|attach|cgroup' | head -30 || true
echo "unprivileged_bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)"
# Does ANY systemd BPF program attach? IP accounting uses the same mechanism.
timeout 20 systemd-run --wait --collect -p IPAccounting=yes /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/18443; echo hi >&3' 2>&1 | grep -iE 'IP traffic|Finished|Failed' || true
journalctl -u noo-harness -b --no-pager -o cat 2>/dev/null | tail -15 || true
grep -E 'CONFIG_CGROUP_BPF|CONFIG_BPF_SYSCALL' "/boot/config-$(uname -r)" 2>/dev/null || true
timeout 15 systemd-run --wait --pipe --quiet --collect -p RuntimeMaxSec=10 -p IPAccounting=yes -p 'IPAddressDeny=0.0.0.0/0 ::/0' -p 'IPAddressAllow=127.0.0.1/32' /bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>&1 | head -3 || true

# ── e2. only loopback and the controller ────────────────────────────────────
# The allow list names single hosts, and a DNS server at any other address,
# private or tailnet-range, gets no question through from inside the hold,
# while the host itself reaches it (the control).
ALLOWED="$(sed -n 's/^IPAddressAllow=//p' "$DROPIN")"
echo "allowed: $ALLOWED"
NOT_HOST="$(for a in $ALLOWED; do case $a in */32|*/128) ;; *) echo "$a" ;; esac; done)"
check "the allow list holds single hosts only" test -z "$NOT_HOST"
A_FILE="$(sort /etc/noo/harness-net/allow | tr '\n' ' ')"
A_UNIT="$(for a in $ALLOWED; do echo "${a%/*}"; done | sort | tr '\n' ' ')"
check "the allow file lists the same addresses" test "$A_FILE" = "$A_UNIT"
ip link add noo-ci-dns type dummy && ip link set noo-ci-dns up
for a in 10.66.0.53 100.64.0.53; do ip addr add "$a/32" dev noo-ci-dns; done
cat > "$WORK/dns-server.py" <<'PY'
import socket, sys, threading
def serve(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((addr, 53))
    while True:
        q, peer = s.recvfrom(512)
        s.sendto(q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x00\x00\x00\x00\x00" + q[12:], peer)
for a in sys.argv[1:]:
    threading.Thread(target=serve, args=(a,), daemon=True).start()
threading.Event().wait()
PY
python3 "$WORK/dns-server.py" 10.66.0.53 100.64.0.53 & PIDS="$PIDS $!"
sleep 1
cat > /usr/local/libexec/noo-ci-dns-ask <<'PY'
#!/usr/bin/env python3
import socket, sys
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
for a in sys.argv[1:]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    try:
        s.sendto(q, (a, 53)); s.recvfrom(512); print("%s answered" % a)
    except Exception:
        print("%s no answer" % a)
PY
chmod 755 /usr/local/libexec/noo-ci-dns-ask
held=(); while IFS= read -r l; do case "$l" in IPAddress*|Environment=*|BindReadOnlyPaths=*|InaccessiblePaths=*) held+=(-p "$l");; esac; done < "$DROPIN"
INSIDE="$(systemd-run --wait --pipe --quiet --collect -p User=nobody "${held[@]}" /usr/local/libexec/noo-ci-dns-ask 10.66.0.53 100.64.0.53 2>&1)"
echo "$INSIDE"
check "control: the host gets an answer from the DNS servers" bash -c "/usr/local/libexec/noo-ci-dns-ask 10.66.0.53 | grep -q answered"
N_ANSWERED="$(grep -c answered <<<"$INSIDE")"; N_NONE="$(grep -c "no answer" <<<"$INSIDE")"
check "inside the hold: no DNS server at another address answers" test "$N_ANSWERED" = 0 -a "$N_NONE" = 2
# A systemd-resolved host (/etc/resolv.conf its symlink): the hold binds the
# resolver directory, and a host rewrite of its resolver file (a rename, as
# resolvers do) leaves the unit reading its own. A runner whose
# /etc/resolv.conf is a plain file is judged on that branch in f3, which every
# run also exercises.
HP="$(systemctl show -p MainPID --value noo-harness)"
RT="$(readlink -f /etc/resolv.conf)"
case "$RT" in /run/systemd/resolve/*) RESOLVED_HOST=yes ;; *) RESOLVED_HOST=no ;; esac
echo "systemd-resolved host: $RESOLVED_HOST ($RT)"
if [ "$RESOLVED_HOST" = yes ]; then
    check "systemd-resolved host: the hold binds the resolver directory" grep -qx "BindReadOnlyPaths=/etc/noo/harness-net/resolvdir:/run/systemd/resolve" "$DROPIN"
    cp -p "$RT" "$RT.noo-ci" && echo "# rewritten by the CI" >> "$RT.noo-ci" && mv -f "$RT.noo-ci" "$RT"
    sleep 1
    HELD_NS="$(nsenter -t "$HP" -m cat /etc/resolv.conf | grep -m1 nameserver)"
    echo "after the host rewrite the unit reads: ${HELD_NS:-nothing}"
    check "after a host rewrite of $RT the unit still reads its own resolv.conf" test "$HELD_NS" = "nameserver 192.0.2.53"
fi

# ── f. the node agent's real reader ─────────────────────────────────────────
if (cd "$REPO/node-agent-go" && NOO_REAL_SYSTEMD=1 go test ./internal/hostsvc -run TestRealSystemdEgress -v -count=1); then
    pass "node agent reads the live unit as enforced"
else
    fail "node agent reads the live unit as enforced"
fi

# ── f2. the harness's own self-test, under the unit's own hold ─────────────
# The gateway's real egress check (egress_selftest.rs check_once), run as a
# transient unit with the drop-in's exact properties and the unit's env file:
# it must find itself held, reach the controller, and keep taking work.
# After f: it rewrites egress.json with its own pid.
if [ -n "${NOO_CI_SELFTEST:-}" ] && [ -x "$NOO_CI_SELFTEST" ]; then
    held=(); while IFS= read -r l; do case "$l" in IPAddress*|Environment=*|BindReadOnlyPaths=*|InaccessiblePaths=*) held+=(-p "$l");; esac; done < "$DROPIN"
    ST="$(systemd-run --wait --pipe --quiet --collect -p User=nobody -p EnvironmentFile=/etc/noo-harness.env -E NOO_REAL_HOLD=1 "${held[@]}" \
        "$NOO_CI_SELFTEST" --ignored --exact harness::egress_selftest::tests::real_hold_serves --nocapture 2>&1)"; ST_RC=$?
    echo "$ST"
    check "the harness's own self-test under the hold: held, controller reached, taking work" test "$ST_RC" = 0
    check "the harness's own self-test ran (1 passed)" grep -q 'test result: ok. 1 passed' <<<"$ST"
else
    fail "the harness's own self-test: no binary (NOO_CI_SELFTEST unset or not executable)"
fi

# ── f3. a host without systemd-resolved: /etc/resolv.conf a plain file ────
# What holds there after the host rewrites that file: the agent reports the
# private resolver file replaced while the hold stays enforced, nothing
# resolves from inside the unit, no resolver outside the allow list answers,
# the harness's own check still finds itself held and keeps taking work, and
# a restart of the harness restores its own file. "From inside" = in the
# unit's own cgroup (its address filter) and mount namespace, as its user.
RS_LINK=""; [ -L /etc/resolv.conf ] && RS_LINK="$(readlink /etc/resolv.conf)"
[ -n "$RS_LINK" ] && cp --remove-destination "$(readlink -f /etc/resolv.conf)" /etc/resolv.conf
OUT3="$(run_block 2>"$WORK/block3.err")"
echo "$OUT3"; cat "$WORK/block3.err"
sleep 3
check "plain-file host: the hold binds its own resolver file onto /etc/resolv.conf" grep -qx "BindReadOnlyPaths=/etc/noo/harness-net/resolv.conf:/etc/resolv.conf" "$DROPIN"
check "plain-file host: the applier restarted the harness under it" grep -q '^APPLIED=.*(harness restarted)' <<<"$OUT3"
HP="$(systemctl show -p MainPID --value noo-harness)"; CG="$(systemctl show -p ControlGroup --value noo-harness)"
inside() { sh -c 'cg=$1; hp=$2; shift 2; echo $$ > "/sys/fs/cgroup$cg/cgroup.procs" && exec nsenter -t "$hp" -m -- setpriv --reuid=65534 --regid=65534 --clear-groups "$@"' inside "$CG" "$HP" "$@"; }
BEFORE="$(nsenter -t "$HP" -m cat /etc/resolv.conf | grep -m1 nameserver)"
check "plain-file host: the unit reads its own resolver file" test "$BEFORE" = "nameserver 192.0.2.53"
cp -p /etc/resolv.conf /etc/resolv.conf.noo-ci && echo "# rewritten by the CI" >> /etc/resolv.conf.noo-ci && mv -f /etc/resolv.conf.noo-ci /etc/resolv.conf
sleep 4
AFTER="$(nsenter -t "$HP" -m cat /etc/resolv.conf | grep -m1 nameserver)"
echo "plain-file host: after the host rewrite the unit reads: ${AFTER:-nothing}"
if (cd "$REPO/node-agent-go" && NOO_REAL_SYSTEMD_RESOLV_REPLACED=1 go test ./internal/hostsvc -run '^TestRealSystemdEgressResolvReplaced$' -v -count=1); then
    pass "plain-file host, after a host rewrite: the node agent reports the private resolver file replaced and the hold enforced"
else
    fail "plain-file host, after a host rewrite: the node agent reports the private resolver file replaced and the hold enforced"
fi
check "control: the host itself resolves example.com" getent hosts example.com
if inside getent hosts example.com >/dev/null 2>&1; then
    fail "plain-file host, after a host rewrite: nothing resolves from inside the unit"
else
    pass "plain-file host, after a host rewrite: nothing resolves from inside the unit"
fi
IN3="$(inside /usr/local/libexec/noo-ci-dns-ask 10.66.0.53 100.64.0.53 127.0.0.53 2>&1)"
echo "$IN3"
check "plain-file host, after a host rewrite: no resolver outside the allow list answers from inside" \
    test "$(grep -c answered <<<"$IN3")" = 0 -a "$(grep -c 'no answer' <<<"$IN3")" = 3
if [ -n "${NOO_CI_SELFTEST:-}" ] && [ -x "$NOO_CI_SELFTEST" ]; then
    ST3="$(inside env -i PATH=/usr/bin:/bin NOO_REAL_HOLD=1 NOO_HARNESS_EGRESS_HOLD=1 NOO_GATEWAY_URL="https://noo-ci-controller:$PORT_HTTP" \
        "$NOO_CI_SELFTEST" --ignored --exact harness::egress_selftest::tests::real_hold_resolv_replaced --nocapture 2>&1)"; ST3_RC=$?
    echo "$ST3"
    check "plain-file host, after a host rewrite: the harness's own check still finds itself held and keeps taking work" \
        bash -c "[ $ST3_RC = 0 ] && grep -q 'test result: ok. 1 passed' <<<\"\$1\"" _ "$ST3"
else
    fail "plain-file host: the harness's own check: no binary (NOO_CI_SELFTEST unset or not executable)"
fi
systemctl restart noo-harness
sleep 2
HP2="$(systemctl show -p MainPID --value noo-harness)"
RESTORED="$(nsenter -t "$HP2" -m cat /etc/resolv.conf | grep -m1 nameserver)"
check "plain-file host: a restart of the harness restores its own resolver file" test "$RESTORED" = "nameserver 192.0.2.53"
# The runner as it was, for the fail-safe below.
[ -n "$RS_LINK" ] && ln -sfn "$RS_LINK" /etc/resolv.conf

# ── g. the fail-safe ────────────────────────────────────────────────────────
sed -i '/ noo-ci-controller$/d' /etc/hosts
echo "192.0.2.77 noo-ci-controller" >> /etc/hosts
rm -f "$DROPIN"
rm -rf /etc/noo/harness-net
systemctl daemon-reload
OUT2="$(run_block 2>"$WORK/block2.err")"
echo "$OUT2"
cat "$WORK/block2.err"
check "fail-safe: tag is UNENFORCED:selfcheck-" grep -q 'harness-egress=UNENFORCED:selfcheck-noo-ci-controller-' <<<"$OUT2"
check "fail-safe: no drop-in installed" test ! -e "$DROPIN"
check "fail-safe: no harness-net installed" test ! -e /etc/noo/harness-net
check "fail-safe: stderr says the hold was not applied" grep -q 'the hold was NOT applied' "$WORK/block2.err"
systemctl daemon-reload
systemctl restart noo-harness
sleep 2
echo "--- systemctl show (fail-safe)"
systemctl show noo-harness -p MainPID -p IPAddressDeny -p IPAddressAllow
check "fail-safe: the unit runs without IPAddressDeny" bash -c '[ -z "$(systemctl show noo-harness -p IPAddressDeny --value)" ]'
# The node agent's real reader on the live unheld unit, and the Codex gate on it.
if (cd "$REPO/node-agent-go" && NOO_REAL_SYSTEMD_UNENFORCED=1 go test ./internal/reconcile -run '^TestRealSystemdUnenforcedRefusesCodex$' -v -count=1); then
    pass "fail-safe: the node agent reads the live unit as unenforced and refuses a Codex harness"
else
    fail "fail-safe: the node agent reads the live unit as unenforced and refuses a Codex harness"
fi

echo
if [ "$FAILS" = 0 ]; then echo "harness-egress-systemd: all assertions passed"; exit 0; fi
echo "harness-egress-systemd: $FAILS assertion(s) FAILED"
exit 1
