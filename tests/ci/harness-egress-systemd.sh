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
pubdenied=false
if o=\$(try 1.1.1.1 443); then echo "public CONNECTED" >> "\$out"
else
    case "\$o" in *"Operation not permitted"*) echo "public EPERM" >> "\$out"; pubdenied=true ;; *) echo "public FAILED-OTHER \$o" >> "\$out" ;; esac
fi
lk=failed
if getent hosts example.com >/dev/null 2>&1; then echo "canary RESOLVED" >> "\$out"; lk=resolved; else echo "canary FAILED" >> "\$out"; fi
if getent hosts noo-ci-controller >/dev/null 2>&1; then echo "rendered RESOLVED" >> "\$out"; else echo "rendered FAILED" >> "\$out"; fi
enf=false; if [ "\$lk" = failed ] && [ "\$pubdenied" = true ]; then enf=true; fi
if [ "\$pubdenied" = true ]; then cr=denied; else cr=other; fi
printf '{"version":1,"pid":%s,"started_at":%s,"lookup":{"name":"example.com","result":"%s"},"connect":{"addr":"1.1.1.1:443","result":"%s"},"enforced":%s}\n' \
    "\$\$" "\$(date +%s)" "\$lk" "\$cr" "\$enf" > "\$R/egress.json"
chmod 644 "\$R/egress.json"
echo done >> "\$out"
mv "\$out" "$RESULT"
sleep infinity
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
run_block() {
    {
        echo 'set -eu'
        sed -n '/^# BEGIN config_unchanged$/,/^# END config_unchanged$/p' "$APPLY"
        sed -n '/^# BEGIN harness_egress$/,/^# END harness_egress$/p' "$APPLY"
        echo 'applied=""; need_harness_restart=0'
        echo 'harness_egress_apply'
        echo 'echo "APPLIED=$applied"; echo "RESTART=$need_harness_restart"'
    } > "$WORK/block.sh"
    bash "$WORK/block.sh"
}

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
systemctl daemon-reload
systemctl restart noo-harness

# ── d/e. what the unit saw ──────────────────────────────────────────────────
for _ in $(seq 1 30); do [ -f "$RESULT" ] && break; sleep 1; done
sleep 2
kill "$TCPDUMP" 2>/dev/null || true
echo "--- ci-result"
cat "$RESULT" 2>&1 || true
echo "--- dns capture"
cat "$WORK/dns.txt"
check "unit wrote its result" test -f "$RESULT"
for want in "loopback ok" "private ok" "public EPERM" "canary FAILED" "rendered RESOLVED" "done"; do
    check "unit saw: $want" grep -qx "$want" "$RESULT"
done
check "no DNS packet mentions example.com" bash -c "! grep -qi example.com '$WORK/dns.txt'"
check "no query went to the resolv.conf address" bash -c "! grep -q '192.0.2.53' '$WORK/dns.txt'"
check "egress.json says enforced" grep -q '"enforced":true' /run/noo-harness/egress.json
echo "--- systemctl show"
systemctl show noo-harness -p MainPID -p IPAddressDeny -p IPAddressAllow -p BindReadOnlyPaths -p InaccessiblePaths
systemctl --version | head -1
check "unit property IPAddressDeny is set" bash -c "systemctl show noo-harness -p IPAddressDeny --value | grep -q ."

# ── f. the node agent's real reader ─────────────────────────────────────────
if (cd "$REPO/node-agent-go" && NOO_REAL_SYSTEMD=1 go test ./internal/hostsvc -run TestRealSystemdEgress -v -count=1); then
    pass "node agent reads the live unit as enforced"
else
    fail "node agent reads the live unit as enforced"
fi

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

echo
if [ "$FAILS" = 0 ]; then echo "harness-egress-systemd: all assertions passed"; exit 0; fi
echo "harness-egress-systemd: $FAILS assertion(s) FAILED"
exit 1
