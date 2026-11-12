#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# egress-capture.sh: record every outbound connection this machine makes for a
# while, then print who made each one, where it went and how many bytes moved.
# It is the "see for yourself" half of docs/security/telemetry.md.
#
#   sudo docs/security/egress-capture.sh --minutes 60 --out ./egress-$(hostname)
#
# What it records (all of it in --out, nowhere else):
#   conntrack.events  every connection's start and end, from the kernel's
#                     connection tracker: addresses, ports, protocol, bytes and
#                     packets each way. Headers only.
#   names.tsv         hostnames: DNS questions and their answer addresses, and
#                     the server name (SNI) of each TLS connection. The packets
#                     these come from are parsed in memory and dropped; only
#                     the name and the address are written.
#   sockets.tsv       once a second, which process owns each open internet
#                     socket (ss -tunp): process name and pid.
#   containers.tsv    every 5 s, each running Docker container's name and IP
#                     (when Docker is installed), so a container's connection
#                     is named by its container.
#   egress.tsv, egress.md
#                     the report: one row per (who, destination, port, proto).
# It never records a payload: no pcap is written, no request or response body,
# no header beyond the TLS server name and the DNS question.
#
# What it changes: nothing, except net.netfilter.nf_conntrack_acct, which it
# sets to 1 so the kernel counts bytes per connection, and restores to its
# previous value on exit (also on Ctrl-C). It adds no firewall rule.
#
# What it needs: root, conntrack (conntrack-tools), tcpdump, ss (iproute2),
# python3. It refuses, saying which is missing, without them.
#
# What it cannot see:
#   - what was sent: it sees who, where and how much, never the content, so a
#     program's ordinary request and its telemetry to the same host look alike;
#   - anything that did not happen while it ran: a reporter on a 24-hour timer
#     shows up only if the capture spans its moment;
#   - a process's connection that opened and closed between two 1 s socket
#     polls is still listed (the kernel saw it) but as "unattributed";
#   - the TLS server name over IPv6, and under Encrypted ClientHello; the DNS
#     answer usually names the address anyway, and an address with no name is
#     listed by address;
#   - traffic in another network namespace than this one (run it on the host,
#     not in a container; Docker containers on this host ARE seen).
#
# Options:
#   --minutes N      how long to capture (default 10); Ctrl-C ends it early.
#   --out DIR        where to write; required; created if absent, must be empty.
#   --classify FILE  optional: a TSV of "who-regex<TAB>host-regex<TAB>class<TAB>why"
#                    lines; each report row takes the class of the first line that
#                    matches, else "unlisted".
#   --report-only    rebuild the report from an existing --out DIR.
set -euo pipefail

MINUTES=10; OUT=""; CLASSIFY=""; REPORT_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --minutes) MINUTES="${2:?--minutes needs a number}"; shift 2 ;;
        --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
        --classify) CLASSIFY="${2:?--classify needs a file}"; shift 2 ;;
        --report-only) REPORT_ONLY=1; shift ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "egress-capture: unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
done
[ -n "$OUT" ] || { echo "egress-capture: --out DIR is required: the capture writes only where you say" >&2; exit 2; }
case "$MINUTES" in ''|*[!0-9]*) echo "egress-capture: --minutes takes a whole number" >&2; exit 2 ;; esac
[ -z "$CLASSIFY" ] || [ -r "$CLASSIFY" ] || { echo "egress-capture: cannot read --classify $CLASSIFY" >&2; exit 2; }
command -v python3 >/dev/null || { echo "egress-capture: needs python3" >&2; exit 2; }

report() {
    python3 - "$OUT" "$CLASSIFY" <<'PY'
import collections, ipaddress, os, re, sys
out, classify = sys.argv[1], sys.argv[2]

def read(name):
    p = os.path.join(out, name)
    return open(p, errors="replace").read().splitlines() if os.path.exists(p) else []

local_nets = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10", "224.0.0.0/4", "ff00::/8")]
def is_local(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(a in n for n in local_nets) or a.is_unspecified

# names: ip -> set(names)
names = collections.defaultdict(set)
for line in read("names.tsv"):
    f = line.split("\t")
    if len(f) >= 4 and f[3]:
        names[f[3]].add(f[2])

# containers: ip -> name (last seen wins)
ctr = {}
for line in read("containers.tsv"):
    f = line.split("\t")
    if len(f) >= 3:
        for ip in f[2].split():
            ctr[ip] = "container:" + f[1].lstrip("/")

# sockets: (proto, lport, rip, rport) -> process
sock = {}
for line in read("sockets.tsv"):
    f = line.split("\t")
    if len(f) >= 6:
        sock[(f[1], f[2], f[3], f[4])] = f[5]

kv = re.compile(r"(\w+)=(\S+)")
flows = {}
host_ips = set(read("host_ips.txt"))
for line in read("conntrack.events") + read("conntrack.final"):
    m = re.search(r"\[(\d+)\.\d+\]", line)
    ts = int(m.group(1)) if m else 0
    proto = "tcp" if " tcp " in f" {line} " else "udp" if " udp " in f" {line} " else None
    if not proto:
        continue
    pairs = kv.findall(line)
    src = [v for k, v in pairs if k == "src"]; dst = [v for k, v in pairs if k == "dst"]
    sp = [v for k, v in pairs if k == "sport"]; dp = [v for k, v in pairs if k == "dport"]
    by = [int(v) for k, v in pairs if k == "bytes"]
    if not src or not dst or not dp:
        continue
    s, d, sport, dport = src[0], dst[0], (sp[0] if sp else ""), dp[0]
    if is_local(d):
        continue
    idm = re.search(r"id=(\d+)", line)
    key = idm.group(1) if idm else f"{proto}{s}{sport}{d}{dport}"
    fl = flows.setdefault(key, {"proto": proto, "src": s, "sport": sport, "dst": d, "dport": dport,
                                "out": 0, "in": 0, "first": ts, "last": ts})
    fl["first"] = min(fl["first"] or ts, ts); fl["last"] = max(fl["last"], ts)
    if len(by) >= 2:
        fl["out"], fl["in"] = max(fl["out"], by[0]), max(fl["in"], by[1])

def who(fl):
    if fl["src"] in ctr:
        return ctr[fl["src"]]
    p = sock.get((fl["proto"], fl["sport"], fl["dst"], fl["dport"]))
    if p:
        return "process:" + p
    if fl["src"] in host_ips:
        return "host process (unattributed)"
    return f"forwarded from {fl['src']} (unattributed)"

rules = []
if classify:
    for line in open(classify):
        if line.strip() and not line.startswith("#"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                rules.append((re.compile(f[0]), re.compile(f[1]), f[2], f[3]))

rows = collections.OrderedDict()
for fl in sorted(flows.values(), key=lambda x: x["first"]):
    w = who(fl)
    host = ",".join(sorted(names.get(fl["dst"], []))) or "(no name seen)"
    k = (w, host, fl["dst"], fl["dport"], fl["proto"])
    r = rows.setdefault(k, {"flows": 0, "out": 0, "in": 0, "first": fl["first"], "last": fl["last"]})
    r["flows"] += 1; r["out"] += fl["out"]; r["in"] += fl["in"]
    r["first"] = min(r["first"], fl["first"]); r["last"] = max(r["last"], fl["last"])

def cls(w, host):
    for rw, rh, c, why in rules:
        if rw.search(w) and rh.search(host):
            return c, why
    return ("unlisted", "") if rules else ("", "")

with open(os.path.join(out, "egress.tsv"), "w") as t, open(os.path.join(out, "egress.md"), "w") as md:
    t.write("who\thost\tip\tport\tproto\tflows\tbytes_out\tbytes_in\tfirst\tlast\tclass\twhy\n")
    md.write("| Who | Destination | IP | Port | Flows | Bytes out | Bytes in | Class | Why |\n|---|---|---|---|---|---|---|---|---|\n")
    for (w, host, ip, port, proto), r in rows.items():
        c, why = cls(w, host)
        t.write(f"{w}\t{host}\t{ip}\t{port}\t{proto}\t{r['flows']}\t{r['out']}\t{r['in']}\t{r['first']}\t{r['last']}\t{c}\t{why}\n")
        md.write(f"| {w} | {host} | {ip} | {port}/{proto} | {r['flows']} | {r['out']} | {r['in']} | {c} | {why} |\n")
print(f"egress-capture: {len(flows)} outbound connection(s) to {len({k[2] for k in rows})} address(es); "
      f"{sum(1 for k in rows if cls(k[0], k[1])[0] == 'unlisted')} row(s) unlisted; report in {out}/egress.md")
PY
}

if [ "$REPORT_ONLY" = 1 ]; then report; exit 0; fi

[ "$(id -u)" = 0 ] || { echo "egress-capture: run as root (sudo): the connection tracker and packet capture need it" >&2; exit 2; }
missing=""
for c in conntrack tcpdump ss; do command -v "$c" >/dev/null || missing="$missing $c"; done
[ -z "$missing" ] || { echo "egress-capture: missing:$missing (Debian/Ubuntu: apt install conntrack tcpdump iproute2; Alpine: apk add conntrack-tools tcpdump iproute2)" >&2; exit 2; }
SYSCTL=/proc/sys/net/netfilter/nf_conntrack_acct
[ -w "$SYSCTL" ] || modprobe nf_conntrack 2>/dev/null || true
[ -w "$SYSCTL" ] || { echo "egress-capture: $SYSCTL is not writable: this kernel has no connection tracker here" >&2; exit 2; }
mkdir -p "$OUT"
[ -z "$(ls -A "$OUT")" ] || { echo "egress-capture: --out $OUT is not empty; give a fresh directory" >&2; exit 2; }
chmod 0700 "$OUT"

ACCT_WAS="$(cat "$SYSCTL")"
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    conntrack -L -o extended,id 2>/dev/null | sed "s/^/[$(date +%s).0] /" > "$OUT/conntrack.final" || true
    echo "$ACCT_WAS" > "$SYSCTL" 2>/dev/null || true
    echo "egress-capture: stopped; nf_conntrack_acct restored to $ACCT_WAS"
    report
}
trap cleanup EXIT
trap 'exit 130' INT TERM
echo 1 > "$SYSCTL"
{ ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1; } > "$OUT/host_ips.txt"

conntrack -E -e NEW,DESTROY -o timestamp,extended,id > "$OUT/conntrack.events" 2>/dev/null &
PIDS+=($!)

NAMES_PARSER="$(cat <<'PY'
import struct, sys, time
r = sys.stdin.buffer
hdr = r.read(24)
if len(hdr) < 24: sys.exit(0)
le = hdr[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
E = "<" if le else ">"
link = struct.unpack(E + "I", hdr[20:24])[0]
out = open(sys.argv[1], "a", buffering=1)
def name(b, o, depth=0):
    labels = []
    while o < len(b) and depth < 20:
        n = b[o]
        if n == 0: return ".".join(labels), o + 1
        if n & 0xC0 == 0xC0:
            p = ((n & 0x3F) << 8) | b[o + 1]
            return ".".join(labels + [name(b, p, depth + 1)[0]]), o + 2
        labels.append(b[o + 1:o + 1 + n].decode("ascii", "replace")); o += 1 + n
    return ".".join(labels), o
def dns(p):
    if len(p) < 12 or not (p[2] & 0x80): return
    qd, an = struct.unpack(">HH", p[4:8]); o = 12; q = ""
    for _ in range(qd):
        q, o = name(p, o); o += 4
    for _ in range(an):
        _, o = name(p, o)
        t, _, _, l = struct.unpack(">HHIH", p[o:o + 10]); o += 10
        if t == 1 and l == 4:
            a4 = ".".join(map(str, p[o:o + 4])); out.write(f"{int(time.time())}\tdns\t{q}\t{a4}\n")
        if t == 28 and l == 16:
            import ipaddress; out.write(f"{int(time.time())}\tdns\t{q}\t{ipaddress.ip_address(p[o:o+16])}\n")
        o += l
def sni(p, dst):
    try:
        o = 5 + 4 + 2 + 32; o += 1 + p[o]
        o += 2 + struct.unpack(">H", p[o:o + 2])[0]; o += 1 + p[o]
        end = o + 2 + struct.unpack(">H", p[o:o + 2])[0]; o += 2
        while o + 4 <= end:
            t, l = struct.unpack(">HH", p[o:o + 4]); o += 4
            if t == 0:
                n = struct.unpack(">H", p[o + 3:o + 5])[0]
                sn = p[o + 5:o + 5 + n].decode("ascii", "replace"); out.write(f"{int(time.time())}\tsni\t{sn}\t{dst}\n"); return
            o += l
    except Exception: return
while True:
    rh = r.read(16)
    if len(rh) < 16: break
    incl = struct.unpack(E + "I", rh[8:12])[0]
    pkt = r.read(incl)
    try:
        if link == 113: proto, off = struct.unpack(">H", pkt[14:16])[0], 16
        elif link == 276: proto, off = struct.unpack(">H", pkt[0:2])[0], 20
        elif link == 1: proto, off = struct.unpack(">H", pkt[12:14])[0], 14
        else: continue
        if proto == 0x0800:
            ihl = (pkt[off] & 0x0F) * 4; ipp = pkt[off + 9]; dst = ".".join(map(str, pkt[off + 16:off + 20])); l4 = off + ihl
        elif proto == 0x86DD:
            import ipaddress; ipp = pkt[off + 6]; dst = str(ipaddress.ip_address(pkt[off + 24:off + 40])); l4 = off + 40
        else: continue
        if ipp == 17: dns(pkt[l4 + 8:])
        elif ipp == 6: sni(pkt[l4 + ((pkt[l4 + 12] >> 4) * 4):], dst)
    except Exception: continue
PY
)"
# Names: DNS answers and TLS ClientHello server names, parsed from a packet
# stream that is never written; only (time, kind, name, address) is kept.
tcpdump -i any -nn -U -s 512 -w - \
    'udp port 53 or (tcp and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (tcp[((tcp[12:1] & 0xf0) >> 2) + 5:1] = 0x01))' 2>/dev/null \
  | python3 -u -c "$NAMES_PARSER" "$OUT/names.tsv" &
PIDS+=($!)

# Who owns each internet socket, once a second (process name and pid only).
( while :; do
    now="$(date +%s)"
    ss -tunpH state established state syn-sent 2>/dev/null | awk -v t="$now" '
        { proto=$1; nl=split($5, l, ":"); r=$6; n=split(r, rp, ":"); rport=rp[n]; rip=substr(r, 1, length(r)-length(rport)-1);
          gsub(/^\[|\]$/, "", rip); lport=l[nl];
          p=""; if (match($0, /users:\(\("[^"]+",pid=[0-9]+/)) { p=substr($0, RSTART+9, RLENGTH-9); sub(/",pid=/, " pid ", p) }
          print t "\t" proto "\t" lport "\t" rip "\t" rport "\t" p }' >> "$OUT/sockets.tsv"
    sleep 1
  done ) &
PIDS+=($!)

if command -v docker >/dev/null 2>&1; then
    ( while :; do
        now="$(date +%s)"
        docker ps -q 2>/dev/null | xargs -r docker inspect -f '{{.Name}}	{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}} {{end}}' 2>/dev/null \
          | sed "s/^/$now	/" >> "$OUT/containers.tsv"
        sleep 5
      done ) &
    PIDS+=($!)
fi

echo "egress-capture: capturing for $MINUTES minute(s) into $OUT (Ctrl-C to stop early)"
sleep "$((MINUTES * 60))"
