# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""docs/security/egress-capture.sh: the "see for yourself" capture.

The capture itself needs root and a live kernel, so these tests hold the two
pure halves (the report and the name parser) to fixtures, and the promises
the script makes to whoever runs it (no payload on disk, the one sysctl
restored, output only under --out, a clear refusal) to its source.
"""
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docs/security/egress-capture.sh"
FIXTURES = ROOT / "tests/fixtures/egress_capture"


def _report(tmp_path, classify=None):
    out = tmp_path / "out"
    shutil.copytree(FIXTURES, out)
    args = ["bash", str(SCRIPT), "--report-only", "--out", str(out)]
    if classify:
        args += ["--classify", str(classify)]
    run = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    rows = [line.split("\t") for line in (out / "egress.tsv").read_text().splitlines()[1:]]
    return run.stdout, rows, (out / "egress.md").read_text()


def test_each_connection_is_named_attributed_and_counted(tmp_path):
    _, rows, md = _report(tmp_path)
    by_who = {r[0]: r for r in rows}
    ctr = by_who["container:noo-ollama"]
    assert ctr[1] == "stats.example.org,telemetry.example.com", "DNS and SNI both name the address"
    assert (ctr[2], ctr[3], ctr[4], ctr[6], ctr[7]) == ("198.51.100.34", "443", "tcp", "1500", "9000"), ctr
    assert by_who["process:noo pid 77"][2] == "198.51.100.3", "a host process is named from the socket poll"
    assert by_who["host process (unattributed)"][3:5] == ["123", "udp"], "a flow nobody owned is still listed"
    assert "192.168.1.20" not in md, "a local-network destination is not egress"
    assert len(rows) == 3


def test_a_classify_file_labels_rows_and_unlisted_is_counted(tmp_path):
    cls = tmp_path / "cls.tsv"
    cls.write_text("container:noo-ollama\tstats\\.example\\.org.*:443$\tc\ta reporter\n^process:noo \t:443$\ta\tthe noo CLI\n^host process\t:80$\ta\tnever matches: the flow is to 123\n")
    stdout, rows, _ = _report(tmp_path, cls)
    assert {r[0]: r[10] for r in rows} == {
        "container:noo-ollama": "c", "process:noo pid 77": "a", "host process (unattributed)": "unlisted"}
    assert "1 row(s) unlisted" in stdout


def _pcap(link):
    def ipv4(src, dst, proto, l4):
        return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, bytes(src), bytes(dst)) + l4

    def qname(n):
        return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"

    dns = (struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + qname("stats.example.org") + struct.pack(">HH", 1, 1)
           + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([198, 51, 100, 34]))
    sn = b"telemetry.example.com"
    ext = struct.pack(">HH", 0, len(sn) + 5) + struct.pack(">HBH", len(sn) + 3, 0, len(sn)) + sn
    body = b"\x03\x03" + b"\0" * 32 + b"\0" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    tls = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    pkts = [ipv4([192, 0, 2, 53], [172, 17, 0, 2], 17, struct.pack(">HHHH", 53, 40000, 8 + len(dns), 0) + dns),
            ipv4([172, 17, 0, 2], [198, 51, 100, 34], 6,
                 struct.pack(">HHIIBBHHH", 40001, 443, 1, 0, 0x50, 0x18, 65535, 0, 0) + tls)]
    head = {276: lambda p: struct.pack(">HHIHBB8s", 0x0800, 0, 2, 1, 4, 6, b"\0" * 8) + p,
            113: lambda p: struct.pack(">HHH8sH", 0, 1, 6, b"\0" * 8, 0x0800) + p}[link]
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
    for p in pkts:
        d = head(p)
        data += struct.pack("<IIII", 0, 0, len(d), len(d)) + d
    return data


def test_the_name_parser_keeps_only_names_and_addresses(tmp_path):
    src = SCRIPT.read_text()
    parser = src[src.index("NAMES_PARSER=\"$(cat <<'PY'\n") + len("NAMES_PARSER=\"$(cat <<'PY'\n"):src.index("\nPY\n)\"\n")]
    for link in (276, 113):  # tcpdump -i any: SLL2 on current libpcap, SLL on older
        out = tmp_path / f"names-{link}.tsv"
        run = subprocess.run([sys.executable, "-c", parser, str(out)], input=_pcap(link), capture_output=True, timeout=30)
        assert run.returncode == 0, run.stderr
        lines = [line.split("\t")[1:] for line in out.read_text().splitlines()]
        assert lines == [["dns", "stats.example.org", "198.51.100.34"], ["sni", "telemetry.example.com", "198.51.100.34"]], (link, lines)


def test_the_promises_it_makes_hold_in_its_source():
    src = SCRIPT.read_text()
    code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
    # No packet reaches the disk: tcpdump writes only to the pipe.
    assert re.findall(r"tcpdump\b[^\n]*", code) and all("-w -" in t for t in re.findall(r"tcpdump -i[^\n]*", code))
    assert ".pcap" not in code
    # The one setting it changes is restored on every exit path.
    assert 'ACCT_WAS="$(cat "$SYSCTL")"' in code and 'echo "$ACCT_WAS" > "$SYSCTL"' in code
    assert "trap cleanup EXIT" in code
    assert not re.search(r"\b(iptables|nft|ip6tables)\b", code), "it adds no firewall rule"
    # It writes only under --out, and refuses clearly.
    assert "--out DIR is required" in code and "is not empty; give a fresh directory" in code
    assert "run as root (sudo)" in code and "missing:" in code


def test_it_refuses_without_out():
    run = subprocess.run(["bash", str(SCRIPT), "--minutes", "1"], capture_output=True, text=True, timeout=30)
    assert run.returncode == 2 and "--out DIR is required" in run.stderr


def test_a_signal_stops_it_at_once_not_after_the_sleep():
    # A rehearsal stops the capture with kill -INT; a foreground sleep would
    # defer the trap (and the report and the sysctl restore) to its end.
    code = SCRIPT.read_text()
    assert 'sleep "$((MINUTES * 60))" &' in code and 'wait "$!"' in code
    assert not re.search(r'^sleep "\$\(\(MINUTES \* 60\)\)"\s*$', code, re.M), "a foreground sleep defers the stop"


def test_every_host_change_is_listed_and_no_packet_can_reach_a_file():
    src = SCRIPT.read_text()
    code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
    # The module load is the one change that outlives the run: listed, and said when done.
    assert "the nf_conntrack kernel module: loaded ONLY if it was not loaded already" in src
    assert re.search(r"modprobe nf_conntrack 2>/dev/null; then\n\s+MOD_LOADED=1\n\s+echo \"egress-capture: loaded the nf_conntrack kernel module", code)
    assert code.count("modprobe nf_conntrack") == 1, "no other module is loaded"
    # The packet path: tcpdump to stdout, piped to the parser, both stderrs discarded,
    # and the parser's one file is names.tsv.
    m = re.search(r"tcpdump -i any -nn -U -s 512 -w - \\\n[^\n]*2>/dev/null \\\n\s+> >\(python3 -u -c \"\$NAMES_PARSER\" \"\$OUT/names.tsv\" 2>/dev/null\) &\nPIDS\+=\(\$!\)", code)
    assert m, "the capture must be one pipe from tcpdump's stdout into the parser"
    parser = src[src.index("NAMES_PARSER=\"$(cat <<'PY'\n"):src.index("\nPY\n)\"\n")]
    assert parser.count("open(") == 1 and "open(sys.argv[1], \"a\"" in parser, "the parser opens names.tsv and nothing else"


def test_a_reused_address_is_credited_to_whoever_held_it_when_the_flow_started(tmp_path):
    # Docker reuses container addresses on recreate: "last seen wins" credited
    # noo-tempo with the Ollama model pull in a rehearsal.
    out = tmp_path / "out"
    shutil.copytree(FIXTURES, out)
    (out / "containers.tsv").write_text(
        "1731359990\t/noo-ollama\t172.17.0.2 \n"
        "1731360005\t/noo-tempo\t172.17.0.2 \n")
    ev = (out / "conntrack.events").read_text()
    ev += ("[1731360010.1]\t    [NEW] ipv4     2 tcp      6 120 SYN_SENT src=172.17.0.2 dst=198.51.100.77 sport=40009 dport=443 "
           "[UNREPLIED] src=198.51.100.77 dst=10.0.0.5 sport=443 dport=40009 id=9\n")
    (out / "conntrack.events").write_text(ev)
    run = subprocess.run(["bash", str(SCRIPT), "--report-only", "--out", str(out)], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    rows = {r.split("\t")[2]: r.split("\t")[0] for r in (out / "egress.tsv").read_text().splitlines()[1:]}
    assert rows["198.51.100.34"] == "container:noo-ollama", "started at 1731360000, while noo-ollama held the address"
    assert rows["198.51.100.77"] == "container:noo-tempo", "started at 1731360010, after noo-tempo took it"


def test_cleanup_never_waits_unbounded():
    # A bare `wait` blocked forever on a child the PID list did not hold.
    code = "\n".join(line for line in SCRIPT.read_text().splitlines() if not line.lstrip().startswith("#"))
    body = code[code.index("cleanup() {"):code.index("\n}\n", code.index("cleanup() {"))]
    assert not re.search(r"^\s*wait(\s|$)", body, re.M), "no bare wait in cleanup"
    assert "kill -KILL" in body and "for _ in $(seq 1 50)" in body


# 2026-11-13 (rc.5 rehearsal, install window): most CLI pulls were
# "host process (unattributed)": a short connection (a redirect, a registry
# token) opened and closed between two 0.2 s socket polls. The owner is now
# looked up when conntrack reports the NEW connection. In an Alpine container
# the same 12 HTTPS fetches went from 6 attributed / 5 unattributed (dev) to
# 12 of 12 attributed.

def _new_local_flow(host_ips: str, line: str) -> str:
    src = SCRIPT.read_text()
    fn = src[src.index("new_local_flow() {\n"):]
    fn = fn[: fn.index("\n}\n") + 3]
    run = subprocess.run(["bash", "-c", fn + 'HOST_IPS="$1"; new_local_flow "$2"', "_", host_ips, line],
                         capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    return run.stdout.strip()


def test_a_new_host_connection_is_named_by_its_local_tuple_in_either_order():
    ips = "172.31.250.10 100.72.0.5 fd7a:115c:a1e0::1"
    out_first = ("[1794585167.068] [NEW] tcp 6 120 SYN_SENT src=172.31.250.10 dst=140.82.114.34 sport=55586 dport=443 "
                 "[UNREPLIED] src=140.82.114.34 dst=172.31.250.10 sport=443 dport=55586 id=7")
    assert _new_local_flow(ips, out_first) == "140.82.114.34 55586"
    reply_first = ("[1794585167.068] [NEW] tcp 6 300 ESTABLISHED src=146.75.38.132 dst=172.31.250.10 sport=443 dport=55240 "
                   "src=172.31.250.10 dst=146.75.38.132 sport=55240 dport=443 id=8")
    assert _new_local_flow(ips, reply_first) == "146.75.38.132 55240"
    v6 = ("[NEW] tcp 6 120 SYN_SENT src=fd7a:115c:a1e0::1 dst=2606:50c0:8000::153 sport=40000 dport=443 "
          "[UNREPLIED] src=2606:50c0:8000::153 dst=fd7a:115c:a1e0::1 sport=443 dport=40000")
    assert _new_local_flow(ips, v6) == "2606:50c0:8000::153 40000"


def test_a_containers_or_a_short_event_is_not_looked_up_as_the_hosts():
    ips = "172.31.250.10"
    container = ("[NEW] tcp 6 120 SYN_SENT src=172.19.0.7 dst=140.82.114.34 sport=41000 dport=443 "
                 "[UNREPLIED] src=140.82.114.34 dst=172.31.250.10 sport=443 dport=41000")
    assert _new_local_flow(ips, container) == "", "a container's flow is named by its container, not by ss"
    assert _new_local_flow(ips, "[NEW] tcp src=172.31.250.10 dst=1.2.3.4") == ""
    # a prefix of a host address is not the host address
    assert _new_local_flow("172.31.250.1", container.replace("172.19.0.7", "172.31.250.10")) == ""


def test_the_new_connection_reader_is_stoppable_and_writes_the_polls_rows():
    src = SCRIPT.read_text()
    code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
    # conntrack's stdout feeds the reader through a process substitution, so $!
    # is conntrack itself and cleanup can stop it (a pipe would leave $! the reader)
    assert re.search(r"conntrack -E -e NEW -o extended 2>/dev/null > >\(set \+e; while IFS= read -r line; do\n", code)
    i = code.index("conntrack -E -e NEW -o extended 2>/dev/null > >(")
    assert "PIDS+=($!)" in code[i:i + 900]
    # both the poll and the NEW lookup write sockets.tsv through the same row format
    assert code.count('awk -v t="$now" "$SS_ROW" >> "$OUT/sockets.tsv"') == 1
    assert code.count('awk -v t="$(date +%s)" "$SS_ROW" >> "$OUT/sockets.tsv"') == 1



# 2026-11-13, rc.6 install window: the snapshot loop died 4 minutes in (during a
# stack recreate) and a later container's Ollama pull was credited to the last
# holder of its address, noo-grafana; and 4 short dockerd requests in a burst of
# parallel pulls were unattributed. Below: the loop survives, a stale sighting
# names no one, a missed interval is reported, the lookup is batched, and the
# inference rule is held to its limits.

def _snapshot_loop_text():
    src = SCRIPT.read_text()
    i = src.index("    ( set +e; while :; do\n        now=\"$(date +%s)\"\n        if ids=")
    j = src.index("      done ) &", i)
    return src[i:j] + "      done )\n"


def _run_loop(tmp_path, loop, inspect_rc):
    fake = tmp_path / "bin"
    fake.mkdir(parents=True)
    (fake / "docker").write_text(
        "#!/bin/sh\n"
        f'case "$1" in ps) echo c1; echo c2; exit 0 ;; inspect) echo "/noo-a\t172.18.0.2 "; exit {inspect_rc} ;; esac\n')
    (fake / "docker").chmod(0o755)
    out = tmp_path / "o"
    out.mkdir()
    script = "set -euo pipefail\nOUT=" + str(out) + "\n" + loop.replace("sleep 2", "sleep 0.2")
    subprocess.run(["timeout", "3", "bash", "-c", script], env={"PATH": f"{fake}:/usr/bin:/bin"},
                   capture_output=True, text=True)
    p = out / "snapshots.tsv"
    return p.read_text().splitlines() if p.exists() else []


def test_the_snapshot_loop_survives_a_failing_inspect_under_errexit(tmp_path):
    loop = _snapshot_loop_text()
    ticks = _run_loop(tmp_path / "a", loop, inspect_rc=1)
    assert len(ticks) >= 5, f"the loop stopped: {ticks}"
    # the mechanism it fixes: the same loop without `set +e` dies at the first failing inspect
    old = _run_loop(tmp_path / "b", loop.replace("( set +e; while", "( while"), inspect_rc=1)
    assert len(old) <= 1, f"without set +e the loop should die under errexit: {old}"


def test_every_docker_call_in_the_snapshot_loop_is_bounded():
    loop = _snapshot_loop_text()
    calls = re.findall(r"(?:timeout 10 )?docker (?:ps|inspect)", loop)
    assert len(calls) == 2 and all(c.startswith("timeout 10 docker") for c in calls), calls
    assert 'echo "$now $st" >> "$OUT/snapshots.tsv"' in loop


def _report_with(tmp_path, containers, snapshots, extra_events, classify=None, infer=False, sockets=None):
    out = tmp_path / "out"
    shutil.copytree(FIXTURES, out)
    (out / "containers.tsv").write_text(containers)
    if snapshots is not None:
        (out / "snapshots.tsv").write_text(snapshots)
    if sockets is not None:
        (out / "sockets.tsv").write_text((out / "sockets.tsv").read_text() + sockets)
    (out / "conntrack.events").write_text((out / "conntrack.events").read_text() + extra_events)
    args = ["bash", str(SCRIPT), "--report-only", "--out", str(out)]
    if classify:
        args += ["--classify", str(classify)]
    if infer:
        args += ["--infer-unattributed"]
    run = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    rows = [r.split("\t") for r in (out / "egress.tsv").read_text().splitlines()[1:]]
    return run.stdout, rows, (out / "egress.md").read_text()


def _new(ts, src, dst, sport, dport=443, rid=1):
    return (f"[{ts}.1]\t    [NEW] ipv4     2 tcp      6 120 SYN_SENT src={src} dst={dst} sport={sport} dport={dport} "
            f"[UNREPLIED] src={dst} dst=10.0.0.5 sport={dport} dport={sport} id={rid}\n")


def test_a_stale_sighting_names_no_container(tmp_path):
    # grafana held .12 until 1731360020; the loop then stopped; a flow from .12 at +300 s
    stdout, rows, md = _report_with(
        tmp_path, "1731360000\t/noo-ollama\t172.17.0.2 \n1731360020\t/noo-grafana\t172.18.0.12 \n",
        "1731360000 ok\n1731360002 ok\n1731360020 ok\n",
        _new(1731360320, "172.18.0.12", "198.51.100.90", 40100, rid=31))
    who = {r[2]: r[0] for r in rows}
    assert who["198.51.100.90"] == "container at 172.18.0.12 (no snapshot near this flow)", who
    assert "noo-grafana" not in {r[0] for r in rows}
    assert "missed interval" in stdout and "missed interval" in md, stdout


def test_a_fresh_sighting_still_names_its_container(tmp_path):
    _, rows, _ = _report_with(
        tmp_path, "1731360000\t/noo-ollama\t172.17.0.2 \n1731360300\t/noo-model-cache\t172.18.0.12 \n",
        "1731360000 ok\n1731360300 ok\n", _new(1731360305, "172.18.0.12", "198.51.100.91", 40101, rid=32))
    assert {r[2]: r[0] for r in rows}["198.51.100.91"] == "container:noo-model-cache"


INFER_CLS = "^process:dockerd \t(^|,)pkg\\.example\\.org(,|:443$)\ta\timage pulls\n"


def _infer_case(tmp_path, infer=True, host_port=443, unattr_name="pkg.example.org"):
    # dockerd's attributed pull to pkg.example.org:443, and an unattributed host
    # flow to the same name (another address of it) on host_port
    names = f"1731360000\tdns\tpkg.example.org\t198.51.100.50\n1731360000\tdns\t{unattr_name}\t198.51.100.51\n"
    tmp_path.mkdir(parents=True, exist_ok=True)
    cls = tmp_path / "cls.tsv"
    cls.write_text(INFER_CLS)
    out = tmp_path / "out"
    shutil.copytree(FIXTURES, out)
    (out / "names.tsv").write_text((out / "names.tsv").read_text() + names)
    (out / "sockets.tsv").write_text((out / "sockets.tsv").read_text() + "1731360001\ttcp\t41000\t198.51.100.50\t443\tdockerd pid 84\n")
    (out / "conntrack.events").write_text((out / "conntrack.events").read_text()
        + _new(1731360001, "10.0.0.5", "198.51.100.50", 41000, rid=41)
        + _new(1731360002, "10.0.0.5", "198.51.100.51", 41001, dport=host_port, rid=42))
    args = ["bash", str(SCRIPT), "--report-only", "--out", str(out), "--classify", str(cls)] + (["--infer-unattributed"] if infer else [])
    run = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    rows = {r.split("\t")[2]: r.split("\t") for r in (out / "egress.tsv").read_text().splitlines()[1:]}
    return run.stdout, rows["198.51.100.51"]


def test_an_unattributed_flow_to_an_attributed_host_and_port_is_inferred(tmp_path):
    stdout, row = _infer_case(tmp_path)
    assert row[0] == "host process (unattributed)", "the row is still printed as unattributed"
    assert (row[10], row[11]) == ("inferred", "inferred from process:dockerd pid 84 in this window"), row
    assert "1 row(s) inferred (1 flow(s))" in stdout, stdout


def test_inference_needs_the_flag_the_same_port_and_the_same_host(tmp_path):
    assert _infer_case(tmp_path / "noflag", infer=False)[1][10] == "unlisted"
    assert _infer_case(tmp_path / "port", host_port=8443)[1][10] == "unlisted", "same host, other port"
    assert _infer_case(tmp_path / "host", unattr_name="other.example.org")[1][10] == "unlisted", "other host"


def test_a_burst_of_new_connections_is_looked_up_with_one_ss():
    code = "\n".join(line for line in SCRIPT.read_text().splitlines() if not line.lstrip().startswith("#"))
    i = code.index("conntrack -E -e NEW -o extended 2>/dev/null > >(")
    body = code[i:code.index("PIDS+=($!)", i)]
    assert "IFS= read -r -t 0.01 line || break" in body, "the reader drains what is queued"
    assert '[ ${#ports[@]} -lt 64 ] || break' in body, "a batch is bounded"
    assert 'filt="${filt:+$filt or }sport = :$p"' in body and 'ss -tunpH "( $filt )"' in body
    assert body.count("ss -tunpH") == 1, "one ss per batch"
