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
