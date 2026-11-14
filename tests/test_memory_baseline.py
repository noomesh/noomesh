# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The install matrix's measured memory baseline (operator 2026-11-14):
scripts/install-cell/memory_baseline.py reads it, run.sh's
probe-memory-baseline runs it at idle after onboard, and the size job's
release-size-report.py --memory reports it per release."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUN_SH = ROOT / "scripts" / "install-cell" / "run.sh"
SCRIPT = ROOT / "scripts" / "install-cell" / "memory_baseline.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MB = _load("memory_baseline", SCRIPT)
SIZE = _load("release_size_mem", ROOT / "scripts" / "release-size-report.py")

LABEL = "node share of a one-machine install"
MiB = 2**20

MEMORY_STAT = """anon 104857600
file 52428800
kernel 3145728
kernel_stack 98304
shmem 0
file_mapped 1048576
inactive_file 20971520
"""


# ---- parsing ----------------------------------------------------------------

def test_memory_stat_is_parsed_by_field():
    st = MB.parse_memory_stat(MEMORY_STAT)
    assert st["anon"] == 100 * MiB and st["file"] == 50 * MiB and st["shmem"] == 0


def test_docker_stats_sizes_are_bytes_and_an_unreadable_one_is_omitted_not_zero():
    text = ("noo-gateway\t123.5MiB / 15.61GiB\n"
            "noo-ollama\t1.5GiB / 15.61GiB\n"
            "noo-redis\t512KiB / 15.61GiB\n"
            "noo-tempo\t-- / --\n"
            "noo-loki\t0B / 0B\n")
    got = MB.parse_docker_stats(text)
    assert got["noo-gateway"] == (round(123.5 * MiB), None)
    assert got["noo-ollama"] == (round(1.5 * 2**30), None)
    assert got["noo-redis"] == (512 * 1024, None)
    for name in ("noo-tempo", "noo-loki"):
        b, why = got[name]
        assert b is None and why, (name, got[name])
    assert MB.parse_size("1.2GB") == 1_200_000_000 and MB.parse_size("--") is None


def test_systemctl_show_figures_and_unset_values_are_omitted_with_reasons():
    p = MB.parse_systemctl_show("LoadState=loaded\nActiveState=active\nMainPID=812\n"
                                "MemoryCurrent=48234496\nMemoryPeak=[not set]\n")
    assert MB.systemd_bytes(p, "MemoryCurrent") == (48234496, None)
    b, why = MB.systemd_bytes(p, "MemoryPeak")
    assert b is None and "[not set]" in why
    b, why = MB.systemd_bytes({"MemoryCurrent": "18446744073709551615"}, "MemoryCurrent")
    assert b is None and why, "systemd's UINT64_MAX is 'no figure', not a measurement"
    b, why = MB.systemd_bytes({}, "MemoryPeak")
    assert b is None and "not reported by this systemd" in why  # 22.04's systemd 249
    assert MB.parse_vmrss("Name:\tnoo-node-agent\nVmRSS:\t   20480 kB\n") == 20 * MiB
    assert MB.parse_vmrss("Name:\tx\n") is None


def test_put_omits_a_figure_with_its_reason_and_never_writes_zero():
    e: dict = {}
    MB.put(e, "anon_bytes", None, "memory.stat unreadable")
    MB.put(e, "file_bytes", 0, None)  # a real measured zero stays a zero
    assert "anon_bytes" not in e["figures"] and e["omitted"]["anon_bytes"] == "memory.stat unreadable"
    assert e["figures"]["file_bytes"] == 0


# ---- classification ---------------------------------------------------------

def _compose_container_names() -> set[str]:
    names = set()
    for f in ROOT.glob("docker-compose*.yml"):
        for m in re.finditer(r"container_name:\s*\$\{NOO_CONTAINER_PREFIX:-noo\}-([a-z0-9-]+)", f.read_text()):
            names.add("noo-" + m.group(1))
    return names


def test_backends_and_their_doors_are_the_node_share_and_the_rest_the_controllers():
    names = _compose_container_names()
    expected_node = {"noo-ollama", "noo-ollama-embed", "noo-ollama-embed-cpu", "noo-llamacpp", "noo-vllm",
                     "noo-vllm-secondary", "noo-tei", "noo-tei-gpu", "noo-reranker", "noo-whisper", "noo-piper",
                     "noo-stunnel-ollama", "noo-stunnel-ollama-embed", "noo-stunnel-ollama-embed-cpu",
                     "noo-stunnel-llamacpp", "noo-stunnel-vllm", "noo-stunnel-vllm-secondary", "noo-stunnel-tei",
                     "noo-stunnel-tei-gpu", "noo-stunnel-reranker", "noo-node-agent", "noo-node-agent-sensors"}
    expected_controller = {"noo-gateway", "noo-postgres", "noo-redis", "noo-nats", "noo-trellion", "noo-worker",
                           "noo-prometheus", "noo-grafana", "noo-loki", "noo-tempo", "noo-alertmanager",
                           "noo-sandbox", "noo-browser"}
    assert expected_node | expected_controller <= names, sorted((expected_node | expected_controller) - names)
    for n in expected_node:
        assert MB.classify(n) == "node", n
        assert MB.classify("/" + n) == "node", "docker inspect's .Name has a leading slash"
    for n in expected_controller:
        assert MB.classify(n) == "controller", n


# ---- end to end, faking only the transport ---------------------------------

CID_A = "a" * 64   # systemd cgroup driver layout
CID_B = "b" * 64   # cgroupfs layout
CID_C = "c" * 64   # no cgroup dir at all


def _fake_host(tmp_path):
    cg = tmp_path / "cgroup"
    proc = tmp_path / "proc"
    a = cg / "system.slice" / f"docker-{CID_A}.scope"
    b = cg / "docker" / CID_B
    agent = cg / "system.slice" / "noo-node-agent.service"
    for d in (a, b, agent):
        d.mkdir(parents=True)
    (a / "memory.stat").write_text(MEMORY_STAT)
    (a / "memory.current").write_text(str(160 * MiB) + "\n")
    (b / "memory.stat").write_text("anon 1073741824\nfile 2147483648\n")
    (b / "memory.current").write_text("max\n")  # unreadable as a figure
    (agent / "memory.stat").write_text("anon 31457280\nfile 10485760\n")
    (agent / "memory.current").write_text(str(44 * MiB))
    (proc / "812").mkdir(parents=True)
    (proc / "812" / "status").write_text("Name:\tnoo-node-agent\nVmRSS:\t   30720 kB\n")
    (proc / "meminfo").write_text("MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\n")
    inspect = [{"Id": CID_A, "Name": "/noo-gateway", "Config": {"Image": "ghcr.io/noomesh/gateway:0.6.24"},
                "State": {"Pid": 0}},
               {"Id": CID_B, "Name": "/noo-ollama", "Config": {"Image": "ghcr.io/noomesh/ollama:0.6.24"},
                "State": {"Pid": 0}},
               {"Id": CID_C, "Name": "/noo-stunnel-ollama", "Config": {"Image": "ghcr.io/noomesh/stunnel:0.6.24"},
                "State": {"Pid": 0}}]
    (tmp_path / "inspect.json").write_text(json.dumps(inspect))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    fakes = {
        # docker: plain call refused (a docker=none cell's old shell), so the
        # script must go through sudo -n (SUDOED=1 below).
        "docker": f"""#!/bin/sh
[ "$SUDOED" = 1 ] || [ "$(id -u)" = 0 ] || {{ echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1; }}
case "$1" in
  ps) printf '%s\\n%s\\n%s\\n' {CID_A} {CID_B} {CID_C} ;;
  inspect) cat '{tmp_path}/inspect.json' ;;
  exec) [ "$2" = noo-ollama ] && printf 'NAME            ID              SIZE      PROCESSOR    UNTIL\nqwen2.5:0.5b    a8b0c5157701    1.0 GB    100%% CPU     4 minutes from now\n' ;;
  stats) printf 'noo-gateway\\t150MiB / 15.6GiB\\nnoo-ollama\\t1GiB / 15.6GiB\\nnoo-stunnel-ollama\\t-- / --\\n' ;;
esac
""",
        "sudo": '#!/bin/sh\n[ "$1" = -n ] && shift\nexport SUDOED=1\nexec "$@"\n',
        "systemctl": f"""#!/bin/sh
case "$2" in
  noo-node-agent) printf 'LoadState=loaded\\nActiveState=active\\nMainPID=812\\nControlGroup=/system.slice/noo-node-agent.service\\nMemoryCurrent={44 * MiB}\\nMemoryPeak=[not set]\\n' ;;
  noo-hostd) printf 'LoadState=loaded\\nActiveState=active\\nMainPID=0\\nControlGroup=/system.slice/noo-hostd.service\\nMemoryCurrent=[not set]\\n' ;;
  *) printf 'LoadState=not-found\\nActiveState=inactive\\nMainPID=0\\n' ;;
esac
""",
        "noo": '#!/bin/sh\necho "noo 0.6.24"\n',
    }
    for n, body in fakes.items():
        (bin_ / n).write_text(body)
        (bin_ / n).chmod(0o755)
    return cg, proc, bin_


def _measure(tmp_path):
    cg, proc, bin_ = _fake_host(tmp_path)
    out = tmp_path / "memory.json"
    r = subprocess.run([sys.executable, str(SCRIPT), "measure", "--out", str(out), "--cell", "ubuntu-22.04-amd64",
                        "--model", "tiny", "--settle", "0", "--cgroup-root", str(cg), "--proc-root", str(proc)],
                       env={"PATH": f"{bin_}:/usr/bin:/bin", "HOME": str(tmp_path)}, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(out.read_text()), r.stdout


def test_measure_reads_both_cgroup_layouts_through_sudo_and_omits_what_it_cannot_read(tmp_path):
    doc, log = _measure(tmp_path)
    c = {x["name"]: x for x in doc["containers"]}
    gw, ol, door = c["noo-gateway"], c["noo-ollama"], c["noo-stunnel-ollama"]
    assert gw["class"] == "controller" and ol["class"] == "node" and door["class"] == "node"
    assert gw["figures"] == {"anon_bytes": 100 * MiB, "file_bytes": 50 * MiB, "memory_current_bytes": 160 * MiB,
                             "docker_stats_bytes": 150 * MiB}
    assert gw["cgroup"].startswith("system.slice/docker-aaaaaaaaaaaa")
    assert ol["figures"]["anon_bytes"] == 2**30 and ol["cgroup"].startswith("docker/bbbbbbbbbbbb")
    assert "memory_current_bytes" not in ol["figures"] and "max" in ol["omitted"]["memory_current_bytes"]
    assert door.get("figures", {}) == {}, "nothing readable: nothing written, certainly not 0"
    assert set(door["omitted"]) == {"anon_bytes", "file_bytes", "memory_current_bytes", "docker_stats_bytes"}
    assert "no cgroup v2 dir" in door["omitted"]["anon_bytes"]
    u = {x["unit"]: x for x in doc["host_units"]}
    agent = u["noo-node-agent"]
    assert agent["present"] and agent["figures"] == {"memory_current_bytes": 44 * MiB, "anon_bytes": 30 * MiB,
                                                     "file_bytes": 10 * MiB, "vmrss_bytes": 30 * MiB}
    assert "[not set]" in agent["omitted"]["memory_peak_bytes"]
    assert u["noo-hostd"]["present"] and "memory_current_bytes" in u["noo-hostd"]["omitted"]
    assert "vmrss_bytes" in u["noo-hostd"]["omitted"]
    assert not u["noo-harness"]["present"] and "not-found" in u["noo-harness"]["why"]
    m = doc["meta"]
    assert m["cell"] == "ubuntu-22.04-amd64" and m["model"] == "tiny" and m["noo_version"] == "noo 0.6.24"
    assert m["settle_seconds"] == 0 and m["host_mem_total_bytes"] == 16384000 * 1024 and m["timestamp"]
    assert LABEL in log and "omitted figures:" in log


def test_totals_are_sums_of_what_was_measured_only(tmp_path):
    doc, _ = _measure(tmp_path)
    t = doc["totals"]
    assert t["containers"]["anon_bytes"] == {"bytes": 100 * MiB + 2**30, "measured": 2, "of": 3}
    assert t["containers"]["memory_current_bytes"] == {"bytes": 160 * MiB, "measured": 1, "of": 3}
    assert t["containers"]["docker_stats_bytes"] == {"bytes": 150 * MiB + 2**30, "measured": 2, "of": 3}
    assert t["host_units"]["memory_current_bytes"] == {"bytes": 44 * MiB, "measured": 1, "of": 2}, \
        "an absent unit is not counted; a present one without a figure is counted as unmeasured"
    assert t["grand"]["memory_current_bytes"] == {"bytes": 204 * MiB, "measured": 2, "of": 5}
    assert t["controller_share"]["anon_bytes"] == {"bytes": 100 * MiB, "measured": 1, "of": 1}
    assert t["node_share"]["anon_bytes"] == {"bytes": 2**30 + 30 * MiB, "measured": 2, "of": 4}
    assert t["node_share_label"] == LABEL


def test_nothing_measurable_is_a_failed_probe_with_the_reason(tmp_path):
    out = tmp_path / "m.json"
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for n in ("docker", "systemctl", "sudo"):
        (bin_ / n).write_text("#!/bin/sh\necho nope >&2\nexit 1\n")
        (bin_ / n).chmod(0o755)
    r = subprocess.run([sys.executable, str(SCRIPT), "measure", "--out", str(out), "--cell", "c", "--settle", "0",
                        "--cgroup-root", str(tmp_path), "--proc-root", str(tmp_path)],
                       env={"PATH": f"{bin_}:/usr/bin:/bin"}, capture_output=True, text=True)
    assert r.returncode == 1 and "nothing could be measured" in r.stdout
    doc = json.loads(out.read_text())
    assert doc["containers_omitted"].startswith("not measured: docker ps failed")
    assert doc["totals"]["grand"]["memory_current_bytes"] == {"bytes": 0, "measured": 0, "of": 0}


# ---- the size report --------------------------------------------------------

def test_the_report_renders_a_measured_cell_and_a_missing_one_as_not_measured(tmp_path):
    doc, _ = _measure(tmp_path)
    art = tmp_path / "memory"
    good = art / "install-cell-ubuntu-22.04-amd64"
    good.mkdir(parents=True)
    (good / "memory.json").write_text(json.dumps(doc))
    failed = art / "install-cell-ubuntu-24.04-amd64-default"
    failed.mkdir()
    (failed / "summary.json").write_text(json.dumps({"result": "fail", "failed_step": "onboard"}))
    cells = SIZE.load_memory([f"ubuntu-22.04-amd64={good / 'memory.json'}",
                              f"ubuntu-24.04-amd64-default={failed / 'memory.json'}",
                              str(art / "install-cell-gone" / "memory.json")])
    assert [c["cell"] for c in cells] == ["ubuntu-22.04-amd64", "ubuntu-24.04-amd64-default", "gone"], \
        "a cell without a memory.json is listed, never dropped"
    md = "\n".join(SIZE.render_memory(cells))
    assert "## Memory at idle (measured)" in md
    assert "### ubuntu-24.04-amd64-default: not measured: no memory.json in the cell's artifact (cell fail at onboard)" in md
    assert "### gone: not measured: no artifact from the cell" in md
    assert f"**{LABEL}**" in md and "| noo-ollama | node |" in md and "| noo-gateway | controller |" in md
    assert "(1 of 3 measured)" in md and "Omitted: " in md
    assert ("fleet, read-only: on 0.6.24+ each node agent exports its own process_resident_memory_bytes and "
            "noo_unit_memory_bytes (#1026); real-hardware node figures (robopi, the Mac) are read from the "
            "metrics door, no manual measurement.") in md
    j = SIZE.memory_json(cells)
    assert j["node_share_label"] == LABEL
    assert {k: j["cells"][1][k] for k in ("cell", "measured", "why")} == {
        "cell": "ubuntu-24.04-amd64-default", "measured": False,
        "why": "no memory.json in the cell's artifact (cell fail at onboard)"}
    # The idle-series cell's series and cold load are listed too, as not measured.
    assert [x["measured"] for x in j["cells"][1]["series"]] == [False, False, False]
    assert j["cells"][1]["coldload"] == {"missing": "no coldload.json in the cell's artifact"}
    assert "series" not in j["cells"][0], "a cell outside SERIES_CELLS with no series files has none"
    assert j["cells"][0]["totals"]["node_share"]["anon_bytes"]["bytes"] == 2**30 + 30 * MiB


def test_the_size_report_main_carries_memory_in_markdown_and_json(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(SIZE, "finals", lambda prefix: ["stack-v2.0.0"])
    monkeypatch.setattr(SIZE, "repo", lambda: "o/r")

    def sh(*cmd):
        if cmd[:3] == ("gh", "release", "download"):
            return ""
        if cmd[:3] == ("gh", "release", "view"):
            return json.dumps({"assets": []})
        if cmd[:2] == ("git", "show"):
            return json.dumps({"images": {}})
        raise AssertionError(cmd)

    monkeypatch.setattr(SIZE, "sh", sh)
    out = tmp_path / "size.json"
    assert SIZE.main(["--json", str(out), "--memory", f"ubuntu-22.04-amd64={tmp_path / 'nope' / 'memory.json'}"]) == 0
    assert "### ubuntu-22.04-amd64: not measured: no artifact from the cell" in capsys.readouterr().out
    assert json.loads(out.read_text())["memory"]["cells"] == [
        {"cell": "ubuntu-22.04-amd64", "measured": False, "why": "no artifact from the cell (it did not run or did not upload)"}]
    assert SIZE.main(["--json", str(out)]) == 0 and "memory" not in json.loads(out.read_text())


def test_the_memory_section_survives_a_failed_size_half(tmp_path, monkeypatch, capsys):
    """The memory comes from the cells' own files: a registry or gh failure in
    the size half must not hide it (printed first, and written to --json)."""
    def boom(prefix):
        raise RuntimeError("gh: HTTP 502")
    monkeypatch.setattr(SIZE, "finals", boom)
    out = tmp_path / "size.json"
    with pytest.raises(RuntimeError):
        SIZE.main(["--json", str(out), "--memory", f"ubuntu-22.04-amd64={tmp_path / 'nope' / 'memory.json'}"])
    assert "not measured: no artifact from the cell" in capsys.readouterr().out
    doc = json.loads(out.read_text())
    assert doc["memory"]["cells"][0]["cell"] == "ubuntu-22.04-amd64" and "size_error" in doc


def test_airllm_is_in_the_node_share():
    assert MB.classify("noo-airllm") == "node"


def test_the_size_job_waits_for_the_cells_and_reads_both_cells_memory():
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load((ROOT / ".github/workflows/install-matrix.yml").read_text())
    size = doc["jobs"]["size"]
    assert size["needs"] == "cell" and size["if"] == "always()", "runs when cells fail"
    dl = [s for s in size["steps"] if str(s.get("uses", "")).startswith("actions/download-artifact@")]
    assert {s["with"]["name"] for s in dl} == {"install-cell-ubuntu-24.04-amd64-default", "install-cell-ubuntu-22.04-amd64"}
    assert all(re.fullmatch(r"actions/download-artifact@[0-9a-f]{40}", s["uses"]) and s.get("continue-on-error")
               for s in dl), "pinned by SHA; a missing artifact fails only its download"
    run = next(s["run"] for s in size["steps"] if s.get("name") == "Size report")
    for cell in ("ubuntu-24.04-amd64-default", "ubuntu-22.04-amd64"):
        assert f'"{cell}=$M/install-cell-{cell}/memory.json"' in run
    assert "--memory" in run


# ---- run.sh -----------------------------------------------------------------

def test_the_probe_runs_after_health_and_verify_and_before_the_first_answer():
    text = RUN_SH.read_text()
    health = text.index("step health 600")
    verify = text.index("step verify 900")
    vjson = text.index("step probe-verify-json 300")
    diag = text.index("step probe-self-agent-diagnostics 120")
    probe = text.index("step probe-memory-baseline ")
    answer = text.index("step first-answer ")
    assert health < verify < vjson < diag < probe < answer, (health, verify, vjson, diag, probe, answer)
    assert text.count("step probe-memory-baseline ") == 1
    line = text[probe:text.index(";;", probe)]
    assert '--out "$OUT/memory.json"' in line and '--settle "$MEMORY_SETTLE_S"' in line
    assert 'MEMORY_SETTLE_S="${MEMORY_SETTLE_S:-60}"' in text


def test_the_probe_is_a_probe_never_the_failed_step(tmp_path):
    text = RUN_SH.read_text()
    probe = text.index("step probe-memory-baseline ")
    line = text[probe:text.index(";;", probe)]
    assert "finish" not in line and "fail_onboarded" not in line and "||" not in line
    C = _load("install_cell_mem", ROOT / "scripts/install-cell/cell.py")
    ok = {"step": "health", "rc": 0, "seconds": 1, "first_error": "", "prompts": [], "warnings": [], "tail": []}
    bad = {**ok, "step": "probe-memory-baseline", "rc": 1, "first_error": "MEMORY BASELINE: nothing could be measured"}
    (tmp_path / "steps.jsonl").write_text(json.dumps(ok) + "\n" + json.dumps(bad) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": "c"}))
    s = C.summarize(tmp_path)
    assert s["result"] == "pass" and "probe-memory-baseline" in s["probes"]


def test_the_probe_is_gated_to_the_two_cells():
    import yaml
    text = RUN_SH.read_text()
    i = text.index('MEMORY_SETTLE_S="${MEMORY_SETTLE_S:-60}"')
    block = text[i:text.index("\nesac\n", i) + len("\nesac\n")]
    wf = yaml.safe_load((ROOT / ".github/workflows/install-matrix.yml").read_text())
    cells = [r["cell"] for r in wf["jobs"]["cell"]["strategy"]["matrix"]["include"]] + ["windows-2025-wsl2"]
    ran = set()
    for cell in cells:
        r = subprocess.run(["bash", "-c", 'step() { echo "RAN $1"; }\n' + block],
                           env={"CELL": cell, "OUT": "/o", "HERE": "/h", "MODEL": "m", "PATH": "/usr/bin:/bin"},
                           capture_output=True, text=True, check=True)
        if "RAN probe-memory-baseline" in r.stdout:
            ran.add(cell)
    assert ran == {"ubuntu-24.04-amd64-default", "ubuntu-22.04-amd64"}, ran


# ---- was a model loaded when it sampled? ------------------------------------

PS_HEADER = "NAME    ID    SIZE    PROCESSOR    UNTIL\n"
PS_HEADER_CTX = "NAME    ID    SIZE    PROCESSOR    CONTEXT    UNTIL\n"


def test_ollama_ps_empty_one_and_two_models_and_not_a_table():
    assert MB.parse_ollama_ps(PS_HEADER) == [], "the header alone: nothing loaded"
    assert MB.parse_ollama_ps(PS_HEADER_CTX + "gemma4:e2b    2a3f    7.2 GB    100% CPU    4096    4 minutes from now\n") \
        == ["gemma4:e2b"]
    assert MB.parse_ollama_ps(PS_HEADER + "gemma4:e2b  2a3f  7.2 GB  100% CPU  4 minutes from now\n"
                              "harrier-embed:latest  9c1d  600 MB  100% CPU  Forever\n") == ["gemma4:e2b", "harrier-embed:latest"]
    for bad in ("", "Error: could not connect to ollama app, is it running?\n", "OCI runtime exec failed\n"):
        assert MB.parse_ollama_ps(bad) is None, bad
    assert MB.parse_ollama_api_ps('{"models": []}') == [] and MB.parse_ollama_api_ps("nope") is None
    assert MB.parse_openai_models('{"data": [{"id": "gemma-4-12b"}]}') == ["gemma-4-12b"]


class FakeHost:
    def __init__(self, cmds=None, http=None):
        self.cmds, self.http = cmds or {}, http or {}

    def cmd(self, *argv, timeout=120):
        return self.cmds.get(argv, (None, f"{argv[0]} exited 1: not faked"))

    def http_get(self, url, timeout=5):
        return self.http.get(url, (None, f"GET {url}: connection refused"))


def test_an_unreadable_answer_is_unknown_with_its_reason_never_none():
    c = {"name": "noo-ollama"}
    host = FakeHost({("docker", "exec", "noo-ollama", "ollama", "ps"):
                     (None, "docker exec exited 126: exec: ollama: executable file not found")})
    a = MB.ask_ollama_container(host, c)
    assert "models" not in a and "executable file not found" in a["unknown"] and "no published loopback port" in a["unknown"]
    v = MB.idle_verdict([a])
    assert v.startswith("unknown: ollama (") and "idle" not in v, v
    assert MB.models_loaded([a]) == []
    # The container has no CLI but its API is on loopback: that source, by name.
    c = {"name": "noo-ollama", "published_ports": [11434]}
    host.http = {"http://127.0.0.1:11434/api/ps": ('{"models": [{"name": "gemma4:e2b"}]}', None)}
    a = MB.ask_ollama_container(host, c)
    assert a["models"] == ["gemma4:e2b"] and a["source"] == "GET http://127.0.0.1:11434/api/ps"
    # A non-table answer is not "nothing loaded" either.
    host = FakeHost({("docker", "exec", "noo-ollama", "ollama", "ps"): ("Error: could not connect\n", None)})
    assert "unknown" in MB.ask_ollama_container(host, {"name": "noo-ollama"})


def test_a_running_llamacpp_or_vllm_server_is_loaded_even_when_it_names_nothing():
    a = MB.ask_openai_server(FakeHost(), {"name": "noo-llamacpp", "published_ports": [8080]}, "llamacpp")
    assert a["models"] == [None] and "connection refused" in a["model_name_unknown"]
    assert MB.idle_verdict([a]) == "loaded: llamacpp:model unnamed"
    host = FakeHost(http={"http://127.0.0.1:8000/v1/models": ('{"data": [{"id": "gemma-4-12b-it"}]}', None)})
    a = MB.ask_openai_server(host, {"name": "noo-vllm", "published_ports": [8000]}, "vllm")
    assert MB.models_loaded([a]) == [{"backend": "vllm", "model": "gemma-4-12b-it", "source": "GET http://127.0.0.1:8000/v1/models"}]
    assert MB.backend_of("noo-stunnel-ollama") is None and MB.backend_of("noo-ollama-embed") == "ollama"


def test_the_idle_verdict_strings():
    idle = {"backend": "ollama", "source": "s", "models": []}
    loaded = {"backend": "ollama", "source": "s", "models": ["qwen2.5:0.5b"]}
    unknown = {"backend": "ollama", "source": "s", "unknown": "docker exec exited 1"}
    assert MB.idle_verdict([]) == "idle: no model loaded"
    assert MB.idle_verdict([idle]) == "idle: no model loaded"
    assert MB.idle_verdict([idle, unknown]) == "unknown: ollama (docker exec exited 1)"
    assert MB.idle_verdict([loaded]) == "loaded: ollama:qwen2.5:0.5b"
    assert MB.idle_verdict([loaded, unknown]).startswith("loaded: ollama:qwen2.5:0.5b (also unknown: ")


def test_memory_json_records_the_loaded_models_and_the_report_heading_shows_the_verdict(tmp_path):
    doc, log = _measure(tmp_path)
    assert doc["idle"] == "loaded: ollama:qwen2.5:0.5b"
    assert doc["models_loaded"] == [{"backend": "ollama", "model": "qwen2.5:0.5b", "source": "docker exec noo-ollama ollama ps",
                                     "size": "1.0 GB", "until": "4 minutes from now", "expires_in_s": 240}]
    assert "at sample time: loaded: ollama:qwen2.5:0.5b" in log
    f = tmp_path / "install-cell-ubuntu-22.04-amd64" / "memory.json"
    f.parent.mkdir()
    f.write_text(json.dumps(doc))
    md = "\n".join(SIZE.render_memory(SIZE.load_memory([str(f)])))
    assert "### ubuntu-22.04-amd64: loaded: ollama:qwen2.5:0.5b" in md, md[:600]
    assert SIZE.memory_json(SIZE.load_memory([str(f)]))["cells"][0]["idle"] == "loaded: ollama:qwen2.5:0.5b"
    old = {k: v for k, v in doc.items() if k != "idle"}
    f.write_text(json.dumps(old))
    assert "### ubuntu-22.04-amd64: unknown: memory.json predates the loaded-model check" in \
        "\n".join(SIZE.render_memory(SIZE.load_memory([str(f)])))
