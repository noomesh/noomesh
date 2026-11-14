# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Is the chat model resident at idle forever, or only warm after install?
(operator 2026-11-14). The default cell samples memory at t0, t0 + 10 min
and t0 + 40 min with nothing using the stack, reading `ollama ps` with its
UNTIL column; after first-answer it stops every model and times one embed
and one chat cold, then warm (coldload.py). The size report renders both."""

from __future__ import annotations

import http.server
import importlib.util
import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN_SH = ROOT / "scripts" / "install-cell" / "run.sh"
MB_PATH = ROOT / "scripts" / "install-cell" / "memory_baseline.py"
COLD = ROOT / "scripts" / "install-cell" / "coldload.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MB = _load("memory_baseline_series", MB_PATH)
CL = _load("coldload_t", COLD)
SIZE = _load("release_size_series", ROOT / "scripts" / "release-size-report.py")
TMB = _load("test_memory_baseline_fixtures", ROOT / "tests" / "test_memory_baseline.py")
DEFAULT = "ubuntu-24.04-amd64-default"

# ollama 0.12's own shape (tabwriter, three spaces of padding, CONTEXT column).
PS_TWO = (
    "NAME                ID              SIZE      PROCESSOR    CONTEXT    UNTIL\n"
    "gemma4:e2b          7fbf7e1d9f6c    7.2 GB    100% CPU     4096       4 minutes from now\n"
    "harrier:latest      2b6f0a3c11de    639 MB    100% CPU     8192       Forever\n"
)


# ---- ollama ps and its UNTIL column ------------------------------------------

def test_until_is_parsed_minutes_forever_and_unknown_wording():
    assert CL.MB.parse_until("4 minutes from now") == {"until": "4 minutes from now", "expires_in_s": 240}
    assert MB.parse_until("29 minutes from now") == {"until": "29 minutes from now", "expires_in_s": 1740}
    assert MB.parse_until("About a minute from now")["expires_in_s"] == 60
    assert MB.parse_until("Less than a second from now")["expires_in_s"] == 0
    assert MB.parse_until("Forever") == {"until": "Forever", "forever": True}
    assert MB.parse_until("forever")["forever"] is True
    odd = MB.parse_until("Stopping...")
    assert odd == {"until": "Stopping..."}, "an unknown wording is neither an expiry nor forever"


def test_ollama_ps_rows_keep_size_until_and_the_raw_line():
    rows = MB.parse_ollama_ps_rows(PS_TWO)
    assert [r["name"] for r in rows] == ["gemma4:e2b", "harrier:latest"]
    g, h = rows
    assert g["size"] == "7.2 GB" and g["processor"] == "100% CPU" and g["context"] == "4096"
    assert g["until"] == "4 minutes from now" and g["expires_in_s"] == 240 and "forever" not in g
    assert h["until"] == "Forever" and h["forever"] is True and "expires_in_s" not in h
    assert g["raw"] == PS_TWO.splitlines()[1].rstrip()
    # One space between cells (no two-space gap anywhere): cut at the header's columns.
    tight = "NAME       ID    SIZE   PROCESSOR UNTIL\nqwen:0.5b  ab12  1 GB   100% CPU  29 minutes from now\n"
    r = MB.parse_ollama_ps_rows(tight)[0]
    assert r["name"] == "qwen:0.5b" and r["until"] == "29 minutes from now" and r["expires_in_s"] == 1740
    assert MB.parse_ollama_ps_rows(PS_TWO.splitlines()[0] + "\n") == []
    assert MB.parse_ollama_ps_rows("Error: could not connect\n") is None


def test_models_loaded_carry_size_and_expiry_and_the_raw_answer_is_kept():
    class Host:
        def cmd(self, *argv, timeout=120):
            return (PS_TWO, None) if argv[:2] == ("docker", "exec") else (None, "x")

        def http_get(self, url, timeout=5):
            return None, "x"

    a = MB.ask_ollama_container(Host(), {"name": "noo-ollama-embed"})
    assert a["raw"] == PS_TWO.rstrip().splitlines()
    got = MB.models_loaded([a])
    assert got[1] == {"backend": "ollama", "model": "harrier:latest", "source": "docker exec noo-ollama-embed ollama ps",
                      "size": "639 MB", "until": "Forever", "forever": True}
    assert got[0]["expires_in_s"] == 240


def test_a_series_sample_waits_until_its_time_and_records_since_t0(tmp_path):
    cg, proc, bin_ = TMB._fake_host(tmp_path)
    out = tmp_path / "memory-idle-t10.json"
    t0 = int(time.time()) - 600
    r = subprocess.run([sys.executable, str(MB_PATH), "measure", "--out", str(out), "--cell", DEFAULT,
                        "--sample", "t10", "--t0", str(t0), "--until", str(t0 + 600),
                        "--cgroup-root", str(cg), "--proc-root", str(proc)],
                       env={"PATH": f"{bin_}:/usr/bin:/bin", "HOME": str(tmp_path)}, capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    m = json.loads(out.read_text())["meta"]
    assert m["sample"] == "t10" and m["t0_epoch"] == t0 and 600 <= m["since_t0_s"] < 660 and m["settle_seconds"] == 0
    assert "until 4 minutes from now" in r.stdout


# ---- the size report ---------------------------------------------------------

def _sample(label, since, models, current):
    t = {k: {"memory_current_bytes": {"bytes": current, "measured": 3, "of": 3}} for k in ("grand", "node_share")}
    return {"idle": ("loaded: " + ", ".join(f"ollama:{m['model']}" for m in models)) if models else "idle: no model loaded",
            "models_loaded": models, "totals": t, "meta": {"cell": DEFAULT, "sample": label, "since_t0_s": since}}


def test_the_series_renders_per_sample_and_a_missing_sample_is_not_measured(tmp_path):
    gem = {"backend": "ollama", "model": "gemma4:e2b", "size": "7.2 GB", "until": "4 minutes from now", "expires_in_s": 240}
    har = {"backend": "ollama", "model": "harrier:latest", "size": "639 MB", "until": "Forever", "forever": True}
    d = tmp_path / f"install-cell-{DEFAULT}"
    d.mkdir()
    s0 = _sample("t0", 0, [gem, har], 9 * 2**30)
    s0.update({"containers": [], "host_units": []})
    s0["totals"].update({k: {f: {"bytes": 0, "measured": 0, "of": 0} for f in MB.TOTAL_FIGURES}
                         for k in ("containers", "host_units", "controller_share")})
    for k in ("grand", "node_share"):
        s0["totals"][k].update({"anon_bytes": {"bytes": 0, "measured": 0, "of": 0},
                                "file_bytes": {"bytes": 0, "measured": 0, "of": 0}})
    (d / "memory.json").write_text(json.dumps(s0))
    (d / "memory-idle-t10.json").write_text(json.dumps(_sample("t10", 601, [har], 2 * 2**30)))
    cells = SIZE.load_memory([str(d / "memory.json")])
    md = "\n".join(SIZE.render_memory(cells))
    assert "#### Idle series (nothing used the stack between samples)" in md
    assert "| t0 | 0 s | loaded: ollama:gemma4:e2b, ollama:harrier:latest | 9216.0 | 9216.0 | " \
           "gemma4:e2b (7.2 GB, until 4 minutes from now), harrier:latest (639 MB, until Forever) |" in md, md
    assert "| t10 | 601 s | loaded: ollama:harrier:latest | 2048.0 | 2048.0 | harrier:latest (639 MB, until Forever) |" in md
    assert "| t40 | | not measured: no memory-idle-t40.json in the cell's artifact | | | |" in md
    j = SIZE.memory_json(cells)["cells"][0]["series"]
    assert [x["sample"] for x in j] == ["t0", "t10", "t40"] and j[2]["measured"] is False
    assert j[1]["models_loaded"][0]["forever"] is True


COLDLOAD = {
    "meta": {"cell": DEFAULT},
    "unload": [{"container": "noo-ollama-embed", "model": "gemma4:e2b", "ok": True},
               {"container": "noo-ollama-embed", "model": "harrier:latest", "ok": False, "why": "exited 1"}],
    "cold_confirmed": "no: still loaded: noo-ollama-embed:harrier:latest",
    "timings": {"cold_embed": {"ok": True, "seconds": 4.21}, "warm_embed": {"ok": True, "seconds": 0.08},
                "cold_chat": {"ok": True, "seconds": 61.5, "first_output_s": 58.0},
                "warm_chat": {"ok": False, "seconds_to_error": 900, "why": "timed out after 900 s"}},
    "key": {"minted": True, "revoked": True},
}


def test_coldload_renders_and_a_missing_one_is_not_measured(tmp_path):
    d = tmp_path / f"install-cell-{DEFAULT}"
    d.mkdir()
    (d / "coldload.json").write_text(json.dumps(COLDLOAD))
    md = "\n".join(SIZE.render_memory(SIZE.load_memory([str(d / "memory.json")])))
    assert "#### Cold load (after first-answer" in md
    assert "unload: noo-ollama-embed:gemma4:e2b stopped, noo-ollama-embed:harrier:latest NOT stopped (exited 1)" in md
    assert "cold before the timings: no: still loaded: noo-ollama-embed:harrier:latest" in md
    assert "| cold embed (POST /api/external/embeddings) | 4.21 | - | ok |" in md
    assert "| cold chat (noo chat --message) | 61.5 | 58.0 | ok |" in md
    assert "| warm chat | - | - | FAILED: timed out after 900 s |" in md, "a failed timing is never shown as 0"
    assert "service-key lifecycle (no value shown) minted=True revoked=True" in md
    (d / "coldload.json").unlink()
    md = "\n".join(SIZE.render_memory(SIZE.load_memory([str(d / "memory.json")])))
    assert "#### Cold load: not measured: no coldload.json in the cell's artifact" in md


# ---- coldload.py --------------------------------------------------------------

def test_cold_verdict_is_unknown_when_a_container_cannot_be_read():
    assert CL.cold_verdict({"c": {"models": []}}) == "yes: nothing loaded after the stops"
    assert CL.cold_verdict({"c": {"models": ["harrier:latest"]}}) == "no: still loaded: c:harrier:latest"
    assert CL.cold_verdict({"c": {"unknown": "exec failed"}}) == "unknown: c (exec failed)"
    assert CL.cold_verdict({}).startswith("unknown:")
    assert CL.key_from_issue_json('note\n{"consumer": "x", "key": "nk_abc"}\n') == "nk_abc"
    assert CL.key_from_issue_json("Error: 401") is None


KEY = "nk_live_" + "Q7wR2tY9uI0pA3sD5fG8hJ1kL4zX6cV"


class _Embedder(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):  # noqa: N802
        _Embedder.seen.append((self.path, self.headers.get("Authorization")))
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps({"model": "harrier:latest", "data": [{"embedding": [0.1, 0.2, 0.3]}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_coldload_unloads_times_cold_and_warm_and_never_writes_the_key(tmp_path):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Embedder)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    stopped = tmp_path / "stopped"
    log = tmp_path / "calls"
    fakes = {
        "docker": f"""#!/bin/sh
echo "docker $*" >> '{log}'
case "$1" in
  ps) printf 'noo-gateway\\nnoo-ollama-embed\\nnoo-stunnel-ollama-embed\\n' ;;
  exec) case "$4" in
      ps) if [ -f '{stopped}' ]; then printf 'NAME    ID    SIZE    PROCESSOR    UNTIL\\n'; else printf '%s' '{PS_TWO.replace("%", "%%")}'; fi ;;
      stop) touch '{stopped}' ;;
    esac ;;
esac
""",
        "noo": f"""#!/bin/sh
echo "noo $*" >> '{log}'
case "$*" in
  "--json security service-key issue"*) echo '{{"consumer": "install-cell-coldload", "scopes": ["embeddings"], "key": "{KEY}"}}' ;;
  "security service-key revoke"*) echo revoked ;;
  chat*) sleep 0.3; echo "Hello! 1. Keep it updated." ;;
esac
""",
        "sudo": '#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n',
    }
    for n, body in fakes.items():
        (bin_ / n).write_text(body)
        (bin_ / n).chmod(0o755)
    out = tmp_path / "coldload.json"
    try:
        r = subprocess.run([sys.executable, str(COLD), "--out", str(out), "--cell", DEFAULT, "--prompt", "Say hello",
                            "--gateway", f"http://127.0.0.1:{srv.server_port}"],
                           env={"PATH": f"{bin_}:/usr/bin:/bin", "HOME": str(tmp_path)}, capture_output=True, text=True,
                           timeout=120)
    finally:
        srv.shutdown()
    assert r.returncode == 0, r.stdout + r.stderr
    text = out.read_text()
    assert KEY not in text and KEY not in r.stdout and KEY not in r.stderr, "the key is never printed or written"
    doc = json.loads(text)
    calls = log.read_text()
    assert "docker exec noo-ollama-embed ollama stop gemma4:e2b" in calls
    assert "docker exec noo-ollama-embed ollama stop harrier:latest" in calls
    assert "noo-stunnel-ollama-embed ollama" not in calls, "the door holds no model"
    assert doc["cold_confirmed"] == "yes: nothing loaded after the stops"
    assert [s["model"] for s in doc["unload"]] == ["gemma4:e2b", "harrier:latest"] and all(s["ok"] for s in doc["unload"])
    assert _Embedder.seen and all(p == "/api/external/embeddings" and a == f"Bearer {KEY}" for p, a in _Embedder.seen)
    t = doc["timings"]
    assert set(t) == {"cold_embed", "cold_chat", "warm_embed", "warm_chat"} and all(x["ok"] for x in t.values())
    assert t["cold_embed"]["dims"] == 3 and t["cold_chat"]["seconds"] >= t["cold_chat"]["first_output_s"] >= 0.25
    assert doc["key"] == {"minted": True, "revoked": True}
    assert calls.index("service-key issue") < calls.index("chat --message Say hello") < calls.index("service-key revoke")
    assert "--scopes embeddings" in calls


def test_coldload_without_a_key_records_why_and_still_times_the_chat(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for n, body in {"docker": "#!/bin/sh\nexit 1\n", "sudo": "#!/bin/sh\nexit 1\n",
                    "noo": '#!/bin/sh\ncase "$*" in chat*) echo hi ;; *) echo "Error: 403 admin only" >&2; exit 1 ;; esac\n'}.items():
        (bin_ / n).write_text(body)
        (bin_ / n).chmod(0o755)
    out = tmp_path / "c.json"
    r = subprocess.run([sys.executable, str(COLD), "--out", str(out), "--cell", DEFAULT, "--prompt", "hi",
                        "--gateway", "http://127.0.0.1:9"], env={"PATH": f"{bin_}:/usr/bin:/bin", "HOME": str(tmp_path)},
                       capture_output=True, text=True, timeout=60)
    doc = json.loads(out.read_text())
    assert r.returncode == 1
    assert doc["cold_confirmed"].startswith("unknown: docker ps failed")
    assert doc["key"]["minted"] is False and "403 admin only" in doc["key"]["why"]
    assert doc["timings"]["cold_embed"] == {"ok": False, "why": "not run: no service key could be minted"}
    assert "seconds" not in doc["timings"]["cold_embed"], "unknown, never 0"
    assert doc["timings"]["cold_chat"]["ok"] is True


# ---- run.sh -------------------------------------------------------------------

def test_the_series_sits_after_verify_and_before_first_answer_and_coldload_after_it():
    text = RUN_SH.read_text()
    verify = text.index("step verify 900")
    vjson = text.index("step probe-verify-json 300")
    base = text.index("step probe-memory-baseline ")
    series = text.index('step "probe-idle-t$IDLE_MIN"')
    answer = text.index("step first-answer ")
    answered = text.index('meta first_answer_s "$(( $(date +%s) - CELL_START ))"')
    cold = text.index("step probe-coldload ")
    rag = text.index("step probe-rag-chat ")
    assert verify < vjson < base < series < answer < answered < cold < rag, (base, series, answer, cold, rag)
    # Nothing runs between the first sample and the series but the series.
    between = text[text.index("\nesac\n", base):series]
    assert "noo " not in between.replace("noo-", "") and between.count("step ") == 0
    loop = text[series - 200:text.index("\n    done\n", series)]
    assert "for IDLE_MIN in 10 40; do" in loop and "--until $(( IDLE_T0 + IDLE_MIN * 60 ))" in loop
    assert '--out "$OUT/memory-idle-t$IDLE_MIN.json"' in loop and '--sample "t$IDLE_MIN"' in loop
    assert ["t10", "t40"] == MB.SERIES_SAMPLES


def _block(text: str, start: str) -> str:
    i = text.index(start)
    return text[i:text.index("\nfi\n", i) + len("\nfi\n")]


def test_the_series_and_coldload_run_on_the_default_cell_only():
    import yaml
    text = RUN_SH.read_text()
    assign = re.search(r"^IDLE_SERIES_CELL=.*$", text, re.M).group(0)
    series = _block(text, 'if [ "$CELL" = "$IDLE_SERIES_CELL" ]; then\n    IDLE_T0=')
    cold = _block(text, 'if [ "$CELL" = "$IDLE_SERIES_CELL" ]; then\n    step probe-coldload')
    wf = yaml.safe_load((ROOT / ".github/workflows/install-matrix.yml").read_text())
    cells = [r["cell"] for r in wf["jobs"]["cell"]["strategy"]["matrix"]["include"]] + ["windows-2025-wsl2"]
    ran: dict[str, set] = {}
    for cell in cells:
        r = subprocess.run(["bash", "-c", 'step() { echo "RAN $1"; }\n' + assign + "\n" + series + cold],
                           env={"CELL": cell, "OUT": "/nonexistent", "HERE": "/h", "MODEL": "m", "PATH": "/usr/bin:/bin"},
                           capture_output=True, text=True, check=True)
        ran[cell] = set(re.findall(r"RAN (\S+)", r.stdout))
    assert ran.pop(DEFAULT) == {"probe-idle-t10", "probe-idle-t40", "probe-coldload"}
    assert all(not v for v in ran.values()), ran
    assert MB.SERIES_CELLS == [DEFAULT] and f"IDLE_SERIES_CELL={DEFAULT}" == assign


def test_the_series_and_coldload_are_probes_never_the_failed_step(tmp_path):
    text = RUN_SH.read_text()
    for start in ('step "probe-idle-t$IDLE_MIN"', "step probe-coldload "):
        i = text.index(start)
        stmt = text[i:text.index("\n", text.index("\n", i) + 1)]
        stmt = stmt[:stmt.index("\n    done") if "\n    done" in stmt else len(stmt)]
        assert "finish" not in stmt and "fail_onboarded" not in stmt and "||" not in stmt, stmt
    C = _load("install_cell_series", ROOT / "scripts/install-cell/cell.py")
    ok = {"step": "first-answer", "rc": 0, "seconds": 1, "first_error": "", "prompts": [], "warnings": [], "tail": []}
    steps = [ok] + [{**ok, "step": s, "rc": 124, "first_error": "TIMEOUT"} for s in
                    ("probe-idle-t10", "probe-idle-t40", "probe-coldload")]
    (tmp_path / "steps.jsonl").write_text("\n".join(json.dumps(s) for s in steps) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": DEFAULT}))
    s = C.summarize(tmp_path)
    assert s["result"] == "pass" and set(s["probes"]) == {"probe-idle-t10", "probe-idle-t40", "probe-coldload"}


def test_the_default_cell_keeps_timeout_headroom_for_the_series():
    import yaml
    wf = yaml.safe_load((ROOT / ".github/workflows/install-matrix.yml").read_text())
    budget = wf["jobs"]["cell"]["timeout-minutes"]
    text = RUN_SH.read_text()
    # The series waits to t0 + 40 min; the cold-load step is capped at 3000 s.
    assert "for IDLE_MIN in 10 40; do" in text and "step probe-coldload 3000 " in text
    measured_cell_minutes = 18  # the default cell's slowest recent run (2026-11-13/14: 12.9-17.6 min)
    assert measured_cell_minutes + 41 + 3000 / 60 < budget, "series + a worst-case cold load must fit 120 min"


def test_the_service_key_status_line_passes_the_upload_scan():
    """Run 43611137767: 'service key: minted=True revoked=True' was redacted
    to 'service key: [REDACTED] revoked=True' and the scan read revoked=True as
    the key's value, withholding the cell's logs. The status line must not be
    key-shaped, in the probe's log or the report."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("cellpy", ROOT / "scripts" / "install-cell" / "cell.py")
    cell = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cell)
    for src in ("scripts/install-cell/coldload.py", "scripts/release-size-report.py"):
        text = (ROOT / src).read_text()
        line = next(l for l in text.splitlines() if "lifecycle (no value shown)" in l)
        sample = "service-key lifecycle (no value shown) minted=True revoked=True\n"
        assert "service key:" not in line, src
        red = cell.redact_line(sample, {})
        assert cell.secret_hits(red) == [], (src, red)
