# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Postgres connections on a one-machine install, measured by the default
install cell (scripts/install-cell/pg_conns.py): pg_stat_activity grouped
per application_name / source container / user@db, against max_connections,
idle and as the MAXIMUM over first-answer and the RAG ingest. A figure that
cannot be read is "unknown: why", never 0; the probes run on the default
cell only and never fail it."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN_SH = ROOT / "scripts" / "install-cell" / "run.sh"
SCRIPT = ROOT / "scripts" / "install-cell" / "pg_conns.py"
DEFAULT = "ubuntu-24.04-amd64-default"
S = "\x1f"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PG = _load("pg_conns_t", SCRIPT)
SIZE = _load("release_size_pg", ROOT / "scripts" / "release-size-report.py")


def _line(app, user, db, state, client, btype, n):
    return S.join([app, user, db, state, client, btype, str(n)])


ACTIVITY = "\n".join([
    _line("", "noo_app", "noomesh", "idle", "172.19.0.7", "client backend", 9),
    _line("", "noo_trellion", "noomesh", "idle", "172.19.0.7", "client backend", 3),
    _line("", "noo_app", "noomesh", "idle", "172.19.0.5", "client backend", 4),
    _line("noo-evolve", "noo_evolve", "noomesh", "active", "172.19.0.9", "client backend", 2),
    _line("", "noo", "noomesh", "idle", "172.19.0.3", "client backend", 10),
    _line("", "", "", "", "local", "autovacuum launcher", 1),
    _line("", "", "", "", "local", "checkpointer", 1),
]) + "\n"
IPS = {"172.19.0.7": "noo-trellion", "172.19.0.5": "noo-worker", "172.19.0.3": "noo-gateway"}


# ---- grouping ------------------------------------------------------------------

def test_rows_group_per_app_source_and_user_and_other_backends_are_not_counted():
    rows = PG.parse_activity(ACTIVITY)
    s = PG.summarize(rows, IPS)
    assert s["total"] == 28, "client backends only: autovacuum and the checkpointer are not max_connections'"
    assert s["by_app"] == {"(none)": 26, "noo-evolve": 2}
    assert s["by_source"] == {"noo-trellion": 12, "noo-worker": 4, "noo-gateway": 10,
                              "172.19.0.9 (no container has this address)": 2}
    assert s["by_user_db"] == {"noo_app@noomesh": 13, "noo_trellion@noomesh": 3, "noo_evolve@noomesh": 2,
                               "noo@noomesh": 10}
    assert s["by_state"] == {"idle": 26, "active": 2}
    assert s["other_backends"] == {"autovacuum launcher": 1, "checkpointer": 1}
    assert PG.source_of("local", IPS) == "(local socket)"


def test_an_error_is_not_an_empty_table_and_the_query_excludes_itself():
    assert PG.parse_activity("") == []
    assert PG.parse_activity("psql: error: connection to server failed\n") is None
    assert PG.parse_activity(_line("a", "b", "c", "d", "e", "f", "x")) is None
    assert "pid <> pg_backend_pid()" in PG.ACTIVITY_SQL
    assert "query" not in PG.ACTIVITY_SQL.split("FROM")[0], "never the query text"
    assert PG.parse_settings(f"100{S}3\n") == {"max_connections": 100, "superuser_reserved_connections": 3}
    assert PG.parse_settings("ERROR: permission denied") is None


# ---- max over a step -----------------------------------------------------------

def _s(at, total, apps, sources=None):
    return {"at": at, "total": total, "by_app": apps, "by_source": sources or {"noo-worker": total},
            "by_user_db": {}, "by_state": {}, "other_backends": {}}


def test_fold_keeps_the_peak_sample_and_each_groups_own_maximum():
    samples = [_s(1, 20, {"(none)": 20}), _s(2, 47, {"(none)": 40, "x": 7}, {"noo-trellion": 30, "noo-worker": 17}),
               {"at": 3, "unknown": "psql in noo-postgres failed (timeout)"}, _s(4, 31, {"(none)": 21, "x": 10})]
    p = PG.fold(samples)
    assert p["total"] == 47 and p["peak_at"] == 2 and p["min_total"] == 20
    assert p["by_app"] == {"(none)": 40, "x": 7}, "the peak sample's own breakdown"
    assert p["by_app_max"] == {"(none)": 40, "x": 10}, "each app's maximum over the step"
    assert p["by_source_max"]["noo-trellion"] == 30
    assert (p["samples"], p["samples_read"]) == (4, 3)
    assert p["unreadable_samples"] == ["psql in noo-postgres failed (timeout)"]
    # Order does not matter: the max, not the last.
    assert PG.fold(list(reversed(samples)))["total"] == 47


# ---- unknown, never 0 ----------------------------------------------------------

def test_nothing_readable_is_unknown_never_zero():
    p = PG.fold([{"at": 1, "unknown": "psql in noo-postgres failed (exited 2)"}])
    assert "total" not in p and p["unknown"].startswith("no sample could be read: psql")
    assert "total" not in PG.fold([]) and PG.fold([])["unknown"] == "no sample taken"
    doc = {"meta": {"cell": DEFAULT}, "settings": {"unknown": "psql failed"},
           "points": [{"point": "idle-after-verify", "kind": "sample", "unknown": "psql failed"}]}
    doc["whole_run_max"] = PG.whole_run_max(doc["points"])
    assert doc["whole_run_max"] == {"unknown": "no point could be read"}
    text = PG.render(doc) + "\n".join(PG.render_report(doc))
    assert "unknown: psql failed" in text and "max_connections unknown" in text
    assert not re.search(r"total 0\b|\| 0 of", text), text
    # The whole-run max skips an unknown point instead of reading it as 0.
    w = PG.whole_run_max([{"point": "a", "unknown": "x"}, {"point": "b", "total": 3}])
    assert w["total"] == 3 and w["point"] == "b" and (w["points_read"], w["points"]) == (1, 2)


# ---- the real script against a fake docker -------------------------------------

def _fake_bin(tmp_path, fail_psql=False):
    (tmp_path / "activity.txt").write_text(ACTIVITY)
    inspect = [{"Name": f"/{n}", "NetworkSettings": {"Networks": {"noomesh_default": {"IPAddress": ip}}}}
               for ip, n in IPS.items()]
    (tmp_path / "inspect.json").write_text(json.dumps(inspect))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    psql = ('echo "psql: error: connection to server on socket failed" >&2; exit 2' if fail_psql else
            f'case "$*" in *pg_stat_activity*) cat "{tmp_path}/activity.txt" ;; '
            f'*max_connections*) printf "100\\0373\\n" ;; esac')
    (bin_ / "docker").write_text(f"""#!/bin/bash
echo "$*" >> "{tmp_path}/docker.calls"
case "$1" in
  ps) if [ "$2" = -q ]; then printf 'a\\nb\\nc\\n'; else printf 'noo-gateway\\nnoo-worker\\nnoo-trellion\\nnoomesh-worker-extra-1\\n'; fi ;;
  inspect) if [ "$2" = -f ]; then echo "0 "; else cat "{tmp_path}/inspect.json"; fi ;;
  exec)
    case "$3" in
      printenv) echo noo ;;
      psql) {psql} ;;
      python3) [ "$2" = noo-trellion ] && {{ echo "boom" >&2; exit 1; }}; echo "4 4" ;;
    esac ;;
esac
""")
    (bin_ / "docker").chmod(0o755)
    (bin_ / "sudo").write_text('#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n')
    (bin_ / "sudo").chmod(0o755)
    return {"PATH": f"{bin_}:/usr/bin:/bin", "HOME": str(tmp_path)}


def _run(env, *args):
    r = subprocess.run([sys.executable, str(SCRIPT), *args], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def test_sample_records_the_point_settings_and_cpu_counts(tmp_path):
    env = _fake_bin(tmp_path)
    out = tmp_path / "pg-conns.json"
    log = _run(env, "sample", "--out", str(out), "--cell", DEFAULT, "--point", "idle-after-verify", "--cpus")
    doc = json.loads(out.read_text())
    p = doc["points"][0]
    assert p["point"] == "idle-after-verify" and p["kind"] == "sample" and p["total"] == 28
    assert p["by_source"]["noo-trellion"] == 12
    assert doc["settings"] == {"max_connections": 100, "superuser_reserved_connections": 3}
    cpus = {c["name"]: c for c in doc["cpus"]["containers"]}
    assert cpus["noo-worker"]["cpu_count"] == 4 and cpus["noo-worker"]["affinity"] == 4
    assert cpus["noo-worker"]["docker_limit"] == "none"
    assert cpus["noo-trellion"]["unknown"], "an unreadable cpu_count is unknown, not 0"
    assert "cpu_count" not in cpus["noo-trellion"] and "noomesh-worker-extra-1" in cpus
    assert "28 of 100" in log and "noo-trellion=12" in log
    calls = (tmp_path / "docker.calls").read_text()
    assert "psql -X -At -F" in calls and "-U noo -d postgres" in calls
    # A second point accumulates; the same point again replaces itself.
    _run(env, "sample", "--out", str(out), "--cell", DEFAULT, "--point", "after-first-answer")
    _run(env, "sample", "--out", str(out), "--cell", DEFAULT, "--point", "after-first-answer")
    doc = json.loads(out.read_text())
    assert [p["point"] for p in doc["points"]] == ["idle-after-verify", "after-first-answer"]
    assert doc["cpus"]["containers"], "a later sample without --cpus keeps the recorded counts"


def test_psql_failing_is_unknown_with_the_reason_and_the_probe_still_exits_0(tmp_path):
    env = _fake_bin(tmp_path, fail_psql=True)
    out = tmp_path / "pg-conns.json"
    _run(env, "sample", "--out", str(out), "--cell", DEFAULT, "--point", "idle-after-verify")
    doc = json.loads(out.read_text())
    p = doc["points"][0]
    assert "total" not in p and "connection to server on socket failed" in p["unknown"]
    assert "unknown" in doc["settings"] and "unknown" in doc["whole_run_max"]


def test_watch_samples_until_the_stop_file_and_fold_records_the_max(tmp_path):
    env = _fake_bin(tmp_path)
    samples, stop, out = tmp_path / "w.jsonl", tmp_path / "stop", tmp_path / "pg-conns.json"
    w = subprocess.Popen([sys.executable, str(SCRIPT), "watch", "--samples", str(samples), "--stop", str(stop),
                          "--interval", "0.2", "--max-seconds", "30"], env=env)
    deadline = time.time() + 20
    while time.time() < deadline and (not samples.exists() or len(samples.read_text().splitlines()) < 3):
        time.sleep(0.1)
    stop.touch()
    assert w.wait(timeout=20) == 0
    lines = [json.loads(l) for l in samples.read_text().splitlines()]
    assert len(lines) >= 3 and all(l["total"] == 28 for l in lines) and "rows" not in lines[0]
    # A busier sample appended by hand: fold must take the maximum.
    with samples.open("a") as f:
        f.write(json.dumps(_s(int(time.time()), 61, {"(none)": 61})) + "\n")
    _run(env, "fold", "--samples", str(samples), "--point", "during-first-answer", "--out", str(out), "--cell", DEFAULT)
    doc = json.loads(out.read_text())
    p = doc["points"][0]
    assert p["kind"] == "max over step" and p["total"] == 61 and p["samples"] == len(lines) + 1
    assert doc["whole_run_max"]["total"] == 61 and doc["whole_run_max"]["point"] == "during-first-answer"


def test_watch_stops_when_its_parent_is_gone(tmp_path):
    env = _fake_bin(tmp_path)
    dead = subprocess.Popen(["true"])
    dead.wait()
    r = subprocess.run([sys.executable, str(SCRIPT), "watch", "--samples", str(tmp_path / "w.jsonl"),
                        "--stop", str(tmp_path / "never"), "--interval", "0.2", "--max-seconds", "30",
                        "--parent", str(dead.pid)], env=env, timeout=20)
    assert r.returncode == 0


# ---- the size report -----------------------------------------------------------

def test_the_size_report_renders_pg_conns_and_a_missing_file_is_not_measured(tmp_path):
    cell = tmp_path / f"install-cell-{DEFAULT}"
    cell.mkdir()
    doc = {"schema": 1, "meta": {"cell": DEFAULT}, "settings": {"max_connections": 100, "superuser_reserved_connections": 3},
           "cpus": {"runner_cpu_count": 4, "containers": [{"name": "noo-worker", "cpu_count": 4, "affinity": 4,
                                                           "docker_limit": "none"}]},
           "points": [{"point": "idle-after-verify", "kind": "sample", **PG.summarize(PG.parse_activity(ACTIVITY), IPS)},
                      {"point": "during-first-answer", **PG.fold([_s(1, 47, {"(none)": 47})])}]}
    doc["whole_run_max"] = PG.whole_run_max(doc["points"])
    (cell / "pg-conns.json").write_text(json.dumps(doc))
    cells = SIZE.load_memory([f"{DEFAULT}={cell}/memory.json"])
    text = "\n".join(SIZE.render_memory(cells))
    assert "#### Postgres connections (measured" in text
    assert "| idle-after-verify | sample | 28 of 100 | (none)=26, noo-evolve=2 |" in text
    assert "| during-first-answer | max over step (1/1 samples) | 47 of 100 |" in text
    assert "whole run max: **47** at during-first-answer" in text
    assert "noo-worker: os.cpu_count()=4 sched_getaffinity=4 docker limit none" in text
    assert "97 for the stack's roles" in text
    assert SIZE.memory_json(cells)["cells"][0]["pg_conns"]["whole_run_max"]["total"] == 47
    # Beside a measured memory.json too (the report's other branch).
    (cell / "memory.json").write_text(json.dumps({"meta": {"cell": DEFAULT}, "containers": [], "host_units": [],
                                                  "totals": SIZE.MB.totals([], [])}))
    text = "\n".join(SIZE.render_memory(SIZE.load_memory([f"{DEFAULT}={cell}/memory.json"])))
    assert "| during-first-answer | max over step (1/1 samples) | 47 of 100 |" in text
    (cell / "memory.json").unlink()
    # The default cell without the file: not measured, by name.
    (cell / "pg-conns.json").unlink()
    text = "\n".join(SIZE.render_memory(SIZE.load_memory([f"{DEFAULT}={cell}/memory.json"])))
    assert "#### Postgres connections: not measured: no pg-conns.json in the cell's artifact" in text
    # Another cell is not expected to have one.
    other = tmp_path / "install-cell-ubuntu-22.04-amd64"
    other.mkdir()
    assert "Postgres connections" not in "\n".join(SIZE.render_memory(SIZE.load_memory([f"{other}/memory.json"])))


# ---- run.sh --------------------------------------------------------------------

def _helpers(text: str) -> str:
    i = text.index("PG_CONNS_CELL=")
    return text[i:text.index("\nfinish() {", i)]


def test_the_pg_probes_run_on_the_default_cell_only(tmp_path):
    import yaml
    text = RUN_SH.read_text()
    assert f"PG_CONNS_CELL={DEFAULT}" in text and PG.PG_CONNS_CELLS == [DEFAULT]
    calls = re.findall(r"^(pg_sample .*|pg_watch_start .*|pg_watch_stop)$", text, re.M)
    assert calls == ["pg_sample idle-after-verify --cpus", "pg_sample idle-after-series",
                     "pg_watch_start during-first-answer 1860", "pg_watch_stop", "pg_sample after-first-answer",
                     "pg_watch_start during-rag-ingest 1560", "pg_watch_stop", "pg_sample after-rag-ingest"]
    wf = yaml.safe_load((ROOT / ".github/workflows/install-matrix.yml").read_text())
    cells = [r["cell"] for r in wf["jobs"]["cell"]["strategy"]["matrix"]["include"]] + ["windows-2025-wsl2"]
    assert DEFAULT in cells
    (tmp_path / "logs").mkdir()
    stub = ('step() { echo "RAN $1"; }\npython3() { echo "BG $*"; }\nwait() { :; }\n'
            + _helpers(text).replace("$HERE", "/h") + "\n" + "\n".join(calls) + "\n")
    for cell in sorted(cells, key=lambda c: c == DEFAULT):  # the default last: its logs stay
        r = subprocess.run(["bash", "-c", stub], env={"CELL": cell, "OUT": str(tmp_path), "PATH": "/usr/bin:/bin"},
                           capture_output=True, text=True)
        ran = re.findall(r"RAN (\S+)", r.stdout)
        if cell == DEFAULT:
            assert ran == ["probe-pg-conns-idle-after-verify", "probe-pg-conns-idle-after-series",
                           "probe-pg-conns-during-first-answer", "probe-pg-conns-after-first-answer",
                           "probe-pg-conns-during-rag-ingest", "probe-pg-conns-after-rag-ingest"], r.stdout + r.stderr
            bg = (tmp_path / "logs" / "pg-watch-during-first-answer.log").read_text()
            assert "BG /h/pg_conns.py watch" in bg and "--parent" in bg
        else:
            assert ran == [] and not list((tmp_path / "logs").iterdir()), (cell, r.stdout)


def test_the_sampler_brackets_first_answer_and_the_rag_probe():
    text = RUN_SH.read_text()
    i = text.index
    assert i("pg_sample idle-after-verify") < i("step probe-memory-baseline ") < i('step "probe-idle-t$IDLE_MIN"') \
        < i("pg_sample idle-after-series") < i("pg_watch_start during-first-answer") < i("step first-answer 1800") \
        < i('meta first_answer_s "$(( $(date +%s) - CELL_START ))"\npg_watch_stop') < i("pg_sample after-first-answer") \
        < i("pg_watch_start during-rag-ingest") < i("step probe-rag-chat 1500") \
        < i("  true'\npg_watch_stop\npg_sample after-rag-ingest") < i("step rag-chat 60")
    # A cell that ends mid-watch (first-answer failed) still folds its samples.
    fin = text[i("\nfinish() {"):i("\nhook() {")]
    assert "pg_watch_stop" in fin.split("kill \"$SAMPLER\"")[0]


def test_the_pg_probes_never_become_the_failed_step(tmp_path):
    text = RUN_SH.read_text()
    helpers = _helpers(text)
    assert "finish" not in helpers.replace("(also from finish)", "") and "fail_onboarded" not in helpers
    assert "||" not in helpers.replace('[ "$CELL" = "$PG_CONNS_CELL" ] || return 0', "").replace(
        '[ -n "$PG_WATCH_PID" ] || return 0', ""), "a pg probe's exit never ends the cell"
    C = _load("install_cell_pg", ROOT / "scripts/install-cell/cell.py")
    ok = {"step": "first-answer", "rc": 0, "seconds": 1, "first_error": "", "prompts": [], "warnings": [], "tail": []}
    steps = [ok] + [{**ok, "step": f"probe-pg-conns-{p}", "rc": 1, "first_error": "x"} for p in
                    ("idle-after-verify", "during-first-answer")]
    (tmp_path / "steps.jsonl").write_text("\n".join(json.dumps(s) for s in steps) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": DEFAULT}))
    assert C.summarize(tmp_path)["result"] == "pass"


def test_the_first_answer_says_cold_after_an_idle_series_and_points_at_the_warm_figure():
    import importlib.util
    spec = importlib.util.spec_from_file_location("srr_fa", ROOT / "scripts" / "release-size-report.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    cold = m.render_first_answer({"first_answer_s": 323, "first_answer_wall_s": 2792, "probe_wait_before_first_answer_s": 2469})
    assert "323 s after install, cold model (after a 40-min idle series" in cold[1] and "Cold load table" in cold[1]
    warm = m.render_first_answer({"first_answer_s": 260, "first_answer_wall_s": 260, "probe_wait_before_first_answer_s": 0})
    assert "260 s after install, right after install" in warm[1] and "cold" not in warm[1]
