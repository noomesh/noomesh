# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The install-matrix harness (2026-11-12): what it keeps out of PUBLIC logs,
how it times and records a step, and the release size math."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess

import pytest
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CELL = ROOT / "scripts" / "install-cell" / "cell.py"
LIB = ROOT / "scripts" / "install-cell" / "lib.sh"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C = _load("install_cell", CELL)
SIZE = _load("release_size", ROOT / "scripts" / "release-size-report.py")

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MX0.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
SECRET_LINES = [
    "  join key: noo1.QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo.abc",
    f"Authorization: Bearer {JWT}",
    "admin password: Tr0ub4dor&3-horse",
    "NOO_CLUSTER_TOKEN=s3cr3t-value-123",
    "export GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVmZ2hpams=",
]


def _redact(text: str) -> str:
    return subprocess.run([sys.executable, str(CELL), "redact"], input=text, capture_output=True,
                          text=True, check=True).stdout


def test_secrets_never_reach_a_public_log():
    out = _redact("\n".join(SECRET_LINES) + "\n")
    for leaked in ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo", JWT, "Tr0ub4dor", "s3cr3t-value", "ghp_abcdef",
                   "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"):
        assert leaked not in out, (leaked, out)
    assert out.count("[REDACTED]") >= len(SECRET_LINES)
    assert "join key: " in out and "admin password: " in out, "the label stays, only the value goes"


def test_a_pem_block_is_masked_whole_and_digests_stay_readable():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabc\n-----END PRIVATE KEY-----\nafter\n"
    out = _redact(pem)
    assert "MIIEv" not in out and "abc" not in out and out.endswith("after\n")
    digest = "sha256:" + "ab" * 32
    assert digest in _redact(f"image digest {digest}\n"), "a digest is evidence, not a secret"
    url = "curl -fsSL https://github.com/noomesh/noomesh/releases/latest/download/install.sh -o install.sh"
    assert _redact(url + "\n").strip() == url, "a URL is evidence too (run 3)"
    assert not C.secret_hits(url)


def test_a_secret_revealed_under_its_name_is_masked_and_scanned():
    # onboard's reveal_secret (prompt.rs): the name, then the value ALONE on
    # the next line, short and shapeless (fa, 2026-11-12).
    shown = "\n  \x1b[1mNOO_AGE_BACKUP_PASSPHRASE\x1b[0m\n\n  correct-horse\nnext line stays\n"
    out = _redact(shown)
    assert "correct-horse" not in out and "NOO_AGE_BACKUP_PASSPHRASE" in out and "next line stays" in out
    assert "\x1b[" not in out
    assert C.secret_hits("  NOO_ADMIN_PASSWORD\n  hunter2\n"), "the scan sees an unmasked value under a name"
    assert not C.secret_hits(out)
    assert _redact("KEY POINTS\nnot a secret\n").count("[REDACTED]") == 0, "a heading with a space is not a name"


def test_the_upload_scan_refuses_anything_secret_shaped(tmp_path):
    (tmp_path / "ok.log").write_text(_redact("\n".join(SECRET_LINES) + "\n"))
    scan = lambda: subprocess.run([sys.executable, str(CELL), "scan", str(tmp_path)],  # noqa: E731
                                  capture_output=True, text=True)
    assert scan().returncode == 0, scan().stderr
    for raw in SECRET_LINES:
        (tmp_path / "leak.log").write_text(raw + "\n")
        r = scan()
        assert r.returncode == 3, (raw, r.stderr)
    (tmp_path / "leak.log").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    assert scan().returncode == 3


def test_a_step_that_hangs_is_killed_with_its_children_at_the_timeout():
    t0 = time.time()
    r = subprocess.run([sys.executable, str(CELL), "run", "2", "--", "sh", "-c", "sleep 60 & sleep 60"],
                       capture_output=True, text=True)
    assert r.returncode == 124 and time.time() - t0 < 30
    assert "TIMEOUT after 2s" in r.stdout


def test_a_record_names_the_first_error_prompts_and_warnings(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("pulling\nPROMPT: Admin email [admin@local]\nContinue? [Y/n]\n"
                   "! verify: tempo not ready\noperator alert: TargetDown loki\n"
                   "Error: compose up failed: port 443 in use\nlater error\n")
    r = C.record("stack-start", 1, 42, str(log))
    assert r["first_error"].startswith("Error: compose up failed: port 443 in use")
    assert len(r["prompts"]) == 2 and len(r["warnings"]) == 2
    assert C.record("x", 0, 1, str(log))["first_error"] == "", "a passing step has no first error"


def test_the_first_error_is_the_line_that_says_so_not_one_that_mentions_failed(tmp_path):
    # Run 1, 2026-11-12: "13 created, ... 0 failed" was picked over the real verdict.
    log = tmp_path / "onboard.log"
    log.write_text("  + Storage directories (13 created, 1 already exist, 0 wrong owner, 0 failed) under /var/lib/noo\n"
                   "  Endpoints\n"
                   "  x onboarding did NOT complete — 1 step(s) failed in a way later steps cannot repair:\n"
                   "  - sandbox AppArmor profile: apparmor_parser could not load it\n"
                   "  Fix the cause and re-run `noo onboard --reconfigure`\n")
    e = C.record("onboard", 1, 176, str(log))["first_error"]
    assert e.startswith("x onboarding did NOT complete") and "apparmor_parser could not load it" in e, e
    assert "0 failed" not in e


def test_lib_step_redacts_records_and_returns_the_exit_code(tmp_path):
    out = tmp_path / "out"
    script = (f'set -uo pipefail; OUT="{out}"; CELL=t; . "{LIB}"; '
              'step leak 30 -- sh -c "echo admin password: hunter2hunter2; echo Error: boom; exit 7"; echo "rc=$?"')
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert "rc=7" in r.stdout and "hunter2" not in r.stdout, r.stdout
    rec = json.loads((out / "steps.jsonl").read_text().splitlines()[0])
    assert rec["step"] == "leak" and rec["rc"] == 7 and rec["first_error"] == "Error: boom"
    assert "hunter2" not in (out / "logs" / "leak.log").read_text()


def _agent_dump_cell(tmp_path, systemd: bool):
    """A cell with run.sh's agent_dump hook and fake sudo/systemctl/journalctl/ps
    on PATH: one step passes, two fail, one fails inside a child bash that
    sources lib.sh (the mode hooks' shape). Returns (stdout, steps, out dir)."""
    run_sh = (ROOT / "scripts/install-cell/run.sh").read_text()
    start, end = run_sh.index("AGENT_DUMPS=0\n"), run_sh.index("export -f agent_dump\n") + len("export -f agent_dump\n")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    fakes = {
        "sudo": '#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n',
        "systemctl": '#!/bin/sh\necho "noo-node-agent.service - active (running) fake-status"\n',
        "journalctl": '#!/bin/sh\necho "agent: placement received fake-journal"\n',
        "ps": '#!/bin/sh\necho "  PID ELAPSED COMMAND"\necho "  42 00:10 /usr/local/bin/noo-node-agent fake-proc"\n',
        # Never the host's own noo or docker (on a dev box they reach a real controller).
        "noo": '#!/bin/sh\necho \'{"lanes": [], "fake": "cluster-show"}\'\n',
        "docker": '#!/bin/sh\n[ "$1" = logs ] && echo "INFO reconcile_nudged node=fake-nudge"\nexit 0\n',
    }
    for n, body in fakes.items():
        (bin_ / n).write_text(body)
        (bin_ / n).chmod(0o755)
    out = tmp_path / "out"
    sysdir = tmp_path / "systemd"
    if systemd:
        sysdir.mkdir()
    # OUT and CELL come from the workflow's env in a real cell, so a mode hook inherits them.
    script = (f'set -uo pipefail; export OUT="{out}" CELL=t; . "{LIB}"; ' + run_sh[start:end] +
              'step ok 30 -- true; step bad 30 -- sh -c "exit 3"; echo "rc=$?"; step bad2 30 -- false; '
              f'bash -c \'. "{LIB}"; step child 30 -- false\'; echo "child=$?"')
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "CELL_SYSTEMD_DIR": str(sysdir)}
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=120)
    steps = [json.loads(l) for l in (out / "steps.jsonl").read_text().splitlines()]
    return r.stdout, steps, out


def test_every_failed_step_dumps_the_node_agent_state_through_step(tmp_path):
    # rc.3 matrix run 2 (WSL2): a placed model, "no lanes" two minutes later,
    # and no agent log in the artifact to say why.
    stdout, steps, out = _agent_dump_cell(tmp_path, systemd=True)
    names = [s["step"] for s in steps]
    assert names == ["ok", "bad", "agent-state-after-bad", "bad2", "agent-state-after-bad2",
                     "child", "agent-state-after-child"], names
    # The failed step's exit code is the caller's, not the dump's.
    assert "rc=3" in stdout and "child=1" in stdout, stdout
    log = (out / "logs" / "agent-state-after-bad.log").read_text()
    assert "fake-status" in log and "fake-journal" in log, log
    assert "fake-nudge" in log and '"fake": "cluster-show"' in log, log
    # Recorded by step(): redacted, in steps.jsonl, and never the failed step.
    assert all(s["rc"] == 0 for s in steps if s["step"].startswith("agent-state-after-"))
    (out / "meta.json").write_text(json.dumps({"cell": "c"}))
    assert C.summarize(out)["failed_step"] == "bad"


def test_without_systemd_the_dump_shows_the_agent_process(tmp_path):
    _, _, out = _agent_dump_cell(tmp_path, systemd=False)
    log = (out / "logs" / "agent-state-after-bad.log").read_text()
    assert "no systemd on this host" in log and "fake-proc" in log and "fake-journal" not in log, log


def test_the_dump_never_reads_the_agent_env_file_and_is_capped():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    body = text[text.index("agent_dump() {"):text.index("ON_STEP_FAIL=agent_dump")]
    assert "noo-node-agent.env" not in body and "agent-secrets" not in body
    assert '[ "$AGENT_DUMPS" -lt 5 ] || return 0' in body

    # A dump that times out (rc 124) is still never "the failed step".


def test_the_agent_state_is_saved_after_the_model_step_even_when_it_passes():
    # WSL2 vs 22.04 (rc.3): only the failing cell left a dump, so the passing
    # one could not be compared. The model is placed in onboard / onboard-model.
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    model = text.index("step onboard-model 1800")
    full = text.index("step onboard 3600")
    call = text.index("\nagent_dump model\n")
    assert call > model and call > full, "after both model paths"
    assert call < text.index("step stack-start"), "before anything else moves the stack"
    body = text[text.index("agent_dump() {"):text.index("ON_STEP_FAIL=agent_dump")]
    assert 'noo --json cluster show "$(hostname)"' in body
    assert 'grep -E "reconcile_nudge|placement"' in body


def test_a_dump_that_times_out_is_not_the_failed_step(tmp_path):
    rec = {"seconds": 1, "first_error": "", "prompts": [], "warnings": [], "tail": []}
    steps = [{**rec, "step": "install", "rc": 0}, {**rec, "step": "agent-state-after-x", "rc": 124}]
    (tmp_path / "steps.jsonl").write_text("\n".join(json.dumps(s) for s in steps) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": "c"}))
    s = C.summarize(tmp_path)
    assert s["result"] == "pass" and s["failed_step"] is None, s


def test_the_summary_names_the_failed_step_and_ignores_leftover_rcs(tmp_path):
    steps = [{"step": "install", "rc": 0, "seconds": 3, "first_error": "", "prompts": [], "warnings": ["! w"], "tail": []},
             {"step": "leftover-docker", "rc": 1, "seconds": 1, "first_error": "LEFTOVER volume noomesh_pg",
              "prompts": [], "warnings": [], "tail": []}]
    (tmp_path / "steps.jsonl").write_text("\n".join(json.dumps(s) for s in steps) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": "c", "limits": ["no GPU"]}))
    s = C.summarize(tmp_path)
    assert s["result"] == "pass" and s["warning_count"] == 1
    steps[0]["rc"] = 2
    steps[0]["first_error"] = "curl: (22) 404"
    (tmp_path / "steps.jsonl").write_text("\n".join(json.dumps(s) for s in steps) + "\n")
    s = C.summarize(tmp_path)
    assert s["result"] == "fail" and s["failed_step"] == "install" and s["first_error"] == "curl: (22) 404"
    assert "Not covered here:** no GPU" in (tmp_path / "summary.md").read_text()
    # A mode whose hook is not written yet ran only the box step: "not run", never "pass".
    (tmp_path / "steps.jsonl").write_text(json.dumps({**steps[0], "rc": 0}) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": "c", "not_run": "onboard-interactive.sh not written yet"}))
    assert C.summarize(tmp_path)["result"] == "not run"
    # A red verify is recorded and reported, but the stranger's path goes on.
    v = {"step": "verify", "rc": 1, "seconds": 9, "first_error": "x 2 problems need you", "prompts": [], "warnings": [], "tail": []}
    (tmp_path / "steps.jsonl").write_text(json.dumps({**steps[0], "rc": 0}) + "\n" + json.dumps(v) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": "c"}))
    s = C.summarize(tmp_path)
    assert s["result"] == "pass" and s["verify"] == "x 2 problems need you"
    assert "cluster verify is RED" in (tmp_path / "summary.md").read_text()


# ---- release size math ------------------------------------------------------

def L(d, s):
    return {"digest": d, "size": s}


def test_upgrade_bytes_are_the_layers_the_previous_final_lacks():
    s = SIZE.sizes([L("a", 10), L("b", 20), L("c", 30)], [L("a", 10)], [L("a", 10), L("b", 20)])
    assert s == {"total_bytes": 60, "own_bytes": 50, "upgrade_bytes": 30}
    assert SIZE.sizes([L("a", 10)], None, None) == {"total_bytes": 10, "own_bytes": None, "upgrade_bytes": 10}, \
        "no base: own is unknown (never a guess); no previous final: everything is downloaded"


def test_the_base_is_the_last_from_resolved_to_our_mirrors():
    df = ("ARG DHI_REGISTRY=dhi.io\nFROM --platform=$BUILDPLATFORM ${DHI_REGISTRY}/golang:1.26@sha256:" + "1" * 64
          + " AS b\nFROM ${DHI_REGISTRY}/alpine-base:3.22@sha256:" + "2" * 64 + "\n")
    assert SIZE.resolve_base(SIZE.final_from(df), {}) == "ghcr.io/noomesh/dhi/alpine-base@sha256:" + "2" * 64
    assert SIZE.resolve_base("${HUB_MIRROR}/library/python:3.12-slim@sha256:" + "3" * 64, {}) == \
        "ghcr.io/noomesh/mirror/library/python@sha256:" + "3" * 64
    bases = {"deps-core": "sha256:" + "4" * 64}
    assert SIZE.resolve_base("${DEPS_CORE}", bases) == "ghcr.io/noomesh/dhi/deps-core@sha256:" + "4" * 64
    assert SIZE.resolve_base("${DEPS_BASE}", bases) is None
    assert SIZE.resolve_base("python:3.12", {}) is None, "an unpinned base is not resolved by name"
    assert SIZE.parse_lock("# stack v1\ngateway@sha256:" + "a" * 64 + "\nsource:trellion@abc\n") == \
        {"gateway": "sha256:" + "a" * 64}


def test_the_workflow_is_hosted_only_reports_only_and_reachable_from_any_tree():
    import yaml
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "install-matrix.yml").read_text())
    on = doc[True]
    assert on["push"]["branches"] == ["ci/install-matrix/**"], "must never match the mutant branches"
    assert "schedule" in on and "workflow_dispatch" in on
    assert doc["permissions"] == {"contents": "read"}
    text = (ROOT / ".github" / "workflows" / "install-matrix.yml").read_text()
    assert "secrets." not in text, "a cell runs our released installer: it gets no secret"
    cells = {r["cell"]: r for r in doc["jobs"]["cell"]["strategy"]["matrix"]["include"]}
    assert cells["ubuntu-24.04-amd64-default"]["model"] == "default", "the stranger's default is tested as shipped"
    assert {r["runner"] for r in cells.values()} >= {"ubuntu-22.04", "ubuntu-24.04", "ubuntu-22.04-arm",
                                                     "ubuntu-24.04-arm", "macos-15"}
    assert os.access(ROOT / "scripts" / "install-cell" / "run.sh", os.X_OK)


def test_a_failed_step_ends_the_cell_and_tears_down_at_most_once(tmp_path):
    # Run 1 (2026-11-12): `finish` did not exit, so after the first failure
    # every later step ran and the teardown repeated after each one.
    import shutil
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "curl").write_text('#!/bin/sh\necho "curl: (56) The requested URL returned error: 403" >&2\nexit 56\n')
    (bin_ / "curl").chmod(0o755)
    env = {"PATH": f"{bin_}:/usr/bin:/bin", "HOME": str(tmp_path / "home"), "OUT": str(tmp_path / "out"),
           "CELL": "t", "RUNNER": "r", "SCOPE": "full"}
    (tmp_path / "home").mkdir()
    assert shutil.which("noo", path=env["PATH"]) is None
    r = subprocess.run(["bash", str(ROOT / "scripts/install-cell/run.sh")], env=env, capture_output=True, text=True,
                       timeout=120)
    steps = [json.loads(l)["step"] for l in (tmp_path / "out" / "steps.jsonl").read_text().splitlines()]
    assert r.returncode == 1, r.stdout[-2000:] + r.stderr[-2000:]
    # The README's line downloads THEN runs (#1058), so a failed download
    # fails the install step itself; nothing after it runs.
    # ...apart from the node agent's state, dumped after the failed step.
    assert steps == ["box", "install", "agent-state-after-install"], steps
    s = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert s["result"] == "fail" and s["failed_step"] == "install"


def test_the_size_report_runs_end_to_end_on_a_faked_registry(tmp_path, monkeypatch, capsys):
    # Run 2 (2026-11-12): a local named `repo` shadowed repo() and main()
    # died after every unit had passed. Drive main() whole, faking only the
    # transport (gh, git, the registry).
    d = lambda c: "sha256:" + c * 64  # noqa: E731
    lock_new = f"gateway@{d('a')}\nollama@{d('b')}\n"
    lock_old = f"gateway@{d('c')}\nollama@{d('b')}\n"
    index = lambda m: {"manifests": [{"digest": m, "platform": {"os": "linux", "architecture": "amd64"}}]}  # noqa: E731
    man = {d("1"): {"layers": [L("base", 10), L("g-new", 20)]},
           d("2"): {"layers": [L("base", 10), L("g-old", 25)]},
           d("3"): {"layers": [L("o", 100)]},
           d("9"): {"layers": [L("base", 10)]}}
    idx = {d("a"): index(d("1")), d("c"): index(d("2")), d("b"): index(d("3")), d("8"): index(d("9"))}
    table = {"images": {"gateway": {"dockerfile": "docker/Dockerfile.gateway-rust"},
                        "ollama": {"dockerfile": "docker/Dockerfile.ollama"}}}

    def sh(*cmd):
        if cmd[:3] == ("gh", "release", "download"):
            return lock_new if cmd[3] == "stack-v2.0.0" and cmd[-3].endswith(".lock") else \
                (lock_old if cmd[-3].endswith(".lock") else "")
        if cmd[:3] == ("gh", "release", "view"):
            return json.dumps({"assets": [{"name": "noo-x", "size": 9_000_000}, {"name": "noo-x.sha256", "size": 90}]})
        if cmd[:2] == ("git", "show"):
            if cmd[2].endswith("release-image-inputs.json"):
                return json.dumps(table)
            return "FROM ${DHI_REGISTRY}/python:3.12@" + d("8") + "\n" if "gateway" in cmd[2] else "FROM scratch\n"
        raise AssertionError(cmd)

    monkeypatch.setattr(SIZE, "sh", sh)
    monkeypatch.setattr(SIZE, "finals", lambda prefix: ["stack-v2.0.0", "stack-v1.0.0"])
    monkeypatch.setattr(SIZE, "repo", lambda: "o/r")
    monkeypatch.setattr(SIZE, "inspect_raw", lambda ref: idx.get(ref.split("@", 1)[1]) or man[ref.split("@", 1)[1]])
    out = tmp_path / "size.json"
    assert SIZE.main(["--json", str(out)]) == 0
    rep = json.loads(out.read_text())
    rows = {r["image"]: r for r in rep["images"]}
    assert rep["prev"] == "stack-v1.0.0"
    assert rows["gateway"]["total_bytes"] == 30 and rows["gateway"]["own_bytes"] == 20 \
        and rows["gateway"]["upgrade_bytes"] == 20
    assert rows["ollama"]["upgrade_bytes"] == 0 and rows["ollama"]["own_bytes"] is None, "unresolvable base: '?'"
    assert rep["cli_assets"] == {"noo-x": 9_000_000}


def test_cleanup_is_skipped_when_docker_is_unreachable_as_the_cell_user(tmp_path):
    # fa, run 43157286042: offboard without docker access removed the data
    # root from under running containers. The harness never offboards then.
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    td = text[text.index("teardown() {"):text.index("\n}\n", text.index("teardown() {"))]
    probe = td.index("if ! docker info >/dev/null 2>&1; then")
    assert probe < td.index("noo offboard --uninstall -y") and "cleanup skipped: docker unreachable as" in td
    assert td.index("return 0", probe) < td.index("noo offboard --uninstall -y"), "the skip returns before any cleanup step"


def test_a_probe_is_reported_on_its_own_and_never_fails_the_cell(tmp_path):
    ok = {"step": "first-answer", "rc": 0, "seconds": 9, "first_error": "", "prompts": [], "warnings": [], "tail": []}
    probe = {"step": "probe-offboard-without-docker", "rc": 1, "seconds": 3,
             "first_error": "PROBE FAIL: ~/.noo is gone", "prompts": [], "warnings": [], "tail": []}
    (tmp_path / "steps.jsonl").write_text(json.dumps(ok) + "\n" + json.dumps(probe) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": "c"}))
    s = C.summarize(tmp_path)
    assert s["result"] == "pass" and s["probes"] == {"probe-offboard-without-docker": "PROBE FAIL: ~/.noo is gone"}
    assert "Probe `probe-offboard-without-docker`: FAIL" in (tmp_path / "summary.md").read_text()
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    assert text.index("step probe-offboard-without-docker") < text.index("\nteardown\nfinish"), "before the real teardown"
    assert "--clear-groups" in text, "the probe must really drop the docker group"


def test_a_failed_probe_skips_the_cleanup_of_the_box_it_altered():
    # Run 4: the offboard probe wiped the box (as fa predicted on 0.6.23),
    # the box then read as a node, and the real uninstall refused.
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    assert "[ \"$ok\" = 1 ]' || PROBE_ALTERED=1" in text, "a failed probe marks the box altered"
    td = text[text.index("teardown() {"):text.index("\n}\n", text.index("teardown() {"))]
    skip = td.index('if [ "${PROBE_ALTERED:-0}" = 1 ]; then')
    assert skip < td.index("noo offboard --uninstall -y") and td.index("return 0", skip) < td.index("noo offboard --uninstall -y")
    assert "noo models switch \"$TINY_MODEL\" --backend ollama --yes" in text, "non-interactive switch needs --yes"


def test_the_self_agent_diagnostics_read_only_the_named_env_keys():
    # The env file holds the agent's token: the probe selects keys, never cats.
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    d = text[text.index("step probe-self-agent-diagnostics"):text.index("true'", text.index("step probe-self-agent-diagnostics"))]
    assert 'grep -E "^(NATS_URL|NOO_GATEWAY_URL|CONTROLLER_URL|NODE_ID)=" /etc/noo-node-agent.env' in d
    assert "cat /etc/noo-node-agent.env" not in d and "TOKEN" not in d


def test_the_cell_saves_verify_as_json_after_verify():
    """cf (#1069): passing verify rows are readable from the artifacts. The JSON
    run is a probe (never the failed step), after the real verify, before the
    first answer, and goes through step() (redacted, scanned, uploaded)."""
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    verify = text.index("step verify 900 -- bash -c 'fresh cluster verify --wait'")
    probe = text.index("step probe-verify-json 300 -- bash -c 'fresh --json cluster verify'\n")
    answer = text.index("step first-answer ")
    assert verify < probe < answer, (verify, probe, answer)


def test_a_driver_loop_is_the_first_error_not_the_pre_install_docker_check(tmp_path):
    # rc.4 literal cell: first_error was "✗ docker: MISSING" (onboard's normal
    # pre-install check), not the loop that ended the step.
    log = tmp_path / "onboard-literal.log"
    log.write_text("  ✗ docker: MISSING — Runs all Noomesh services\n  ✓ curl: curl 8.5.0\n"
                   + "  Admin password: \nPROMPT: Admin password:\nANSWER: enter\n\n  (a value is required)\n" * 3
                   + "DRIVER: LOOP: the same prompt answered 6 times in a row with 'enter'\n")
    e = C.record("onboard-literal", 2, 73, str(log))["first_error"]
    assert e.startswith("DRIVER: LOOP"), e


def test_a_masked_value_beside_non_ascii_text_passes_the_upload_scan(tmp_path):
    # rc.3 literal cell: "age key: [REDACTED] — …" JSON-escaped to "—",
    # which the scan read as the key's 6-character value and withheld the artifact.
    log = tmp_path / "onboard.log"
    log.write_text(_redact("  ✓ Secrets encrypted at rest (SOPS+age). BACK UP your age key: AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQ — it is the root of trust.\n"))
    assert "AGE-SECRET-KEY" not in log.read_text()
    out = subprocess.run([sys.executable, str(CELL), "record", "onboard", "1", "3", str(log)],
                         capture_output=True, text=True, encoding="utf-8", check=True).stdout
    assert "\\u2014" not in out and "—" in out, "the record keeps the em dash as text"
    (tmp_path / "up").mkdir()
    (tmp_path / "up" / "steps.jsonl").write_text(out, encoding="utf-8")
    r = subprocess.run([sys.executable, str(CELL), "scan", str(tmp_path / "up")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_verify_runs_from_a_fresh_login_and_one_probe_keeps_the_old_shell():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    assert "step verify 900 -- bash -c 'fresh cluster verify --wait'" in text
    assert "step probe-verify-json 300 -- bash -c 'fresh --json cluster verify'" in text
    assert 'sudo -iu "$(id -un)" -- "$NOO_BIN" "$@"' in text, "a docker=none cell's verify is a new login session"
    old = text[text.index("step probe-verify-old-shell"):]
    old = old[:old.index("\nfi\n")]
    assert "fresh" not in old and "noo --json cluster verify" in old, "the old-shell probe must not log in again"
    assert "not-judged-with-docker-remedy" in old


def test_the_restart_probe_runs_20_only_on_the_22_04_cell_and_offboard_checks_with_sudo():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    assert 'NETNS_RESTARTS=5; [ "$CELL" = ubuntu-22.04-amd64 ] && NETNS_RESTARTS=20' in text
    probe = text[text.index("step probe-docker-restart-namespace-joiners"):]
    probe = probe[:probe.index("\n  true'")]
    assert 'seq 1 "$NETNS_RESTARTS"' in probe and "seq 1 20" not in probe
    off = text[text.index("step probe-offboard-without-docker"):]
    assert "sudo docker ps -q --filter name=noo-gateway" in off
    assert "\n  docker ps -q --filter name=noo-gateway" not in off


def test_the_rag_probe_asks_the_pages_query_then_three_chat_paths_and_is_never_judged():
    # general 11-13: rc.6 run 43487245793 showed `noo chat` does not return an
    # ingested document while `noo rag query` does; the page now proves the doc
    # with the query only. The probe reads that query line from the page and
    # asks the same question on noo chat, noo inference agent (/api/agent/run,
    # the MCP noo_agentic_inference route) and the console socket.
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    page = ROOT / "docs/getting-started/first-chat.md"
    lines = text[text.index('RAG_QUERY_LINE="$(sed -n '):]
    lines = lines[:lines.index("\nexport RAG_QUERY_LINE")]
    got = subprocess.run(
        ["bash", "-c", lines.replace('"$RAG_DOC_PAGE"', f"'{page}'") + '\nprintf "%s|%s" "$RAG_QUERY_LINE" "$RAG_CHAT_LINE"'],
        capture_output=True, text=True, check=True).stdout
    query, chat = got.split("|")
    assert "anything.md" in query and f'noo rag query "{query}"' in page.read_text()
    assert "noo chat --message" not in page.read_text().split("your own document")[1].split("## ")[0], \
        "the page proves the document with noo rag query, not noo chat"
    assert chat == "summarise what you know from anything.md"
    probe = text[text.index("step probe-rag-chat 1500"):]
    probe = probe[:probe.index("\n  true'")]
    ingest = probe.index('\n  noo rag ingest "$HOME/notes/anything.md" 2>&1')
    wait = probe.index('if noo rag query "$RAG_QUERY_LINE" 2>&1 | grep -qiE "$fact"; then indexed=yes')
    ask = probe.index("for path in chat agent console; do")
    assert ingest < wait < ask
    assert 'chat) out="$(noo chat --message "$RAG_CHAT_LINE" 2>&1)"' in probe
    assert 'agent) out="$(timeout 300 noo inference agent "$RAG_CHAT_LINE" 2>&1)"' in probe
    assert 'console) out="$(timeout 330 python3 -I "$RAG_WS_CHAT" "$RAG_CHAT_LINE" 2>&1)"' in probe
    assert 'fact="14(th)? (of )?march|ZIRCON-4471|kestrel"' in probe
    assert 'if printf "%s" "$out" | grep -qiE "$fact"; then got=yes' in probe
    assert "RAG PROBE: $path returned the fact=$got" in probe and "exit 1" not in probe
    wf = (ROOT / ".github/workflows/install-matrix.yml").read_text()
    assert wf.count("docs/getting-started/first-chat.md") >= 2, "both jobs check the page out"


def _pty():
    return _load("onboard_pty", ROOT / "scripts/install-cell/onboard_pty.py")


def test_the_literal_pass_types_what_the_install_doc_says_and_enter_elsewhere():
    # general 11-14: stranger-24.04-literal was a permanent red (Enter at the
    # admin password, six times). The doc now names every prompt Enter cannot
    # pass, and the literal pass follows the doc, not a list of its own.
    d = _pty()
    rows = d.doc_answers((ROOT / "docs/getting-started/install.md").read_text())
    want = {
        "Admin password:": ("PW", "typed <password> (the install doc's table)"),
        "Confirm password:": ("PW", "typed <password> (the install doc's table)"),
        "Stored both in a password manager OFF this machine [y/N]:": ("y", "typed y (the install doc's table)"),
        "Tailscale is not installed. Install it now (official installer, may prompt for sudo)? [Y/n]:":
            ("n", "typed n (the install doc's table)"),
        "Join your tailnet now? (runs `tailscale up`; opens a login link where you sign in) [Y/n]:":
            ("n", "typed n (the install doc's table)"),
        "Admin username [admin]:": ("", "enter"),
        "Anthropic API key (blank to skip):": ("", "enter"),
        # Documented, and Enter is its answer: a new install is lean (No).
        "Install dashboards, log search and request traces (Grafana, Loki, Tempo; about 250 MiB idle)? [y/N]:":
            ("", "enter"),
    }
    for prompt, expected in want.items():
        assert d.answer(prompt, "literal", "PW", rows) == expected, prompt
    # The attentive pass is unchanged and does not read the doc.
    assert d.answer("Admin password:", "attentive", "PW") == ("PW", "typed <password>")


def test_a_literal_pass_without_the_doc_table_stops_with_a_driver_error(tmp_path):
    empty = tmp_path / "install.md"
    empty.write_text("# Install\n\nRun noo onboard.\n")
    p = subprocess.run([sys.executable, str(ROOT / "scripts/install-cell/onboard_pty.py"), "--pass", "literal",
                        "--doc", str(empty), "--", "true"], capture_output=True, text=True)
    assert p.returncode == 5 and "DRIVER: the install doc has no 'What the wizard asks you' table" in p.stdout


def _refusal_step():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    body = text[text.index("step onboard-refuses 600 -- sh -c '") + len("step onboard-refuses 600 -- sh -c '"):]
    return body[:body.index("'\n    teardown")]


REFUSAL = ("  x this is a Linux arm64 (aarch64) machine: a controller needs Linux on x86_64 (amd64) today. "
           "The controller's images (...) are published for amd64 only. This machine can join an amd64 "
           "controller as a node instead: see docs/getting-started/supported-hardware.md.")


def _refuse(tmp_path, out, rc, containers=0):
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    (tmp_path / "out.txt").write_text(out + "\n")
    (fake / "noo").write_text(f"#!/bin/sh\ncat {tmp_path / 'out.txt'}\nexit {rc}\n")
    (fake / "noo").chmod(0o755)
    (fake / "docker").write_text("#!/bin/sh\n" + "".join("echo c%d\n" % i for i in range(containers)))
    (fake / "docker").chmod(0o755)
    p = subprocess.run(["sh", "-c", _refusal_step()], env={"PATH": f"{fake}:/usr/bin:/bin"}, capture_output=True, text=True)
    return p.returncode, p.stdout


def test_an_arm64_cell_passes_on_a_clean_refusal_and_fails_on_anything_else(tmp_path):
    rc, out = _refuse(tmp_path, REFUSAL, 1)
    assert rc == 0 and "REFUSAL OK" in out, out
    rc, out = _refuse(tmp_path, REFUSAL, 0)
    assert rc == 1 and "exited 0 on a machine it must refuse" in out
    rc, out = _refuse(tmp_path, "error: something else broke", 1)
    assert rc == 1 and "does not name the reason" in out
    rc, out = _refuse(tmp_path, REFUSAL.replace("can join an amd64 controller as a node instead", "cannot be used"), 1)
    assert rc == 1 and "does not name the way on" in out
    rc, out = _refuse(tmp_path, REFUSAL, 1, containers=2)
    assert rc == 1 and "left 2 noo- container(s)" in out


def test_the_arm64_rows_expect_the_refusal_and_the_doc_is_checked_out():
    wf = (ROOT / ".github/workflows/install-matrix.yml").read_text()
    for cell in ("ubuntu-24.04-arm64", "ubuntu-22.04-arm64"):
        line = next(l for l in wf.splitlines() if f"cell: {cell}," in l)
        assert "expect: refusal" in line, line
    assert "EXPECT: ${{ matrix.expect || '' }}" in wf
    assert wf.count("docs/getting-started/install.md") >= 2, "the literal pass reads the install doc"
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    assert text.index('if [ "${EXPECT:-}" = refusal ]; then') < text.index('if [ "$ONBOARD" = interactive ]; then')


def test_the_console_chat_client_finds_the_cluster_ca_where_the_cli_does(tmp_path):
    ws = _load("ws_chat_ca", ROOT / "scripts/install-cell/ws_chat.py")
    (tmp_path / ".noo").mkdir()
    (tmp_path / ".noo" / ".env").write_text("X=1\nNOO_TLS_CA=/srv/noo/pki/ca.crt\n")
    got = ws.cluster_ca_candidates({}, str(tmp_path))
    assert got == [str(tmp_path / ".config/mesh/pki/ca.crt"), "/srv/noo/pki/ca.crt", "/etc/noo/pki/ca.crt"], got
    got = ws.cluster_ca_candidates({"NOO_TLS_CA": "/a/ca.crt", "NOO_PKI_DIR": "/p"}, str(tmp_path))
    assert got[:2] == ["/a/ca.crt", "/p/ca.crt"], got


def test_the_console_chat_client_frames_and_reads_what_the_gateway_sends():
    ws = _load("ws_chat", ROOT / "scripts/install-cell/ws_chat.py")
    import socket
    a, b = socket.socketpair()
    try:
        a.sendall(ws.frame('{"prompt": "' + "x" * 300 + '"}'))
        raw = b.recv(1024)
        assert raw[0] == 0x81 and raw[1] == 0x80 | 126, "a masked text frame, 16-bit length"
        n = int.from_bytes(raw[2:4], "big"); mask = raw[4:8]
        body = bytes(c ^ mask[k % 4] for k, c in enumerate(raw[8:8 + n]))
        assert json.loads(body)["prompt"] == "x" * 300
        b.sendall(b"\x81" + bytes([5]) + b"hello")
        assert ws.read_frame(a) == (1, b"hello")
    finally:
        a.close(); b.close()

def test_the_offboard_probe_is_skipped_by_name_on_a_root_cell():
    # rc.5 matrix run 1, WSL2 (root): root reaches docker by uid, so "a shell
    # without the docker group" cannot be made; offboard -y rightly wiped the
    # box and the probe reported FAIL. On uid 0 it is skipped, saying why.
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    i = text.index('if [ "$(id -u)" = 0 ]; then\nstep probe-offboard-without-docker 30')
    block = text[i:text.index("\nfi\n", i)]
    assert "PROBE SKIPPED: this cell runs as root (uid 0)" in block
    assert "\nelse\nstep probe-offboard-without-docker 600 -- sh -c '" in block, "the real probe still runs for a non-root cell"


def _run_sh_var(name: str) -> str:
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    m = re.search(r"^%s='([^']*)'$" % name, text, re.M)
    assert m, name
    return m.group(1)


def test_the_first_answer_step_asks_the_prompt_the_doc_gives():
    # One source: the cell reads docs/getting-started/first-chat.md's first
    # `noo chat --message "…"` line; the workflow checks that file out.
    doc = (ROOT / "docs/getting-started/first-chat.md").read_text()
    r = subprocess.run(["sed", "-n", r's/^noo chat --message "\(.*\)"$/\1/p'], input=doc, capture_output=True, text=True)
    first = r.stdout.splitlines()[0]
    assert first == "Say hello, then give me two short tips for keeping a home server healthy.", first
    assert "this machine" not in first.lower(), "a small model cannot see the host"
    wf = (ROOT / ".github/workflows/install-matrix.yml").read_text()
    assert wf.count("docs/getting-started/first-chat.md") == 2, "both jobs check the doc out"
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    assert 'out="$(noo chat --message "$FIRST_PROMPT")"' in text


@pytest.mark.parametrize("answer, bad", [
    ("Please provide an image or description of the machine you are referring to.", True),  # gemma4:e2b, rc.4-rc.6
    ("Could you clarify which machine you mean?", True),
    ("I cannot see your computer, so I can't answer that.", True),
    ("I don't have access to your system.", True),
    ("Hello! How can I help you keep your home server healthy?", True),  # qwen2.5:0.5b, rc.6 branch run
    ("Hello! I'm Qwen. Do you have any specific questions or topics you'd like to discuss?", True),
    ("Hi! What would you like to know?", True),
    ("Hello! 1. Keep the OS and packages updated. 2. Watch disk space and back up regularly.", False),
    ("Hi there. Tip one: monitor temperatures. Tip two: test your backups.", False),
    # gemma's real shape, ending politely: the list makes it an answer
    ("Hello!\nHere are two tips:\n1. **Backups:** automate them.\n2. **Updates:** apply them.\nHow can I help you further?", False),
])
def test_a_request_for_more_input_or_a_refusal_is_not_an_answer(answer, bad):
    # The step's own decision, run as written: strong pattern, or a deflection
    # in an answer that lists nothing.
    script = (
        'out="$1"\n'
        'listed="$(printf "%s\\n" "$out" | grep -cE "^[[:space:]]*([0-9]+[.)]|[-*]|•)[[:space:]]")"\n'
        'if printf "%s" "$out" | grep -qiE "$NA" || { [ "$listed" = 0 ] && printf "%s" "$out" | grep -qiE "$DF"; }; then exit 0; fi\n'
        'exit 1\n'
    )
    env = {**os.environ, "NA": _run_sh_var("FIRST_ANSWER_NOT_AN_ANSWER"), "DF": _run_sh_var("FIRST_ANSWER_DEFLECTION")}
    r = subprocess.run(["sh", "-c", script, "t", answer], env=env)
    assert (r.returncode == 0) is bad, (answer, r.returncode)
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    assert '{ [ "$listed" = 0 ] && printf "%s" "$out" | grep -qiE "$FIRST_ANSWER_DEFLECTION"; }' in text


def test_first_chat_never_asks_the_chat_model_about_cluster_state():
    # rc.6 branch run 43482649578: asked "which nodes and models do you have
    # right now?", gemma4:e2b answered about itself ("I am Gemma 4 … I don't
    # have a list of physical nodes") while `noo cluster status` showed the
    # node running ollama:gemma4:e2b. The chat path does not read cluster
    # state, so the page asks the CLI.
    doc = (ROOT / "docs/getting-started/first-chat.md").read_text()
    asks = [l for l in doc.splitlines() if l.startswith('noo chat --message "')]
    assert not any(re.search(r"\b(nodes?|models?|cluster|gpus?)\b.*(have|running|right now)", l, re.I) for l in asks), asks
    assert "\nnoo cluster status\n" in doc



def test_only_the_default_model_fails_on_a_non_answer_and_a_tiny_cell_notes_it():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    i = text.index("step first-answer 1800")
    block = text[i:text.index("' || fail_onboarded", i)]
    fail = block.index('FIRST-ANSWER FAIL: the model asked for more input')
    assert 'if [ "$MODEL" = default ]; then' in block[:fail], "the FAIL is gated on the product default model"
    assert "FIRST-ANSWER NOTE: the tiny test model ($TINY_MODEL)" in block and "not a product verdict" in block
    assert "export FIRST_PROMPT FIRST_ANSWER_NOT_AN_ANSWER FIRST_ANSWER_DEFLECTION MODEL TINY_MODEL" in text
