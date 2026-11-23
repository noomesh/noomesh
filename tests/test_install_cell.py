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
    assert call < text.index("step health 600"), "before anything else moves the stack"
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
    # Since noomesh#1164 `noo chat` looks in the knowledge base, so the page may
    # show a chat line about the document; the cell then asks exactly that
    # line (and rag-chat judges it), else its own default.
    import re
    shown = re.findall(r'^noo chat --message "(.*anything\.md.*)"$', page.read_text(), re.M)
    assert chat == (shown[0] if shown else "summarise what you know from anything.md")
    probe = text[text.index("step probe-rag-chat 1500"):]
    probe = probe[:probe.index("\n  true'")]
    ingest = probe.index('\n  noo rag ingest "$HOME/notes/anything.md" 2>&1')
    wait = probe.index('if noo rag query "$RAG_QUERY_LINE" 2>&1 | grep -qiE "$fact"; then indexed=yes')
    ask = probe.index("for path in chat agent console; do")
    assert ingest < wait < ask
    assert 'chat) c0="$(date +%s)"; out="$(noo chat --message "$RAG_CHAT_LINE" 2>&1)"' in probe
    assert 'agent) a0="$(date +%s)"; out="$(timeout 300 noo inference agent "$RAG_CHAT_LINE" 2>&1)"; arc=$?' in probe
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
        # Documented with Enter as its answer: the cell explains the Docker hold
        # (#1555), and none of its words may be read as text to type.
        "Install the missing prerequisites now? (uses sudo) [Y/n]:": ("", "enter"),
        "Anthropic API key (blank to skip):": ("", "enter"),
        # Documented, and Enter is its answer: a new install is lean (No).
        "Install dashboards, log search and request traces (Grafana, Loki, Tempo; about 250 MiB idle)? [y/N]:":
            ("", "enter"),
    }
    for prompt, expected in want.items():
        assert d.answer(prompt, "literal", "PW", rows) == expected, prompt
    # The attentive pass is unchanged and does not read the doc.
    assert d.answer("Admin password:", "attentive", "PW") == ("PW", "typed <password>")


def test_every_answer_the_install_doc_table_gives_is_y_n_or_a_password():
    # rc.2's stranger-24.04-literal looped six times: a row whose answer is
    # Enter gained a backticked command in its explanation, and the literal
    # pass reads the first backticked token of an answer cell as the text to
    # type. An answer cell may name only `y`, `n` or a password; anything else
    # it explains goes in plain words or below the table.
    d = _pty()
    rows = d.doc_answers((ROOT / "docs/getting-started/install.md").read_text())
    assert rows, "the install doc's prompt table was not found"
    odd = [(frag, ans) for frag, ans in rows if ans not in ("y", "n", "<password>")]
    assert not odd, f"an answer cell's first backticked token is not y, n or a password: {odd}"


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


def _rag_chat_step():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    body = text[text.index("step rag-chat 60 -- sh -c '") + len("step rag-chat 60 -- sh -c '"):]
    return body[:body.index("' || fail_onboarded")]


def _judge(tmp_path, verdict, route="yes", model="default"):
    v = tmp_path / "verdict"
    if verdict is not None:
        v.write_text(verdict + "\n")
    env = {"PATH": "/usr/bin:/bin", "RAG_VERDICT": str(v), "RAG_CHAT_ROUTE": route, "MODEL": model, "TINY_MODEL": "qwen2.5:0.5b"}
    p = subprocess.run(["sh", "-c", _rag_chat_step().replace("\'\"\'\"\'", "'")], env=env, capture_output=True, text=True)
    return p.returncode, p.stdout


def test_the_rag_chat_line_is_judged_only_on_a_build_with_the_coordinator_route_and_a_real_model(tmp_path):
    # general 11-14: from noomesh#1164 `noo chat` retrieves; the page's chat
    # line must then bring the fact back. Not on an older build, and only a
    # NOTE on a tiny-model cell.
    assert _judge(tmp_path, "got=no indexed=yes")[0] == 1, "the new route, the default model, no fact: FAIL"
    rc, out = _judge(tmp_path, "got=no indexed=yes")
    assert "RAG-CHAT FAIL" in out
    rc, out = _judge(tmp_path, "got=yes indexed=yes")
    assert rc == 0 and "RAG-CHAT PASS" in out
    rc, out = _judge(tmp_path, "got=no indexed=yes", route="no")
    assert rc == 0 and "not judged: this build has no POST /api/inference/chat" in out, "an older rc never goes red"
    rc, out = _judge(tmp_path, "got=no indexed=yes", model="tiny")
    assert rc == 0 and "RAG-CHAT NOTE" in out and "not a product verdict" in out
    rc, out = _judge(tmp_path, "got=no indexed=no")
    assert rc == 0 and "not judged: the index never returned the fact" in out
    rc, out = _judge(tmp_path, None)
    assert rc == 0 and "not judged" in out, "no verdict (the probe never reached chat) is not a product FAIL"
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    assert text.index("step probe-rag-chat 1500") < text.index("step rag-chat 60"), "judged after the probe wrote its verdict"
    assert '[ "$path" = chat ] && echo "got=$got indexed=$indexed" > "$RAG_VERDICT"' in text


def _detect(tmp_path, noo_names_route, code):
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    block = text[text.index("RAG_CHAT_ROUTE=no\n"):text.index("export RAG_CHAT_ROUTE")]
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    (fake / "noo").write_text("#!/bin/sh\n# " + ("POST /api/inference/chat" if noo_names_route else "/api/inference/stream") + "\n")
    (fake / "noo").chmod(0o755)
    (fake / "python3").write_text(f"#!/bin/sh\necho '{code}'\n")
    (fake / "python3").chmod(0o755)
    p = subprocess.run(["bash", "-c", block + 'echo "$RAG_CHAT_ROUTE"'],
                       env={"PATH": f"{fake}:/usr/bin:/bin", "RAG_WS_CHAT": "x"}, capture_output=True, text=True)
    return p.stdout.strip()


def test_the_coordinator_route_is_detected_from_both_the_cli_and_the_gateway(tmp_path):
    assert _detect(tmp_path, True, "422") == "yes"
    assert _detect(tmp_path, True, "405") == "yes"
    assert _detect(tmp_path, True, "404") == "no", "the gateway has no such route"
    assert _detect(tmp_path, False, "422") == "no", "the CLI under test still speaks the raw stream"
    assert _detect(tmp_path, True, "unknown (URLError)") == "no", "cannot tell: not judged"


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


def test_first_answer_is_install_to_answer_not_the_probes_before_it():
    # general, rc.1 run 43642041751: the default cell read 2,792 s because the
    # memory baseline and the 40-minute idle series run before first-answer.
    cell = _load("cell_fa", ROOT / "scripts/install-cell/cell.py")
    steps = [{"step": n, "seconds": s} for n, s in [
        ("install", 2), ("onboard", 219), ("stack-start", 25), ("verify", 33), ("probe-verify-json", 4),
        ("probe-memory-baseline", 63), ("probe-idle-t10", 602), ("probe-idle-t40", 1799),
        ("idle-chat-unloaded", 1), ("first-answer", 44), ("probe-coldload", 48)]]
    assert cell.first_answer_times(steps, 2792) == (2792 - 2469, 2469)
    assert cell.first_answer_times(steps[:4] + steps[9:], 327) == (327, 0), "no probes before it: unchanged"
    assert cell.first_answer_times(steps, None) == (None, 0)
    assert cell.first_answer_times([{"step": "onboard", "seconds": 5}], 90) == (90, 0), "no first-answer step: the wall number"


def test_the_summary_reports_both_numbers(tmp_path):
    cell = _load("cell_fa2", ROOT / "scripts/install-cell/cell.py")
    import json as _j
    rows = [("install", 2), ("probe-idle-t10", 600), ("first-answer", 40)]
    (tmp_path / "steps.jsonl").write_text("".join(
        _j.dumps({"step": n, "rc": 0, "seconds": s, "first_error": "", "warnings": [], "prompts": []}) + "\n" for n, s in rows))
    (tmp_path / "meta.json").write_text(_j.dumps({"cell": "c", "first_answer_s": 700}))
    out = cell.summarize(tmp_path)
    assert out["first_answer_s"] == 100 and out["first_answer_wall_s"] == 700 and out["probe_wait_before_first_answer_s"] == 600
    md = (tmp_path / "summary.md").read_text()
    assert "first answer 100 s after the cell started (not counting 600 s of probes before it; 700 s on the wall clock)" in md


def _ctx_wrapper():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    body = text[text.index("judged_ctx() {"):]
    lead = 'step "$name" "$t" -- sh -c \''
    body = body[body.index(lead) + len(lead):]
    return body[:body.index("' \\\n        context-fit")]


def test_a_context_fit_not_judged_never_fails_the_cell(tmp_path):
    # harness's context_fit.py (noomesh#1217): 0 PASS, 1 FAIL, 2 NOT JUDGED.
    # On rc.1 and older every judge is NOT JUDGED and the cell must stay green.
    fake = tmp_path / "bin"
    fake.mkdir()
    for rc in (0, 1, 2):
        (fake / "python3").write_text(f"#!/bin/sh\nexit {rc}\n")
        (fake / "python3").chmod(0o755)
        p = subprocess.run(["sh", "-c", _ctx_wrapper(), "context-fit", "ctx.py", "running"],
                           env={"PATH": f"{fake}:/usr/bin:/bin"}, capture_output=True, text=True)
        want = {0: 0, 1: 1, 2: 0}[rc]
        assert p.returncode == want, (rc, p.returncode, p.stdout)
        assert ("NOT JUDGED" in p.stdout) == (rc == 2)


def test_the_pinned_context_runs_on_one_cell_after_the_unpinned_judges():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    assert 'CONTEXT_PIN_CELL=stranger-24.04' in text
    i_rag = text.index("step rag-chat 60")
    i_run = text.index("judged_ctx context-fit-running 400 running")
    i_turns = text.index('judged_ctx context-fit-turns 900 turns --out "$OUT/context-fit"')
    i_pin = text.index('if [ "$CELL" = "$CONTEXT_PIN_CELL" ] && [ -f "$CONTEXT_FIT" ]; then')
    assert i_rag < i_run < i_turns < i_pin, "unpinned judges first; the pin changes the chat context for the rest of the cell"
    pinned = text[i_pin:text.index("\nfi\n", i_pin)]
    order = [pinned.index(k) for k in ("--env OLLAMA_CONTEXT_LENGTH=4096", "stack restart --force gateway",
                                        "running --expect-decided 4096", "pinned-check", "doesnt-fit")]
    assert order == sorted(order), "pin, restart (the gateway caches the decided context 600 s), then judge"
    # pinned-running's FAIL is recorded but does not stop the cell, so the
    # pinned-check and doesnt-fit verdicts still come (rc.3 run 43715012498).
    assert "judged_ctx_continue context-fit-pinned-running 400 running --expect-decided 4096" in pinned
    cont = text[text.index("judged_ctx_continue() {"):text.index("\n}\n", text.index("judged_ctx_continue() {"))]
    assert cont.rstrip().endswith("|| true") and "fail_onboarded" not in cont, cont
    assert 'step "$name" 10 -- sh -c \'echo "CONTEXT-FIT: not judged: context_fit.py is not in this tree"\'' in text


def test_the_slots_ab_proves_the_daemon_runs_what_it_set():
    """rc.3 run 43715012498: the slots4 cell's compose_env said 4, the
    launcher kept an earlier value ("1 already set") and the A/B compared one
    slot with one slot. The step now reads the daemon itself and fails unless
    it runs EMBED_SLOTS; every cell prints its own for the other side."""
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    ab = text[text.index("step embed-slots-ab"):text.index("|| fail_onboarded", text.index("step embed-slots-ab"))]
    assert "docker exec noo-ollama-embed printenv OLLAMA_NUM_PARALLEL" in ab, ab
    assert '[ "$got" = "$1" ] || {' in ab and "exit 1; }" in ab, ab
    probe = text[text.index("step probe-embed-slots"):]
    assert "docker exec noo-ollama-embed printenv OLLAMA_NUM_PARALLEL" in probe.split("\n")[0]


def test_the_ollama_verified_probe_reads_the_container_onboard_pulled_into(tmp_path):
    """i1021 (rc.4 printed `(ollama ?)`): the probe read `ollama --version` from
    noo-ollama, but a standalone onboard pulls into noo-ollama-embed. It picks
    the container the way pull_ollama does (NOO_STANDALONE=1 or a
    .noo-standalone marker, else noo-ollama) and prints the version and the
    container on every OLLAMA-VERIFIED line, PASS or FAIL."""
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    start = text.index("onboard_ollama_container() {")
    fn = text[start:text.index("\n}\n", start) + 3]

    def pick(home, standalone=""):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "NOO_STANDALONE": standalone}
        r = subprocess.run(["bash", "-c", fn + "onboard_ollama_container"], env=env, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    plain = tmp_path / "plain"
    plain.mkdir()
    assert pick(plain) == "noo-ollama"
    assert pick(plain, "1") == "noo-ollama-embed"
    one_box = tmp_path / "onebox"
    (one_box / "noomesh").mkdir(parents=True)
    (one_box / "noomesh" / ".noo-standalone").write_text("")
    assert pick(one_box) == "noo-ollama-embed"
    # onboard's own rule, which this mirrors
    steps = (ROOT / "noo-cli/src/onboard/steps.rs").read_text()
    assert 'let target = if standalone { "noo-ollama-embed" } else { "noo-ollama" };' in steps

    probe = text[text.index("step probe-ollama-verified"):]
    probe = probe[:probe.index("\n# PROBE", 1)]
    assert 'oc="$(onboard_ollama_container)"' in probe, probe
    assert "docker exec noo-ollama ollama" not in probe, probe
    assert "export -f onboard_ollama_container" in text
    lines = [ln for ln in probe.splitlines() if "OLLAMA-VERIFIED " in ln]
    assert len(lines) == 2 and all("(ollama ${ov:-?} in $oc)" in ln for ln in lines), lines


# ── the plain start after onboard (recreated.py) ───────────────────────────
RC = _load("install_cell_recreated", ROOT / "scripts" / "install-cell" / "recreated.py")


def _rc_files(tmp_path, before: dict, after: dict):
    b, a = tmp_path / "before", tmp_path / "after"
    b.write_text("".join(f"{n} {i} {s} {d}\n" for n, (i, s, d) in before.items()))
    a.write_text("".join(f"{n} {i} {s} {d}\n" for n, (i, s, d) in after.items()))
    return str(b), str(a)


STACK = {"noo-gateway": ("g1", "gateway", "postgres:service_healthy:false"),
         "noo-postgres": ("p1", "postgres", "-"),
         "noo-trellion": ("t1", "trellion", "gateway:service_started:true,postgres:service_healthy:false")}


def _run_judge(tmp_path, after: dict, *mode: str):
    b, a = _rc_files(tmp_path, STACK, after)
    r = subprocess.run([sys.executable, str(ROOT / "scripts/install-cell/recreated.py"), "judge", "X", b, a, *mode],
                       capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def test_start_idempotent_passes_only_when_no_id_moved(tmp_path):
    assert _run_judge(tmp_path, dict(STACK), "--none") == (0, "X PASS: 0 containers recreated (3 unchanged)")
    moved = dict(STACK, **{"noo-postgres": ("p2", "postgres", "-")})
    assert _run_judge(tmp_path, moved, "--none") == (1, "X FAIL: 1 recreated: noo-postgres")
    gone = {k: v for k, v in STACK.items() if k != "noo-trellion"}
    rc, out = _run_judge(tmp_path, gone, "--none")
    assert rc == 1 and "removed: noo-trellion" in out


def test_start_input_change_allows_only_the_service_and_its_dependents(tmp_path):
    only_gw = dict(STACK, **{"noo-gateway": ("g2", "gateway", "postgres:service_healthy:false")})
    rc, out = _run_judge(tmp_path, only_gw, "--only", "gateway")
    assert rc == 0 and out.startswith("X PASS: only gateway recreated;"), out
    with_dep = dict(only_gw, **{"noo-trellion": ("t2", "trellion", STACK["noo-trellion"][2])})
    rc, out = _run_judge(tmp_path, with_dep, "--only", "gateway")
    assert rc == 0 and "1 that depend on it: noo-trellion" in out, out
    stray = dict(only_gw, **{"noo-postgres": ("p2", "postgres", "-")})
    rc, out = _run_judge(tmp_path, stray, "--only", "gateway")
    assert rc == 1 and "do not depend on gateway: noo-postgres" in out, out
    rc, out = _run_judge(tmp_path, dict(STACK), "--only", "gateway")
    assert rc == 1 and "gateway was not recreated" in out, out


def test_start_recreate_needs_every_container_recreated(tmp_path):
    every = {n: (i + "x", s, d) for n, (i, s, d) in STACK.items()}
    assert _run_judge(tmp_path, every, "--all") == (0, "X PASS: all 3 containers recreated")
    one_kept = dict(every, **{"noo-postgres": STACK["noo-postgres"]})
    assert _run_judge(tmp_path, one_kept, "--all") == (1, "X FAIL: 1 not recreated: noo-postgres")


def test_an_empty_before_is_never_a_pass(tmp_path):
    b, a = _rc_files(tmp_path, {}, {})
    ok, line = RC.judge("X", RC.read(b), RC.read(a), "none")
    assert not ok and "no stack container was recorded" in line


def test_the_stranger_checks_health_and_the_three_start_checks_fail_the_cell():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    health = text.index("step health 600 ")
    assert "step stack-start " not in text, "README step 3 is `noo health`: the wizard leaves the stack running"
    order = [text.index(f"step {n} ") for n in ("start-idempotent", "start-input-change", "start-input-restore",
                                                 "start-recreate", "health-after-starts")]
    assert health < order[0] and order == sorted(order)
    for name, verdict, mode in [("start-idempotent", "START-IDEMPOTENT", "--none"),
                                ("start-input-change", "START-INPUT-CHANGE", "--only gateway"),
                                ("start-recreate", "START-RECREATE", "--all")]:
        body = text[text.index(f"step {name} "):]
        body = body[:body.index("|| fail_onboarded") + len("|| fail_onboarded")]
        assert f"judge {verdict} " in body and body.rstrip().endswith(f"{mode}' _ \"$RC_PY\" \"$OUT\" || fail_onboarded"), name
        assert not name.startswith("probe-"), "a probe never fails the cell"
    assert "noo stack start --recreate" in text[order[3]:order[4]]


def test_a_failed_start_check_is_the_cells_failure(tmp_path):
    rec = {"step": "start-idempotent", "rc": 1, "seconds": 1, "first_error": "START-IDEMPOTENT FAIL: 13 recreated",
           "prompts": [], "warnings": [], "tail": []}
    (tmp_path / "steps.jsonl").write_text(json.dumps(rec) + "\n")
    (tmp_path / "meta.json").write_text("{}")
    out = C.summarize(tmp_path)
    assert out["result"] == "fail" and out["failed_step"] == "start-idempotent"


# ── the upload scan: key=value judged on the line WITH its masks ───────────
# 0.6.27 -> rc.1 upgrade cell, run 44709015537: the applier's summary
# `applied: … node.key=unchanged …` was masked to `node.key=[REDACTED]`, the
# scan stripped the mask, read `node.key= agent-env` and withheld the artifact.
APPLIED = "applied: node.crt=unchanged node.key=unchanged agent-env"


@pytest.mark.parametrize("line", ["key=abcd1234", "key= abcd1234", "token: wxyz5678",
                                  "node.key=[REDACTED] token=wxyz5678",
                                  "token=wxyz5678 node.key=[REDACTED]",
                                  "a=[REDACTED] b: [REDACTED] password=hunter22"])
def test_an_unmasked_key_value_is_a_hit(line):
    assert C.secret_hits(line), line


@pytest.mark.parametrize("line", ["node.key=[REDACTED] agent-env",
                                  "node.key=[REDACTED]  token: [REDACTED]  agent-env",
                                  'password: "[REDACTED]" next'])
def test_a_masked_pair_is_clean(line):
    assert not C.secret_hits(line), (line, C.secret_hits(line))


def test_the_applier_summary_is_redacted_then_clean():
    out = _redact(APPLIED + "\n")
    assert out == "applied: node.crt=unchanged node.key=[REDACTED] agent-env\n", out
    assert not C.secret_hits(out), C.secret_hits(out)


# Every shape the scan detects, in lines a cell could print: the redactor
# masks each, so its output always passes the scan (the release lead).
SHAPE_CORPUS = SECRET_LINES + [
    "key=abcd1234", "key= abcd1234", "token: wxyz5678", APPLIED,
    "applied: a=b node.key=unchanged token=wxyz5678 secret: s3cr3tval",
    'PASSWORD="hunter2222" api_key=ABCDEFGH private-key: zzzz9999',
    "url?token=noo1.QUJDREVGR0hJSktM&x=1 and key=xyz-noo1.abcdef",
    "Bearer " + JWT + " token=" + JWT,
    "x ghp_abcdefghijklmnopqrstuvwxyz0123456789 GHO_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
    "run QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVmZ2hpams= end",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END RSA PRIVATE KEY-----",
    "  NOO_ADMIN_PASSWORD\n  hunter2",
    "secret=[REDACTED]tail key=[REDACTED]",
]


@pytest.mark.parametrize("raw", SHAPE_CORPUS)
def test_redacted_output_always_passes_the_scan(raw):
    assert C.secret_hits(raw), ("the corpus line must be secret-shaped", raw)
    out = _redact(raw + "\n")
    assert not C.secret_hits(out), (raw, out, C.secret_hits(out))


def test_the_redactor_and_the_scan_share_one_shape_list():
    src = CELL.read_text()
    redact = src[src.index("def redact_line"):src.index("def secret_hits")]
    scan = src[src.index("def secret_hits"):src.index("def cmd_run")]
    for k in range(len(C.SECRET_SHAPES)):
        assert f"SECRET_SHAPES[{k}]" in redact, k
    assert "SECRET_SHAPES[:3]" in scan and "SECRET_SHAPES[3].finditer(line)" in scan
    assert len(C.SECRET_SHAPES) == 4


# ── (d) the plain start after a provision (START-AFTER-PROVISION) ──────────
PROV_SNAP = {"noo-gateway": ("g1", "gateway", "nats:service_started:false"),
             "noo-nats": ("n1", "nats", "-"),
             "noo-postgres": ("p1", "postgres", "-")}
PROV_OK = "  bundle carries this node's own NATS credential; 4 users rendered and noo-nats reloaded\n+ applied\n"
START_0 = "  Containers          3 running, 0 recreated\n"
START_NATS = ("  Containers          3 running, 2 recreated\n"
              "    recreated gateway: its compose config or image changed\n"
              "    recreated nats: its inputs changed (config monitoring/nats/users.conf)\n")
NATS_MOVED = dict(PROV_SNAP, **{"noo-nats": ("n2", "nats", "-"), "noo-gateway": ("g2", "gateway", "nats:service_started:false")})


def _after_prov(tmp_path, after, start_log, changed="yes", record="confirmed", start_rc="0", prov_rc="0", prov=PROV_OK):
    tmp_path.mkdir(parents=True, exist_ok=True)
    b, a = _rc_files(tmp_path, PROV_SNAP, after)
    (tmp_path / "start.log").write_text(start_log)
    (tmp_path / "prov.log").write_text(prov)
    r = subprocess.run([sys.executable, str(ROOT / "scripts/install-cell/recreated.py"), "after-provision",
                        "START-AFTER-PROVISION", b, a, str(tmp_path / "start.log"), start_rc, changed, record,
                        str(tmp_path / "prov.log"), prov_rc], capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def test_after_provision_passes_when_nats_is_not_recreated(tmp_path):
    rc, out = _after_prov(tmp_path, dict(PROV_SNAP), START_0)
    assert rc == 0 and out.startswith("START-AFTER-PROVISION PASS: nats not recreated"), out


def test_after_provision_fails_naming_nats_and_its_reason(tmp_path):
    rc, out = _after_prov(tmp_path, NATS_MOVED, START_NATS)
    assert rc == 1 and out.startswith("START-AFTER-PROVISION FAIL: 2 recreated"), out
    assert "noo-nats (recreated nats: its inputs changed (config monitoring/nats/users.conf))" in out, out
    assert "noo-gateway (recreated gateway: its compose config or image changed)" in out, out
    rc, out = _after_prov(tmp_path / "u", NATS_MOVED, START_NATS, record="unconfirmed")
    assert rc == 1 and "(record: unconfirmed)" in out, out


def test_after_provision_notes_an_unchanged_users_conf(tmp_path):
    rc, out = _after_prov(tmp_path, dict(PROV_SNAP), START_0, changed="no")
    assert (rc, out) == (0, "START-AFTER-PROVISION NOTE: users.conf unchanged by the provision; nothing to reload")
    # nothing changed, yet nats moved: that is not a note
    rc, out = _after_prov(tmp_path / "m", NATS_MOVED, START_NATS, changed="no")
    assert rc == 1 and " FAIL: users.conf unchanged by the provision, yet nats was recreated" in out, out


def test_after_provision_notes_a_build_that_records_no_reload(tmp_path):
    rc, out = _after_prov(tmp_path, NATS_MOVED, START_NATS, record="none")
    assert rc == 0 and out.startswith("START-AFTER-PROVISION NOTE: this build does not record nats reloads"), out


def test_after_provision_fails_a_failed_start_or_an_unreadable_users_conf(tmp_path):
    rc, out = _after_prov(tmp_path, dict(PROV_SNAP), "x the stack did not start\n", start_rc="1")
    assert rc == 1 and "FAIL: noo stack start exited 1: x the stack did not start" in out, out
    rc, out = _after_prov(tmp_path / "u", dict(PROV_SNAP), START_0, changed="unknown")
    assert rc == 1 and "users.conf could not be read" in out, out


def test_the_reload_record_is_read_from_the_start_inputs_state(tmp_path):
    st = tmp_path / "state.json"
    rec = lambda: subprocess.run([sys.executable, str(ROOT / "scripts/install-cell/recreated.py"), "reload-record",  # noqa: E731
                                  str(st)], capture_output=True, text=True).stdout.strip()
    assert rec() == "none"
    st.write_text(json.dumps({"version": 1, "services": {}}))
    assert rec() == "none"
    st.write_text(json.dumps({"reloaded": {"nats": {"container": "n1", "paths": {"/i/monitoring/nats/users.conf": None}}}}))
    assert rec() == "unconfirmed"
    st.write_text(json.dumps({"reloaded": {"nats": {"container": "n1", "paths": {"/i/monitoring/nats/users.conf": "ab12"}}}}))
    assert rec() == "confirmed"


# ── the rotation in the default cell (START-AFTER-FORCED-RESTART) ──────────
RESTART_BEFORE = {"noo-gateway": ("g1", "gateway", "-"), "noo-nats": ("n1", "nats", "-"),
                  "noo-worker": ("w1", "worker", "nats:service_started:false"),
                  "noo-trellion": ("t1", "trellion", "gateway:service_started:true")}
RESTARTED = {n: (i + "r", sv, d) for n, (i, sv, d) in RESTART_BEFORE.items()}


def _forced(tmp_path, after, start_log=START_0, start_rc="0", restart_rc="0", restarted=None,
            restart_log="+ stack recreated — the holders now present the new credential\n"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    files = {}
    for k, d in (("b", RESTART_BEFORE), ("r", RESTARTED if restarted is None else restarted), ("a", after)):
        files[k] = tmp_path / k
        files[k].write_text("".join(f"{n} {i} {sv} {dd}\n" for n, (i, sv, dd) in d.items()))
    (tmp_path / "start.log").write_text(start_log)
    (tmp_path / "restart.log").write_text(restart_log)
    r = subprocess.run([sys.executable, str(ROOT / "scripts/install-cell/recreated.py"), "after-forced-restart",
                        "START-AFTER-FORCED-RESTART", str(files["b"]), str(files["r"]), str(files["a"]),
                        str(tmp_path / "start.log"), start_rc, restart_rc, str(tmp_path / "restart.log")],
                       capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def test_forced_restart_passes_when_nothing_it_recreated_moves_again(tmp_path):
    rc, out = _forced(tmp_path, dict(RESTARTED), start_log="  Containers          4 running, 0 recreated\n")
    assert rc == 0 and out.startswith("START-AFTER-FORCED-RESTART PASS: none of the 4 containers"), out
    assert "noo-trellion" in out and "noo-worker" in out and "4 running, 0 recreated" in out, out


def test_forced_restart_fails_naming_worker_and_trellion_with_their_reasons(tmp_path):
    after = dict(RESTARTED, **{"noo-worker": ("w9", "worker", "-"), "noo-trellion": ("t9", "trellion", "-")})
    log = ("  Containers          4 running, 2 recreated\n"
           "    recreated trellion: its compose config or image changed\n"
           "    recreated worker: its inputs changed (secret nats_worker_password)\n")
    rc, out = _forced(tmp_path, after, start_log=log)
    assert rc == 1 and "FAIL: 2 of the 4 containers the --restart recreated were recreated again" in out, out
    assert "noo-worker (recreated worker: its inputs changed (secret nats_worker_password))" in out, out
    assert "noo-trellion (recreated trellion: its compose config or image changed)" in out, out


def test_forced_restart_has_no_note_fallback(tmp_path):
    rc, out = _forced(tmp_path, dict(RESTARTED), restart_rc="1", restart_log="! stack recreate FAILED\n")
    assert rc == 1 and "FAIL: the rotation's --restart exited 1: ! stack recreate FAILED" in out, out
    rc, out = _forced(tmp_path / "s", dict(RESTARTED), start_rc="1", start_log="x up failed\n")
    assert rc == 1 and "FAIL: noo stack start exited 1: x up failed" in out, out
    rc, out = _forced(tmp_path / "n", dict(RESTART_BEFORE), restarted=dict(RESTART_BEFORE))
    assert rc == 1 and "the --restart did not recreate the worker" in out, out


ROTATION_CELL = "ubuntu-24.04-amd64-default"


def _rotation_block() -> str:
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    start = text.index("FORCED_RESTART_CELL=")
    return text[start:text.index("\nfi\n", start) + 4]


def test_the_rotation_runs_after_first_answer_the_start_checks_and_the_probes():
    text = (ROOT / "scripts/install-cell/run.sh").read_text()
    at = text.index("step start-after-rotation ")
    for before in ("step start-idempotent ", "step start-input-change ", "step start-recreate ",
                   "step health-after-starts ", "step first-answer ", "step context-pin-restart "):
        assert text.index(before) < at, before
    assert at < text.index("step probe-docker-restart-namespace-joiners ") < text.index("\nteardown\nfinish")
    block = _rotation_block()
    for cmd in ("noo cluster nats-creds rotate worker --yes", "noo cluster nats-creds rotate worker --restart --yes"):
        assert text.count(cmd) == 1 and block.index(cmd) < block.index("\nelse\n"), "only in the default cell's branch"
    assert f"FORCED_RESTART_CELL={ROTATION_CELL}\n" in text


def _fake_cli(d: Path, inst: Path, record: bool, nats_moves: bool, forced_moves: bool):
    d.mkdir()
    ids, calls, starts = d / "ids", d / "calls", d / "starts"
    ids.write_text("g1 n1 w1 t1")
    starts.write_text("0")
    conf, state = inst / "monitoring" / "nats" / "users.conf", inst / ".noo-start-inputs.json"
    rec = json.dumps({"reloaded": {"nats": {"container": "n1", "paths": {str(conf): "ab12"}}}}) if record else "{}"
    (d / "docker").write_text(f"""#!/bin/sh
case "$1" in
  ps) echo "c1 c2 c3 c4" ;;
  inspect) set -- $(cat {ids}); echo "noo-gateway $1 gateway <no value>"; echo "noo-nats $2 nats <no value>"
           echo "noo-worker $3 worker nats:service_started:false"; echo "noo-trellion $4 trellion gateway:service_started:true" ;;
esac
""")
    (d / "noo").write_text(f"""#!/bin/bash
echo "$*" >> {calls}
set -- $*
read g n w t < {ids}
case "$1 $2 $3 $4" in
  "cluster nats-creds rotate worker")
    echo "worker-$RANDOM" >> {conf}; echo '{rec}' > {state}
    echo "+ noo-nats reloaded (SIGHUP) — the server now verifies the NEW digest"
    echo "! noo-worker, noo-trellion, noo-trellion-intel hold the OLD password"
    if [ "$5" = --restart ]; then echo "${{g}}r ${{n}}r ${{w}}r ${{t}}r" > {ids}; echo "+ stack recreated"; fi ;;
  "cluster provision "*) echo "bundle carries this node's own NATS credential; 4 users rendered and noo-nats reloaded" ;;
  "stack start  ")
    k=$(( $(cat {starts}) + 1 )); echo $k > {starts}
    if [ $k = 1 ]; then
      {'n=${n}x;' if nats_moves else ''} echo "$g $n ${{w}}x ${{t}}x" > {ids}
      echo "  Containers          4 running, 2 recreated"
      echo "    recreated worker: its inputs changed (secret nats_worker_password)"
      {'echo "    recreated nats: its inputs changed (config monitoring/nats/users.conf)"' if nats_moves else ''}
    else
      {'echo "$g $n ${w}y $t" > ' + str(ids) + '; echo "    recreated worker: its compose config or image changed"' if forced_moves else 'echo "  Containers          4 running, 0 recreated"'}
    fi ;;
esac
""")
    (d / "hostname").write_text("#!/bin/sh\necho node-a\n")
    for f in ("docker", "noo", "hostname"):
        (d / f).chmod(0o755)
    return calls


def _run_rotation_block(tmp_path, cell, record=True, nats_moves=False, forced_moves=False):
    home = tmp_path / "home"
    inst = home / ".noo"
    (inst / "monitoring" / "nats").mkdir(parents=True)
    (inst / ".noo-standalone").write_text("")
    (inst / "monitoring" / "nats" / "users.conf").write_text("accounts {}\n")
    calls = _fake_cli(tmp_path / "bin", inst, record, nats_moves, forced_moves)
    out = tmp_path / "out"
    out.mkdir()
    script = ('step() { shift 2; [ "$1" = -- ] && shift; "$@"; }\n'
              f'RC_PY={ROOT / "scripts/install-cell/recreated.py"}; OUT={out}; CELL={cell}\n' + _rotation_block())
    env = dict(os.environ, HOME=str(home), PATH=f"{tmp_path / 'bin'}:{os.environ['PATH']}")
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=120)
    verdicts = {l.split()[0]: l for l in r.stdout.splitlines() if l.startswith("START-AFTER-")}
    return r, verdicts, (calls.read_text() if calls.exists() else "")


def test_the_default_cell_rotates_then_judges_both_starts(tmp_path):
    r, v, calls = _run_rotation_block(tmp_path, ROTATION_CELL)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert v["START-AFTER-PROVISION"].startswith("START-AFTER-PROVISION PASS: nats not recreated"), v
    assert "also recreated: noo-trellion" in v["START-AFTER-PROVISION"] and "noo-worker (recreated worker" in v["START-AFTER-PROVISION"]
    assert v["START-AFTER-FORCED-RESTART"].startswith("START-AFTER-FORCED-RESTART PASS: none of the 4"), v
    assert [c.split()[:5] for c in calls.splitlines()] == [
        ["cluster", "nats-creds", "rotate", "worker", "--yes"], ["cluster", "provision", "node-a", "--wait"],
        ["stack", "start"], ["cluster", "nats-creds", "rotate", "worker", "--restart"], ["stack", "start"]]
    assert "rotate| ! noo-worker" in r.stdout, "the rotation's warning is prefixed, not a stranger's warning"
    assert not re.search(r"(?m)^\s*(!|⚠)", r.stdout)


def test_the_default_cell_fails_each_assert_by_name(tmp_path):
    r, v, _ = _run_rotation_block(tmp_path, ROTATION_CELL, nats_moves=True)
    assert r.returncode == 1 and " FAIL: " in v["START-AFTER-PROVISION"] and "noo-nats (recreated nats:" in v["START-AFTER-PROVISION"], v
    r, v, _ = _run_rotation_block(tmp_path / "f", ROTATION_CELL, forced_moves=True)
    assert r.returncode == 1 and " PASS: " in v["START-AFTER-PROVISION"], v
    assert "noo-worker (recreated worker: its compose config or image changed)" in v["START-AFTER-FORCED-RESTART"], v
    r, v, _ = _run_rotation_block(tmp_path / "n", ROTATION_CELL, record=False, nats_moves=True)
    assert r.returncode == 0 and "NOTE: this build does not record nats reloads" in v["START-AFTER-PROVISION"], v


def test_another_cell_never_rotates_and_says_where_it_runs(tmp_path):
    r, v, calls = _run_rotation_block(tmp_path, "ubuntu-22.04-amd64")
    assert r.returncode == 0 and calls == "", calls
    assert v["START-AFTER-PROVISION"] == f"START-AFTER-PROVISION NOTE: runs in the {ROTATION_CELL} cell only (it rotates the worker NATS credential and recreates the stack)"
    assert v["START-AFTER-FORCED-RESTART"] == f"START-AFTER-FORCED-RESTART NOTE: runs in the {ROTATION_CELL} cell only"


def test_the_rag_evidence_file_goes_through_the_redactor_and_the_upload_scan(tmp_path):
    sse = f"data: {{\"type\":\"tool_result\",\"output\":\"Authorization: Bearer {JWT}\"}}"
    red = _redact("RAG-CHAT EVIDENCE: x\n  sse: " + sse + "\n  gw: NOO_CLUSTER_TOKEN=s3cr3t-value-123\n")
    assert JWT not in red and "s3cr3t-value-123" not in red
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "rag-chat-evidence.log").write_text(red)
    assert C.cmd_scan([str(tmp_path)]) == 0
    (logs / "rag-chat-evidence.log").write_text("  sse: " + sse + "\n")
    assert C.cmd_scan([str(tmp_path)]) == 3
