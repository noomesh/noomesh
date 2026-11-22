# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""mirror-images.yml dispatches plan first and only ever adds or fails.

scripts/mirror-plan.py prints, read-only, what a `mode=copy` dispatch would do
with every lane (copy an absent tag, skip one already at the source digest,
FAIL one at another digest). The workflow's default mode is the plan; the
copy job needs an explicit `mode=copy`, and the plan job cannot write
packages.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF_PATH = ROOT / ".github/workflows/mirror-images.yml"

spec = importlib.util.spec_from_file_location("mirror_plan", ROOT / "scripts/mirror-plan.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

D = "sha256:" + "a" * 64
B = "sha256:" + "b" * 64


def _wf() -> dict:
    return yaml.safe_load(WF_PATH.read_text())


# ── the workflow ─────────────────────────────────────────────────────────────

def test_the_dispatch_defaults_to_the_plan():
    mode = _wf()[True]["workflow_dispatch"]["inputs"]["mode"]   # yaml reads `on:` as True
    assert mode["type"] == "choice" and mode["options"] == ["plan", "copy"]
    assert mode["default"] == "plan"


def test_the_copy_job_runs_only_on_an_explicit_copy():
    job = _wf()["jobs"]["mirror"]
    assert "inputs.mode == 'copy'" in job["if"], job["if"]
    assert "github.repository == 'noomesh/noomesh'" in job["if"]
    assert job["needs"] == "plan", "the plan prints before any write"


def test_only_the_copy_job_can_write_packages():
    wf = _wf()
    assert wf["permissions"] == {"contents": "read"}, "no workflow-wide write"
    assert wf["jobs"]["plan"]["permissions"] == {"contents": "read", "packages": "read"}
    assert wf["jobs"]["mirror"]["permissions"]["packages"] == "write"
    assert "write" not in str(wf["jobs"]["plan"])


def test_the_plan_job_runs_the_plan_script_into_the_summary():
    steps = _wf()["jobs"]["plan"]["steps"]
    run = next(s["run"] for s in steps if "mirror-plan.py" in s.get("run", ""))
    assert run.strip() == 'python3 scripts/mirror-plan.py --summary "$GITHUB_STEP_SUMMARY"'
    assert "inputs.mode" not in str(_wf()["jobs"]["plan"].get("if", "")), "the plan runs in both modes"


def test_dispatches_do_not_race():
    c = _wf()["concurrency"]
    assert c["cancel-in-progress"] is False and c["group"]


# ── the lane parser is the workflow's own matrix ────────────────────────────

def test_the_line_parser_reads_what_yaml_reads():
    want = [{k: v for k, v in ln.items() if k in ("source", "dest", "dest_org", "auth")}
            for ln in _wf()["jobs"]["mirror"]["strategy"]["matrix"]["include"]]
    assert P.lanes(WF_PATH.read_text()) == want
    assert len(want) > 20


def test_the_parser_stops_at_the_end_of_a_lane():
    text = ("        include:\n          - source: a@" + D + "\n            dest: a:1\n"
            "    steps:\n      - name: x\n        run: |\n          dest: b:2\n          dest_org: evil\n")
    assert P.lanes(text) == [{"source": "a@" + D, "dest": "a:1"}]


def test_a_lane_without_dest_is_refused():
    with pytest.raises(P.PlanError, match="no dest"):
        P.lanes("          - source: a@" + D + "\n            auth: hub\n")


# ── classification, with a stubbed registry ─────────────────────────────────

def _one(dest="nats:2.14.3", source=f"nats:2.14.3@{D}", org="noomesh", extra=""):
    return (f"          - source: {source}\n            dest: {dest}\n"
            + (f"            dest_org: {org}\n" if org else "") + extra)


def _plan(text, answers, token=None):
    calls = []

    def fetch(repo, tag, tok=None):
        calls.append((repo, tag, tok))
        return answers[(repo, tag, tok)]
    return P.plan(text, "noomesh", fetch=fetch, token=token), calls


@pytest.mark.parametrize("state, have, mirror, action", [
    ("absent", "", "absent", "copy (add)"),
    ("present", D, "same", "skip (already the source digest)"),
    ("present", B, f"DIFFERENT (mirror {B})", "FAIL (would move the tag; refused)"),
    ("unreadable", "", "unreadable anonymously (private, or not created yet)", "guard decides at copy time"),
    ("error:manifest HTTP 500", "", "error:manifest HTTP 500", "guard decides at copy time"),
], ids=["absent", "same", "different", "unreadable", "error"])
def test_each_state_maps_to_one_action(state, have, mirror, action):
    rows, calls = _plan(_one(), {("noomesh/nats", "2.14.3", None): (state, have)})
    assert calls == [("noomesh/nats", "2.14.3", None)], "read anonymously first"
    assert rows == [{"dest": "ghcr.io/noomesh/nats:2.14.3", "source": "nats:2.14.3", "digest": D,
                     "mirror": mirror, "action": action}]


def test_an_unreadable_tag_is_re_read_with_the_token():
    rows, calls = _plan(_one(), {("noomesh/nats", "2.14.3", None): ("unreadable", ""),
                                 ("noomesh/nats", "2.14.3", "t"): ("present", B)}, token="t")
    assert [c[2] for c in calls] == [None, "t"]
    assert rows[0]["action"].startswith("FAIL") and "not public" in rows[0]["mirror"]


def test_a_lane_copying_a_moving_tag_fails_whatever_the_registry_says():
    rows, _ = _plan(_one(source="nats:2.14.3"), {("noomesh/nats", "2.14.3", None): ("absent", "")})
    assert rows[0]["action"].startswith("FAIL (source is a moving tag")


def test_two_lanes_for_one_destination_fail():
    rows, _ = _plan(_one() + _one(org=None), {("noomesh/nats", "2.14.3", None): ("absent", "")})
    assert [r["action"] for r in rows] == ["FAIL (2 lanes copy this destination)"] * 2


def test_dest_org_and_owner_build_the_destination():
    assert P.dest_repo({"dest": "redis:8", "dest_org": "noomesh/dhi"}, "noomesh") == ("noomesh/dhi/redis", "8")
    assert P.dest_repo({"dest": "pgvector:pg18"}, "someone") == ("someone/pgvector", "pg18")


def test_main_exits_1_and_prints_a_different_lane(tmp_path, monkeypatch, capsys):
    wf = tmp_path / "wf.yml"
    wf.write_text(_one() + _one(dest="nginx:1.27-alpine", source=f"nginx:1.27-alpine@{D}"))
    monkeypatch.setattr(P, "fetch_digest", lambda repo, tag, token=None:
                        ("present", B) if repo.endswith("nats") else ("absent", ""))
    monkeypatch.delenv("GHCR_TOKEN", raising=False)
    summary = tmp_path / "summary.md"
    assert P.main(["--workflow", str(wf), "--summary", str(summary)]) == 1
    cap = capsys.readouterr()
    assert "::error::ghcr.io/noomesh/nats:2.14.3: DIFFERENT" in cap.err
    assert "**FAIL (would move the tag; refused)**" in cap.out
    assert "2 lanes: 1 copy, 0 skip, 1 FAIL" in cap.out
    assert "## mirror-images plan (read-only)" in summary.read_text() and B in summary.read_text()


def test_main_exits_0_when_nothing_would_fail(tmp_path, monkeypatch):
    wf = tmp_path / "wf.yml"
    wf.write_text(_one())
    monkeypatch.setattr(P, "fetch_digest", lambda repo, tag, token=None: ("present", D))
    assert P.main(["--workflow", str(wf)]) == 0


# ── the registry reader: read-only, digest = the bytes ──────────────────────

def _http_stub(monkeypatch, token_code=200, manifest=(200, {}, b'{"m": 1}')):
    calls = []

    def http(url, headers):
        calls.append((url, dict(headers)))
        if "/token?" in url:
            return token_code, {}, b'{"token": "tk"}'
        return manifest
    monkeypatch.setattr(P, "_http", http)
    return calls


def test_fetch_hashes_the_manifest_bytes(monkeypatch):
    body = b'{"m": 1}'
    calls = _http_stub(monkeypatch, manifest=(200, {}, body))
    assert P.fetch_digest("noomesh/nats", "2.14.3") == ("present", "sha256:" + hashlib.sha256(body).hexdigest())
    assert calls[0][0] == "https://ghcr.io/token?scope=repository:noomesh/nats:pull&service=ghcr.io"
    assert "Authorization" not in calls[0][1]
    assert calls[1][0] == "https://ghcr.io/v2/noomesh/nats/manifests/2.14.3"
    assert calls[1][1]["Authorization"] == "Bearer tk" and "image.index" in calls[1][1]["Accept"]


@pytest.mark.parametrize("token_code, manifest, state", [
    (200, (404, {}, b""), "absent"),
    (200, (401, {}, b""), "unreadable"),
    (200, (403, {}, b""), "unreadable"),
    (401, (200, {}, b"{}"), "unreadable"),
    (200, (500, {}, b""), "error:manifest HTTP 500"),
    (200, (200, {"docker-content-digest": B}, b"{}"), "error:registry says"),
], ids=["404", "401", "403", "token-401", "500", "header-mismatch"])
def test_fetch_classifies_the_answer(monkeypatch, token_code, manifest, state):
    _http_stub(monkeypatch, token_code, manifest)
    assert P.fetch_digest("noomesh/nats", "2.14.3")[0].startswith(state)


def test_fetch_with_a_token_authenticates_the_token_request(monkeypatch):
    calls = _http_stub(monkeypatch)
    P.fetch_digest("noomesh/dhi/rust", "1", "secret")
    assert calls[0][1]["Authorization"].startswith("Basic ")


def test_the_reader_only_gets():
    src = (ROOT / "scripts/mirror-plan.py").read_text()
    assert 'method="GET"' in src
    for verb in ("PUT", "POST", "DELETE", "PATCH"):
        assert f'method="{verb}"' not in src
