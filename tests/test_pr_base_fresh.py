# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""scripts/pr-base-fresh.py: refuse to merge a PR whose CI predates its base.

The 2026-10-09 case: #859's CI ran on a dev without ced944e7 (which added
`spdx.py --check` to preflight); ced944e7 landed, #859 was merged on its old
green and dev went red. Served at the transport (urllib), not by stubbing the
script's functions.
"""
from __future__ import annotations

import importlib.util
import io
import json
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "o/r"


def _load():
    spec = importlib.util.spec_from_file_location("pr_base_fresh", ROOT / "scripts/pr-base-fresh.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Api:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def urlopen(self, req, timeout=None):
        self.calls.append(req.full_url)
        for frag, payload in self.routes.items():
            if frag in req.full_url:
                if isinstance(payload, Exception):
                    raise payload
                return io.BytesIO(json.dumps(payload).encode())
        raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)


def _commit(sha, date, msg="m"):
    return {"sha": sha, "commit": {"committer": {"date": date}, "message": msg}}


def _routes(missing, run_created="2026-10-09T18:59:00Z", merged=False, runs=True):
    return {
        "/pulls/859": {"head": {"sha": "h859"}, "base": {"ref": "dev"}, "merged": merged},
        "runs?head_sha=h859": {"workflow_runs": [
            {"head_sha": "h859", "created_at": run_created}] if runs else []},
        "/compare/h859...dev": {"ahead_by": len(missing), "commits": missing},
    }


def _main(monkeypatch, capsys, routes):
    mod = _load()
    api = _Api(routes)
    monkeypatch.setattr(urllib.request, "urlopen", api.urlopen)
    monkeypatch.setenv("GH_TOKEN", "tok")
    rc = mod.main(["859", "--repo", REPO])
    cap = capsys.readouterr()
    assert api.calls, "never reached the transport"
    return rc, cap.out + cap.err


def test_the_859_case_is_stale(monkeypatch, capsys) -> None:
    missing = [_commit("ced944e7aa", "2026-10-09T19:04:00Z", "licensing: SPDX headers + --check")]
    rc, out = _main(monkeypatch, capsys, _routes(missing))
    assert rc == 1, out
    assert "STALE" in out and "ced944e7" in out


def test_base_commits_ci_already_saw_are_fresh(monkeypatch, capsys) -> None:
    missing = [_commit("old1", "2026-10-09T18:00:00Z")]
    rc, out = _main(monkeypatch, capsys, _routes(missing))
    assert rc == 0 and "fresh" in out, out


def test_an_up_to_date_branch_is_fresh(monkeypatch, capsys) -> None:
    rc, out = _main(monkeypatch, capsys, _routes([]))
    assert rc == 0, out


def test_no_ci_run_cannot_tell(monkeypatch, capsys) -> None:
    rc, out = _main(monkeypatch, capsys, _routes([], runs=False))
    assert rc == 2 and "CANNOT TELL" in out


def test_an_api_error_cannot_tell(monkeypatch, capsys) -> None:
    r = _routes([])
    r["/compare/"] = urllib.error.HTTPError("u", 500, "x", {}, None)
    del r["/compare/h859...dev"]
    rc, out = _main(monkeypatch, capsys, r)
    assert rc == 2, out


def test_a_truncated_compare_cannot_tell(monkeypatch, capsys) -> None:
    r = _routes([_commit("a", "2026-10-09T18:00:00Z")])
    r["/compare/h859...dev"]["ahead_by"] = 400
    rc, _ = _main(monkeypatch, capsys, r)
    assert rc == 2


def test_already_merged_cannot_tell(monkeypatch, capsys) -> None:
    rc, out = _main(monkeypatch, capsys, _routes([], merged=True))
    assert rc == 2 and "already merged" in out
