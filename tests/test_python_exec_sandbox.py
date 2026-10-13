# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""H-I2 regression: python_exec must not run arbitrary code in-process on the
host. It requires the isolated sandbox; in-process execution is refused unless
an operator explicitly opts in (dev only).

Runnable via pytest or `PYTHONPATH=src python3 tests/test_python_exec_sandbox.py`.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import noomesh.tools.python_tool as pt
from noomesh.tools.python_tool import _run_python


def _clear_optin():
    os.environ.pop("NOO_ALLOW_LOCAL_PYTHON_EXEC", None)


def test_refuses_in_process_without_sandbox_or_optin():
    _clear_optin()
    out = _run_python({"code": "print('PWNED')"}, None)
    assert "disabled" in out.lower()
    assert "PWNED" not in out            # code was NOT executed
    assert "NOO_SANDBOX_URL" in out


def test_optin_allows_in_process_execution():
    os.environ["NOO_ALLOW_LOCAL_PYTHON_EXEC"] = "1"
    try:
        out = _run_python({"code": "print(6 * 7)"}, None)
    finally:
        _clear_optin()
    assert "42" in out                   # explicit dev opt-in runs it


def test_sandbox_path_used_when_configured_not_subprocess():
    _clear_optin()
    calls = {}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"output": "sandboxed-ok"}

    def fake_post(url, **kwargs):
        calls["url"] = url
        calls["json"] = kwargs.get("json")
        return _Resp()

    # If code ran in-process instead of the sandbox, this marker would appear.
    def fail_subprocess(*a, **k):
        raise AssertionError("subprocess must NOT be used when a sandbox is set")

    orig_post, orig_run = pt.httpx.post, pt.subprocess.run
    pt.httpx.post = fake_post
    pt.subprocess.run = fail_subprocess
    try:
        out = _run_python({"code": "print('x')"}, "http://sandbox:9000")
    finally:
        pt.httpx.post, pt.subprocess.run = orig_post, orig_run

    assert out == "sandboxed-ok"
    assert calls["url"] == "http://sandbox:9000/exec"
    assert calls["json"]["code"] == "print('x')"


if __name__ == "__main__":
    failures = 0
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
