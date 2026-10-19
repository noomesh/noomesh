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


def test_optin_allows_in_process_execution(monkeypatch):
    monkeypatch.setattr(pt, "_inside_the_stack", lambda: False)  # a source checkout
    os.environ["NOO_ALLOW_LOCAL_PYTHON_EXEC"] = "1"
    try:
        out = _run_python({"code": "print(6 * 7)"}, None)
    finally:
        _clear_optin()
    assert "42" in out                   # explicit dev opt-in runs it


def test_optin_is_refused_inside_the_deployed_stack(monkeypatch):
    """The hatch is a checkout-only dev tool: in a container, or under the
    launcher (NOO_LAUNCHED=1), the env var opens nothing and the code is NOT run."""
    monkeypatch.setenv("NOO_ALLOW_LOCAL_PYTHON_EXEC", "1")
    monkeypatch.setattr(pt, "_inside_the_stack", lambda: True)
    out = _run_python({"code": "print('PWNED')"}, None)
    assert "disabled" in out.lower()
    assert "PWNED" not in out
    assert "deployed stack" in out


def test_launcher_sentinel_counts_as_the_stack(monkeypatch):
    monkeypatch.setattr(pt.os.path, "exists", lambda p: False)
    monkeypatch.setenv("NOO_LAUNCHED", "1")
    assert pt._inside_the_stack() is True
    monkeypatch.delenv("NOO_LAUNCHED")
    assert pt._inside_the_stack() is False


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
        calls["kwargs"] = kwargs
        return _Resp()

    # If code ran in-process instead of the sandbox, this marker would appear.
    def fail_subprocess(*a, **k):
        raise AssertionError("subprocess must NOT be used when a sandbox is set")

    orig_post, orig_run = pt.httpx.post, pt.subprocess.run
    pt.httpx.post = fake_post
    pt.subprocess.run = fail_subprocess
    try:
        out = _run_python({"code": "print('x')"}, "https://sandbox:9000")
    finally:
        pt.httpx.post, pt.subprocess.run = orig_post, orig_run

    assert out == "sandboxed-ok"
    assert calls["url"] == "https://sandbox:9000/exec"
    assert calls["json"]["code"] == "print('x')"
    # The cluster TLS context rides every call: CA verify + the caller's leaf.
    assert "verify" in calls["kwargs"] and "cert" in calls["kwargs"]


def test_sandbox_client_presents_the_cluster_leaf(tmp_path, monkeypatch):
    for name in ("ca.crt", "leaf.crt", "leaf.key"):
        (tmp_path / name).write_text("x")
    monkeypatch.setenv("NOO_TLS_CA", str(tmp_path / "ca.crt"))
    monkeypatch.setenv("NOO_TLS_CERT", str(tmp_path / "leaf.crt"))
    monkeypatch.setenv("NOO_TLS_KEY", str(tmp_path / "leaf.key"))
    import ssl

    monkeypatch.setattr(ssl, "create_default_context", lambda cafile=None: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    kw = pt.sandbox_tls_kwargs()
    assert kw["cert"] == (str(tmp_path / "leaf.crt"), str(tmp_path / "leaf.key"))
    assert isinstance(kw["verify"], ssl.SSLContext)
    assert kw["verify"].verify_mode == ssl.CERT_REQUIRED and kw["verify"].check_hostname


def test_plaintext_sandbox_url_is_refused_not_dialled():
    _clear_optin()

    def no_dial(*a, **k):
        raise AssertionError("a plaintext sandbox URL must not be dialled")

    orig_post = pt.httpx.post
    pt.httpx.post = no_dial
    try:
        out = _run_python({"code": "print('x')"}, "http" + "://sandbox:9000")
    finally:
        pt.httpx.post = orig_post
    assert "not https" in out and "https://sandbox:9000" in out


if __name__ == "__main__":
    failures = 0
    # Fixture-taking tests (tmp_path, monkeypatch) run under pytest only.
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v) and not v.__code__.co_argcount]
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
