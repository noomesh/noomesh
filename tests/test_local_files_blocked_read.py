# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""H-I3 regression: local_files must never expose secret files via
read / find / list (previously blocked only on write).

Runnable via pytest or `PYTHONPATH=src python3 tests/test_local_files_blocked_read.py`.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from noomesh.tools.local_files import (
    _blocked_pattern_match,
    _read_files,
    _find_files,
    _list_directories,
)


def test_blocked_pattern_match_covers_secrets_not_normal_files():
    for secret in [".env", "prod.env", "server.key", "tls.pem", "id_rsa",
                   "id_ed25519", "aws_credentials", "db.secret"]:
        assert _blocked_pattern_match(secret), f"{secret} should be blocked"
    for ok in ["main.py", "README.md", "notes.txt", "data.json", "app.log"]:
        assert _blocked_pattern_match(ok) is None, f"{ok} should be allowed"
    # case-insensitive + only the basename matters
    assert _blocked_pattern_match("/home/u/.SSH/ID_RSA")
    assert _blocked_pattern_match("/a/b/PROD.ENV")


def _seed(tmp):
    with open(os.path.join(tmp, "notes.txt"), "w") as f:
        f.write("hello world normal content")
    with open(os.path.join(tmp, ".env"), "w") as f:
        f.write("SECRET_TOKEN=supersecretvalue123")
    with open(os.path.join(tmp, "id_rsa"), "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA")  # leak-ok: a truncated fake key body ("AAAA") for the blocked-read test


def test_read_blocks_secret_content_but_returns_normal():
    with tempfile.TemporaryDirectory() as tmp:
        _seed(tmp)
        out = _read_files(
            {"paths": [os.path.join(tmp, "notes.txt"), os.path.join(tmp, ".env"),
                       os.path.join(tmp, "id_rsa")]},
            10000, [],
        )
        assert "hello world normal content" in out          # normal file read
        assert "supersecretvalue123" not in out              # .env content NOT leaked
        assert "BEGIN OPENSSH PRIVATE KEY" not in out         # key content NOT leaked
        assert "[blocked]" in out                             # explicitly blocked


def test_find_filters_out_secret_paths():
    with tempfile.TemporaryDirectory() as tmp:
        _seed(tmp)
        out = _find_files({"paths": [os.path.join(tmp, "*")]}, [])
        assert "notes.txt" in out
        assert ".env" not in out
        assert "id_rsa" not in out


def test_list_hides_secret_entries():
    with tempfile.TemporaryDirectory() as tmp:
        _seed(tmp)
        out = _list_directories({"paths": [tmp]}, [])
        assert "notes.txt" in out
        assert ".env" not in out
        assert "id_rsa" not in out


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
