# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noomesh.secret_env` — the one reader for tier-1 secrets.

Mirrors the Rust `secret_env::tests` case for case: trailing newline
stripped exactly once, `\\r\\n`, unreadable → error naming the path, empty
file → error, both-set → refusal, precedence `_FILE` > `NOO_SECRET_` >
plain. The two manifests are compared in `test_file_reader_parity.py`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from noomesh import secret_env
from noomesh.secret_env import (
    SecretConflictError,
    SecretFileError,
    both_set_conflicts,
    refuse_on_conflicts,
    secret,
    secret_or_empty,
)


def _file(tmp_path: Path, content: bytes, name: str = "s") -> str:
    p = tmp_path / name
    p.write_bytes(content)
    return str(p)


def test_trailing_newline_is_stripped_exactly_once(tmp_path: Path) -> None:
    assert secret("X", {"X_FILE": _file(tmp_path, b"s3cret\n\n")}) == "s3cret\n"
    assert secret("X", {"X_FILE": _file(tmp_path, b"s3cret\n")}) == "s3cret"
    assert secret("X", {"X_FILE": _file(tmp_path, b"s3cret")}) == "s3cret"


def test_crlf_counts_as_one_newline(tmp_path: Path) -> None:
    assert secret("X", {"X_FILE": _file(tmp_path, b"s3cret\r\n")}) == "s3cret"


def test_a_multi_line_pem_survives_intact(tmp_path: Path) -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n"  # leak-ok: four-letter placeholder, not key material
    assert secret("X", {"X_FILE": _file(tmp_path, pem.encode())}) == pem[:-1]


def test_unreadable_file_is_an_error_naming_the_path(tmp_path: Path) -> None:
    path = str(tmp_path / "missing")
    with pytest.raises(SecretFileError) as ei:
        secret("X", {"X_FILE": path, "X": "plain"})  # and does NOT fall through
    assert path in str(ei.value)
    assert "X_FILE" in str(ei.value)


def test_empty_file_is_an_error_not_unset(tmp_path: Path) -> None:
    path = _file(tmp_path, b"\n")
    with pytest.raises(SecretFileError) as ei:
        secret("X", {"X_FILE": path, "X": "plain"})
    assert path in str(ei.value)
    assert "empty" in str(ei.value)


def test_precedence_is_file_then_prefix_then_plain(tmp_path: Path) -> None:
    env = {"X_FILE": _file(tmp_path, b"from-file\n"), "NOO_SECRET_X": "from-prefix", "X": "from-plain"}
    assert secret("X", env) == "from-file"
    del env["X_FILE"]
    assert secret("X", env) == "from-prefix"
    del env["NOO_SECRET_X"]
    assert secret("X", env) == "from-plain"
    assert secret("X", {}) is None
    assert secret_or_empty("X", {}) == ""


def test_empty_values_count_as_unset_at_every_tier() -> None:
    assert secret("X", {"X_FILE": "", "NOO_SECRET_X": "", "X": "plain"}) == "plain"
    assert secret("X", {"X": ""}) is None


def test_both_set_is_a_conflict_only_when_both_are_non_empty() -> None:
    names = ("A", "B", "C")
    env = {"A": "x", "A_FILE": "/p", "B": "x", "B_FILE": "", "C_FILE": "/p"}
    assert both_set_conflicts(names, env) == ["A"]
    assert both_set_conflicts(names, {}) == []


def test_refuse_on_conflicts_names_every_skewed_name(tmp_path: Path) -> None:
    env = {"A": "x", "A_FILE": "/p", "B": "y", "B_FILE": "/q"}
    with pytest.raises(SecretConflictError) as ei:
        refuse_on_conflicts(("A", "B", "C"), env)
    assert ei.value.names == ["A", "B"]
    # A named-but-broken file is refused at boot too, not just per call.
    with pytest.raises(SecretFileError):
        refuse_on_conflicts(("A",), {"A_FILE": str(tmp_path / "missing")})
    refuse_on_conflicts(("A",), {"A": "fine"})  # no raise


def test_the_default_lookup_is_the_process_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SECRET_ENV_TEST_X", "plain")
    monkeypatch.delenv("SECRET_ENV_TEST_X_FILE", raising=False)
    monkeypatch.delenv("NOO_SECRET_SECRET_ENV_TEST_X", raising=False)
    assert secret("SECRET_ENV_TEST_X") == "plain"
    monkeypatch.setenv("SECRET_ENV_TEST_X_FILE", _file(tmp_path, b"from-file\n"))
    assert secret("SECRET_ENV_TEST_X") == "from-file"
    assert both_set_conflicts(("SECRET_ENV_TEST_X",)) == ["SECRET_ENV_TEST_X"]
    assert os.environ["SECRET_ENV_TEST_X"] == "plain"  # the reader never mutates env


def test_secrets_manager_delegates_to_the_one_reader(tmp_path: Path, monkeypatch) -> None:
    """`SecretsManager.get_secret` used to carry its own copy of the
    NOO_SECRET_ rule; now the `_FILE` tier reaches it too."""
    from noomesh.secrets import SecretsManager

    monkeypatch.setenv("SM_TEST_KEY_FILE", _file(tmp_path, b"from-file\n"))
    monkeypatch.setenv("SM_TEST_KEY", "plain")
    assert SecretsManager().get_secret("SM_TEST_KEY") == "from-file"
    monkeypatch.delenv("SM_TEST_KEY_FILE")
    assert SecretsManager().get_secret("SM_TEST_KEY") == "plain"


def test_manifest_names_are_unique_upper_snake_and_not_file_vars() -> None:
    names = secret_env.FILE_BACKED_SECRETS
    assert len(names) >= 10, names
    assert len(set(names)) == len(names)
    for n in names:
        assert n == n.upper() and n.replace("_", "").isalnum(), n
        assert not n.endswith("_FILE"), n
        assert not n.startswith("NOO_SECRET_"), n


# The same byte vectors the Rust reader is pinned against in
# `gateway-rust/src/secret_env.rs::tests::byte_vectors_match_the_python_reader`.
# Change one side, change both: the point is that one file answers the same
# in both runtimes. (Until 2026-09-29 this reader opened the file in text
# mode, so `abc\r` came back as `abc` here and `abc\r` in Rust.)
BYTE_VECTORS: list[tuple[bytes, str]] = [
    (b"a\rb\r", "a\rb\r"),
    (b"abc\r\n\r\n", "abc\r\n"),
    (b"x\n", "x"),
    (b"x\r\n", "x"),
    (b"abc\r", "abc\r"),
    (b"a\r\nb\n", "a\r\nb"),
]


@pytest.mark.parametrize("raw,want", BYTE_VECTORS)
def test_byte_vectors_match_the_rust_reader(tmp_path: Path, raw: bytes, want: str) -> None:
    assert secret("X", {"X_FILE": _file(tmp_path, raw)}) == want


def test_the_rust_side_pins_the_same_vectors() -> None:
    """The Rust test must carry every vector above, byte for byte, so a
    change to one reader's newline handling cannot pass alone."""
    rs = (Path(__file__).resolve().parents[1] / "gateway-rust/src/secret_env.rs").read_text()
    m = re.search(r"fn byte_vectors_match_the_python_reader\(\) \{(.*?)\n    \}", rs, re.S)
    assert m, "the Rust byte-vector test is gone — the parity pin with it"
    body = m.group(1)
    pairs = re.findall(r'\(b"((?:[^"\\]|\\.)*)", "((?:[^"\\]|\\.)*)"\)', body)
    assert len(pairs) == len(BYTE_VECTORS), pairs

    def unesc(s: str) -> str:
        return s.encode().decode("unicode_escape")

    assert [(unesc(a).encode(), unesc(b)) for a, b in pairs] == BYTE_VECTORS
