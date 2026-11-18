# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Test input validation"""
import pytest
from noomesh.validation import ToolInputValidator, ValidationError


def test_path_validation():
    """Test path sanitization"""
    validator = ToolInputValidator()

    # Valid paths
    assert validator.sanitize_path("test.txt") == "test.txt"
    assert validator.sanitize_path("dir/file.txt") == "dir/file.txt"

    # Invalid paths
    with pytest.raises(ValidationError):
        validator.sanitize_path("../etc/passwd")

    with pytest.raises(ValidationError):
        validator.sanitize_path("/etc/passwd", allow_absolute=False)

    with pytest.raises(ValidationError):
        validator.sanitize_path("test\x00.txt")


def test_code_validation():
    """Test code sanitization"""
    validator = ToolInputValidator()

    # Valid code
    safe_code = validator.sanitize_code("print('hello')", allow_dangerous=False)
    assert "hello" in safe_code

    # Dangerous code
    with pytest.raises(ValidationError):
        validator.sanitize_code("import os; os.system('rm -rf /')", allow_dangerous=False)

    with pytest.raises(ValidationError):
        validator.sanitize_code("eval('malicious')", allow_dangerous=False)

    # Allow dangerous when explicitly allowed
    dangerous = validator.sanitize_code("import os", allow_dangerous=True)
    assert "os" in dangerous


def test_url_validation():
    """Test URL sanitization"""
    validator = ToolInputValidator()

    # Valid URLs
    assert validator.sanitize_url("https://example.com")
    assert validator.sanitize_url("http://example.com/path")

    # Invalid URLs
    with pytest.raises(ValidationError):
        validator.sanitize_url("http://localhost/admin")

    with pytest.raises(ValidationError):
        validator.sanitize_url("http://127.0.0.1/")

    with pytest.raises(ValidationError):
        validator.sanitize_url("ftp://example.com")


def test_no_egress_allowlist_knob_is_read(monkeypatch):
    """NOO_EGRESS_ALLOWLIST restricted nothing (sanitize_url, its only reader,
    has no caller) yet was documented as "hosts tools may reach". A documented
    security knob that restricts nothing is worse than none, so it is gone:
    setting it must not change what sanitize_url accepts, and no doc or
    example may name it again."""
    import pathlib
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    monkeypatch.setenv("NOO_EGRESS_ALLOWLIST", "only.example.org")
    assert ToolInputValidator.sanitize_url("https://example.com") == "https://example.com"
    root = pathlib.Path(__file__).resolve().parents[1]
    for rel in ("docs/reference/env.md", ".env.example", "noomesh.yaml.example", "src/noomesh/validation.py"):
        assert "NOO_EGRESS_ALLOWLIST" not in (root / rel).read_text(), rel
