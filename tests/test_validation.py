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


def test_no_url_validator_or_egress_allowlist_knob_remains():
    """sanitize_url (an SSRF check) had no caller anywhere, and
    NOO_EGRESS_ALLOWLIST, read only inside it, restricted nothing: both are
    gone, so neither can be mistaken for a guard. Outbound requests are
    bounded where they are made (docs/security/networks-and-containers.md)."""
    import pathlib

    assert not hasattr(ToolInputValidator, "sanitize_url")
    root = pathlib.Path(__file__).resolve().parents[1]
    for rel in ("docs/reference/env.md", ".env.example", "noomesh.yaml.example", "src/noomesh/validation.py"):
        assert "NOO_EGRESS_ALLOWLIST" not in (root / rel).read_text(), rel
