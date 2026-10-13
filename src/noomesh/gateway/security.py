# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Input sanitisation and security helpers for the gateway.

ℹ️ LIVE PYTHON LIBRARY — NOT a router. Most HTTP-facing security checks
have moved to ``gateway-rust/src/security.rs`` and middleware, but the
helpers here (``moderate_external_content``, ``scan_skill_content``,
``get_security_manager``) are still called by Python tools
(``tools/web_search.py``, ``prompt_skills/evolver.py``) at runtime. Stays
Python Phase 2 turns these into a ``ContentModerator``
provider injected into the harness.

Provides:
- Path traversal prevention for file operations
- Command injection prevention for python_tool
- XSS prevention for web UI responses
- Input length enforcement
- Rate limiting helpers
- Blocked-file-pattern matching
"""
from __future__ import annotations

import fnmatch
import html
import os
import re
import time as _time
from collections import deque
from pathlib import Path
from typing import Optional

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Defaults (overridden by SecurityConfig at runtime)
# ---------------------------------------------------------------------------

_DEFAULT_MAX_INPUT_LENGTH = 50_000
_DEFAULT_BLOCKED_PATTERNS = [
    "*.env",
    "*.key",
    "*.pem",
    "*credentials*",
    "*.secret",
    "*id_rsa*",
    "*id_ed25519*",
]

_PATH_TRAVERSAL_RE = re.compile(r"(^|[\\/])\.\.($|[\\/])")
_SHELL_META_RE = re.compile(r"[;&|`$(){}!<>]")
_SQL_INJECTION_RE = re.compile(
    r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC)\b.*--"
    r"|'\s*(OR|AND)\s+['\d])",
    re.IGNORECASE,
)
_XSS_PATTERN_RE = re.compile(
    r"<\s*script|javascript\s*:|on\w+\s*=",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Sanitisation results
# ---------------------------------------------------------------------------

class SanitisationError(Exception):
    """Raised when input fails a security check."""

    def __init__(self, message: str, check: str):
        super().__init__(message)
        self.check = check


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------

def check_path_traversal(user_path: str) -> str:
    """Validate that *user_path* does not contain traversal sequences.

    Returns the normalised path string on success.
    Raises ``SanitisationError`` if traversal is detected.
    """
    normalised = user_path.replace("\\", "/")

    if _PATH_TRAVERSAL_RE.search(normalised):
        logger.warning(
            "security_path_traversal_blocked",
            raw_path=user_path[:200],
        )
        if _security_manager:
            _security_manager.record("path_traversal")
        raise SanitisationError(
            f"Path traversal detected in: {user_path[:100]}",
            check="path_traversal",
        )

    try:
        resolved = str(Path(user_path).resolve())
    except (OSError, ValueError):
        raise SanitisationError(
            f"Invalid path: {user_path[:100]}",
            check="path_traversal",
        )

    return resolved


def is_path_within(path: str | Path, allowed_roots: list[str | Path]) -> bool:
    """Return True if *path* resolves to a location inside one of *allowed_roots*."""
    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError):
        return False

    for root in allowed_roots:
        try:
            root_resolved = Path(root).resolve()
            if resolved == root_resolved or resolved.is_relative_to(root_resolved):
                return True
        except (OSError, ValueError):
            continue
    return False


def matches_blocked_pattern(
    filename: str,
    blocked_patterns: Optional[list[str]] = None,
) -> bool:
    """Return True if *filename* matches any blocked glob pattern."""
    patterns = blocked_patterns or _DEFAULT_BLOCKED_PATTERNS
    basename = os.path.basename(filename)
    for pattern in patterns:
        if fnmatch.fnmatch(basename, pattern):
            logger.warning(
                "security_blocked_file_pattern",
                filename=basename,
                pattern=pattern,
            )
            return True
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# Command / code injection
# ---------------------------------------------------------------------------

def check_shell_metacharacters(value: str, field_name: str = "input") -> None:
    """Raise if *value* contains shell meta-characters.

    Use this on fields that should be plain identifiers or file names,
    NOT on free-text fields like code or queries.
    """
    if _SHELL_META_RE.search(value):
        logger.warning(
            "security_shell_meta_blocked",
            field=field_name,
            snippet=value[:100],
        )
        raise SanitisationError(
            f"Disallowed characters in {field_name}",
            check="shell_metacharacters",
        )


def check_python_code_safety(code: str) -> list[str]:
    """Return a list of warning strings about potentially dangerous patterns.

    This does NOT block execution -- it returns advisory warnings that the
    caller (exec approval manager) can use to escalate risk level.
    """
    warnings: list[str] = []

    dangerous_patterns = [
        (r"\bos\.system\b", "os.system() call"),
        (r"\bsubprocess\b", "subprocess usage"),
        (r"\b__import__\b", "dynamic import"),
        (r"\beval\b\s*\(", "eval() call"),
        (r"\bexec\b\s*\(", "exec() call"),
        (r"\bopen\b\s*\(.*/etc/", "reading system files"),
        (r"\brmtree\b", "recursive directory deletion"),
        (r"\bos\.remove\b|\bos\.unlink\b", "file deletion"),
        (r"\bsocket\b", "network socket usage"),
        (r"\bctypes\b", "ctypes FFI usage"),
    ]

    for pattern, description in dangerous_patterns:
        if re.search(pattern, code):
            warnings.append(description)

    if warnings:
        logger.info(
            "security_python_code_warnings",
            warnings=warnings,
            code_length=len(code),
        )

    return warnings


# ---------------------------------------------------------------------------
# SQL injection (advisory -- we use parameterised queries)
# ---------------------------------------------------------------------------

def check_sql_injection(value: str) -> bool:
    """Return True if *value* looks like a SQL injection probe."""
    if _SQL_INJECTION_RE.search(value):
        logger.warning(
            "security_sql_injection_probe",
            snippet=value[:200],
        )
        return True
    return False


# ---------------------------------------------------------------------------
# XSS prevention
# ---------------------------------------------------------------------------

def sanitise_html(text: str) -> str:
    """Escape HTML entities to prevent XSS in web UI responses."""
    return html.escape(text, quote=True)


def check_xss(value: str) -> bool:
    """Return True if *value* contains potential XSS payloads."""
    if _XSS_PATTERN_RE.search(value):
        logger.warning(
            "security_xss_detected",
            snippet=value[:200],
        )
        return True
    return False


def strip_xss(value: str) -> str:
    """Remove common XSS vectors from a string."""
    cleaned = re.sub(r"<\s*script[^>]*>.*?</\s*script\s*>", "", value, flags=re.I | re.S)
    cleaned = re.sub(r"javascript\s*:", "", cleaned, flags=re.I)
    cleaned = re.sub(r"\bon\w+\s*=\s*[\"'][^\"']*[\"']", "", cleaned, flags=re.I)
    return cleaned


# ---------------------------------------------------------------------------
# Input length enforcement
# ---------------------------------------------------------------------------

def enforce_input_length(
    value: str,
    max_length: int = _DEFAULT_MAX_INPUT_LENGTH,
    field_name: str = "input",
) -> str:
    """Truncate *value* to *max_length* characters.

    Logs a warning if truncation occurs.
    """
    if len(value) <= max_length:
        return value

    logger.warning(
        "security_input_truncated",
        field=field_name,
        original_length=len(value),
        max_length=max_length,
    )
    return value[:max_length]


# ---------------------------------------------------------------------------
# Rate limiter helpers
# ---------------------------------------------------------------------------

class SlidingWindowRateLimiter:
    """In-memory sliding window rate limiter.

    Use ``slowapi`` for the FastAPI middleware (already integrated in app.py).
    This class is for non-HTTP contexts (e.g. channel messages, agent loops).
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._buckets: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        """Return True if the request is within the rate limit."""
        import time

        now = time.time()
        cutoff = now - self.window

        bucket = self._buckets.get(key, [])
        bucket = [t for t in bucket if t > cutoff]
        self._buckets[key] = bucket

        if len(bucket) >= self.max_requests:
            logger.warning(
                "security_rate_limit_exceeded",
                key=key,
                count=len(bucket),
                max=self.max_requests,
            )
            if _security_manager:
                _security_manager.record("rate_limit")
            return False

        bucket.append(now)
        return True

    def reset(self, key: str) -> None:
        """Reset the counter for *key*."""
        self._buckets.pop(key, None)


# ---------------------------------------------------------------------------
# Prompt skill content scanner
# ---------------------------------------------------------------------------

_SKILL_INJECTION_PATTERNS: list[tuple[str, str, bool]] = [
    # (regex, description, is_critical)
    # Prompt injection
    (r"ignore\s+(all\s+)?previous\s+instructions", "CRITICAL: prompt injection — ignore previous instructions", True),
    (r"disregard\s+(all\s+)?prior", "CRITICAL: prompt injection — disregard prior", True),
    (r"system\s+prompt\s+override", "CRITICAL: prompt injection — system prompt override", True),
    (r"new\s+instructions\s*:", "CRITICAL: prompt injection — new instructions directive", True),
    # Role hijacking
    (r"you\s+are\s+not\b", "Role hijacking — 'you are not'", False),
    (r"forget\s+everything", "CRITICAL: role hijacking — forget everything", True),
    (r"your\s+real\s+purpose", "Role hijacking — 'your real purpose'", False),
    (r"\byou\s+are\s+now\b", "Role hijacking — 'you are now'", False),
    # Exfiltration
    (r"\bsend\s+to\s+https?://", "CRITICAL: exfiltration — send to URL", True),
    (r"\bpost\s+to\s+https?://", "CRITICAL: exfiltration — post to URL", True),
    (r"\bcurl\b.*https?://", "Exfiltration — curl command", False),
    (r"\bwebhook\b", "Exfiltration — webhook reference", False),
    (r"\bexfiltrate\b", "CRITICAL: exfiltration directive", True),
    (r"transmit\s+user\s+data", "CRITICAL: exfiltration — transmit user data", True),
    # Safety bypass
    (r"no\s+restrictions", "Safety bypass — no restrictions", False),
    (r"disable\s+safety", "CRITICAL: safety bypass — disable safety", True),
    (r"bypass\s+moderation", "CRITICAL: safety bypass — bypass moderation", True),
    (r"ignore\s+guardrails", "CRITICAL: safety bypass — ignore guardrails", True),
    # Credential harvesting (in instructional context)
    (r"(give|send|output|print|return)\s+(me\s+)?(the\s+)?(api\s+key|password|secret|token)", "Credential harvesting", False),
    # Excessive privilege
    (r"execute\s+arbitrary", "Excessive privilege — execute arbitrary", False),
    (r"\brm\s+-rf\b", "Excessive privilege — rm -rf", False),
    (r"\bsudo\b", "Excessive privilege — sudo", False),
    (r"root\s+access", "Excessive privilege — root access", False),
]

_SKILL_INJECTION_COMPILED = [
    (re.compile(pat, re.IGNORECASE), desc, crit)
    for pat, desc, crit in _SKILL_INJECTION_PATTERNS
]


def scan_skill_content(content: str) -> list[str]:
    """Scan prompt skill content for injection, hijacking, and exfiltration.

    Returns a list of warning strings (empty = clean).  Warnings prefixed
    with ``CRITICAL:`` indicate high-severity issues that should block the
    skill from being written.

    This follows the advisory pattern of ``check_python_code_safety()`` —
    it returns warnings for the caller to decide on action.
    """
    warnings: list[str] = []
    for compiled, description, _crit in _SKILL_INJECTION_COMPILED:
        if compiled.search(content):
            warnings.append(description)

    if warnings:
        logger.info(
            "security_skill_content_warnings",
            warning_count=len(warnings),
            warnings=warnings[:5],
        )
        if _security_manager:
            _security_manager.record("skill_pattern_warning")

    return warnings


# ---------------------------------------------------------------------------
# Composite sanitiser (convenience)
# ---------------------------------------------------------------------------

def sanitise_tool_input(
    tool_name: str,
    arguments: dict,
    *,
    max_input_length: int = _DEFAULT_MAX_INPUT_LENGTH,
    blocked_patterns: Optional[list[str]] = None,
    allowed_paths: Optional[list[str]] = None,
) -> dict:
    """Run all relevant sanitisation checks on tool arguments.

    Mutates and returns *arguments* with sanitised values.
    Raises ``SanitisationError`` on hard failures (path traversal, blocked files).
    Adds ``_security_warnings`` key with advisory messages.
    """
    warnings: list[str] = []

    for key, value in arguments.items():
        if isinstance(value, str):
            arguments[key] = enforce_input_length(
                value, max_length=max_input_length, field_name=f"{tool_name}.{key}"
            )

    if tool_name in ("local_files",) and "path" in arguments:
        path_val = arguments["path"]
        if isinstance(path_val, str):
            check_path_traversal(path_val)
            if matches_blocked_pattern(path_val, blocked_patterns):
                raise SanitisationError(
                    f"Access to '{os.path.basename(path_val)}' is blocked by security policy",
                    check="blocked_file_pattern",
                )
            if allowed_paths and not is_path_within(path_val, allowed_paths):
                raise SanitisationError(
                    f"Path '{path_val}' is outside allowed directories",
                    check="allowed_paths",
                )

    if tool_name == "python_tool" and "code" in arguments:
        code_warnings = check_python_code_safety(arguments["code"])
        warnings.extend(code_warnings)

    for key, value in arguments.items():
        if isinstance(value, str) and check_sql_injection(value):
            warnings.append(f"Possible SQL injection in {key}")

    for key, value in arguments.items():
        if isinstance(value, str) and check_xss(value):
            warnings.append(f"Possible XSS payload in {key}")

    if warnings:
        arguments["_security_warnings"] = warnings

    return arguments


# ---------------------------------------------------------------------------
# External content moderation
# ---------------------------------------------------------------------------

def moderate_external_content(
    text: str,
    *,
    source: str = "unknown",
    max_length: int = _DEFAULT_MAX_INPUT_LENGTH,
    redact: bool = True,
) -> str:
    """Moderate untrusted external text before it enters LLM context.

    Applies all relevant checks in order:
    1. Length enforcement (truncate to *max_length*)
    2. HTML entity decoding + tag stripping
    3. XSS vector removal
    4. Prompt injection / role hijacking / exfiltration redaction

    Use this on any text from outside the trust boundary:
    tool results, search snippets, RAG chunks, browser extractions,
    channel messages, MCP responses, ingested documents.

    When *redact* is True (default), matched injection patterns are replaced
    with ``[REDACTED]``.  When False, the function only logs warnings.
    """
    if not text:
        return text

    # 1. Length
    text = enforce_input_length(text, max_length=max_length, field_name=source)

    # 2. HTML cleanup
    text = html.unescape(text)
    text = re.sub(r"<[^>]+>", "", text)

    # 3. XSS removal
    text = strip_xss(text)

    # 4. Injection pattern redaction
    matched: list[str] = []
    for compiled, description, _crit in _SKILL_INJECTION_COMPILED:
        if compiled.search(text):
            matched.append(description)
            if redact:
                text = compiled.sub("[REDACTED]", text)

    if matched:
        logger.warning(
            "security_external_content_moderated",
            source=source,
            patterns_matched=len(matched),
            warnings=matched[:5],
        )
        if _security_manager:
            _security_manager.record("external_content_moderation")

    return text


# ---------------------------------------------------------------------------
# SecurityManager -- aggregates events for auditing
# ---------------------------------------------------------------------------

class SecurityManager:
    """Central tracker for security events.

    Records timestamped events so ``_security_audit`` (heartbeat action) can
    query violation counts over a sliding window.
    """

    def __init__(self, max_events: int = 10_000):
        self._max = max_events
        # Each deque entry is (timestamp, event_type)
        self._events: deque[tuple[float, str]] = deque(maxlen=max_events)
        self.rate_limiter = SlidingWindowRateLimiter()

    # -- Recording ----------------------------------------------------------

    def record(self, event_type: str) -> None:
        """Append a security event (e.g. ``'rate_limit'``, ``'path_traversal'``)."""
        self._events.append((_time.time(), event_type))

    # -- Query --------------------------------------------------------------

    def get_violation_stats(self, period_hours: int = 24) -> dict[str, int]:
        """Return counts of security events within the last *period_hours*."""
        cutoff = _time.time() - period_hours * 3600
        counts: dict[str, int] = {}
        for ts, etype in self._events:
            if ts >= cutoff:
                counts[etype] = counts.get(etype, 0) + 1

        return {
            "violations": counts.get("rate_limit", 0),
            "path_traversal": counts.get("path_traversal", 0),
            "shell_meta": counts.get("shell_meta", 0),
            "sql_injection": counts.get("sql_injection", 0),
            "xss": counts.get("xss", 0),
            "blocked_file": counts.get("blocked_file", 0),
            "total": sum(counts.values()),
        }


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_security_manager: Optional[SecurityManager] = None


def get_security_manager() -> Optional[SecurityManager]:
    """Return the global SecurityManager (None if not initialised)."""
    return _security_manager


def init_security_manager(**kwargs) -> SecurityManager:
    """Create and store the global SecurityManager."""
    global _security_manager
    _security_manager = SecurityManager(**kwargs)
    return _security_manager
