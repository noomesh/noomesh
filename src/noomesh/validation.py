# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Input validation and sanitization for security"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from typing import Optional
from urllib.parse import urlparse


class ValidationError(Exception):
    """Raised when input validation fails"""
    pass


class ToolInputValidator:
    """Validates and sanitizes tool inputs to prevent security issues"""

    @staticmethod
    def sanitize_path(path: str, allow_absolute: bool = False) -> str:
        """
        Sanitize file path to prevent directory traversal attacks

        Args:
            path: File path to sanitize
            allow_absolute: Whether to allow absolute paths

        Returns:
            Normalized safe path

        Raises:
            ValidationError: If path is unsafe
        """
        if not path or not path.strip():
            raise ValidationError("Path cannot be empty")

        # Normalize the path
        normalized = os.path.normpath(path)

        # Check for directory traversal attempts
        if ".." in normalized.split(os.sep):
            raise ValidationError("Path cannot contain '..' (directory traversal)")

        # Check for absolute paths if not allowed
        if not allow_absolute and os.path.isabs(normalized):
            raise ValidationError("Absolute paths are not allowed")

        # Check for null bytes
        if "\x00" in normalized:
            raise ValidationError("Path cannot contain null bytes")

        # Check for suspicious patterns
        dangerous_patterns = [
            r'^\.|\.\./',  # Hidden files or parent dir
            r'/\./',       # Hidden directories
            r'~',          # Home directory expansion
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, normalized):
                raise ValidationError(f"Path contains dangerous pattern: {pattern}")

        return normalized

    @staticmethod
    def sanitize_code(
        code: str,
        max_length: int = 50000,
        allow_dangerous: bool = False
    ) -> str:
        """
        Sanitize Python code for execution

        Args:
            code: Python code to sanitize
            max_length: Maximum allowed code length
            allow_dangerous: Whether to allow potentially dangerous operations

        Returns:
            Validated code

        Raises:
            ValidationError: If code is unsafe
        """
        if not code or not code.strip():
            raise ValidationError("Code cannot be empty")

        if len(code) > max_length:
            raise ValidationError(
                f"Code exceeds maximum length of {max_length} characters"
            )

        # Check for null bytes
        if "\x00" in code:
            raise ValidationError("Code cannot contain null bytes")

        if not allow_dangerous:
            # Block dangerous imports and operations
            dangerous_patterns = [
                (r'import\s+os\b', "import os"),
                (r'from\s+os\s+import', "from os import"),
                (r'import\s+subprocess', "import subprocess"),
                (r'from\s+subprocess\s+import', "from subprocess import"),
                (r'import\s+sys', "import sys (use with caution)"),
                (r'__import__\s*\(', "__import__()"),
                (r'\beval\s*\(', "eval()"),
                (r'\bexec\s*\(', "exec()"),
                (r'\bcompile\s*\(', "compile()"),
                (r'\bopen\s*\(.*[\'"]w', "open() with write mode"),
                (r'globals\s*\(\)', "globals()"),
                (r'locals\s*\(\)', "locals()"),
                (r'__\w+__', "dunder methods"),
            ]

            for pattern, description in dangerous_patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    raise ValidationError(
                        f"Code contains potentially dangerous operation: {description}"
                    )

        return code

    @staticmethod
    def sanitize_url(url: str, allowed_schemes: Optional[list[str]] = None) -> str:
        """
        Sanitize a URL to prevent SSRF (M-I6).

        Rejects non-http(s) schemes, then resolves the host and rejects any URL
        whose host resolves to a private / loopback / link-local / reserved
        address — which also defeats decimal/hex/octal IP encodings and (at
        validation time) DNS-rebinding, since they resolve to the same blocked
        address. When ``NOO_EGRESS_ALLOWLIST`` is set (comma-separated domain
        suffixes), the host MUST match one of them — a mandatory egress
        allow-list.

        NOTE: this validates; it does not pin the resolved IP for the actual
        fetch, so a caller that re-resolves at connect time is still subject to
        rebinding. Fetch paths should connect to the IP this check resolved.

        Args:
            url: URL to sanitize
            allowed_schemes: Allowed URL schemes (default: http, https)

        Returns:
            The validated URL (unchanged).

        Raises:
            ValidationError: If the URL is unsafe.
        """
        if not url or not url.strip():
            raise ValidationError("URL cannot be empty")
        url = url.strip()

        if allowed_schemes is None:
            allowed_schemes = ["http", "https"]

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if not scheme:
            raise ValidationError("URL must include a scheme (e.g., http://)")
        if scheme not in allowed_schemes:
            raise ValidationError(
                f"URL scheme '{scheme}' not allowed. Allowed: {allowed_schemes}"
            )

        host = (parsed.hostname or "").lower()  # urlparse strips userinfo/port/brackets
        if not host:
            raise ValidationError("URL must include a host")

        # Mandatory egress allow-list, when configured.
        allowlist = [
            d.strip().lower()
            for d in os.getenv("NOO_EGRESS_ALLOWLIST", "").split(",")
            if d.strip()
        ]
        if allowlist:
            if not any(host == d or host.endswith("." + d) for d in allowlist):
                raise ValidationError(
                    f"host '{host}' is not in the egress allow-list (NOO_EGRESS_ALLOWLIST)"
                )

        # Never allow the obvious loopback name even before resolution.
        if host in ("localhost", "localhost.localdomain"):
            raise ValidationError("URL host resolves to a forbidden (loopback) address")

        # Resolve and reject any non-global address. Fail closed on lookup error.
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if scheme == "https" else 80),
                                       proto=socket.IPPROTO_TCP)
        except OSError as e:
            raise ValidationError(f"could not resolve host '{host}': {e}") from e

        for info in infos:
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr.split("%")[0])  # strip zone id
            except ValueError:
                raise ValidationError(f"host '{host}' resolved to an unparseable address")
            if not ip.is_global or ip.is_reserved or ip.is_multicast:
                raise ValidationError(
                    f"URL host '{host}' resolves to a forbidden ({addr}) address"
                )

        return url

    @staticmethod
    def sanitize_command(
        command: str,
        allowed_commands: Optional[list[str]] = None
    ) -> str:
        """
        Sanitize shell command to prevent command injection

        Args:
            command: Command to sanitize
            allowed_commands: Whitelist of allowed commands

        Returns:
            Validated command

        Raises:
            ValidationError: If command is unsafe
        """
        if not command or not command.strip():
            raise ValidationError("Command cannot be empty")

        command = command.strip()

        # Check for command injection patterns
        dangerous_chars = [";", "|", "&", "$", "`", "\n", "\r"]
        for char in dangerous_chars:
            if char in command:
                raise ValidationError(
                    f"Command contains forbidden character: {repr(char)}"
                )

        # If whitelist provided, check against it
        if allowed_commands:
            cmd_name = command.split()[0]
            if cmd_name not in allowed_commands:
                raise ValidationError(
                    f"Command '{cmd_name}' not in allowed list"
                )

        return command

    @staticmethod
    def validate_json_size(data: dict, max_size_bytes: int = 1_000_000) -> dict:
        """
        Validate JSON payload size

        Args:
            data: JSON data to validate
            max_size_bytes: Maximum allowed size in bytes

        Returns:
            Validated data

        Raises:
            ValidationError: If payload is too large
        """
        import json

        size = len(json.dumps(data).encode('utf-8'))
        if size > max_size_bytes:
            raise ValidationError(
                f"JSON payload size ({size} bytes) exceeds maximum ({max_size_bytes} bytes)"
            )

        return data

    @staticmethod
    def sanitize_sql(query: str) -> str:
        """
        Basic SQL injection prevention (for display/logging only)

        WARNING: This is NOT sufficient for actual SQL queries.
        Always use parameterized queries!

        Args:
            query: SQL query to sanitize

        Returns:
            Sanitized query (for display purposes)
        """
        if not query or not query.strip():
            raise ValidationError("Query cannot be empty")

        # Block obvious SQL injection patterns
        dangerous_patterns = [
            r'--',           # SQL comments
            r'/\*.*\*/',     # Multi-line comments
            r';.*drop\s+',   # Drop statements
            r';.*delete\s+', # Delete statements
            r';.*update\s+', # Update statements
            r'union\s+select', # Union injections
            r'xp_\w+',       # Extended procedures
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                raise ValidationError(
                    f"Query contains potentially dangerous pattern: {pattern}"
                )

        return query
