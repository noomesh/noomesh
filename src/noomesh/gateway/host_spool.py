# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Host-watcher command spool — shared write helper.

The gateway container has ZERO Docker access (no /var/run/docker.sock, no
docker CLI). Instead of talking to Docker directly, every container-lifecycle
operation (recreate / restart / rebuild) is written as an atomic JSON command
file into the spool dir (``NOO_HOST_SPOOL_DIR``, default ``/var/run/noo-spool``),
which is a bind mount of the host's ``./.noo-host-spool``. A host-side daemon
(``noo-hostd``, node-agent-go/cmd/noo-hostd; it replaced the retired bash
``noo-host-watcher.sh``) watches that dir and performs the actual
docker/compose operations from the host project root.

Command JSON schema (see node-agent-go/internal/hostd for the consumer):
    {
      "op":           "recreate" | "restart" | "rebuild" | "backup"
                      | "rotate" | "stack-rebuild",
      "service":      "<compose service or container name>",
      "health_check": bool,                  # recreate only
      "rollback":     {"sha": "...", "files": [...]} | None,  # audit/alert only
      "args":         ["--quick", ...],      # stack-rebuild only
      "requested_by": "<caller id>",
      "ts":           "<iso8601 utc>"
    }

Atomic write: a temp file is created in the spool dir, then ``os.replace``'d to
``<name>.cmd.json`` (rename is atomic within the same directory). The filename
scheme is ``<time_ns>-<8 hex>`` so names are unique and ordered.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

DEFAULT_SPOOL_DIR = "/var/run/noo-spool"


def _spool_dir() -> str:
    return os.environ.get("NOO_HOST_SPOOL_DIR", DEFAULT_SPOOL_DIR)


def _command_name() -> str:
    """Unique, ordered command name: <unix_nanos>-<8 hex>."""
    return f"{time.time_ns()}-{os.urandom(4).hex()}"


def write_command(
    op: str,
    service: str,
    *,
    health_check: bool = False,
    rollback: dict | None = None,
    requested_by: str = "",
    args: list[str] | None = None,
    spool_dir: str | None = None,
) -> str | None:
    """Write a spool command file atomically. Returns the file path on
    success, or None on failure. Never raises — a failed spool write must
    not crash the caller (it just means the host watcher won't act).

    ``args`` carries extra arguments for ops that take them (currently
    ``stack-rebuild``); the watcher validates each one against a strict
    allowlist. ``spool_dir`` overrides the env-derived path — the host-side
    CLI writes straight to ``<repo>/.noo-host-spool`` instead of the
    container mount point."""
    spool_dir = spool_dir or _spool_dir()
    payload: dict[str, Any] = {
        "op": op,
        "service": service,
        "health_check": bool(health_check),
        "rollback": rollback,
        "args": list(args or []),
        "requested_by": requested_by,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    name = _command_name()
    final_path = os.path.join(spool_dir, f"{name}.cmd.json")
    try:
        os.makedirs(spool_dir, exist_ok=True)
        data = json.dumps(payload)
        # Write to a temp file in the SAME dir, then atomic rename so the
        # watcher never observes a half-written file.
        fd, tmp_path = tempfile.mkstemp(
            prefix=f".{name}.", suffix=".tmp", dir=spool_dir
        )
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            # mkstemp creates 0600 owned by the gateway's uid (65532). The host
            # watcher runs as the operator (uid 1000) and is NOT the owner, so
            # under 0600 it cannot read the command at all — jq then reports
            # "not valid JSON" and the command is REJECTED, which reads like a
            # malformed payload rather than a permission problem. Group-readable
            # lets the watcher (same gid via the spool dir's setgid bit) read it.
            # Still not world-readable: this is a host-executor command channel.
            os.chmod(tmp_path, 0o640)
            os.replace(tmp_path, final_path)
        except Exception:
            # Clean up the temp file on any failure before re-raising.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        logger.info(
            "host_spool_command_written",
            op=op,
            service=service,
            health_check=bool(health_check),
            requested_by=requested_by,
            path=final_path,
        )
        return final_path
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "host_spool_command_write_failed",
            op=op,
            service=service,
            spool_dir=spool_dir,
            error=f"{type(exc).__name__}: {exc}",
        )
        return None
