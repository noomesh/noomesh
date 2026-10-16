# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Decide what an ingest ``source`` is, and refuse what it may not read.

Every document reaches the knowledge base through ``worker.rag.ingest``:
the dashboard upload and the JSON API (text), ``noo rag ingest`` (the CLI
reads the file itself and sends text), the MCP ``noo_rag_ingest`` tool
(``source`` or ``text``), and the gateway's watched-folder and Drive loops
(a file staged under ``/data/ingest/working``, passed as ``source``).
``PageIndexRAG.ingest`` reads ANY string that names an existing file, so
without a gate here ``source="/run/secrets/db-password"`` was a one-call
read of the service's own secrets into a KB the same caller can query.

Three kinds of input, decided here and nowhere else:

* ``text``  -- stored as text and never handed to anything that could
  reinterpret it as a path.
* ``file``  -- an existing file whose REAL path (symlinks followed) lies
  under a declared root and outside the deny-list.
* refused   -- URLs (ingest does not fetch: fetch with the web tool and
  pass the text), directories and globs (ingest takes one file), and any
  path outside the roots.

The roots are the operator's declaration, the same one the native
``local_files`` read policy uses (``config.get_file_allowed_paths()``:
``tools.allowed_paths`` + watched-folder mounts + workspace), plus the
gateway's staging directory.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import structlog

logger = structlog.get_logger()

# Where the gateway's ingest loops stage watched-folder and Drive files
# (gateway-rust/src/ingest_loop.rs WORKING_DIR). Always a root: the loops
# cannot ingest anything else, and nothing but the gateway writes here.
STAGING_DIR = "/data/ingest/working"

# Never ingestable, whatever a root was declared to include. Prefix match
# on the RESOLVED path.
DENIED_PREFIXES = (
    "/app",
    "/run",
    "/var/run",
    "/tls",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    "/boot",
    "/data/config",
)

_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_GLOB_CHARS = set("*?[")
_PATH_LEAD = ("/", "~", "./", "../")
_MAX_PATHLIKE = 4096


class IngestRefused(ValueError):
    """The source may not be ingested. The message names the fix."""


@dataclass(frozen=True)
class Resolved:
    kind: str  # "text" | "file"
    value: str  # the text, or the resolved file path


def declared_roots() -> list[Path]:
    """Resolved operator-declared roots plus the staging dir.

    An unreadable config yields only the staging dir (fail closed: no
    operator-declared directory is ingestable).
    """
    raw: list[str] = []
    try:
        from ..config import get_file_allowed_paths
        raw = list(get_file_allowed_paths())
    except Exception:
        logger.warning("rag_ingest_roots_unreadable")
    raw.append(STAGING_DIR)
    roots: list[Path] = []
    for entry in raw:
        if not entry:
            continue
        try:
            r = Path(entry).resolve()
        except Exception:
            continue
        if r not in roots:
            roots.append(r)
    return roots


def _own_config_paths() -> list[Path]:
    out: list[Path] = []
    try:
        from ..config import get_config_path
        p = get_config_path()
        if p:
            out.append(Path(p).resolve())
    except Exception:
        pass
    env = os.getenv("NOO_CONFIG")
    if env:
        try:
            out.append(Path(env).resolve())
        except Exception:
            pass
    return out


def is_denied(resolved: Path) -> bool:
    """The service's own secrets, PKI, config and home: never ingestable."""
    text = str(resolved)
    for prefix in DENIED_PREFIXES:
        if text == prefix or text.startswith(prefix + "/"):
            return True
    try:
        home = Path.home().resolve()
        if home != Path("/") and (resolved == home or resolved.is_relative_to(home)):
            return True
    except Exception:
        pass
    for cfg in _own_config_paths():
        if resolved == cfg or resolved == cfg.parent / "noomesh.yaml":
            return True
    return False


def path_allowed(path: Path, roots: list[Path]) -> bool:
    """Is *path*, after resolving symlinks, inside a root and not denied?"""
    try:
        resolved = path.resolve()
    except Exception:
        return False
    if is_denied(resolved):
        return False
    return any(resolved == r or resolved.is_relative_to(r) for r in roots)


def roots_hint(roots: list[Path]) -> str:
    shown = ", ".join(str(r) for r in roots) or "(none)"
    return (
        f"allowed roots: {shown}. To allow another directory an operator adds it "
        "to tools.allowed_paths (or a watched folder) in noomesh.yaml and "
        "restarts; the service's own secrets, PKI and config are never allowed. "
        "Or send the content itself as `text`."
    )


def _pathlike(s: str) -> bool:
    """Does a single-line string look like a filesystem reference?"""
    if "\n" in s or "\x00" in s or len(s) >= _MAX_PATHLIKE:
        return False
    if s.startswith(_PATH_LEAD):
        return True
    if any(c in _GLOB_CHARS for c in s) and "/" in s and " " not in s:
        return True
    try:
        return Path(s).exists()
    except (OSError, ValueError):
        return False


def text_would_be_read_as_path(text: str) -> bool:
    """True if a path-reading ingester would open *text* instead of storing it."""
    if "\n" in text or "\x00" in text or len(text) >= _MAX_PATHLIKE:
        return False
    try:
        return Path(text).is_file()
    except (OSError, ValueError):
        return False


def classify(source: str, text: str, roots: list[Path] | None = None) -> Resolved:
    """Turn the request's ``source`` / ``text`` into text or a vetted file.

    ``text`` wins when both are given (``source`` is then only a label).
    Raises :class:`IngestRefused` with an explained message otherwise.
    """
    if text:
        return Resolved("text", text)
    source = source or ""
    stripped = source.strip()
    if not stripped:
        raise IngestRefused("Provide 'source' or 'text'")

    if _URL_RE.match(stripped):
        raise IngestRefused(
            f"ingest does not fetch URLs ({stripped.split('://', 1)[0]}://...). "
            "Fetch the page with a web tool and send its content as `text` "
            "(with `source_uri` set to the URL if you want it recorded)."
        )

    if not _pathlike(stripped):
        return Resolved("text", source)

    roots = declared_roots() if roots is None else roots
    expanded = os.path.expanduser(stripped)
    # Judge a glob by its fixed prefix: a pattern can only match inside the
    # directory it names, and `..` / symlinks in that prefix are resolved.
    has_glob = any(c in _GLOB_CHARS for c in expanded)
    probe = expanded
    if has_glob:
        probe = os.path.dirname(re.split(r"[*?\[]", expanded, maxsplit=1)[0] + "x") or "/"
    p = Path(probe)
    if not path_allowed(p, roots):
        raise IngestRefused(
            f"refusing '{stripped}': it is outside the directories noomesh may ingest "
            f"from (or is one the service keeps private). {roots_hint(roots)}"
        )
    if has_glob or p.is_dir():
        raise IngestRefused(
            f"'{stripped}' is a "
            f"{'glob' if has_glob else 'directory'}; ingest takes one file per call. "
            "Name the file, or place the files in a watched folder "
            "(`noo rag scan` ingests them)."
        )
    try:
        resolved = p.resolve(strict=True)
    except (OSError, RuntimeError):
        raise IngestRefused(f"no such file: '{stripped}'") from None
    if not resolved.is_file():
        raise IngestRefused(f"'{stripped}' is not a regular file")
    return Resolved("file", str(resolved))
