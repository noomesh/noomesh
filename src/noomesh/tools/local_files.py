# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from __future__ import annotations

import asyncio
import fnmatch
import glob
import structlog
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from .base import ToolSpec
from ..validation import ToolInputValidator, ValidationError

logger = structlog.get_logger(__name__)

# Binary / rich-document extensions that should NOT be read as raw bytes.
_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    # Documents
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".odt", ".ods", ".odp", ".rtf", ".epub",
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif",
    ".webp", ".svg", ".ico", ".heic", ".heif",
    # Audio / video
    ".mp3", ".wav", ".flac", ".ogg", ".mp4", ".mkv", ".avi",
    ".mov", ".webm", ".m4a",
    # Archives
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz",
    # Compiled / binary
    ".exe", ".dll", ".so", ".dylib", ".o", ".pyc", ".pyo",
    ".class", ".wasm", ".bin",
})

# Subset we can extract text from via markitdown
_EXTRACTABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".odt", ".ods", ".odp", ".rtf", ".epub", ".html", ".htm",
})

# Code file extensions → language name (for syntax hints to the LLM)
_CODE_LANGUAGES: dict[str, str] = {
    # Python
    ".py": "python", ".pyi": "python", ".pyw": "python",
    # Julia
    ".jl": "julia",
    # Go
    ".go": "go",
    # Rust
    ".rs": "rust",
    # JavaScript / TypeScript
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx", ".jsx": "jsx",
    # C / C++
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cxx": "cpp",
    ".cc": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    # Java / Kotlin / Scala
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    # C# / F#
    ".cs": "csharp", ".fs": "fsharp",
    # Ruby / Perl / PHP
    ".rb": "ruby", ".pl": "perl", ".pm": "perl", ".php": "php",
    # Shell
    ".sh": "bash", ".bash": "bash", ".zsh": "zsh",
    ".fish": "fish", ".ps1": "powershell", ".psm1": "powershell",
    # Web
    ".html": "html", ".htm": "html", ".css": "css", ".scss": "scss",
    ".sass": "sass", ".less": "less", ".vue": "vue", ".svelte": "svelte",
    # Data / Config
    ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml",
    ".xml": "xml", ".ini": "ini", ".cfg": "ini", ".conf": "conf",
    # SQL
    ".sql": "sql",
    # Markdown / text
    ".md": "markdown", ".rst": "rst", ".tex": "latex",
    # Lua / Zig / Nim / Elixir / Haskell / OCaml
    ".lua": "lua", ".zig": "zig", ".nim": "nim",
    ".ex": "elixir", ".exs": "elixir", ".hs": "haskell", ".ml": "ocaml",
    # R / MATLAB
    ".r": "r", ".R": "r", ".m": "matlab",
    # Swift / Dart
    ".swift": "swift", ".dart": "dart",
    # Docker / Make / Proto
    ".proto": "protobuf",
}

# Filenames (no extension) that are code/config
_CODE_FILENAMES: dict[str, str] = {
    "Dockerfile": "dockerfile",
    "Makefile": "makefile",
    "Jenkinsfile": "groovy",
    "Vagrantfile": "ruby",
    "Gemfile": "ruby",
    "Rakefile": "ruby",
    "CMakeLists.txt": "cmake",
    ".gitignore": "gitignore",
    ".dockerignore": "dockerignore",
    ".env": "dotenv",
    ".env.example": "dotenv",
}

try:
    from markitdown import MarkItDown as _MarkItDown
except ImportError:
    _MarkItDown = None  # type: ignore[assignment,misc]


def _get_protected_mount_paths() -> set[str]:
    """Return mount paths of directories with protected labels (e.g. code)."""
    try:
        from ..config import get_config
        return set(get_config().watched_folders.protected_mount_paths)
    except Exception:
        return set()


def _is_protected_path(path: str, protected: set[str]) -> bool:
    """Return True if *path* falls under a protected directory."""
    if not protected:
        return False
    resolved = str(Path(path).resolve())
    for p in protected:
        p_resolved = str(Path(p).resolve())
        if resolved == p_resolved or resolved.startswith(p_resolved + "/"):
            return True
    return False


def build_local_files_tool(
    default_max_bytes: int = 12000,
    allowed_paths: Sequence[str] | None = None,
    host_to_mount: dict[str, str] | None = None,
    labeled_dirs: list[dict[str, str]] | None = None,
    writable_paths: Sequence[str] | None = None,
) -> ToolSpec:
    """Build the local_files tool, optionally restricted to *allowed_paths*.

    When *allowed_paths* is non-empty every requested path must fall under
    one of the listed directories.  The allow-list is also surfaced in the
    tool description so the LLM knows which directories are accessible.

    *host_to_mount* maps host paths to container mount paths so the tool can
    auto-translate when the LLM sends a host-side path (e.g. the user says
    "read /mnt/c/Users/.../Papers/file.pdf" but inside the container the
    file is at /user-dirs/Papers/file.pdf).

    *labeled_dirs* optionally describes each directory with a category label
    so the LLM knows what kind of content is in each directory.

    *writable_paths* lists mount paths where the ``save`` action is allowed.
    Directories must be toggled writable via the dashboard.
    """
    allow_list: list[str] = list(allowed_paths) if allowed_paths else []
    path_map: dict[str, str] = dict(host_to_mount) if host_to_mount else {}
    writable_list: list[str] = list(writable_paths) if writable_paths else []

    if allow_list:
        # Build directory description with labels if available
        if labeled_dirs:
            dir_parts = []
            for ld in labeled_dirs:
                mount = ld["mount"]
                label = ld.get("label", "")
                dir_parts.append(f"{mount} ({label})" if label else mount)
            dirs_display = ", ".join(dir_parts)
        else:
            dirs_display = ", ".join(allow_list)
        description = (
            "Interact with local files and directories. "
            "Actions: 'read' (default) reads file contents, "
            "'list' lists directory entries, "
            "'find' searches for files/folders by name pattern, "
            "'save' writes content to a file (writable workspace dirs only, requires approval). "
            "Supports glob patterns. Host paths are auto-translated to container paths. "
            f"Allowed directories: {dirs_display}"
        )
    else:
        description = (
            "Interact with local files and directories. "
            "Actions: 'read' (default) reads file contents, "
            "'list' lists directory entries, "
            "'find' searches for files/folders by name pattern, "
            "'save' writes content to a file (writable workspace dirs only, requires approval). "
            "Supports glob patterns."
        )

    if writable_list:
        description += f" Writable workspace: {', '.join(writable_list)}"

    return ToolSpec(
        name="local_files",
        description=description,
        parameters={
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "File/directory paths or glob patterns."
                        + (f" Must be under: {dirs_display}" if allow_list else "")
                    ),
                },
                "action": {
                    "type": "string",
                    "enum": ["read", "list", "find", "save"],
                    "description": (
                        "Action: 'read' file contents, 'list' directory entries, "
                        "'find' files/folders by pattern, 'save' write content to file. Default: 'read'."
                    ),
                },
                "content": {
                    "type": "string",
                    "description": "Content to write (required for 'save' action). Supported extensions: .md, .txt, .csv, .json, .yaml, .html",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Max bytes per file for 'read' action (default 12000).",
                },
            },
            "required": ["paths"],
        },
        handler=lambda args: _handle_action(args, default_max_bytes, allow_list, path_map, writable_list),
    )


# ---------------------------------------------------------------------------
# Allow-list enforcement
# ---------------------------------------------------------------------------

def _check_allowed(path: str, allow_list: list[str]) -> str | None:
    """Return an error string if *path* is outside the allow-list, else None."""
    if not allow_list:
        return None
    resolved = str(Path(path).resolve())
    for allowed in allow_list:
        allowed_resolved = str(Path(allowed).resolve())
        if resolved == allowed_resolved or resolved.startswith(allowed_resolved + "/"):
            return None
    return f"[denied] {path} — not in allowed directories: {', '.join(allow_list)}"


def _blocked_patterns() -> list[str]:
    """Secret/credential filename globs that tools must never access.
    Sourced from security.blocked_file_patterns; the fallback matches the
    config default (kept in sync)."""
    try:
        from ..config import get_config
        return list(get_config().security.blocked_file_patterns)
    except Exception:
        return ["*.env", "*.key", "*.pem", "*credentials*", "*.secret",
                "*id_rsa*", "*id_ed25519*"]


def _blocked_pattern_match(filename: str) -> str | None:
    """Return the blocked glob that *filename* matches, else None. Case-insensitive.
    Applied to EVERY local_files action (read/list/find/save) so secrets can't be
    exfiltrated via reads/enumeration, not just blocked on write (H-I3)."""
    name = Path(filename).name
    for pattern in _blocked_patterns():
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(name.lower(), pattern.lower()):
            return pattern
    return None


def _check_writable(path: str, writable_list: list[str]) -> str | None:
    """Return an error string if *path* is outside the writable dirs, else None."""
    if not writable_list:
        return "[denied] No writable directories configured. Toggle a directory to writable via the dashboard."
    resolved = str(Path(path).resolve())
    for w in writable_list:
        w_resolved = str(Path(w).resolve())
        if resolved == w_resolved or resolved.startswith(w_resolved + "/"):
            return None
    return f"[denied] {path} — not in writable directories: {', '.join(writable_list)}"


# Allowed file extensions for the save action
_SAVE_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({
    ".md", ".txt", ".csv", ".json", ".yaml", ".yml", ".html",
})


def _save_file(args: Dict, allow_list: list[str], writable_list: list[str]) -> str:
    """Save content to a single file in a writable workspace directory."""
    paths = args.get("paths")
    if not paths:
        return "Error: 'paths' is required."
    if isinstance(paths, str):
        paths = [paths]
    if len(paths) != 1:
        return "Error: 'save' action only supports a single file path."

    content = args.get("content")
    if not content:
        return "Error: 'content' is required for save action."

    raw = paths[0]
    try:
        validated = ToolInputValidator.sanitize_path(str(raw), allow_absolute=True)
    except ValidationError as exc:
        return f"[error] Invalid path: {exc}"

    # 1. Allow-list check
    denied = _check_allowed(validated, allow_list)
    if denied:
        return denied

    # 2. Writable-list check
    denied = _check_writable(validated, writable_list)
    if denied:
        return denied

    # 3. Extension check
    suffix = Path(validated).suffix.lower()
    if suffix not in _SAVE_ALLOWED_EXTENSIONS:
        return (
            f"[denied] Unsupported extension '{suffix}'. "
            f"Allowed: {', '.join(sorted(_SAVE_ALLOWED_EXTENSIONS))}"
        )

    # 4. Blocked file patterns check (security.blocked_file_patterns)
    blocked = _blocked_pattern_match(validated)
    if blocked:
        return f"[blocked] '{Path(validated).name}' matches blocked pattern '{blocked}'"

    # 5. Exec approval (HIGH risk) — : via ExecApprovalGate provider
    try:
        from .._providers import ApprovalRequest, default_exec_approval_gate
        gate = default_exec_approval_gate()
        req = ApprovalRequest(
            name="local_files",
            action="write",
            arguments={"paths": [validated], "content_length": len(content)},
            raw_text=f"Save file to workspace: {validated} ({len(content)} chars)",
        )
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                decision = pool.submit(asyncio.run, gate.check(req)).result(timeout=60)
        else:
            decision = asyncio.run(gate.check(req))
        if not decision.approved:
            return (
                f"[approval denied] Write to {validated} was not approved. "
                f"Reason: {decision.reason or 'denied or timed out'}"
            )
    except Exception as exc:
        logger.warning("save_file_approval_error", error=str(exc))
        return f"[error] Approval check failed: {exc}"

    # 6. Write the file
    try:
        target = Path(validated)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        logger.info("local_files_saved", path=validated, size=len(content))
        return f"[saved] {validated} ({len(content)} chars written)"
    except Exception as exc:
        return f"[error] Failed to write {validated}: {exc}"


# ---------------------------------------------------------------------------
# Action dispatcher
# ---------------------------------------------------------------------------

def _translate_path(raw: str, path_map: dict[str, str]) -> str:
    """Translate a host-side path to its container mount if applicable."""
    if not path_map:
        return raw
    for host_prefix, mount_prefix in path_map.items():
        if raw == host_prefix or raw.startswith(host_prefix + "/"):
            translated = mount_prefix + raw[len(host_prefix):]
            logger.debug("path_translated host=%s -> container=%s", raw, translated)
            return translated
    return raw


def _translate_paths(args: Dict, path_map: dict[str, str]) -> Dict:
    """Return a copy of *args* with host paths translated to container paths."""
    if not path_map:
        return args
    paths = args.get("paths")
    if not paths:
        return args
    if isinstance(paths, str):
        paths = [paths]
    translated = [_translate_path(p, path_map) for p in paths]
    return {**args, "paths": translated}


def _handle_action(args: Dict, default_max_bytes: int, allow_list: list[str],
                    path_map: dict[str, str] | None = None,
                    writable_list: list[str] | None = None) -> str:
    args = _translate_paths(args, path_map or {})

    # Check whether any requested path falls under a protected directory.
    # If so, flag it via exec approval so the coordinator asks the user first.
    paths = args.get("paths", [])
    if isinstance(paths, str):
        paths = [paths]
    protected = _get_protected_mount_paths()
    if protected:
        protected_hits = [p for p in paths if _is_protected_path(p, protected)]
        if protected_hits:
            try:
                from .._providers import ApprovalRequest, default_exec_approval_gate
                import asyncio
                gate = default_exec_approval_gate()
                req = ApprovalRequest(
                    name="local_files",
                    action="read",
                    arguments={"paths": protected_hits},
                    raw_text=f"Read from protected (code) directory: {', '.join(protected_hits)}",
                )
                # Run the async approval check from sync context
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # We're inside an async context already — create a task
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        decision = pool.submit(
                            asyncio.run, gate.check(req)
                        ).result(timeout=10)
                else:
                    decision = asyncio.run(gate.check(req))
                if not decision.approved:
                    return (
                        f"[protected] Access to code directory requires approval. "
                        f"Paths: {', '.join(protected_hits)}. "
                        f"Reason: {decision.reason or 'approval denied or timed out'}"
                    )
            except Exception as exc:
                logger.warning("protected_path_approval_error", error=str(exc))

    action = (args.get("action") or "read").lower()
    if action == "list":
        return _list_directories(args, allow_list)
    elif action == "find":
        return _find_files(args, allow_list)
    elif action == "save":
        return _save_file(args, allow_list, writable_list or [])
    return _read_files(args, default_max_bytes, allow_list)


def _list_directories(args: Dict, allow_list: list[str]) -> str:
    """List directory contents."""
    paths = args.get("paths")
    if not paths:
        return "Error: 'paths' is required."
    if isinstance(paths, str):
        paths = [paths]

    outputs = []
    for raw in paths:
        try:
            validated = ToolInputValidator.sanitize_path(str(raw), allow_absolute=True)
        except ValidationError:
            continue

        denied = _check_allowed(validated, allow_list)
        if denied:
            outputs.append(denied)
            continue

        p = Path(validated)
        if not p.exists():
            outputs.append(f"[not found] {p}")
            continue
        if not p.is_dir():
            outputs.append(f"[not a directory] {p}")
            continue
        try:
            entries = sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
            # Don't reveal secret/credential filenames in a listing (H-I3).
            entries = [e for e in entries if _blocked_pattern_match(e.name) is None]
            lines = []
            for entry in entries[:200]:  # Cap at 200 entries
                kind = "dir" if entry.is_dir() else "file"
                size = ""
                if entry.is_file():
                    try:
                        size = f" ({entry.stat().st_size:,} bytes)"
                    except OSError:
                        pass
                lines.append(f"  [{kind}] {entry.name}{size}")
            header = f"[directory] {p} ({len(entries)} entries)"
            if len(entries) > 200:
                header += " (showing first 200)"
            outputs.append(header + "\n" + "\n".join(lines))
        except PermissionError:
            outputs.append(f"[permission denied] {p}")
        except Exception as exc:
            outputs.append(f"[error] {p}: {exc}")

    return "\n\n".join(outputs) or "No results."


def _find_files(args: Dict, allow_list: list[str]) -> str:
    """Find files/folders matching patterns."""
    paths = args.get("paths")
    if not paths:
        return "Error: 'paths' is required. Provide glob patterns like '/mnt/c/Users/*/Documents/**/Papers'."
    if isinstance(paths, str):
        paths = [paths]

    outputs = []
    for raw in paths:
        try:
            validated = ToolInputValidator.sanitize_path(str(raw), allow_absolute=True)
        except ValidationError:
            continue

        denied = _check_allowed(validated, allow_list)
        if denied:
            outputs.append(denied)
            continue

        matches = sorted(glob.glob(validated, recursive=True))
        # Filter matches against allow-list too
        if allow_list:
            matches = [m for m in matches if _check_allowed(m, allow_list) is None]
        # Don't reveal the paths of secret/credential files (H-I3).
        matches = [m for m in matches if _blocked_pattern_match(Path(m).name) is None]

        if matches:
            lines = []
            for m in matches[:100]:
                p = Path(m)
                kind = "dir" if p.is_dir() else "file"
                lines.append(f"  [{kind}] {m}")
            header = f"[find] {raw} → {len(matches)} matches"
            if len(matches) > 100:
                header += " (showing first 100)"
            outputs.append(header + "\n" + "\n".join(lines))
        else:
            outputs.append(f"[find] {raw} → no matches")

    return "\n\n".join(outputs) or "No results."


def _expand_paths(paths: Iterable[str], allow_list: list[str]) -> List[Path]:
    expanded: List[Path] = []
    for raw in paths:
        # Validate each path pattern
        try:
            # Allow absolute paths for file reading
            validated = ToolInputValidator.sanitize_path(str(raw), allow_absolute=True)
        except ValidationError:
            # Skip invalid paths instead of failing completely
            continue

        denied = _check_allowed(validated, allow_list)
        if denied:
            continue

        matches = [Path(p) for p in glob.glob(validated, recursive=True)]
        # Filter expanded matches against allow-list
        if allow_list:
            matches = [m for m in matches if _check_allowed(str(m), allow_list) is None]
        expanded.extend(matches or [Path(validated)])
    return expanded


def _read_files(args: Dict, default_max_bytes: int, allow_list: list[str]) -> str:
    paths = args.get("paths")
    if not paths:
        return "Error: 'paths' is required."
    if isinstance(paths, str):
        paths = [paths]
    max_bytes = int(args.get("max_bytes") or default_max_bytes)

    outputs = []
    for path in _expand_paths(paths, allow_list):
        # Never return the CONTENTS of a secret/credential file (H-I3): the
        # blocked-pattern set was previously enforced only on write, so `read`
        # could exfiltrate .env / *.key / id_rsa even inside an allowed dir.
        blocked = _blocked_pattern_match(path.name)
        if blocked:
            outputs.append(f"[blocked] {path} — matches blocked pattern '{blocked}' (secret file)")
            continue
        if not path.exists():
            outputs.append(f"[missing] {path}")
            continue
        if path.is_dir():
            outputs.append(f"[skip-dir] {path}")
            continue

        suffix = path.suffix.lower()

        # ── Binary / rich document files ─────────────────────────
        if suffix in _BINARY_EXTENSIONS:
            text = _extract_text(path, suffix, max_bytes)
            outputs.append(text)
            continue

        # ── Regular text files ───────────────────────────────────
        try:
            data = path.read_bytes()
            # Detect binary content even without a known extension
            # Check for null bytes and common binary file signatures
            _is_binary = (
                b"\x00" in data[:4096]
                or data[:5] == b"%PDF-"
                or data[:4] in (b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"PK\x03\x04")
            )
            if _is_binary:
                # Try text extraction if it looks like a known document type
                if suffix in _EXTRACTABLE_EXTENSIONS:
                    text = _extract_text(path, suffix, max_bytes)
                    outputs.append(text)
                else:
                    outputs.append(
                        f"[binary] {path} ({len(data):,} bytes) — "
                        "binary file, cannot display as text"
                    )
                continue
            if len(data) > max_bytes:
                data = data[:max_bytes]
                truncated = True
            else:
                truncated = False
            text = data.decode("utf-8", errors="replace")

            # Code-aware formatting: line numbers + language hint
            lang = _detect_language(path)
            if lang:
                outputs.append(_format_code(path, text, lang, truncated))
            else:
                outputs.append(f"[file] {path}\n{text}")
        except Exception as exc:
            outputs.append(f"[error] {path}: {exc}")

    return "\n\n".join(outputs)


def _extract_text(path: Path, suffix: str, max_bytes: int) -> str:
    """Try to extract readable text from a binary/document file.

    Copies to a local temp file first to avoid CIFS/9p/OneDrive mount
    locking issues, then processes the local copy.
    """
    size = path.stat().st_size
    meta = f"{path} ({size:,} bytes, {suffix} file)"

    # Try markitdown for extractable document formats
    if suffix in _EXTRACTABLE_EXTENSIONS and _MarkItDown is not None:
        import shutil
        import tempfile

        tmp_path: Path | None = None
        try:
            # Copy to local tmp to avoid CIFS/OneDrive mount issues
            with tempfile.NamedTemporaryFile(
                suffix=suffix, prefix="noo_read_", delete=False,
            ) as tmp:
                tmp_path = Path(tmp.name)
            # copyfile (not copy/copy2) — copy's copymode fails with EPERM
            # when source is CIFS (0o777) and dest has different owner UID
            shutil.copyfile(str(path), str(tmp_path))

            md = _MarkItDown()
            result = md.convert(str(tmp_path))
            text = (result.text_content or "").strip()
            if text:
                if len(text) > max_bytes:
                    text = text[:max_bytes] + "\n... [truncated]"
                return f"[document] {meta}\n{text}"
            logger.warning("local_files_extract_empty", path=str(path), suffix=suffix)
        except Exception as exc:
            logger.warning("local_files_extract_failed", path=str(path),
                           suffix=suffix, error=str(exc))
        finally:
            if tmp_path:
                tmp_path.unlink(missing_ok=True)

    # For images: report metadata only (coordinator can use OCR tools separately)
    if suffix in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif",
                   ".webp", ".heic", ".heif"):
        return (
            f"[image] {meta} — use an image analysis tool or "
            "`noo rag ingest` to extract content"
        )

    # Generic binary: just report what it is
    return f"[binary] {meta} — cannot display as text"


def _detect_language(path: Path) -> str | None:
    """Detect programming language from file extension or name."""
    # Check exact filename first (Dockerfile, Makefile, etc.)
    lang = _CODE_FILENAMES.get(path.name)
    if lang:
        return lang
    # Check prefix patterns (Dockerfile.gateway, Makefile.prod, etc.)
    name = path.name
    if name.startswith("Dockerfile"):
        return "dockerfile"
    if name.startswith("Makefile"):
        return "makefile"
    # Then check extension
    return _CODE_LANGUAGES.get(path.suffix.lower()) or _CODE_LANGUAGES.get(path.suffix)


def _format_code(path: Path, text: str, lang: str, truncated: bool) -> str:
    """Format code with line numbers and a language-tagged fence."""
    lines = text.splitlines()
    total = len(lines)
    width = len(str(total)) or 1
    numbered = "\n".join(
        f"{i:{width}d}  {line}" for i, line in enumerate(lines, 1)
    )
    header = f"[{lang}] {path} ({total} lines)"
    if truncated:
        header += " [truncated]"
    return f"{header}\n```{lang}\n{numbered}\n```"
