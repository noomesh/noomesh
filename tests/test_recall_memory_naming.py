# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The subsystem is called "recall memory"; "video memory" is a historical name.

Phase A renamed every surface a person reads.
This keeps the old term from creeping back into them. Identifiers that still
carry the old spelling (the deprecated `video_memory` section,
NOO_VIDEO_MEMORY_PATH, the /api/v1/video-memory/* alias paths, the pip extra
alias) are stripped from a line before it is checked, so a line that only
names one of those is fine and a line that also says "video memory" in prose
is not.

Phase B renamed the identifiers too, keeping the old ones as
aliases for one release after 0.6.0; the second half of this file holds code
to the new names outside the alias sites.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SURFACES = [
    "docs",
    "prompts",
    "noo-cli/src",
    "noo-cli/NOO_CLI.md",
    "gateway-rust/mcp-tools.json",
    "gateway-rust/mcp-tools-local.json",
    "src/noomesh/mcp/tool_defs",
    "src/noomesh/recall_cli.py",
    "src/noomesh/gateway/static/openapi.json",
    "src/noomesh/gateway/static/openapi.public.json",
    "ui/apps/web/src",
    "ui/mock",
    "ui/contracts/openapi.json",
    "ui/packages/api/src/schema.d.ts",
]
SUFFIXES = {".md", ".json", ".py", ".rs", ".ts", ".tsx", ".css", ".mjs", ".yaml", ".yml"}

# Spellings that are identifiers, not prose.
ALLOWED = re.compile(
    r"video_memory|VIDEO_MEMORY|VideoMemory"
    r"|/video-memory|video-memory/"
    r"|['\"`]video-memory['\"`]"
    r"|\[.*video-memory.*\]",
)
PROSE = re.compile(r"video[ -]memory", re.IGNORECASE)


def _files():
    for rel in SURFACES:
        p = ROOT / rel
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix in SUFFIXES and "node_modules" not in f.parts:
                    yield f


def test_no_video_memory_prose_on_user_facing_surfaces():
    offenders = []
    for f in _files():
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            if PROSE.search(ALLOWED.sub("", line)):
                offenders.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()[:100]}")
    assert not offenders, 'say "recall memory", not "video memory":\n' + "\n".join(offenders)


def test_guard_sees_the_surfaces():
    assert len(list(_files())) > 50
    assert len(list(_code_files())) > 300


# ── Phase B: internal identifiers too ─────────────────────────
#
# The internals were renamed with aliases for one release after 0.6.0. Code may
# name the old spelling only where it IS the alias, a sibling repo's name, or
# the data directory (which keeps its path on purpose).

CODE = [
    "src/noomesh",
    "gateway-rust/src",
    "noo-cli/src",
    "noo-cli/tests",
    "config",
    "ui/apps/web/src",
    "ui/mock",
    "docker",
    "scripts",
    "noomesh.yaml.example",
    "docker-compose.yml",
    "docker-compose.trellion.yml",
    "docker-compose.trellion-intel.yml",
]
CODE_SUFFIXES = SUFFIXES | {".sh", ".toml", ".example", ""}
# Generated from the alias routes (each old operation is `deprecated: true`).
GENERATED = {"src/noomesh/gateway/static"}
# Files that hold the alias code itself: the old spelling is their job.
ALIAS_FILES = {
    "src/noomesh/config.py",              # section/env/class aliases + warnings
    "src/noomesh/gateway/deps.py",        # Services.video_memory property
    "gateway-rust/src/routes/recall.rs",  # /api/v1/video-memory/* alias routes
    "gateway-rust/src/routes/settings.rs",  # RENAMED_CONFIG_SECTIONS
    "gateway-rust/src/auth.rs",           # config:video_memory scope alias
    "noo-cli/src/commands/secrets.rs",    # EQUIVALENT_SCOPES
    "noo-cli/src/commands/cluster_verify.rs",
    "docker-compose.trellion.yml",        # NOO_VIDEO_MEMORY_PATH for trellion
    "noomesh.yaml.example",               # keeps `video_memory:` until evolve reads the new key
}
OLD_IDENT = re.compile(r"video_memory|VideoMemory|VIDEO_MEMORY|video-memory|vidmem", re.IGNORECASE)
# A line may still name the old spelling when it says why.
OK_LINE = re.compile(
    r"846|[Dd]eprecated|retired|followups/"
    r"|VideoMemoryManager|VideoMemoryConfig as _Trellion|memory\.video|trellion\.live\.video"  # trellion's
    r"|/data/video[-_]memory|default=\"video-memory\"|\{base_dir\}/video-memory"  # data locations
)


def _code_files():
    for rel in CODE:
        p = ROOT / rel
        files = [p] if p.is_file() else (p.rglob("*") if p.is_dir() else [])
        for f in files:
            r = str(f.relative_to(ROOT))
            if (f.is_file() and (f.suffix in CODE_SUFFIXES or f.name.startswith("Dockerfile"))
                    and "node_modules" not in f.parts and "target" not in f.parts
                    and not any(r.startswith(g) for g in GENERATED)):
                yield f


def test_old_identifiers_only_where_they_are_the_alias():
    offenders = []
    for f in _code_files():
        rel = str(f.relative_to(ROOT))
        if rel in ALIAS_FILES:
            continue
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            if OLD_IDENT.search(line) and not OK_LINE.search(line):
                offenders.append(f"{rel}:{n}: {line.strip()[:100]}")
    assert not offenders, (
        "the internals say recall_memory now; name the old spelling only "
        "in an alias site, with a reason:\n" + "\n".join(offenders)
    )


def test_alias_files_still_carry_their_alias():
    """The allow-list is not a blanket: each file on it must still hold the
    old spelling. When the aliases go (release after 0.6.0), drop the rows."""
    stale = [rel for rel in ALIAS_FILES if not OLD_IDENT.search((ROOT / rel).read_text())]
    assert not stale, stale
