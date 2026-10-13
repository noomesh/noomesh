# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""docs/reference/env.md and config.md versus the code that reads the variables.

A variable documented here that nothing reads is an operator setting a dial
that is wired to nothing (the `NOO_RERANK_URL` and `NOO_HOSTFS_ROOT` rows sat
here for months after their readers were deleted); a variable the settings
registry accepts that no doc names is a switch nobody can find. Two directions:

* every `UPPER_CASE` name in env.md is referenced by at least one tracked file
  outside docs/, internal/ and tests/ (a Rust/Go/Python reader, a compose file,
  a launcher script, or the CLI) — unless its own row says it is retired,
  removed, unread, or a refusal, which is the documented way to keep a stale
  name out of an operator's `.env`;
* every key the gateway's settings registry (`routes/settings.rs`, the
  behavioural-flag and string registries) accepts is named in config.md or
  env.md;
* a curated list of operator-facing knobs that must stay documented.

Planted: add `| `NOO_NOT_READ_ANYWHERE` | — | x |` to env.md and the first
test names it; drop `NOO_OPS_WAIT_GRAPH_ENTITY_CLEANUP_SECS` from both docs
and the second names it.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_MD = ROOT / "docs" / "reference" / "env.md"
CONFIG_MD = ROOT / "docs" / "reference" / "config.md"
SETTINGS_RS = ROOT / "gateway-rust" / "src" / "routes" / "settings.rs"

# Top-level directories that are prose, tests or scratch. (`node-agent-go/internal`
# is code, so "internal" is only skipped at the top.)
SKIP_TOP = {"docs", "internal", "tests", ".worktrees", "legacy"}
SKIP_ANYWHERE = {".git", "target", "node_modules", "__pycache__"}
SOURCE_SUFFIXES = {".rs", ".go", ".py", ".sh", ".yml", ".yaml", ".tmpl", ".toml", ".conf",
                   ".example", ".env", ".json", ".ini", ".service"}
# Set by the shell, the CI runner or compose itself, not read by this tree.
ENVIRONMENT_PROVIDED = {"HOME", "PWD", "PATH", "RUST_LOG", "DOCKER_HOST", "INVOCATION_ID"}
# Read by an add-on sibling repository, named in env.md's "Add-on containers"
# section and documented in that repository's docs/configuration.md.
SIBLING_OWNED = {"TRELLION_ENTITY_QUALITY", "TRELLION_ENTITY_QUALITY_CONFIG",
                 "RETRIEVAL_TRACKER_MAX_RECORDS", "NOO_TRELLION_SCHEMA"}
# A row carrying one of these words documents the ABSENCE of a reader on purpose.
RETIRED_WORDS = ("retired", "removed", "unread", "refus", "gone", "inert", "ignored", "no longer")

NAME = re.compile(r"`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")


def _corpus() -> str:
    parts: list[str] = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if rel.parts[0] in SKIP_TOP or set(rel.parts) & SKIP_ANYWHERE or not path.is_file():
            continue
        if path.suffix in SOURCE_SUFFIXES or path.name.startswith(("Dockerfile", ".env")):
            try:
                parts.append(path.read_text(errors="ignore"))
            except OSError:
                continue
    return "\n".join(parts)


def _documented(md: Path) -> dict[str, str]:
    """name -> the table row / paragraph line it appears on (all occurrences joined)."""
    out: dict[str, list[str]] = {}
    for line in md.read_text().splitlines():
        for name in NAME.findall(line):
            out.setdefault(name, []).append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def test_every_documented_variable_has_a_reader() -> None:
    docs = _documented(ENV_MD)
    assert len(docs) > 300, "env.md parse found almost nothing; the guard is blind"
    corpus = _corpus()
    ops_src = (ROOT / "gateway-rust" / "src" / "routes" / "ops.rs").read_text()
    op_types = {n.upper().replace(".", "_") for n in re.findall(r'name:\s*"([a-z_]+\.[a-z_]+)"', ops_src)}
    assert "GRAPH_RECLUSTER" in op_types, "op type parse found nothing"
    unread = []
    for name, rows in sorted(docs.items()):
        if name in ENVIRONMENT_PROVIDED or name in SIBLING_OWNED:
            continue
        if name in op_types:  # the <TYPE> in NOO_OPS_WAIT_<TYPE>_SECS, spelled graph.recluster in code
            continue
        if re.search(rf"(?<![A-Z0-9_]){re.escape(name)}(?![A-Z0-9_])", corpus):
            continue
        # not found: acceptable only if every mention says it is gone
        if all(any(w in line.lower() for w in RETIRED_WORDS) for line in rows.splitlines()):
            continue
        unread.append(name)
    assert not unread, (
        "env.md documents variables nothing in the tree reads or passes: "
        f"{unread}. Remove the row, or mark it retired if an operator may still "
        "have it set."
    )


def test_every_settings_registry_key_is_documented() -> None:
    src = SETTINGS_RS.read_text()
    keys = set(re.findall(r'key:\s*"([A-Z][A-Z0-9_]+)"', src))
    assert "NOO_HEARTBEAT_TZ" in keys and len(keys) >= 10, "settings registry parse found too little"
    text = ENV_MD.read_text() + CONFIG_MD.read_text()
    missing = sorted(
        k for k in keys
        if k not in text
        # per-op-type wait keys are documented as the NOO_OPS_WAIT_<TYPE>_SECS family
        and not (k.startswith("NOO_OPS_WAIT_") and "NOO_OPS_WAIT_<TYPE>_SECS" in text)
    )
    assert not missing, f"settings registry keys documented in neither env.md nor config.md: {missing}"


# Operator-facing knobs added deliberately; each must stay on the page.
MUST_BE_DOCUMENTED = {
    "env.md": [
        "PAGEINDEX_EMBEDDING_EXTRA_URLS", "EMBEDDING_DIM", "OLLAMA_EMBED_NUM_PARALLEL",
        "OLLAMA_EMBED_CPU_NUM_PARALLEL", "COMPOSE_PROFILES", "RETRIEVAL_TRACKER_PATH",
        "NOO_WORKER_SURFACES", "NOO_HEARTBEAT_TZ", "NOO_OPS_WAIT_<TYPE>_SECS",
        "TRELLION_EMBED_", "TRELLION_ENTITY_QUALITY", "TRELLION_ENTITY_QUALITY_CONFIG",
    ],
    "config.md": [
        "embedding_extra_urls", "embedding_dim", "NOO_OPS_WAIT_GRAPH_ENTITY_CLEANUP_SECS",
        "NOO_HEARTBEAT_TZ", "NOO_REPORTS_DRIVE_FOLDER_ID",
    ],
}


def test_curated_knobs_stay_documented() -> None:
    texts = {"env.md": ENV_MD.read_text(), "config.md": CONFIG_MD.read_text()}
    missing = {
        doc: [n for n in names if n not in texts[doc]]
        for doc, names in MUST_BE_DOCUMENTED.items()
    }
    missing = {d: m for d, m in missing.items() if m}
    assert not missing, f"operator-facing knobs missing from the reference: {missing}"
