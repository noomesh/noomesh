# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""One data-root default, held in agreement across the codebase.

An unset NOO_DATA_ROOT used to fall back to /mnt/d/noo — one Windows
machine's drive — in about twenty places, so a node or controller without
the setting mounted directories Docker creates EMPTY and downloaded its
models again, silently. Now:

- the node agent, the noo CLI and the Python CLI share ONE default value,
  a neutral Linux path, and this test holds the two copies together;
- the compose file has NO fallback: it refuses to render without a root;
- no shipped code path falls back to a machine-specific path.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NEUTRAL = "/var/lib/noo"


def _one(pattern: str, path: str) -> str:
    text = (REPO / path).read_text()
    found = re.findall(pattern, text)
    assert len(found) == 1, f"{path}: expected one default, found {found}"
    return found[0]


def test_both_copies_of_the_default_agree_and_are_neutral():
    assert "const DefaultDataRoot = StandardLinuxRoot" in (
        REPO / "node-agent-go/internal/dataroots/dataroots.go"
    ).read_text(), "the agent's default must be its policy's standard location"
    go = _one(r'const StandardLinuxRoot = "([^"]+)"', "node-agent-go/internal/dataroots/policy.go")
    rust = _one(r'pub\(crate\) const DEFAULT_DATA_ROOT: &str = "([^"]+)";', "noo-cli/src/commands/data_root.rs")
    assert go == rust == NEUTRAL, (go, rust)


def test_compose_refuses_an_unset_root_instead_of_guessing():
    text = (REPO / "docker-compose.cluster.yml").read_text()
    uses = re.findall(r"\$\{NOO_DATA_ROOT(:[-?])", text)
    assert uses, "the compose file no longer reads NOO_DATA_ROOT; this test proves nothing"
    assert set(uses) == {":?"}, "every NOO_DATA_ROOT reference must refuse when unset (`:?`), never fall back"


def _shipped_lines(path: Path):
    """Non-comment source lines; Rust/Go test code excluded."""
    text = path.read_text(errors="replace")
    if path.suffix == ".rs":
        text = text.split("#[cfg(test)]")[0]
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith(("//", "#", "*", "///")):
            continue
        yield n, line


def test_no_shipped_code_falls_back_to_a_machine_specific_root():
    roots = ["node-agent-go", "noo-cli/src", "gateway-rust/src", "src", "scripts"]
    offenders = []
    checked = 0
    for root in roots:
        for path in (REPO / root).rglob("*"):
            if path.suffix not in {".go", ".rs", ".py", ".sh"} or not path.is_file():
                continue
            if path.name.endswith("_test.go") or "/tests/" in str(path) or path.name.startswith("test_"):
                continue
            checked += 1
            for n, line in _shipped_lines(path):
                # The one sanctioned mention: the earlier defaults an
                # undeclared node is KEPT on (never a fallback for a new one).
                if line.lstrip().startswith("var LegacyDefaults = ") and path.name == "dataroots.go":
                    continue
                if "/mnt/d/noo" in line:
                    offenders.append(f"{path.relative_to(REPO)}:{n}: {line.strip()}")
    assert checked > 100, f"only {checked} files scanned; the walk is broken"
    assert not offenders, "machine-specific data root in shipped code:\n" + "\n".join(offenders)
