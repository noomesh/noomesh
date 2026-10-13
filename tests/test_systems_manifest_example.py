# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The documented `systems:` example must match what the CLI actually requires.

`noo systems` parses this manifest, and `gateway-rust` parses it again on the
other side of a process boundary. Neither can check the committed example from
its own test suite: `scripts/cargo-docker.sh` mounts only the crate directory,
so `noomesh.yaml.example` does not exist inside either Rust test environment.

So the agreement is checked here, from the repo root, where the file is
visible. The Rust side owns the parse; this side owns the fact that the text
operators are told to copy actually satisfies it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "noomesh.yaml.example"

# Every field `SystemEntry` requires. A field added on the Rust side without
# being documented here fails this test rather than an operator's install.
REQUIRED = {"role", "ddl_role", "schema", "password_env", "ddl_password_env"}
OPTIONAL = {"enabled_when", "extensions"}


def _documented_systems() -> dict:
    """Uncomment the `# systems:` block and parse it."""
    text = EXAMPLE.read_text()
    # The EXACT line, not a substring: the block is introduced by a prose
    # heading that also begins "# systems:", and matching that swallowed the
    # whole explanation as if it were YAML.
    lines = text.splitlines()
    start_line = next(
        i for i, l in enumerate(lines) if l.rstrip() == "# systems:"
    )
    text = "\n".join(lines[start_line:])
    start = 0
    block = []
    for line in text[start:].splitlines():
        if not line.startswith("#"):
            break
        bare = re.sub(r"^#\s?", "", line)
        # The commented block is bounded by a box-drawing rule, which is not
        # YAML once uncommented. Dropping blank/rule lines keeps this reading
        # the real example rather than a copy that would drift from it.
        if not bare.strip() or set(bare.strip()) <= set("─-"):
            continue
        block.append(bare)
    doc = yaml.safe_load("\n".join(block))
    assert doc and "systems" in doc, "the example's systems block did not parse"
    return doc["systems"]


def test_every_documented_system_has_the_required_fields():
    for name, entry in _documented_systems().items():
        missing = REQUIRED - set(entry)
        assert not missing, f"{name}: example is missing {sorted(missing)}"
        unknown = set(entry) - REQUIRED - OPTIONAL
        assert not unknown, (
            f"{name}: example documents {sorted(unknown)}, which the CLI does not parse — "
            "either add it to SystemEntry or drop it from the example"
        )


def test_the_two_credentials_are_distinct():
    """A shared credential would collapse the DDL/runtime split silently."""
    for name, entry in _documented_systems().items():
        assert entry["password_env"] != entry["ddl_password_env"], (
            f"{name}: the migration and runtime roles must not share a credential"
        )


RETIRED_FLAGS = {"NOO_PRO_ENABLED", "NOO_TRELLION_ENABLED", "NOO_TRELLION_INTEL_ENABLED", "NOO_VOICE_ENABLED"}


def test_an_addon_named_system_carries_no_flag():
    """A system whose name is an add-on follows the `addons:` map (the
    gateway's `intent_declared`, the CLI's `systems` gate). Writing an
    `enabled_when` beside it is a second home for one boolean — and the
    example used to teach `enabled_when: NOO_PRO_ENABLED`, a flag the
    launcher refuses to START on."""
    systems = _documented_systems()
    for name in ("trellion", "evolve"):
        assert "enabled_when" not in systems[name], (
            f"{name} is an add-on: its switch is addons.{name}, not an env flag"
        )
    for name, entry in systems.items():
        assert entry.get("enabled_when") not in RETIRED_FLAGS, (
            f"{name} gates on a retired flag {entry['enabled_when']} — the launcher refuses it"
        )
