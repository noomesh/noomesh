# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The CLA text has one source: the public CLA.md is the kit master, byte for byte.

A signature is only meaningful if the text signers read is the text the kit
ships. Two copies that drift would let the public repo carry wording the kit
(and the sibling repos built from it) never had.
"""
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_public_cla_equals_kit_master():
    public = (ROOT / "CLA.md").read_bytes()
    kit = (ROOT / "internal/noomesh/licensing/CLA.md").read_bytes()
    assert public == kit, "CLA.md and internal/noomesh/licensing/CLA.md differ; edit both"


def test_cla_is_versioned_and_not_a_draft():
    text = (ROOT / "CLA.md").read_text()
    assert "**Version 1.0**" in text
    assert "DRAFT" not in text and "Draft for counsel" not in text
    assert '**"Work"**' in text, "section 3 uses the Work; it must be defined"


# PAI_TRELLION_CHECKOUT points at a checkout of the sibling repo; CI's test job
# sparse-checks-out trellion's .github, CLA.md and COMMERCIAL-LICENSE.md
# there. Locally the default is a sibling directory beside this repo.
SIBLING = Path(os.environ.get("PAI_TRELLION_CHECKOUT", ROOT.parent / "trellion"))


def _sibling(name: str) -> Path:
    path = SIBLING / name
    if not path.is_file():
        pytest.skip(f"no trellion {name} at {path}; CI checks it out")
    return path


def test_trellion_cla_equals_ours():
    """Both projects share one CLA: a one-sided edit in either repo changes what signers read."""
    assert _sibling("CLA.md").read_bytes() == (ROOT / "CLA.md").read_bytes(), (
        "trellion's CLA.md differs from noomesh's; land the change in both")


def test_trellion_commercial_licence_equals_the_kit_master():
    kit = ROOT / "internal/noomesh/licensing/COMMERCIAL-LICENSE.md"
    assert _sibling("COMMERCIAL-LICENSE.md").read_bytes() == kit.read_bytes(), (
        "trellion's COMMERCIAL-LICENSE.md differs from the kit master; land the change in both")

