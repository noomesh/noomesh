# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""/etc/noo/data-root-owner is the local host's statement alone (i677,
operator 2026-11-14): no provision-bundle kind carries it and the applier never
writes it, so nothing from the controller can name a data-root owner on a
node. Only the local self-install (provision.rs, inside its own sudo) writes it."""

import re
from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
FILE = "/etc/noo/data-root-owner"


def test_the_applier_never_writes_the_owner_file_and_no_kind_names_it():
    apply = (ROOT / "scripts/noo-apply.sh").read_text()
    assert FILE not in apply and "data-root-owner" not in apply, "noo-apply must never write it"
    kinds = re.search(r'^KNOWN_KINDS="([^"]*)"', apply, re.M).group(1).split()
    assert kinds and not any("owner" in k for k in kinds), kinds


def test_the_bundle_builder_has_no_kind_for_it_and_only_the_local_lane_writes_it():
    prov = (ROOT / "noo-cli/src/commands/provision.rs").read_text()
    uses = [m.start() for m in re.finditer(re.escape("DATA_ROOT_OWNER_FILE"), prov)]
    assert uses, "the constant exists"
    # Only the declaration, the local script and the local lane's read use it
    # (tests are not product code: own_code_lines drops them, lines kept).
    code = rs.own_code_lines(prov)
    lines = [l.strip() for l in code.splitlines() if "DATA_ROOT_OWNER_FILE" in l]
    assert len(lines) == 3, lines
    assert '"data-root-owner"' not in code, "no bundle kind is named after it"
    # Elsewhere the path may be NAMED (verify's remedy tells the reader where
    # the declaration lives) but never written: no write verb beside it.
    writes = re.compile(r"write|tee |install |File::create|OpenOptions|>")
    for other in (ROOT / "noo-cli/src").rglob("*.rs"):
        if other.name == "provision.rs":
            continue
        for l in rs.own_code_lines(other.read_text()).splitlines():
            if FILE in l:
                assert not writes.search(l), f"{other}: writes the owner file: {l.strip()}"
