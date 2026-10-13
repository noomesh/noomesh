# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Provisioning removes every CA filename this project has retired.

A CA left in `/usr/local/share/ca-certificates/` under an old name is not
inert. `noomesh-cluster-ca.crt` sat there at 0640 root:root after the
rename, and an unreadable file in that directory makes the WHOLE platform
trust store unreadable to non-root processes: the harness could not reach
the bus and crash-looped roughly 1900 times before anyone connected the
two. Nothing installed that name any more, and nothing
removed it either.

`prep-host.sh` already swept the `metis-` and `pai-` names, so the sweep
existed — the rename just never added itself to it. These pin both halves:
every retired name is swept, and the name provisioning currently INSTALLS
is not (sweeping that would delete the anchor on every re-prep, and the
node would then refuse the first bundle).
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PREP = REPO / "scripts/prep-host.sh"
CLI = REPO / "noo-cli/src/commands/security_local.rs"

CA_DIR = "/usr/local/share/ca-certificates"
RETIRED = ["metis-cluster-ca.crt", "pai-cluster-ca.crt", "noomesh-cluster-ca.crt"]


def sweep_block() -> str:
    """The `for CA in … ; do … done` loop that deletes retired anchors."""
    body = PREP.read_text()
    m = re.search(r"for CA in (.*?)\bdo\b", body, re.S)
    assert m, "prep-host.sh no longer has a `for CA in …` sweep at all"
    return m.group(1)


def test_every_retired_ca_name_is_swept() -> None:
    swept = sweep_block()
    missing = [n for n in RETIRED if f"{CA_DIR}/{n}" not in swept]
    assert not missing, f"prep-host.sh leaves these retired anchors behind: {missing}"


def test_the_name_provisioning_installs_is_not_swept() -> None:
    """Derived from the CLI's own constant, not restated here."""
    m = re.search(r'LINUX_CA_DEST[^=]*=\s*"([^"]+)"', CLI.read_text())
    assert m, "could not find LINUX_CA_DEST in security_local.rs"
    current = m.group(1)
    assert current.startswith(CA_DIR), f"unexpected trust-store path {current}"
    assert current not in sweep_block(), (
        f"prep-host.sh sweeps {current}, the anchor it installs — a re-prep would "
        "delete the CA and the node would refuse the next bundle"
    )


def test_the_sweep_refreshes_the_store_after_deleting() -> None:
    """A deleted file with a stale symlink still pointing at it is the
    residue that started this. The loop must re-run update-ca-certificates."""
    body = PREP.read_text()
    m = re.search(r"for CA in .*?\bdone\b", body, re.S)
    assert m, "no sweep loop found"
    assert "update-ca-certificates" in m.group(0), (
        "the sweep deletes the file but never refreshes the store, so the hash "
        "symlinks are left dangling"
    )
