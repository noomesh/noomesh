# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A gate key the gateway refuses to boot with must be known to the CLI that
rolls the stack, and must never be written by the wizard.

The gateway REFUSES TO START while `noomesh.yaml` carries a retired gate
(`RETIRED_YAML_GATES` in gateway-rust/src/posture.rs), which is right: a
security control the operator set in YAML and the gateway ignores exists
only in their head. But the refusal lands during a roll, when the API that
would fix it is exactly what is down — that happened live on 2026-09-12,
and the controller stayed down until the key was removed by hand.

Two rules keep that from recurring, and the crates share no library, so
these are pinned here rather than by a type:

1. `noo upgrade --stack` knows the same list the gateway refuses on, so it
   can migrate the key into posture BEFORE rolling.
2. No onboarding path writes one of those keys back into the file.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POSTURE_RS = ROOT / "gateway-rust/src/posture.rs"
UPGRADE_RS = ROOT / "noo-cli/src/commands/upgrade.rs"
ONBOARD_DIR = ROOT / "noo-cli/src/onboard"

ENTRY = re.compile(r'\(\s*"([a-z_]+)"\s*,\s*"([a-z_]+)"\s*,\s*"([A-Z_0-9]+)"\s*\)')


def _entries(path: Path, const_name: str) -> set[tuple[str, str, str]]:
    src = path.read_text()
    start = src.index(const_name)
    body = src[start : src.index("];", start)]
    return set(ENTRY.findall(body))


def test_the_cli_knows_every_gate_the_gateway_refuses_on() -> None:
    gateway = _entries(POSTURE_RS, "RETIRED_YAML_GATES")
    cli = _entries(UPGRADE_RS, "RETIRED_YAML_GATES")
    assert gateway, "the gateway's retired-gate list could not be parsed"
    assert gateway == cli, (
        "gateway-rust/src/posture.rs and noo-cli/src/commands/upgrade.rs disagree about "
        f"which YAML gates are retired: gateway-only={sorted(gateway - cli)}, "
        f"cli-only={sorted(cli - gateway)}. A gateway that refuses to boot on a key the "
        "upgrade does not migrate takes the controller down mid-roll."
    )


def test_the_wizard_never_writes_a_retired_gate_key() -> None:
    gateway = _entries(POSTURE_RS, "RETIRED_YAML_GATES")
    offenders: list[str] = []
    for rs in sorted(ONBOARD_DIR.rglob("*.rs")):
        src = rs.read_text()
        for _section, key, _posture in gateway:
            # A write looks like `"<key>"` used as a YAML key; a mention in a
            # comment does not.
            for line in src.splitlines():
                stripped = line.strip()
                if stripped.startswith("//") or f'"{key}"' not in stripped:
                    continue
                offenders.append(f"{rs.relative_to(ROOT)}: {stripped[:100]}")
    assert not offenders, (
        "an onboarding path writes a key the gateway refuses to start with; a fresh "
        "install would come up dead:\n  " + "\n  ".join(offenders)
    )
