# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The /health add-on enum must cover every word the gateway can emit.

This is the payload-shape half of the contract, and nothing else checks it.
`check-openapi-drift.py` and `gen-openapi.py --check` both work at PATH level:
they prove every route has an entry and every entry has a route. A response
body whose enum has drifted from the code passes both, which is exactly how
this got out of step.

The failure it guards against is not cosmetic. `addons::health_word` gained
`unlicensed` in proposal 34; the console's enum did not, so an add-on that is
switched on but unlicensed rendered as "reported a state this console does not
recognise" — the console blaming itself for a state the operator can fix with
one command.

The spec is allowed to declare a word the gateway cannot yet emit (`unhealthy`
is specced and deliberately unimplemented), but never the reverse: a word the
gateway emits and the contract omits leaves every client guessing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "src" / "noomesh" / "gateway" / "static" / "openapi.json"
ADDONS_RS = ROOT / "gateway-rust" / "src" / "addons.rs"


def _spec_enum() -> list[str]:
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    schema = spec["paths"]["/health"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    return schema["properties"]["addons"]["additionalProperties"]["enum"]


def _emitted_words() -> set[str]:
    """String literals returned by `health_word`'s match arms."""
    src = ADDONS_RS.read_text(encoding="utf-8")
    m = re.search(r"pub fn health_word\([^)]*\)[^{]*\{(.*?)\n\}", src, re.S)
    assert m, "health_word not found — the guard cannot read what is emitted"
    return set(re.findall(r'=>\s*"([a-z_]+)"', m.group(1)))


def test_every_emitted_addon_state_is_in_the_spec() -> None:
    emitted = _emitted_words()
    assert emitted, "parsed no words out of health_word"
    missing = emitted - set(_spec_enum())
    assert not missing, (
        f"/health can emit {sorted(missing)} but the OpenAPI enum does not list "
        f"it. Every client treats an unlisted word as unknown, so the operator "
        f"is told the console is confused rather than what is actually true. "
        f"Add it to the enum in {SPEC.relative_to(ROOT)} and to the console's "
        f"AddonState union."
    )


def test_specced_but_unemitted_states_are_called_out() -> None:
    """The reverse direction is allowed, but must be deliberate and documented.

    A word in the enum that no code path produces is fine — it reserves the
    shape so a client needs no change when it arrives — but only if the
    description says so. An undocumented extra is indistinguishable from a
    word someone deleted from the gateway and forgot to remove here.
    """
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    schema = spec["paths"]["/health"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]["properties"]["addons"]
    unemitted = set(schema["additionalProperties"]["enum"]) - _emitted_words()
    description = schema.get("description", "")
    for word in sorted(unemitted):
        assert word in description, (
            f"{word!r} is in the enum but nothing emits it, and the description "
            f"does not mention it. Either document why it is reserved or drop it."
        )


@pytest.mark.parametrize("word", ["enabled", "disabled", "unlicensed"])
def test_the_three_live_states_are_present(word: str) -> None:
    """Belt and braces: the parser above could silently match nothing.

    These three are what `health_word` returns today. If the regex ever stops
    finding the arms, `test_every_emitted_addon_state_is_in_the_spec` would
    pass vacuously; this fails instead.
    """
    assert word in _spec_enum()
