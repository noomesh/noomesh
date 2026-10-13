# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The ops settings are registered in BOTH registries, with the same defaults.

`gateway-rust/src/routes/settings.rs::STRING_REGISTRY` is authoritative (it is what
`POST /api/settings/flags/set` accepts); `src/noomesh/settings.py::_STRING_SETTINGS`
mirrors it for Python readers. A key in one and not the other is a setting an admin
can change in one place and nothing reads in the other.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _rust():
    src = (ROOT / "gateway-rust/src/routes/settings.rs").read_text()
    return dict(re.findall(r'StringSpec \{ key: "(NOO_OPS_[A-Z_]+)", category: "ops",\s*default: "([^"]*)"', src))


def _python():
    from noomesh import settings
    return {k: v for k, v in settings._STRING_SETTINGS.items() if k.startswith("NOO_OPS_")}


def test_ops_string_settings_are_mirrored_with_equal_defaults():
    rust, py = _rust(), _python()
    assert rust, "no NOO_OPS_* settings found in STRING_REGISTRY"
    assert rust == py


def test_every_registered_op_type_has_a_wait_setting():
    ops = (ROOT / "gateway-rust/src/routes/ops.rs").read_text()
    names = re.findall(r'name: "([a-z_.]+)",\n\s*summary', ops)
    # A tripwire, deliberately exact: a new op type must arrive with its wait
    # setting in BOTH registries (bump this when you add one).
    assert len(names) == 8
    for name in names:
        key = "NOO_OPS_WAIT_" + name.upper().replace(".", "_") + "_SECS"
        assert key in _rust(), f"{key} missing from STRING_REGISTRY"
