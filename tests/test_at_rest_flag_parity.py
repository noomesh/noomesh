# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The at-rest opt-out flag (i10a) is registered identically in the gateway
(`routes/settings.rs::FLAG_REGISTRY`) and the Python mirror
(`noomesh/settings.py::_FLAGS`), is DB-only, and is person-only in the setter.
"""
from __future__ import annotations

import re
from pathlib import Path

from noomesh import settings as py_settings

ROOT = Path(__file__).resolve().parent.parent
SETTINGS_RS = (ROOT / "gateway-rust" / "src" / "routes" / "settings.rs").read_text()
KEY = "at_rest.unencrypted_accepted"


def _rust_flags() -> dict[str, tuple[str, bool, bool]]:
    consts = dict(re.findall(r'const (\w+): &str = "([^"]+)";', SETTINGS_RS))
    block = SETTINGS_RS[SETTINGS_RS.index("const FLAG_REGISTRY"):SETTINGS_RS.index("struct StringSpec")]
    out = {}
    for m in re.finditer(
        r'FlagSpec \{ key: ([^,]+), category: "([^"]+)", default: (true|false),.*?db_only: (true|false) \}',
        block, re.S,
    ):
        k = m.group(1).strip()
        k = consts.get(k, k.strip('"'))
        out[k] = (m.group(2), m.group(3) == "true", m.group(4) == "true")
    return out


def test_rust_and_python_register_the_same_flags():
    rust = _rust_flags()
    assert KEY in rust and "kiosk.graph_labels" in rust, "registry parse found too little"
    py = {f.key: (f.category, f.default) for f in py_settings._FLAGS}
    assert {k: v[:2] for k, v in rust.items()} == py


def test_the_decision_flag_is_off_and_db_only():
    category, default, db_only = _rust_flags()[KEY]
    assert default is False
    assert db_only is True


def test_the_setter_refuses_non_persons_for_it():
    assert re.search(r'PERSON_ONLY_FLAGS: &\[&str\] = &\[AT_REST_UNENCRYPTED_ACCEPTED\]', SETTINGS_RS)
    setter = SETTINGS_RS[SETTINGS_RS.index("async fn settings_flags_set("):]
    gate = setter.index("needs_person(&key)")
    assert gate < setter.index("INSERT INTO noo_settings")
    assert "Origin::Person" in setter[gate:gate + 200]
