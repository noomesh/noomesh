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


def _person_only() -> list[str]:
    m = re.search(r'PERSON_ONLY_FLAGS: &\[&str\] = &\[([^\]]*)\]', SETTINGS_RS)
    assert m, "PERSON_ONLY_FLAGS not found"
    return [x.strip() for x in m.group(1).split(",") if x.strip()]


def test_the_setter_refuses_non_persons_for_it():
    assert "AT_REST_UNENCRYPTED_ACCEPTED" in _person_only()
    setter = SETTINGS_RS[SETTINGS_RS.index("async fn settings_flags_set("):]
    gate = setter.index("needs_person(&key)")
    # The write is the repo call now (i195 refactor 5); the SQL lives in repo/settings.rs.
    assert gate < setter.index("repo::settings::upsert(")
    assert "Origin::Person" in setter[gate:gate + 200]


# ── i10a PR-C: the recovery-key acknowledgement ──────────────────────────

ACK = "at_rest.recovery_key_acknowledged"


def test_the_recovery_key_acknowledgement_is_registered_off_db_only_and_person_only():
    rust = _rust_flags()
    assert ACK in rust, "the acknowledgement flag is not in FLAG_REGISTRY"
    category, default, db_only = rust[ACK]
    assert (category, default, db_only) == ("security", False, True)
    assert "AT_REST_RECOVERY_KEY_ACKNOWLEDGED" in _person_only()
    py = {f.key: f for f in py_settings._FLAGS}
    assert ACK in py and py[ACK].default is False and py[ACK].category == "security"


def test_the_cli_writes_the_same_key_it_reads():
    cli = (ROOT / "noo-cli" / "src" / "commands" / "at_rest_volume.rs").read_text()
    assert f'pub(crate) const RECOVERY_SETTING: &str = "{ACK}";' in cli
