# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Every core service-key name must stay unavailable to an add-on."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_core_service_keys_are_reserved_in_the_shared_addon_validator():
    secrets = (ROOT / 'noo-cli/src/commands/secrets.rs').read_text()
    registry = secrets.split('pub const CORE_REGISTRY:', 1)[1].split('\n];', 1)[0]
    names = {key.lower().replace('_', '-') for key in re.findall(r'key: "NOO_SVC_KEY_([A-Z0-9_]+)"', registry)}
    shared = (ROOT / 'crates/addon-manifest/src/lib.rs').read_text()
    reserved = shared.split('pub const CORE_SERVICE_NAMES:', 1)[1].split(';', 1)[0]
    assert names, 'Core registry parser must not silently match nothing'
    assert names <= set(re.findall(r'"([a-z0-9-]+)"', reserved))
