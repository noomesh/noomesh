# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The operator's friendly-URL selection must reach the gateway container."""
from pathlib import Path

import yaml


def test_voice_space_selection_is_forwarded_to_gateway():
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / 'docker-compose.cluster.yml').read_text())
    environment = compose['services']['gateway']['environment']
    assert 'NOO_VOICE_SPACE_ADDON=${NOO_VOICE_SPACE_ADDON:-}' in environment
