# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Integration test configuration — auto-skip when no gateway is available."""

import os

import pytest

GATEWAY_URL = os.getenv("NOO_GATEWAY_URL", "")


def pytest_collection_modifyitems(config, items):
    """Skip integration tests when NOO_GATEWAY_URL is not set."""
    if GATEWAY_URL:
        return
    skip = pytest.mark.skip(reason="NOO_GATEWAY_URL not set — skipping integration tests")
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(skip)


@pytest.fixture
def gateway_url() -> str:
    """Base URL of the running PAI gateway."""
    return GATEWAY_URL.rstrip("/")
