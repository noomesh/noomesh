# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Integration smoke tests — requires a running PAI gateway.

Run with:
    NOO_GATEWAY_URL=http://localhost:8000 pytest tests/integration/ -v
"""

import time

import httpx
import pytest


@pytest.mark.integration
class TestGatewaySmoke:
    def test_gateway_health(self, gateway_url):
        """Gateway /health returns 200."""
        resp = httpx.get(f"{gateway_url}/health", timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") in ("ok", "degraded")

    def test_autonomy_running(self, gateway_url):
        """Autonomy engine reports running=True."""
        resp = httpx.get(f"{gateway_url}/api/autonomy/status", timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("running") is True


@pytest.mark.integration
class TestIngestTriggersAutonomy:
    """End-to-end: ingest a doc -> autonomy detects unembedded -> job created."""

    def test_ingest_triggers_autonomy(self, gateway_url):
        # 1. Record baseline
        status_resp = httpx.get(f"{gateway_url}/api/v1/rag/status", timeout=10)
        assert status_resp.status_code == 200
        baseline = status_resp.json().get("unembedded_pages", 0)

        # 2. Ingest a test document
        ingest_resp = httpx.post(
            f"{gateway_url}/api/v1/docs/ingest",
            json={
                "content": "PAI integration test document for autonomy smoke test.",
                "title": f"smoke-test-{int(time.time())}",
                "doc_type": "text",
            },
            timeout=30,
        )
        assert ingest_resp.status_code in (200, 201), f"Ingest failed: {ingest_resp.text}"

        # 3. Verify unembedded_pages increased
        status_resp = httpx.get(f"{gateway_url}/api/v1/rag/status", timeout=10)
        assert status_resp.status_code == 200
        new_count = status_resp.json().get("unembedded_pages", 0)
        assert new_count > baseline, (
            f"Expected unembedded_pages > {baseline}, got {new_count}"
        )

        # 4. Poll audit log for autonomy entry (up to 120s)
        deadline = time.monotonic() + 120
        found = False
        while time.monotonic() < deadline:
            audit_resp = httpx.get(
                f"{gateway_url}/api/autonomy/audit",
                params={"limit": 20},
                timeout=10,
            )
            if audit_resp.status_code == 200:
                entries = audit_resp.json()
                if isinstance(entries, dict):
                    entries = entries.get("entries", [])
                for entry in entries:
                    if "unembedded" in str(entry.get("condition", "")).lower():
                        found = True
                        break
            if found:
                break
            time.sleep(5)

        assert found, "Autonomy did not fire an unembedded_documents condition within 120s"
