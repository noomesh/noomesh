# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""End-to-end checks for the native Rust external MCP door (`/mcp/user`; the `/mcp/external` alias was removed in stack-v0.2.40).

These drive the real HTTP endpoint, which the unit tests deliberately do not.
That distinction is the point: PR #408 shipped an `UnboundLocalError` that
500'd every internal MCP request, and it survived a green suite because every
test exercised the identity helpers in isolation and none exercised a request
path. Door behaviour needs door-level tests.

Skipped automatically unless `NOO_GATEWAY_URL` is set (tests/integration/conftest.py).

Credentials, when present, unlock the deeper cases:

    NOO_MCP_BOUND_KEY     a service key issued WITH --user   (authorised path)
    NOO_MCP_UNBOUND_KEY   a service key issued WITHOUT --user (must be refused)

Without them the unauthenticated cases still run — those need no secrets and
cover the failure that matters most, an open door.
"""

import os

import httpx
import pytest

GATEWAY_URL = os.getenv("NOO_GATEWAY_URL", "").rstrip("/")
BOUND_KEY = os.getenv("NOO_MCP_BOUND_KEY", "")
UNBOUND_KEY = os.getenv("NOO_MCP_UNBOUND_KEY", "")

DOOR = "/mcp/user"
HEADERS = {"Content-Type": "application/json",
           "Accept": "application/json, text/event-stream"}


def _rpc(method: str, params=None, rpc_id=1) -> dict:
    body = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
    if params is not None:
        body["params"] = params
    return body


def _post(url: str, body: dict, token: str = "") -> httpx.Response:
    headers = dict(HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # verify=False: the gateway serves a cluster-CA cert and the point here is
    # the door's authorisation behaviour, not TLS chain validation.
    with httpx.Client(timeout=30.0, verify=False) as c:
        return c.post(f"{url}{DOOR}", json=body, headers=headers)


@pytest.mark.integration
class TestExternalDoorAuth:
    """No credential, a bad one, or an unbound one must never reach a tool."""

    def test_no_bearer_is_rejected(self, gateway_url):
        r = _post(gateway_url, _rpc("tools/list"))
        assert r.status_code in (401, 404), (
            f"expected 401 (or 404 when the door is disabled), got "
            f"{r.status_code}: {r.text[:200]}"
        )

    def test_garbage_bearer_is_rejected(self, gateway_url):
        """Any rejection is fine; which layer rejects is not the contract.

        401 and 403 are both correct and both reachable: the door answers 403
        for an unresolvable key, while a gateway that has not deployed the door
        yet lets `require_any_auth` answer 401 first. Asserting one exact code
        would make this test fail on a perfectly secure system — which it did,
        on the pre-cutover binary.
        """
        r = _post(gateway_url, _rpc("tools/list"), token="not-a-real-key")
        assert r.status_code in (401, 403, 404), (
            f"unknown key must be rejected, got {r.status_code}: {r.text[:200]}"
        )

    def test_no_bearer_never_returns_a_tool_list(self, gateway_url):
        """The specific catastrophe: an open door that answers anyway.

        A 200 carrying `result.tools` here means anyone on the tailnet can
        enumerate and call the cluster's tools.
        """
        r = _post(gateway_url, _rpc("tools/list"))
        if r.status_code == 200:
            payload = r.json()
            assert "result" not in payload or "tools" not in payload.get("result", {}), (
                "UNAUTHENTICATED CALLER RECEIVED THE TOOL LIST — the door is open"
            )

    @pytest.mark.skipif(not UNBOUND_KEY, reason="NOO_MCP_UNBOUND_KEY not set")
    def test_unbound_key_is_refused_not_downgraded(self, gateway_url):
        """A machine key must not fall back to operator.

        This is the escalation the door exists to remove: under the Python
        hub this exact credential dispatched as cluster-HMAC, i.e. with more
        authority than any human account on the system.
        """
        r = _post(gateway_url, _rpc("tools/list"), token=UNBOUND_KEY)
        assert r.status_code == 403, (
            f"unbound key must be refused, got {r.status_code}: {r.text[:300]}"
        )
        assert "user" in r.text.lower(), "the 403 should name the fix"


@pytest.mark.integration
@pytest.mark.skipif(not BOUND_KEY, reason="NOO_MCP_BOUND_KEY not set")
class TestExternalDoorProtocol:
    """Handshake and discovery with a properly bound key."""

    def test_initialize_returns_this_server(self, gateway_url):
        r = _post(gateway_url, _rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "integration-test", "version": "1"},
        }), token=BOUND_KEY)
        assert r.status_code == 200, r.text[:300]
        result = r.json()["result"]
        assert result["serverInfo"]["name"] == "mesh-external"
        assert result["protocolVersion"]

    def test_tools_list_is_populated_and_camelcase(self, gateway_url):
        """`inputSchema`, not `input_schema`.

        Clients silently ignore the snake_case spelling, which makes every
        tool look argument-less — a failure with no error anywhere.
        """
        r = _post(gateway_url, _rpc("tools/list"), token=BOUND_KEY)
        assert r.status_code == 200, r.text[:300]
        tools = r.json()["result"]["tools"]
        assert tools, "door served an empty tool list"
        assert all("inputSchema" in t for t in tools)
        names = {t["name"] for t in tools}
        assert "noo_rag_query" in names

    def test_unknown_method_is_a_jsonrpc_error_not_a_crash(self, gateway_url):
        r = _post(gateway_url, _rpc("does/not/exist"), token=BOUND_KEY)
        assert r.status_code == 200
        assert r.json()["error"]["code"] == -32601

    def test_unknown_tool_is_rejected(self, gateway_url):
        r = _post(gateway_url, _rpc("tools/call", {
            "name": "noo_not_a_real_tool", "arguments": {},
        }), token=BOUND_KEY)
        assert r.status_code == 200
        assert "error" in r.json(), "unknown tool should be a JSON-RPC error"


@pytest.mark.integration
@pytest.mark.skipif(not BOUND_KEY, reason="NOO_MCP_BOUND_KEY not set")
class TestExternalDoorScoping:
    """The payoff: the caller's own scopes apply, not the operator's."""

    def test_read_tool_succeeds(self, gateway_url):
        r = _post(gateway_url, _rpc("tools/call", {
            "name": "noo_rag_query",
            "arguments": {"question": "what documents are available?"},
        }), token=BOUND_KEY)
        assert r.status_code == 200, r.text[:300]
        result = r.json()["result"]
        assert result["content"], "no content returned"
        assert result.get("isError") is not True, (
            f"read-path tool failed: {result['content'][0].get('text', '')[:300]}"
        )

    def test_write_tool_is_denied_for_a_read_scope_caller(self, gateway_url):
        """`noo_rag_ingest` must 403 when the bound user is read-scope.

        If this passes instead, the call is running as the operator and the
        whole per-user mechanism is inert — the exact silent failure this
        door was built to prevent. Skipped when the bound key belongs to a
        write-scope account, where success is correct.
        """
        if os.getenv("NOO_MCP_BOUND_KEY_IS_WRITE"):
            pytest.skip("bound key is write-scope; denial is not expected")

        r = _post(gateway_url, _rpc("tools/call", {
            "name": "noo_rag_ingest",
            "arguments": {"text": "integration probe", "title": "probe"},
        }), token=BOUND_KEY)
        assert r.status_code == 200, r.text[:300]
        result = r.json()["result"]
        text = result["content"][0].get("text", "")
        assert result.get("isError") is True, (
            "read-scope caller was allowed to ingest — the call is running as "
            f"the operator, not as the bound user. Response: {text[:300]}"
        )
        assert "403" in text or "forbidden" in text.lower(), (
            f"expected a 403 from the gateway, got: {text[:300]}"
        )
