# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Pydantic-based tool definitions for the PAI MCP server.

Tools are defined as Pydantic models with typed inputs and declarative metadata.
A generic HTTP proxy dispatcher handles execution for most tools. Tools with
custom response formatting override the ``format_response`` method.

This module replaces the hand-written TOOLS list and handler functions in
tools.py. The FastMCP server in fastmcp_server.py registers these
automatically.

Architecture:
    FastMCP @mcp.tool() ← uses these models for schema + dispatch
    NATS tool worker    ← calls dispatch() directly
    Schema catalog      ← generated from model metadata at startup
"""
from __future__ import annotations

import contextvars
import enum
import logging
import os
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from pydantic import BaseModel


logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class AuthLevel(str, enum.Enum):
    NONE = "none"
    CLUSTER = "cluster"
    JWT = "jwt"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class HttpMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


# ═══════════════════════════════════════════════════════════════
# Base tool definition
# ═══════════════════════════════════════════════════════════════

class ToolDef(BaseModel):
    """Base class for PAI tool definitions.

    Subclass this to define a tool. The generic dispatcher uses the metadata
    to proxy the request to the gateway HTTP API. Override ``format_response``
    for custom response formatting.

    Example::

        class PaiRagStatus(ToolDef):
            name: ClassVar[str] = "noo_rag_status"
            description: ClassVar[str] = "Check PageIndex health."
            method: ClassVar[HttpMethod] = HttpMethod.GET
            path: ClassVar[str] = "/api/v1/rag/status"

    For tools with parameters, add typed fields::

        class PaiRagQuery(ToolDef):
            name: ClassVar[str] = "noo_rag_query"
            description: ClassVar[str] = "Answer questions from the knowledge base."
            method: ClassVar[HttpMethod] = HttpMethod.POST
            path: ClassVar[str] = "/api/v1/rag/query"

            question: str = Field(description="The question to answer")
            strategy: str = Field(default="hybrid", description="Search strategy")
    """

    # -- Metadata (ClassVar = not part of input schema) --
    name: ClassVar[str]
    description: ClassVar[str]
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str]
    # Default to CLUSTER auth: after the require_any_auth middleware
    # tightening, the gateway rejects unauthenticated requests on all
    # /api/* paths. MCP tools call the gateway over HTTP, so they need
    # to attach the cluster HMAC bearer or get 401 back. Tools that
    # truly need anonymous access (e.g. health probes) can override to
    # NONE explicitly.
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    tags: ClassVar[List[str]] = []
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW
    nats_subject: ClassVar[str] = "worker.tool.noo"
    parallelizable: ClassVar[bool] = True
    timeout_secs: ClassVar[int] = 30

    @staticmethod
    def _api_key(field_name: str, field_info: Any) -> str:
        """Return the wire key for a field, otherwise the Python field name.

        This ensures that fields declared as ``name_field: str = Field(alias="name")``
        produce ``"name"`` in path substitution, request bodies, and query params.

        ``serialization_alias`` is checked FIRST and is the right tool when the
        client-facing name and the wire name must differ: `model_json_schema()`
        renders in validation mode, so a plain ``alias`` renames the parameter
        an MCP client has to pass, while a serialization alias changes only
        what goes out to the gateway.

        That distinction is not academic. `noo_graph_search_entities` used to
        rename `query` → `q` in a hand-written `get_params`, which the Rust
        door cannot see: it sent `query=`, the route reads `q`, and every
        search returned an empty list with HTTP 200.
        """
        ser_alias = getattr(field_info, "serialization_alias", None)
        if ser_alias:
            return ser_alias
        alias = getattr(field_info, "alias", None)
        if alias:
            return alias
        # Pydantic v2 may store alias in validation_alias
        val_alias = getattr(field_info, "validation_alias", None)
        if isinstance(val_alias, str):
            return val_alias
        return field_name

    # Names the field whose value IS the request body, instead of the body
    # being an object of every non-path field. Declared as DATA, not as a
    # `get_body` override, because the Rust MCP doors build the body from the
    # generated manifest and never run this class — an override fixes the
    # Python client only. See `get_body` and scripts/build-mcp-manifest.py.
    body_field: ClassVar[str] = ""

    def get_path(self) -> str:
        """Return the HTTP path, substituting any {field} placeholders."""
        path = self.path
        for field_name, field_info in self.model_fields.items():
            api_key = self._api_key(field_name, field_info)
            placeholder = f"{{{api_key}}}"
            if placeholder in path:
                value = getattr(self, field_name)
                path = path.replace(placeholder, str(value))
        return path

    def get_body(self) -> Optional[Dict[str, Any]]:
        """Build request body from non-None fields (POST/PUT only)."""
        if self.method in (HttpMethod.GET, HttpMethod.DELETE):
            return None
        if self.body_field:
            value = getattr(self, self.body_field, None)
            return value if isinstance(value, dict) else None
        body = {}
        for field_name, field_info in self.model_fields.items():
            value = getattr(self, field_name)
            api_key = self._api_key(field_name, field_info)
            # Skip fields used in path substitution
            if f"{{{api_key}}}" in self.path:
                continue
            # Skip None/unset optional fields
            if value is None:
                continue
            # Skip fields with default values that weren't explicitly set
            # (only include if the value differs from default or was provided)
            body[api_key] = value
        return body or None

    def get_params(self) -> Optional[Dict[str, Any]]:
        """Build query params from non-None fields (GET/DELETE only)."""
        if self.method not in (HttpMethod.GET, HttpMethod.DELETE):
            return None
        params = {}
        for field_name, field_info in self.model_fields.items():
            value = getattr(self, field_name)
            api_key = self._api_key(field_name, field_info)
            if f"{{{api_key}}}" in self.path:
                continue
            if value is None:
                continue
            params[api_key] = value
        return params or None

    def get_headers(self) -> Optional[Dict[str, str]]:
        """Return extra headers for this request (override in subclass)."""
        return None

    def format_response(self, data: Any) -> str:
        """Format the gateway response into a string for the LLM.

        Override this in subclasses for custom response formatting.
        Default: JSON pretty-print.
        """
        if isinstance(data, str):
            return data
        try:
            from .. import json_fast as json
            return json.dumps(data, default=str, indent=2)
        except ImportError:
            import json
            return json.dumps(data, default=str, indent=2)

    @classmethod
    def to_tool_schema(cls) -> Dict[str, Any]:
        """Generate the tool schema for the Rust gateway / tools.json."""
        return {
            "type": "function",
            "function": {
                "name": cls.name,
                "description": cls.description,
                "parameters": cls.model_json_schema(),
            },
            "tags": cls.tags,
            "execution": {
                "parallelizable": cls.parallelizable,
                "timeout_secs": cls.timeout_secs,
                "risk_level": cls.risk_level.value,
                "nats_subject": cls.nats_subject,
            },
        }


# ═══════════════════════════════════════════════════════════════
# Generic HTTP proxy dispatcher
# ═══════════════════════════════════════════════════════════════

# Reuse the connection pool from tools.py
from ..config import env_or_yaml as _env_or_yaml

# https always: the gateway has no plaintext listener.
GATEWAY_URL = _env_or_yaml(
    "NOO_GATEWAY_URL", lambda c: c.services.gateway_url,
    "https://localhost:8080")
_JWT_TOKEN = os.getenv("NOO_JWT_TOKEN", "")
_TIMEOUT = float(_env_or_yaml("NOO_MCP_TIMEOUT", lambda c: c.mcp.timeout, 120))

# ── Per-caller identity ──────────────────────────────────────────────────────
# This dispatcher serves TWO callers: in-process code acting as the operator
# (which keeps dispatching with this container's own service key / cluster
# HMAC), and `worker.tool.generic`, where the gateway delegates a tool call
# made BY A USER. A ContextVar keeps the identity out of every tool signature
# — unset means "operator", exactly the old behaviour.
#
# Why the service credential is not enough for a named user: it authenticates
# an ACTOR, not a subject. The gateway scopes it in its own branch of
# require_any_auth (bypassing scope_allows), and _resolve_kb_roles returns
# None — unrestricted — when there is no _requester. The call has to carry a
# real user token so a read-scope user behaves like a read-scope user.
#
# That token is MINTED BY THE GATEWAY, per dispatch, and arrives in the
# request envelope (`gateway-rust/src/worker_delegation.rs`).
# This process never mints one and does not hold NOO_JWT_SECRET: with HS256,
# holding the key that verifies a login is holding the key that forges one.
_CALLER_IDENTITY: "contextvars.ContextVar[Optional[Tuple[str, List[str], Optional[str]]]]" = (
    contextvars.ContextVar("noo_mcp_caller_identity", default=None)
)


class DelegationMissing(PermissionError):
    """A user-bound dispatch arrived without the gateway's delegated token."""


def set_caller_identity(username: str, scopes: List[str], token: Optional[str] = None) -> None:
    """Bind subsequent dispatches in this context to a Mesh user.

    ``token`` is the delegated user token the gateway minted for THIS
    dispatch (the envelope's ``delegated_token``). Without it every
    dispatch in the context refuses — it never falls back to minting, and
    never to the operator credential.

    Not a context manager on purpose: the handler's task IS the scope, and
    it owns its own context.
    """
    _CALLER_IDENTITY.set((username, list(scopes or []), token or None))


def get_caller_identity() -> Optional[Tuple[str, List[str]]]:
    """Current bound user, or None when dispatching as the operator."""
    bound = _CALLER_IDENTITY.get()
    return None if bound is None else (bound[0], bound[1])

import httpx

_http_client: Optional[httpx.AsyncClient] = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        from noomesh._providers import default_http_context
        _http_ctx = default_http_context()
        verify = _http_ctx.verify
        cert = _http_ctx.cert
        _http_client = httpx.AsyncClient(
            timeout=_TIMEOUT,
            verify=verify,
            cert=cert,
            limits=httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
                keepalive_expiry=30,
            ),
        )
    return _http_client


async def close_http_client() -> None:
    global _http_client
    if _http_client is not None and not _http_client.is_closed:
        await _http_client.aclose()
        _http_client = None


def _auth_headers(auth: AuthLevel) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    # A bound caller overrides the process credential for EITHER auth level:
    # the point is that the request carries their subject and scopes, not the
    # operator's. Falls through to the operator path only when unbound.
    caller = _CALLER_IDENTITY.get()
    if caller is not None:
        username, _scopes, token = caller
        if not token:
            # Refuse HERE, by name. Never mint (this process holds no
            # signing secret, by design) and never fall through to the
            # operator credential — that would run a named user's call
            # with more authority than they have.
            raise DelegationMissing(
                f"tool call for {username!r} carried no delegated token: the gateway mints one "
                "per dispatch — a gateway older than this worker does not, so "
                "roll the gateway and worker together"
            )
        headers["Authorization"] = f"Bearer {token}"
        return headers
    if auth == AuthLevel.CLUSTER:
        # The one door: this container's own NOO_GATEWAY_KEY,
        # and nothing else — the shared-HMAC fallback is retired. This used to be gated on NOO_CLUSTER_SECRET being present,
        # which made a container holding its own key but not the fleet
        # secret send NO credential at all.
        try:
            from noomesh.cluster.cluster_auth import internal_gateway_headers
            headers.update(internal_gateway_headers("mcp-server"))
        except ImportError:
            pass
    elif auth == AuthLevel.JWT and _JWT_TOKEN:
        headers["Authorization"] = f"Bearer {_JWT_TOKEN}"
    return headers


#: Longest single long-poll the gateway honours (gateway-rust/src/ops.rs MAX_WAIT_SECS).
_OP_POLL_WAIT_SECS = 20


async def _await_operation(client: "httpx.AsyncClient", headers: Dict[str, str], handle: Dict[str, Any]) -> Any:
    """Poll an operation handle to its end and return the result the route would have.

    ``GET /api/v1/ops/{id}?wait=`` holds the request until the operation finishes,
    so this is a handful of requests, not a busy loop. A failed operation raises the
    same exception class the synchronous route's status would have (400 -> ValueError,
    503 -> ConnectionError, else RuntimeError). Out of time raises TimeoutError naming
    the op id: the operation is still running, and ``noo_op_status`` can pick it up.
    """
    import time

    op_id = handle["op_id"]
    url = f"{GATEWAY_URL}/api/v1/ops/{op_id}"
    deadline = time.monotonic() + _TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"operation {op_id} is still running after {_TIMEOUT}s; "
                f"poll it with noo_op_status (op_id={op_id})"
            )
        wait = max(1, min(_OP_POLL_WAIT_SECS, int(remaining)))
        resp = await client.get(url, headers=headers, params={"wait": wait})
        resp.raise_for_status()
        op = resp.json()
        status = op.get("status")
        if status == "succeeded":
            return op.get("result")
        if status == "failed":
            reason = op.get("error") or "the operation failed"
            code = op.get("result_status")
            if code == 400:
                raise ValueError(f"Bad request: {reason}")
            if code == 503:
                raise ConnectionError(f"Gateway unavailable (503): {reason}")
            raise RuntimeError(f"Operation {op_id} failed: {reason}")
        if status in ("cancelled", "expired"):
            raise RuntimeError(f"Operation {op_id} {status}")


async def dispatch(tool: ToolDef) -> str:
    """Execute a tool definition by proxying to the gateway HTTP API.

    This is the generic dispatcher that handles all HTTP-proxied tools.
    It reads the tool's metadata to determine method, path, auth, body/params,
    and calls format_response on the result.
    """
    client = _get_http_client()
    url = f"{GATEWAY_URL}{tool.get_path()}"
    headers = _auth_headers(tool.auth)
    extra_headers = tool.get_headers()
    if extra_headers:
        headers.update(extra_headers)

    try:
        if tool.method == HttpMethod.GET:
            resp = await client.get(url, headers=headers, params=tool.get_params())
        elif tool.method == HttpMethod.DELETE:
            resp = await client.delete(url, headers=headers, params=tool.get_params())
        elif tool.method == HttpMethod.PUT:
            resp = await client.put(url, headers=headers, json=tool.get_body() or {})
        else:  # POST
            resp = await client.post(url, headers=headers, json=tool.get_body() or {})

        resp.raise_for_status()

        try:
            data = resp.json()
        except Exception:
            data = resp.text

        # An operation-backed route (gateway ops.rs) answers 202 with a handle
        # when its run outlasted the route's bounded wait. This dispatcher's
        # callers want the RESULT, so follow the handle with long-polls until
        # the operation finishes or this process's own timeout is spent.
        if resp.status_code == 202 and isinstance(data, dict) and data.get("op_id"):
            data = await _await_operation(client, headers, data)

        return tool.format_response(data)

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        detail = exc.response.text[:500]
        if status == 400:
            raise ValueError(f"Bad request: {detail}") from exc
        if status in (401, 403):
            raise PermissionError(f"Auth failed (HTTP {status})") from exc
        if status == 404:
            raise LookupError(f"Not found: {tool.get_path()}") from exc
        if status == 503:
            raise ConnectionError("Gateway unavailable (503)") from exc
        raise RuntimeError(f"Gateway error (HTTP {status}): {detail}") from exc
    except (httpx.TimeoutException, httpx.ReadTimeout, httpx.WriteTimeout):
        raise TimeoutError(
            f"Request to {tool.get_path()} timed out after {_TIMEOUT}s."
        ) from None
    except httpx.ConnectError:
        raise ConnectionError(
            f"Cannot connect to gateway at {GATEWAY_URL}"
        ) from None


# ═══════════════════════════════════════════════════════════════
# Tool registry — collects all ToolDef subclasses
# ═══════════════════════════════════════════════════════════════

_TOOL_REGISTRY: Dict[str, type[ToolDef]] = {}


def register(cls: type[ToolDef]) -> type[ToolDef]:
    """Class decorator to register a tool definition."""
    _TOOL_REGISTRY[cls.name] = cls
    return cls


def _ensure_tool_defs_registered() -> None:
    """Populate the registry by importing ``tool_defs``.

    Registration is an import side effect of ``tool_defs/*``. Until the
    2026-08-17 shim retirement that import lived in ``mcp/tools.py``, so any
    caller that skipped the shim and hit this module directly saw an EMPTY
    registry unless something else had imported the shim first (the
    workers/tools.py dispatch chain worked only because its step 3 imported
    the shim, back-filling step 1 for the *next* call). Lazy import here —
    ``tool_defs`` imports this module, so a top-level import would be
    circular; after the first call it is a dict hit in sys.modules.
    """
    from . import tool_defs  # noqa: F401


_tools_filter_cache: Optional[frozenset] = None


def _enabled_names() -> Optional[frozenset]:
    """The NOO_MCP_TOOLS allow-list, or None when unrestricted.

    Read once (env → yaml → "all"), matching the import-time caching the
    retired shim had — the filter is deploy config, not runtime state.
    """
    global _tools_filter_cache
    if _tools_filter_cache is None:
        from ..config import env_or_yaml

        raw = env_or_yaml("NOO_MCP_TOOLS", lambda c: c.mcp.tools_filter, "all")
        _tools_filter_cache = (
            frozenset({"__all__"})
            if raw == "all"
            else frozenset(t.strip() for t in raw.split(",") if t.strip())
        )
    return None if "__all__" in _tools_filter_cache else _tools_filter_cache


def get_enabled_tools() -> List[Dict[str, Any]]:
    """Tool definitions in the legacy dict format, NOO_MCP_TOOLS-filtered.

    (Moved verbatim from the retired ``mcp/tools.py`` shim.)
    """
    _ensure_tool_defs_registered()
    allowed = _enabled_names()
    return [
        {
            "name": name,
            "description": cls.description,
            "input_schema": cls.model_json_schema(),
        }
        for name, cls in _TOOL_REGISTRY.items()
        if allowed is None or name in allowed
    ]


async def handle_tool_call(name: str, arguments: Dict[str, Any]) -> str:
    """Filter-enforcing dispatch — the retired shim's public entry point.

    ``call_tool`` stays unfiltered on purpose: internal callers (the NATS
    worker's step-1 fast path) never went through the filter, and preserving
    that asymmetry preserves behaviour exactly.
    """
    _ensure_tool_defs_registered()
    allowed = _enabled_names()
    if allowed is not None and name not in allowed:
        raise PermissionError(f"Tool '{name}' is disabled by NOO_MCP_TOOLS filter")
    return await call_tool(name, arguments)


def get_all_tools() -> Dict[str, type[ToolDef]]:
    """Return all registered tool definitions."""
    _ensure_tool_defs_registered()
    return dict(_TOOL_REGISTRY)


def get_external_tools() -> Dict[str, type[ToolDef]]:
    """Return only tools tagged 'external' — safe to expose to third-party harnesses.

    Used by the /mcp/user endpoint (named `mcp`-scoped service-key auth) so
    external agents (hermes, openclaw, etc.) get a curated capability set
    without admin or self-modify tools leaking through.
    """
    return {
        name: cls
        for name, cls in _TOOL_REGISTRY.items()
        if "external" in cls.tags
    }


def get_tool_class(name: str) -> Optional[type[ToolDef]]:
    """Look up a tool definition by name."""
    _ensure_tool_defs_registered()
    return _TOOL_REGISTRY.get(name)


async def call_tool(name: str, arguments: Dict[str, Any]) -> str:
    """Dispatch a tool call by name — used by NATS worker and MCP server."""
    _ensure_tool_defs_registered()
    cls = _TOOL_REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown tool: {name}")
    tool = cls.model_validate(arguments)
    return await dispatch(tool)


def generate_tool_schemas() -> List[Dict[str, Any]]:
    """Generate tool schemas for all registered tools (replaces tools.json)."""
    return [cls.to_tool_schema() for cls in _TOOL_REGISTRY.values()]
