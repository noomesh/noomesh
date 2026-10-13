# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Browser automation tool — the worker's side of the agent ``browser`` tool.

the design: this module no longer starts or stops containers on a node
agent. It did so with the static ``NOO_NODE_AGENT_TOKEN`` at
``https://localhost:8081``, which from the worker container is the worker
itself, so no session ever started. Agents now admit only the controller's
certificate. ``start_session`` refuses with a reason naming the gateway's
browser routes (``/api/tools/browser/*``), which start, drive and stop the
same ``noo-browser`` container with the controller's leaf.

Integration:
    - Registered in ``tools_executor.ToolRegistry`` as ``"browser"``
    - Classified as **SEQUENTIAL** in ``parallel_executor`` (stateful session)
    - Gateway router at ``/api/tools/browser/*``
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
import structlog

logger = structlog.get_logger()


def _browser_key() -> str:
    """The browser door's OWN key, through the one reader.

    Not the fleet secret: that is every node's credential, and this worker is
    not a node. The gateway refuses a fleet token from this container.
    """
    from ..secret_env import secret_or_empty

    return secret_or_empty("NOO_BROWSER_KEY")


def _browser_headers() -> dict[str, str]:
    """Auth headers for calls INTO the browser container.

    The browser service requires an HMAC bearer under its own key
    (`NOO_BROWSER_KEY`) on every route.
    Tokens are minted per call: they carry a five-minute window and a
    long-lived browser session outlives one.
    """
    # secret_env, not os.getenv: compose delivers the key as a FILE
    # (NOO_BROWSER_KEY_FILE); a raw env read minted no bearer.
    secret = _browser_key()
    if not secret:
        # The service will answer 503 and say why; minting nothing here
        # keeps the misconfiguration in one place instead of two.
        return {}
    from noomesh.cluster.cluster_auth import create_cluster_token

    return {"Authorization": f"Bearer {create_cluster_token('worker', secret)}"}


# Why a browser start from this process is refused. The
# agent tool bridge shows it to the model as "Browser action failed: ...".
BROWSER_REFUSAL = (
    "browser session not started: this process cannot start containers on a "
    "node agent. Agents admit only the controller's certificate, and the "
    "static node-agent token this used to send is being retired. "
    "Use the gateway's browser routes instead: "
    "POST /api/tools/browser/action (it starts a session when none is "
    "open), or `noo browser open <url>`."
)


# Container image name (must be pre-built via the Dockerfile)
BROWSER_IMAGE = "noo-browser:latest"

# Internal port the browser server listens on
BROWSER_PORT = 9222

# Resource limits
MEMORY_LIMIT = "1g"
CPU_LIMIT = 1.0

# Container name prefix
CONTAINER_PREFIX = "noo-browser-"

# Health poll settings
HEALTH_POLL_INTERVAL = 2.0  # seconds
HEALTH_POLL_TIMEOUT = 30.0  # seconds


@dataclass
class BrowserSession:
    """Tracks a running browser container."""
    container_name: str
    node_id: Optional[str]
    base_url: str
    started_at: float = field(default_factory=time.time)
    last_action: float = field(default_factory=time.time)


class BrowserTool:
    """Manages Playwright browser containers on cluster nodes.

    Lifecycle:
    1. ``start_session`` — spin up a container (prefer tier-3 CPU nodes).
    2. ``navigate / click / type_text / extract / screenshot / execute_js``
       — proxy HTTP to the running container.
    3. ``stop_session`` — explicitly stop, or let idle timeout handle it.

    The SkillExecutor is used only for initial container launch.  Subsequent
    actions talk directly to the container's HTTP API via httpx.
    """

    def __init__(self, **_ignored: Any):
        """No node-agent address or TLS context any more.

        ``get_agent_url`` / ``default_agent_url`` / ``http_context`` were
        only for the node-agent calls that ``start_session`` and
        ``stop_session`` made. Nothing passed the first two, so every start
        dialled ``https://localhost:8081``, the worker's own container.
        Old keyword arguments are accepted and ignored.
        """
        self._sessions: Dict[str, BrowserSession] = {}

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    async def start_session(
        self,
        node_id: Optional[str] = None,
        url_allowlist: Optional[List[str]] = None,
        url_blocklist: Optional[List[str]] = None,
    ) -> BrowserSession:
        """Refuse: this process cannot start a container on a node agent.

        Starting the browser container is a node-agent call
        (``POST /api/containers/start``), and agents admit only the
        controller's certificate. The static ``NOO_NODE_AGENT_TOKEN`` this
        sent is being retired, and the address it went to,
        ``https://localhost:8081``, was this worker's own container, so no
        start from here ever reached an agent. The gateway's
        ``POST /api/tools/browser/sessions/start`` does the same start with
        the controller's leaf.
        """
        logger.error(
            "browser_node_agent_refused",
            node_id=node_id or "local",
            reason="no controller credential in this process",
        )
        raise RuntimeError(BROWSER_REFUSAL)

    async def stop_session(self, session_id: str) -> None:
        """Forget a session. No agent call.

        ``start_session`` refuses, so no session reaches ``_sessions`` any
        more and there is no container to stop from here. A session the
        gateway started is stopped by the gateway
        (``POST /api/tools/browser/sessions/{id}/stop``).
        """
        session = self._sessions.pop(session_id, None)
        if session:
            logger.info("browser_session_forgotten", container=session.container_name)

    async def stop_all(self) -> None:
        """Stop all running browser sessions."""
        for sid in list(self._sessions.keys()):
            await self.stop_session(sid)

    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Return info about all active browser sessions."""
        result = {}
        for sid, s in self._sessions.items():
            result[sid] = {
                "container_name": s.container_name,
                "node_id": s.node_id,
                "base_url": s.base_url,
                "started_at": s.started_at,
                "idle_sec": round(time.time() - s.last_action, 1),
            }
        return result

    # ------------------------------------------------------------------
    # Browser actions (proxy to container HTTP API)
    # ------------------------------------------------------------------

    async def navigate(self, session_id: str, url: str, screenshot: bool = True) -> dict:
        """Navigate to a URL."""
        session = self._get_session(session_id)
        return await self._post(session, "/navigate", {
            "url": url,
            "screenshot": screenshot,
        })

    async def click(self, session_id: str, selector: str) -> dict:
        """Click an element by CSS selector."""
        session = self._get_session(session_id)
        return await self._post(session, "/click", {"selector": selector})

    async def type_text(self, session_id: str, selector: str, text: str) -> dict:
        """Type text into an element."""
        session = self._get_session(session_id)
        return await self._post(session, "/type", {"selector": selector, "text": text})

    async def extract(
        self, session_id: str, selector: str, attribute: Optional[str] = None, all_matches: bool = False
    ) -> dict:
        """Extract data from elements matching a selector."""
        session = self._get_session(session_id)
        return await self._post(session, "/extract", {
            "selector": selector,
            "attribute": attribute,
            "all_matches": all_matches,
        })

    async def screenshot(self, session_id: str) -> dict:
        """Capture a full-page screenshot."""
        session = self._get_session(session_id)
        return await self._post(session, "/screenshot", {})

    async def execute_js(self, session_id: str, script: str) -> dict:
        """Execute JavaScript on the current page."""
        session = self._get_session(session_id)
        return await self._post(session, "/execute", {"script": script})

    async def status(self, session_id: str) -> dict:
        """Get session status from the container."""
        session = self._get_session(session_id)
        return await self._get(session, "/status")

    # ------------------------------------------------------------------
    # High-level execute method (used by ToolExecutor integration)
    # ------------------------------------------------------------------

    async def execute(self, action: str, **params) -> dict:
        """Route an agent tool call to the appropriate browser action.

        If no session exists, one is started automatically.
        """
        # Auto-start a session if none exists
        session_id = params.pop("session_id", None)
        if not session_id:
            if self._sessions:
                session_id = next(iter(self._sessions))
            else:
                session = await self.start_session(
                    node_id=params.pop("node_id", None),
                    url_allowlist=params.pop("url_allowlist", None),
                    url_blocklist=params.pop("url_blocklist", None),
                )
                session_id = next(
                    k for k, v in self._sessions.items()
                    if v.container_name == session.container_name
                )

        action_map = {
            "navigate": self.navigate,
            "click": self.click,
            "type": self.type_text,
            "extract": self.extract,
            "screenshot": self.screenshot,
            "execute": self.execute_js,
            "status": self.status,
            "stop": self._stop_action,
        }

        handler = action_map.get(action)
        if not handler:
            return {"error": f"Unknown browser action: {action}. Available: {', '.join(action_map.keys())}"}

        if action == "stop":
            await self.stop_session(session_id)
            return {"status": "stopped", "session_id": session_id}

        # Pass session_id as first arg, rest as kwargs
        return await handler(session_id, **params)

    async def _stop_action(self, session_id: str) -> dict:
        """Helper for the execute dispatch."""
        await self.stop_session(session_id)
        return {"status": "stopped"}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_session(self, session_id: str) -> BrowserSession:
        session = self._sessions.get(session_id)
        if not session:
            raise RuntimeError(f"No browser session: {session_id}")
        session.last_action = time.time()
        return session

    async def _post(self, session: BrowserSession, path: str, body: dict) -> dict:
        """POST to the browser container API."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{session.base_url}{path}", json=body, headers=_browser_headers()
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            try:
                detail = exc.response.json().get("detail", str(exc))
            except Exception:
                detail = str(exc)
            return {"error": detail}
        except Exception as exc:
            return {"error": f"Browser request failed: {exc}"}

    async def _get(self, session: BrowserSession, path: str) -> dict:
        """GET from the browser container API."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{session.base_url}{path}", headers=_browser_headers()
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            return {"error": f"Browser request failed: {exc}"}


# ---------------------------------------------------------------------------
# Global instance
# ---------------------------------------------------------------------------

_browser_tool: Optional[BrowserTool] = None


def get_browser_tool() -> BrowserTool:
    """Get or create the global BrowserTool."""
    global _browser_tool
    if _browser_tool is None:
        _browser_tool = BrowserTool()
    return _browser_tool


def init_browser_tool(**kwargs) -> BrowserTool:
    """Create and store the global BrowserTool."""
    global _browser_tool
    _browser_tool = BrowserTool(**kwargs)
    return _browser_tool
