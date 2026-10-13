# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Browser automation micro-service — runs inside a Docker container.

Provides HTTP endpoints for Playwright-based browser actions:
navigate, click, type, extract, screenshot, execute, and status.
"""
from __future__ import annotations

import asyncio
import base64
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

IDLE_TIMEOUT = int(os.getenv("BROWSER_IDLE_TIMEOUT", "300"))  # 5 min
MAX_SESSION_SEC = int(os.getenv("BROWSER_MAX_SESSION", "600"))  # 10 min
URL_ALLOWLIST = [u.strip() for u in os.getenv("BROWSER_URL_ALLOWLIST", "").split(",") if u.strip()]
URL_BLOCKLIST = [u.strip() for u in os.getenv("BROWSER_URL_BLOCKLIST", "").split(",") if u.strip()]
VIEWPORT_WIDTH = int(os.getenv("BROWSER_VIEWPORT_WIDTH", "1280"))
VIEWPORT_HEIGHT = int(os.getenv("BROWSER_VIEWPORT_HEIGHT", "720"))

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
#
# Every route used to be open. `POST /execute` is `page.evaluate(script)`
# — arbitrary JavaScript with the browser's cookies and network position
# — and the service sat on `noo-cluster` beside postgres, redis, NATS and
# every third-party image on the node. Anything that could open a socket
# owned the browser.
#
# The credential is an HMAC bearer (`actor:timestamp:hex-sha256`,
# five-minute window) under this door's OWN key, `NOO_BROWSER_KEY`
# — held by the gateway, noo-worker and this container, and
# nothing else. It used to be the fleet secret every node holds, so a leak
# of the browser's copy was a leak of every node's credential; now a leak of
# this key opens this door and nothing else. The
# verification is inlined rather than imported from
# `noomesh.cluster.cluster_auth` because this image is the upstream
# Playwright image with FastAPI on top — it has no `noomesh` package and
# deliberately ships one file.
#
# No key means no service: with `NOO_BROWSER_KEY` unset every route answers
# 503. An unauthenticated browser is not a degraded mode.
#
# This file ships alone (no `noomesh` package in the Playwright image), so
# the `secret_env` reader is inlined here — same rule, same order:
# NAME_FILE > NOO_SECRET_NAME > NAME; a named file that is unreadable or
# empty is a refusal, not "unset".
def _secret(name: str) -> str:
    path = os.getenv(f"{name}_FILE", "")
    if path:
        # newline="": keep the bytes (a text-mode read turns `\r` into
        # `\n`), exactly as noomesh.secret_env and the Rust reader do.
        with open(path, encoding="utf-8", newline="") as fh:
            raw = fh.read()
        value = raw[:-2] if raw.endswith("\r\n") else raw[:-1] if raw.endswith("\n") else raw
        if not value:
            raise RuntimeError(f"{name}_FILE names {path}, which is empty")
        return value
    return os.getenv(f"NOO_SECRET_{name}", "") or os.getenv(name, "")


BROWSER_KEY = _secret("NOO_BROWSER_KEY")
_TOKEN_MAX_AGE = 300
_CLOCK_SKEW = 30


def _verify_cluster_token(token: str) -> bool:
    """Constant-time HMAC check of a `node:ts:sig` cluster token."""
    import hashlib
    import hmac

    try:
        node_id, timestamp, signature = token.split(":")
    except ValueError:
        return False
    try:
        age = time.time() - int(timestamp)
    except ValueError:
        return False
    if age > _TOKEN_MAX_AGE or age < -_CLOCK_SKEW:
        return False
    expected = hmac.new(
        BROWSER_KEY.encode(), f"{node_id}:{timestamp}".encode(), hashlib.sha256
    ).hexdigest()
    # 64 hex only — the width every emitter sends. The 32-char legacy
    # prefix's one-release window is closed.
    return len(signature) == 64 and hmac.compare_digest(signature.encode("utf-8", "replace"), expected.encode())


async def require_cluster_auth(request: Request) -> None:
    """Reject anything without a valid cluster bearer."""
    if not BROWSER_KEY:
        raise HTTPException(
            503,
            "NOO_BROWSER_KEY is not set — the browser service refuses to "
            "run unauthenticated",
        )
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or not _verify_cluster_token(token.strip()):
        raise HTTPException(401, "browser credential required")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

_browser = None
_context = None
_page = None
_playwright = None
_last_activity: float = 0.0
_session_start: float = 0.0
_idle_checker_task = None


def _touch():
    """Update last activity timestamp."""
    global _last_activity
    _last_activity = time.monotonic()


def _check_url(url: str) -> None:
    """Validate URL against allow/block lists."""
    lower = url.lower()
    if URL_BLOCKLIST:
        for pattern in URL_BLOCKLIST:
            if pattern.lower() in lower:
                raise HTTPException(403, f"URL blocked by policy: {pattern}")
    if URL_ALLOWLIST:
        if not any(pattern.lower() in lower for pattern in URL_ALLOWLIST):
            raise HTTPException(403, "URL not in allowlist")


# ---------------------------------------------------------------------------
# Browser lifecycle
# ---------------------------------------------------------------------------

async def _start_browser():
    """Launch Playwright Chromium browser."""
    global _browser, _context, _page, _playwright, _session_start

    from playwright.async_api import async_playwright

    _playwright = await async_playwright().start()
    _browser = await _playwright.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--disable-setuid-sandbox",
            # Chromium's own background traffic to Google — component and
            # variations updates, Safe Browsing list fetches, crash and
            # domain-reliability reports, UMA. Playwright passes most of
            # these by default; they are stated here so the claim in
            # docs/security/telemetry.md does not rest on a library default.
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-domain-reliability",
            "--disable-breakpad",
            "--disable-client-side-phishing-detection",
            "--disable-sync",
            "--metrics-recording-only",
            "--no-pings",
        ],
    )
    _context = await _browser.new_context(
        viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
        user_agent="PAI-Browser/1.0",
    )
    _page = await _context.new_page()
    _session_start = time.monotonic()
    _touch()


async def _stop_browser():
    """Shut down browser and Playwright."""
    global _browser, _context, _page, _playwright

    if _page:
        try:
            await _page.close()
        except Exception:
            pass
        _page = None
    if _context:
        try:
            await _context.close()
        except Exception:
            pass
        _context = None
    if _browser:
        try:
            await _browser.close()
        except Exception:
            pass
        _browser = None
    if _playwright:
        try:
            await _playwright.stop()
        except Exception:
            pass
        _playwright = None


async def _idle_checker():
    """Background task that stops the process when idle or max session reached."""
    while True:
        await asyncio.sleep(10)
        elapsed = time.monotonic() - _session_start
        idle = time.monotonic() - _last_activity

        if elapsed > MAX_SESSION_SEC:
            print(f"[browser] Max session duration reached ({MAX_SESSION_SEC}s), shutting down")
            os._exit(0)

        if idle > IDLE_TIMEOUT:
            print(f"[browser] Idle timeout ({IDLE_TIMEOUT}s), shutting down")
            os._exit(0)


def _require_page():
    """Raise if no page is available."""
    if _page is None:
        raise HTTPException(503, "Browser not initialized")
    elapsed = time.monotonic() - _session_start
    if elapsed > MAX_SESSION_SEC:
        raise HTTPException(503, "Session expired")
    return _page


# ---------------------------------------------------------------------------
# App + lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _idle_checker_task
    await _start_browser()
    _idle_checker_task = asyncio.create_task(_idle_checker())
    yield
    if _idle_checker_task:
        _idle_checker_task.cancel()
    await _stop_browser()


# `dependencies=` applies to EVERY route on this app, including ones
# added later — a new endpoint cannot arrive unauthenticated by omission.
app = FastAPI(
    title="PAI Browser Agent",
    lifespan=lifespan,
    dependencies=[Depends(require_cluster_auth)],
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class NavigateRequest(BaseModel):
    url: str
    wait_until: str = "domcontentloaded"
    screenshot: bool = True


class NavigateResponse(BaseModel):
    url: str
    title: str
    text: str
    screenshot_b64: Optional[str] = None


class ClickRequest(BaseModel):
    selector: str
    timeout_ms: int = 5000


class TypeRequest(BaseModel):
    selector: str
    text: str
    clear_first: bool = True
    timeout_ms: int = 5000


class ExtractRequest(BaseModel):
    selector: str
    attribute: Optional[str] = None
    all_matches: bool = False


class ExecuteRequest(BaseModel):
    script: str


class ScreenshotResponse(BaseModel):
    screenshot_b64: str
    width: int
    height: int


class StatusResponse(BaseModel):
    alive: bool
    current_url: str
    session_elapsed_sec: float
    idle_sec: float
    viewport: dict


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/navigate", response_model=NavigateResponse)
async def navigate(req: NavigateRequest):
    """Navigate to a URL, return page text and optional screenshot."""
    _check_url(req.url)
    page = _require_page()
    _touch()

    try:
        await page.goto(req.url, wait_until=req.wait_until, timeout=30000)
    except Exception as exc:
        raise HTTPException(502, f"Navigation failed: {exc}")

    title = await page.title()
    text = await page.inner_text("body")
    # Truncate text to avoid huge responses
    if len(text) > 50000:
        text = text[:50000] + "\n... (truncated)"

    screenshot_b64 = None
    if req.screenshot:
        png = await page.screenshot(type="png")
        screenshot_b64 = base64.b64encode(png).decode("ascii")

    _touch()
    return NavigateResponse(
        url=page.url,
        title=title,
        text=text,
        screenshot_b64=screenshot_b64,
    )


@app.post("/click")
async def click(req: ClickRequest):
    """Click an element by CSS selector."""
    page = _require_page()
    _touch()
    try:
        await page.click(req.selector, timeout=req.timeout_ms)
    except Exception as exc:
        raise HTTPException(422, f"Click failed: {exc}")
    _touch()
    return {"status": "clicked", "selector": req.selector}


@app.post("/type")
async def type_text(req: TypeRequest):
    """Type text into an element."""
    page = _require_page()
    _touch()
    try:
        if req.clear_first:
            await page.fill(req.selector, req.text, timeout=req.timeout_ms)
        else:
            await page.type(req.selector, req.text, timeout=req.timeout_ms)
    except Exception as exc:
        raise HTTPException(422, f"Type failed: {exc}")
    _touch()
    return {"status": "typed", "selector": req.selector, "length": len(req.text)}


@app.post("/extract")
async def extract(req: ExtractRequest):
    """Extract data from elements matching a selector."""
    page = _require_page()
    _touch()
    try:
        if req.all_matches:
            elements = await page.query_selector_all(req.selector)
            results = []
            for el in elements:
                if req.attribute:
                    val = await el.get_attribute(req.attribute)
                else:
                    val = await el.inner_text()
                results.append(val)
            _touch()
            return {"selector": req.selector, "count": len(results), "data": results}
        else:
            el = await page.query_selector(req.selector)
            if not el:
                raise HTTPException(404, f"Element not found: {req.selector}")
            if req.attribute:
                val = await el.get_attribute(req.attribute)
            else:
                val = await el.inner_text()
            _touch()
            return {"selector": req.selector, "count": 1, "data": [val]}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, f"Extract failed: {exc}")


@app.post("/execute")
async def execute_js(req: ExecuteRequest):
    """Execute JavaScript on the current page."""
    page = _require_page()
    _touch()
    try:
        result = await page.evaluate(req.script)
    except Exception as exc:
        raise HTTPException(422, f"JS execution failed: {exc}")
    _touch()
    return {"result": result}


@app.post("/screenshot", response_model=ScreenshotResponse)
async def screenshot():
    """Capture a full-page screenshot."""
    page = _require_page()
    _touch()
    png = await page.screenshot(type="png", full_page=True)
    _touch()
    return ScreenshotResponse(
        screenshot_b64=base64.b64encode(png).decode("ascii"),
        width=VIEWPORT_WIDTH,
        height=VIEWPORT_HEIGHT,
    )


@app.get("/status", response_model=StatusResponse)
async def status():
    """Health check / session status."""
    page = _require_page()
    return StatusResponse(
        alive=True,
        current_url=page.url,
        session_elapsed_sec=round(time.monotonic() - _session_start, 1),
        idle_sec=round(time.monotonic() - _last_activity, 1),
        viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("BROWSER_PORT", "9222"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
