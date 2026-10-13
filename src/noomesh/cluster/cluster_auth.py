# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Lightweight shared-secret authentication for inter-node cluster communication.

Uses HMAC-signed, time-limited tokens to verify that requests come from
legitimate cluster members.  Requests are rejected with 503 if
NOO_CLUSTER_SECRET is not configured — use ``noo onboard`` to generate
cluster secrets.

This is separate from user-facing JWT auth, which the Rust gateway owns (gateway-rust/src/auth.rs).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from fastapi import HTTPException, Request

from ..secret_env import secret_or_empty as _secret

# Cluster secret: shared by all nodes, set at provision time. Read through
# `secret_env` (NAME_FILE > NOO_SECRET_NAME > NAME) — evaluated once at import,
# as before; the reader is what changed, not when it runs.
CLUSTER_SECRET = _secret("NOO_CLUSTER_SECRET")
# No NOO_CONTROLLER_SECRET here. It once signed every
# Python self-call when the container held no key of its own; that fallback
# is retired, and the gateway refuses a controller-secret HMAC from anyone.
# A self-call presents this container's OWN key or nothing.
# Static bearer token — also accepted (used by Prometheus, infrastructure tools)
_NODE_AGENT_TOKEN = _secret("NOO_NODE_AGENT_TOKEN")


def generate_cluster_secret() -> str:
    """Generate a random cluster secret (run once at cluster init)."""
    return secrets.token_urlsafe(32)


def internal_gateway_headers(actor: str = "internal") -> dict[str, str]:
    """Return the Authorization header for an in-process Python -> gateway
    self-call: this container's OWN key, and nothing else.

    THE one door for a Python -> gateway self-call. Nothing else in this
    package builds a self-call Authorization header;
    `tests/test_one_door_for_internal_gateway_credentials.py` pins that,
    because the value of a per-consumer key is lost the moment a second call
    site signs its own way.

    The key is `NOO_GATEWAY_KEY` — a row in `noo_service_keys` (svc:worker,
    svc:trellion, svc:trellion-intel): scoped, quota-capped, revocable, with a
    last_used_at. There is NO shared-secret fallback: the
    controller-secret HMAC this used to mint when the key was unset is
    refused by the gateway for every actor, so falling back would only turn
    a clear "no key" into an anonymous 403.

    With no key this returns ``{}`` and says so ONCE, loudly, naming the fix
    (`actor` is kept only for that line): the gateway then answers 401, which
    surfaces the misconfiguration instead of hiding it.
    """
    key = _secret("NOO_GATEWAY_KEY").strip()
    if key:
        return {"Authorization": f"Bearer {key}"}
    _warn_no_key_once(actor)
    return {}


_NO_KEY_WARNED: set[str] = set()


def _warn_no_key_once(actor: str) -> None:
    if actor in _NO_KEY_WARNED:
        return
    _NO_KEY_WARNED.add(actor)
    try:
        import structlog

        structlog.get_logger(__name__).error(
            "gateway_self_call_has_no_key",
            actor=actor,
            detail=(
                "NOO_GATEWAY_KEY is not set in this container, so this self-call carries no "
                "credential and the gateway will refuse it. The shared-secret fallback is "
                "retired. Fix: noo security service-key provision worker "
                "(trellion / trellion-intel for the add-on containers)"
            ),
        )
    except Exception:  # noqa: BLE001 — a log line must never break the call
        pass


def create_cluster_token(node_id: str, secret: str) -> str:
    """Create a time-limited HMAC token for cluster communication.

    Token format: {node_id}:{timestamp}:{hmac_signature}
    Valid for 5 minutes (heartbeat interval is 30s, so plenty of margin).
    ``secret`` is REQUIRED: there is no default key
    to fall back to, so no caller can sign with a shared secret by omission.
    The one in-tree caller is the browser container's door
    (``tools/browser_tool.py``), which passes the browser door's OWN key
    (``NOO_BROWSER_KEY``) — never the fleet secret, which no controller
    service holds any more.
    It never signs with the controller secret: no Python process holds it,
    and the gateway refuses a controller-secret HMAC from every caller.
    """
    if not secret:
        raise ValueError("create_cluster_token needs an explicit secret")
    timestamp = str(int(time.time()))
    message = f"{node_id}:{timestamp}"
    # Full 64-hex HMAC-SHA256. This was the LAST emitter still truncating
    # to 32 chars: the Rust gateway, the noo CLI, the Go
    # node-agent and trellion all send the full digest, and the Go
    # node-agent verifier accepts ONLY the full width — so a Python-minted
    # token could authenticate to the gateway but never to a node. One
    # canonical width lets the gateway retire its dual-width acceptance.
    signature = hmac.new(
        secret.encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    return f"{node_id}:{timestamp}:{signature}"


def verify_cluster_token(
    token: str, secret: str | None = None, max_age: int = 300
) -> tuple[bool, str]:
    """Verify a cluster token.

    Returns (valid, node_id).
    """
    secret = secret or CLUSTER_SECRET
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return False, ""
        node_id, timestamp, signature = parts

        # Check age
        age = time.time() - int(timestamp)
        if age > max_age or age < -30:  # allow 30s clock skew
            return False, node_id

        # Verify HMAC — the full 64-hex width only. The 32-char legacy
        # prefix's one-release window is closed here and
        # in the Rust gateway alike.
        message = f"{node_id}:{timestamp}"
        expected = hmac.new(
            secret.encode(), message.encode(), hashlib.sha256
        ).hexdigest()
        if len(signature) == 64 and hmac.compare_digest(signature, expected):
            return True, node_id
        return False, node_id
    except Exception:
        return False, ""


# ── FastAPI dependency ─────────────────────────────────────────────


async def require_cluster_auth(request: Request):
    """FastAPI dependency that validates cluster authentication.

    Accepts two token types:
    1. HMAC cluster token (node_id:timestamp:signature) — for inter-node calls
    2. Static NOO_NODE_AGENT_TOKEN bearer — for Prometheus / infrastructure tools

    Console/browser actions go through the gateway's ``/api/cluster/*`` routes
    (user-authenticated), which call the node agent with cluster auth.

    Rejects with 503 if neither secret is configured.
    """
    if not CLUSTER_SECRET and not _NODE_AGENT_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Cluster auth not configured — set NOO_CLUSTER_SECRET (run noo onboard)",
        )

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        _audit_cluster("cluster_auth_failure", "", "missing_token", request)
        raise HTTPException(status_code=401, detail="Missing cluster auth token")

    token = auth[7:]

    # Mode 1: static bearer token (Prometheus, infrastructure tools)
    if _NODE_AGENT_TOKEN and hmac.compare_digest(token, _NODE_AGENT_TOKEN):
        request.state.cluster_node_id = "infra"
        return

    # Mode 2: HMAC cluster token (inter-node communication)
    if CLUSTER_SECRET:
        valid, node_id = verify_cluster_token(token)
        if valid:
            request.state.cluster_node_id = node_id
            return

    _audit_cluster("cluster_auth_failure", "", "invalid_token", request)
    raise HTTPException(status_code=403, detail="Invalid cluster auth token")


def _audit_cluster(event_type: str, node_id: str, outcome: str, request: Request) -> None:
    """Fire audit event for cluster auth attempt (best-effort)."""
    try:
        from ..gateway.audit_log import audit

        client_ip = request.client.host if request.client else "unknown"
        audit(
            event_type,
            severity="warning",
            actor=node_id or client_ip,
            resource=str(request.url.path),
            outcome=outcome,
            client_ip=client_ip,
        )
    except Exception:
        pass


# ── Node Registration Tokens ──────────────────────────────────────────


class NodeRegistrationTokenStore:
    """One-time tokens for initial node registration.

    Admin generates a token for a node_id; the node uses it exactly once
    during first registration, then switches to HMAC-based auth.
    """

    def __init__(self):
        self._tokens: dict[str, dict] = {}  # token -> {node_id, created, used}

    def issue_token(self, node_id: str, ttl: int = 3600) -> str:
        """Issue a single-use registration token (default 1 hour TTL)."""
        token = secrets.token_urlsafe(32)
        self._tokens[token] = {
            "node_id": node_id,
            "created": time.time(),
            "ttl": ttl,
            "used": False,
        }
        return token

    def validate_token(self, token: str, node_id: str) -> bool:
        """Validate and consume a registration token. Returns True once."""
        entry = self._tokens.get(token)
        if entry is None:
            return False
        if entry["used"]:
            return False
        if entry["node_id"] != node_id:
            return False
        if time.time() - entry["created"] > entry["ttl"]:
            del self._tokens[token]
            return False
        entry["used"] = True
        return True

    def cleanup_expired(self) -> int:
        """Remove expired/used tokens. Returns count removed."""
        now = time.time()
        to_remove = [
            t for t, e in self._tokens.items()
            if e["used"] or (now - e["created"] > e["ttl"])
        ]
        for t in to_remove:
            del self._tokens[t]
        return len(to_remove)


# Global singleton
_registration_store: NodeRegistrationTokenStore | None = None


def get_registration_store() -> NodeRegistrationTokenStore:
    global _registration_store
    if _registration_store is None:
        _registration_store = NodeRegistrationTokenStore()
    return _registration_store
