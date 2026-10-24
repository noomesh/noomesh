# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""DB-authoritative security posture — Python side (peer of Rust posture.rs).

The Rust gateway and the Python worker_pool run in SEPARATE CONTAINERS since
the design (noo-worker with SURFACES=core, noo-trellion with SURFACES=ml);
the in-gateway supervised child is gone. Each has its own env. Rust applies
posture at its startup; this applies it to the worker_pool's env at ITS
startup (in
``_init_python_services``, after the conversation store's engine is ready and
before NATS subscriptions go live), so the Python gates also reflect the DB
posture rather than just ``.env``. Restart-to-apply.

Only the app-tier allow-list is applied (never arbitrary env from a DB row).
Bootstrap-tier gates (TLS, secrets) are not managed here.
"""
from __future__ import annotations

import os

import structlog

log = structlog.get_logger(__name__)

# Must match gateway-rust/src/posture.rs::POSTURE_KEYS.
POSTURE_KEYS = (
    # NOO_MULTI_USER removed: tenant isolation is no longer flag-gated.
    # Unattributed data reads resolve a scope (sole account) or fail closed
    # — see ``identity.scope`` — so there is nothing left to switch on.
    # NOO_AUTH_ENABLED / NOO_CLUSTER_AUTH_STRICT removed (config-graduation
    # phase 1): auth and strict cluster-token verification are invariants,
    # not posture knobs — always on, fail-closed.
    "NOO_EXEC_APPROVAL_MODE",
    "NOO_NODE_AGENT_PRIVILEGED",
    # Opens the user MCP door (/mcp/user) — see posture.rs for why
    # this is posture rather than noomesh.yaml.
    "NOO_MCP_EXTERNAL_ENABLED",
    # (NOO_NATS_LEGACY_SHARED_CREDS, the shared-bus-user bridge, was retired
    # with the user itself — the design. Every process presents its own
    # NATS principal; there is no bridge to hold open.)
    # (NOO_SELF_CALL_SHARED_SECRET, the shared-secret-buys-inference bridge,
    # was retired: the gateway refuses the inference surface to a shared
    # secret outright. A stale row is an unknown key and is skipped.)
    # The v1 (replayable) cluster token bridge: open when unset, "0" refuses
    # it. Mirrors posture.rs; the parity test pins them together.
    "NOO_CLUSTER_TOKEN_V1",
    # Retired bridges (NOO_CLUSTER_LEGACY_FULL_ACCESS,
    # NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH, NOO_BUS_PRINCIPAL, and the retired
    # approval gate NOO_APPROVAL_BREAK_GLASS) are not here:
    # nothing reads them, and the Rust gateway refuses to boot while a row
    # still holds one open (posture.rs RETIRED_BRIDGES).
)


async def apply_security_posture(engine) -> None:
    """Override ``os.environ`` for the app-tier gate keys from
    ``noo_security_posture`` using an async engine. Best-effort — a missing
    table / DB error / no engine leaves env (`.env`) as the posture; never
    raises."""
    if engine is None:
        return
    try:
        from sqlalchemy import text as _sql_text

        applied = 0
        async with engine.connect() as conn:
            res = await conn.execute(_sql_text("SELECT key, value FROM noo_security_posture"))
            for key, value in res.fetchall():
                key = str(key)
                if key in POSTURE_KEYS:
                    os.environ[key] = str(value)
                    applied += 1
                    log.info("security_posture_applied_from_db", gate=key)
        if applied:
            log.info("security_posture_loaded", count=applied)
    except Exception as e:
        log.debug("security_posture_not_loaded", error=str(e))
