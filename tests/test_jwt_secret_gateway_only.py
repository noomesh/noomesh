# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The login signing secret reaches the gateway and nothing else.

`NOO_JWT_SECRET` is HS256: the key that verifies a login is the key that
forges one. The worker used to hold it for one reason — `worker.tool.generic`
minted a user JWT to call the gateway as the person who asked. The gateway
now mints that token per dispatch (`gateway-rust/src/worker_delegation.rs`)
and the worker presents it, so no other container needs the secret.

These read the COMPOSED projection (base + every add-on overlay, every
profile): the worker and trellion pick secrets up through anchors and
`extends`, so a single file's text is not what a container receives.
"""

from __future__ import annotations

from pathlib import Path

from tests._compose_projection import env_of, full_projection

ROOT = Path(__file__).resolve().parents[1]

SECRET = "NOO_JWT_SECRET"
SOURCE = "noo_jwt_secret"
HOLDER = "gateway"


def _holders(doc: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, svc in (doc.get("services") or {}).items():
        why: list[str] = []
        for s in svc.get("secrets") or []:
            src = s.get("source") if isinstance(s, dict) else s
            if src == SOURCE:
                why.append(f"secrets: {SOURCE}")
        for k in env_of(svc):
            if k in (SECRET, f"{SECRET}_FILE"):
                why.append(f"environment: {k}")
        if why:
            out[name] = why
    return out


def test_no_service_but_the_gateway_receives_the_jwt_secret() -> None:
    holders = _holders(full_projection())
    assert HOLDER in holders, (
        f"parsed no {SECRET} delivery to the gateway at all — the parse is wrong, "
        "and every other assertion here would pass vacuously"
    )
    others = {k: v for k, v in holders.items() if k != HOLDER}
    assert not others, (
        f"{SECRET} is delivered beyond the gateway: {others}. Only the gateway may hold the "
        "login signing secret — a worker acts as a user with the per-dispatch token the gateway "
        "mints (worker_delegation.rs)."
    )


def test_the_worker_code_never_mints_a_user_token() -> None:
    """The worker-side half: nothing on the tool-dispatch path signs a JWT or
    reads the secret. A plant that restores the local mint fails here even
    if the compose file still keeps the secret away."""
    for rel in (
        "src/noomesh/mcp/tool_models.py",
        "src/noomesh/workers/tools.py",
        "src/noomesh/agents/parallel_collab.py",
    ):
        code = "\n".join(
            line for line in (ROOT / rel).read_text().splitlines() if not line.lstrip().startswith("#")
        )
        for needle in ('get_secret("NOO_JWT_SECRET"', 'secret_or_empty("NOO_JWT_SECRET"', "jwt.encode(", "_jwt.encode("):
            assert needle not in code, f"{rel} mints or reads the signing secret again ({needle})"


def test_the_registry_names_only_the_gateway() -> None:
    import re

    src = (ROOT / "noo-cli/src/commands/secrets.rs").read_text()
    m = re.search(r'key:\s*"NOO_JWT_SECRET",.*?consumers:\s*&\[(.*?)\]', src, re.S)
    assert m, "NOO_JWT_SECRET's SecretSpec not found"
    assert re.findall(r'"([^"]+)"', m.group(1)) == ["noo-gateway"]
