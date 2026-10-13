# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tailscale API operations shared by the CLI and the gateway/MCP surface.

Env (repo .env / gateway environment):
    NOO_TAILSCALE_API_KEY     — API access token (admin console → Settings → Keys)
    NOO_TAILSCALE_TAILNET     — optional; defaults to "-" (the key's tailnet)
    NOO_BOOTSTRAP_SCRIPT_URL  — optional override for the join script URL
                                (the gateway stopped serving
                                /bootstrap-node.sh on 2026-09-27, so the
                                NGROK_DOMAIN fallback is gone)
"""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx

API_BASE = "https://api.tailscale.com/api/v2"
# The public bootstrap script. It lives in its own repo (noomesh/bootstrap),
# not in the main one: the previous value named a `noomesh` repo under the
# old org that never existed, so every default one-liner 404ed. Must agree with
# the Rust twin in gateway-rust/src/routes/cluster.rs. Reached only via
# `noo-py cluster mint-join-key` (the Rust CLI's native command does not use
# this module); an explicit NOO_BOOTSTRAP_SCRIPT_URL / --script-url wins.
OSS_SCRIPT_URL = "https://raw.githubusercontent.com/noomesh/bootstrap/main/scripts/bootstrap-node.sh"


class TailscaleError(RuntimeError):
    pass


def _env(key: str) -> str:
    return os.environ.get(key, "").strip()


def _require_api_key() -> str:
    key = _env("NOO_TAILSCALE_API_KEY")
    if not key:
        raise TailscaleError(
            "NOO_TAILSCALE_API_KEY is not set — create one in the Tailscale "
            "admin console (Settings → Keys) and store it in the secret "
            "store (`sops secrets/env.sops`); the launcher injects it into "
            "the gateway/trellion env. Never put it in .env."
        )
    return key


def _tailnet() -> str:
    return _env("NOO_TAILSCALE_TAILNET") or "-"


def script_url() -> str:
    url = _env("NOO_BOOTSTRAP_SCRIPT_URL")
    if url:
        return url
    return OSS_SCRIPT_URL


def _key_payload(tag: str, expiry_minutes: int, reusable: bool) -> dict:
    return {
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": reusable,
                    "ephemeral": False,
                    "preauthorized": True,
                    "tags": [tag],
                }
            }
        },
        "expirySeconds": expiry_minutes * 60,
        # Tailscale rejects punctuation like ():/ in descriptions
        "description": f"noo-join-{tag.replace(':', '-')}",
    }


def _compose_result(
    auth_key: str, tag: str, expiry_minutes: int, reusable: bool,
    ssh_user: Optional[str], ssh_pubkey: Optional[str],
) -> dict[str, Any]:
    args = f"--auth-key {auth_key}"
    if ssh_pubkey:
        args += f' --ssh-pubkey "{ssh_pubkey}"'
    if ssh_user:
        args += f" --ssh-user {ssh_user}"
    url = script_url()
    return {
        "auth_key": auth_key,
        "tag": tag,
        "expiry_minutes": expiry_minutes,
        "reusable": reusable,
        "script_url": url,
        "one_liner": f"curl -fsSL {url} | sudo bash -s -- {args}",
        "next_step": "run the one_liner on the joining node; then "
                     "`noo cluster provision <node-name> --wait` on the controller",
    }


def _raise_for_api(resp: httpx.Response, tag: str) -> None:
    if resp.status_code != 200:
        hint = ""
        if "tag" in resp.text.lower():
            hint = f" (is '{tag}' declared under tagOwners in the tailnet ACL policy?)"
        raise TailscaleError(f"Tailscale API {resp.status_code}: {resp.text[:300]}{hint}")


def mint_join_key(
    tag: str = "tag:worker",
    expiry_minutes: int = 60,
    reusable: bool = False,
    ssh_user: Optional[str] = None,
    ssh_pubkey: Optional[str] = None,
) -> dict[str, Any]:
    """Mint a pre-authorized tagged auth key (sync — CLI path)."""
    resp = httpx.post(
        f"{API_BASE}/tailnet/{_tailnet()}/keys",
        json=_key_payload(tag, expiry_minutes, reusable),
        auth=(_require_api_key(), ""),
        timeout=15,
    )
    _raise_for_api(resp, tag)
    auth_key = resp.json().get("key", "")
    if not auth_key:
        raise TailscaleError(f"Tailscale API returned no key: {resp.text[:200]}")
    return _compose_result(auth_key, tag, expiry_minutes, reusable, ssh_user, ssh_pubkey)


async def mint_join_key_async(
    tag: str = "tag:worker",
    expiry_minutes: int = 60,
    reusable: bool = False,
    ssh_user: Optional[str] = None,
    ssh_pubkey: Optional[str] = None,
) -> dict[str, Any]:
    """Mint a pre-authorized tagged auth key (async — gateway/MCP path)."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{API_BASE}/tailnet/{_tailnet()}/keys",
            json=_key_payload(tag, expiry_minutes, reusable),
            auth=(_require_api_key(), ""),
        )
    _raise_for_api(resp, tag)
    auth_key = resp.json().get("key", "")
    if not auth_key:
        raise TailscaleError(f"Tailscale API returned no key: {resp.text[:200]}")
    return _compose_result(auth_key, tag, expiry_minutes, reusable, ssh_user, ssh_pubkey)
