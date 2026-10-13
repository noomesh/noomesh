# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The search provider knobs the docs name actually reach the gateway.

`docs/reference/config.md` and `env.md` have said "set TAVILY_API_KEY or
BRAVE_SEARCH_API_KEY in the secret store" since an earlier change shipped the
providers. Until 2026-09-27 neither key was in the secret registry (so the
rotate verb refused it as unknown) and compose passed neither the keys nor
NOO_SEARCH_PROVIDER into the gateway — a stored key never reached the
process. A documented control that does not exist is worse than none: the
operator follows the page and the report still fails.

This reads the raw compose file (not a projection) because the question is
"is the variable on the gateway's environment list", nothing more.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests._compose_projection import load_raw, untag

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "docker-compose.cluster.yml"
KNOBS = ["NOO_SEARCH_PROVIDER", "NOO_SEARCH_SEARXNG_URL", "TAVILY_API_KEY", "BRAVE_SEARCH_API_KEY"]


def _gateway_env_names() -> set[str]:
    services = untag(load_raw(COMPOSE))["services"]
    env = services["gateway"].get("environment") or []
    if isinstance(env, dict):
        return set(env.keys())
    return {e.split("=", 1)[0] for e in env if isinstance(e, str)}


# The two keys are secrets: the earlier change they reach the gateway as
# `/run/secrets` files, and its environment carries only the `<NAME>_FILE`
# pointer `secret_env` follows. Either spelling means "the gateway sees it".
FILE_BACKED = {"TAVILY_API_KEY", "BRAVE_SEARCH_API_KEY"}


def test_every_search_knob_reaches_the_gateway() -> None:
    names = _gateway_env_names()
    missing = [k for k in KNOBS if k not in names and not (k in FILE_BACKED and f"{k}_FILE" in names)]
    assert not missing, f"the gateway never sees {missing}; the docs say to set them"


def test_the_docs_name_exactly_these_knobs() -> None:
    """If a provider gains a knob, the docs and this list move together."""
    text = (REPO / "docs" / "reference" / "config.md").read_text() + (REPO / "docs" / "reference" / "env.md").read_text()
    documented = set(re.findall(r"\b(NOO_SEARCH_[A-Z_]+|TAVILY_API_KEY|BRAVE_SEARCH_API_KEY)\b", text))
    assert documented == set(KNOBS), f"documented {sorted(documented)} != guarded {sorted(KNOBS)}"
