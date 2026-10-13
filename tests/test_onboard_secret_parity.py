# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The onboarding wizard's generated-secret table and the Docker-secrets
map must not drift.

`noo onboard` mints `secrets/<name>.txt` for every entry in the Rust
`SECRETS` table and writes the matching env var. `_SECRET_FILE_TO_ENV`
maps the same filenames when those files are mounted as Docker secrets.
A name that means `NATS_GATEWAY_PASSWORD` in one and something else in the
other is a credential that silently arrives under the wrong key — the
process then falls back to the shared user and nobody notices, because
falling back works.

Equality is deliberately NOT asserted: the wizard mints things Docker
secrets never carry (agent_review_key) and the map covers things the wizard
does not mint (admin_password). What must hold is that every
name present in BOTH agrees, and that the per-principal NATS credentials
are in both.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _rust_secrets() -> dict[str, str]:
    text = (REPO / "noo-cli/src/onboard/mod.rs").read_text()
    m = re.search(r"pub\(crate\) const SECRETS: &\[\(&str, &str\)\] = &\[(.*?)\n\];", text, re.S)
    assert m, "onboard/mod.rs: no SECRETS table"
    return dict(re.findall(r'\("([a-z0-9_]+)",\s*"([A-Z0-9_]+)"\)', m.group(1)))


def _python_map() -> dict[str, str]:
    text = (REPO / "src/noomesh/secrets.py").read_text()
    m = re.search(r"_SECRET_FILE_TO_ENV = \{(.*?)\n\}", text, re.S)
    assert m, "secrets.py: no _SECRET_FILE_TO_ENV"
    return dict(re.findall(r'"([a-z0-9_]+)":\s*"([A-Z0-9_]+)"', m.group(1)))


def test_shared_names_map_to_the_same_env_var() -> None:
    rust, py = _rust_secrets(), _python_map()
    for name in set(rust) & set(py):
        assert rust[name] == py[name], f"{name}: wizard says {rust[name]}, secrets.py says {py[name]}"


def test_per_principal_nats_credentials_are_in_both() -> None:
    rust, py = _rust_secrets(), _python_map()
    for name, env in (
        ("nats_gateway_password", "NATS_GATEWAY_PASSWORD"),
        ("nats_worker_password", "NATS_WORKER_PASSWORD"),
    ):
        assert rust.get(name) == env, f"wizard SECRETS lacks {name} → {env}"
        assert py.get(name) == env, f"_SECRET_FILE_TO_ENV lacks {name} → {env}"


def test_the_retired_shared_bus_pair_is_in_neither() -> None:
    """an earlier change retired the shared NATS user: nothing mints its password
    and no Docker-secret file maps onto either variable any more."""
    rust, py = _rust_secrets(), _python_map()
    for env in ("NATS_USER", "NATS_PASSWORD"):
        assert env not in rust.values(), f"the wizard still mints {env}"
        assert env not in py.values(), f"_SECRET_FILE_TO_ENV still maps {env}"
