# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cluster-global role provisioning for the mesh Alembic chain.

THE DEFECT THIS EXISTS TO CLOSE.

Migrations 033/034/038 create the ``noo_app`` / ``noo_evolve`` /
``noo_trellion`` login roles. Everything else in the chain is per-DATABASE
DDL, but **roles are CLUSTER-GLOBAL**. So a tool that builds a schema in a
throwaway database — ``scripts/generate-mesh-baseline.sh``, the sqlx
equivalence check, any future fixture harness — still reaches the real roles
of whatever cluster it is pointed at. On 2026-08-04 that reset all three
production credentials to a placeholder committed in the repo and crash-looped
the gateway on ``password authentication failed for user "noo_app"``.

THE SIGNAL IS EXPLICIT, NOT INFERRED.

``NOO_DB_SCHEMA_ONLY=1`` says "this run wants a SCHEMA, not an install". There
is no way to infer that: a fresh install and a baseline build issue the same
statements against the same catalogue, and the only difference is intent. In
schema-only mode:

* a role that ALREADY EXISTS is left completely alone — no ``ALTER ROLE``, so
  no password and no attribute of a live credential can be rewritten
* a role that does not exist is still created, because the grants and the
  ownership transfers that follow need it to exist; its password is a random
  per-run value when none was supplied, so nothing predictable is ever set

Outside schema-only mode behaviour is unchanged: the password is REQUIRED, the
role is created if absent, and an existing role's password is re-asserted from
the secret store. That last part is load-bearing — it is how a drifted
credential self-heals — and it is exactly what must not happen during a
baseline build.

``NOO_DB_SCHEMA_ONLY`` is set by the baseline scripts and by nothing else. It
must never appear in compose, ``.env``, or ``secrets/env.sops``.
"""
from __future__ import annotations

import os
import secrets as _secrets

SCHEMA_ONLY_ENV = "NOO_DB_SCHEMA_ONLY"

_TRUE = {"1", "true", "yes", "on"}


def schema_only() -> bool:
    """True when this chain run is building a schema, not provisioning a host."""
    return os.environ.get(SCHEMA_ONLY_ENV, "").strip().lower() in _TRUE


def role_password(env_var: str, missing_message: str) -> str:
    """The password for a login role, or a throwaway one in schema-only mode.

    Raises ``RuntimeError`` with *missing_message* when the variable is unset
    and this is a real install — a predictable password on a login role is
    worse than a failed migration.
    """
    from ..secret_env import secret_or_empty

    password = secret_or_empty(env_var).strip()
    if password:
        return password
    if schema_only():
        # Disposable cluster, disposable credential. Random rather than a
        # constant: a constant in a repo that syncs to a public mirror is a
        # published credential, which is how the 2026-08-04 incident ended.
        return _secrets.token_urlsafe(32)
    raise RuntimeError(missing_message)


def role_exists(conn, role: str) -> bool:
    return bool(
        conn.exec_driver_sql(
            "SELECT 1 FROM pg_roles WHERE rolname = %(r)s", {"r": role}
        ).scalar()
    )


def ensure_login_role(conn, role: str, password: str, *, attributes: str) -> bool:
    """Create *role* if absent. Never rewrite an existing role in schema-only mode.

    Returns True when the role was created by this call.

    *attributes* is the attribute clause shared by CREATE and the reassertion
    (e.g. ``"LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"``).
    """
    # CREATE/ALTER ROLE do not accept bound parameters, so the literal is
    # escaped by doubling single quotes. The value comes from the operator's
    # own secret store, not from user input.
    escaped = password.replace("'", "''")

    if not role_exists(conn, role):
        conn.exec_driver_sql(
            f"CREATE ROLE {role} {attributes} PASSWORD '{escaped}'"
        )
        return True

    if schema_only():
        # The whole point. This role belongs to a real cluster that merely
        # happens to host our throwaway database; touching it is the bug.
        return False

    conn.exec_driver_sql(f"ALTER ROLE {role} WITH PASSWORD '{escaped}'")
    return False
