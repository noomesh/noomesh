# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""One reader for every secret: env, ``NOO_SECRET_`` env, or a FILE.

Phase 2 of the file-backed-secrets plan (the design carries the add-on
side). Compose still delivers every secret as an environment variable
today; this module is what lets a later compose change hand the same
container ``/run/secrets/<name>`` instead, with no reader changing again.
The Rust gateway has the same rule in ``gateway-rust/src/secret_env.rs``
and ``tests/test_file_reader_parity.py`` keeps the two manifests agreeing.

Resolution, for ``secret("NAME")``:

1. ``NAME_FILE`` set and non-empty → read the file, strip exactly one
   trailing ``\\n`` (or ``\\r\\n``). Unreadable or empty → :class:`SecretFileError`
   naming the path. A named file that cannot be read is a broken install,
   not "unset": falling through to the env would make a mis-mounted secret
   look like a missing one.
2. ``NOO_SECRET_NAME`` non-empty → that (the SecretsManager convention that
   predates this module; ``SecretsManager.get_secret`` delegates here).
3. ``NAME`` non-empty → that.
4. ``None`` — the call site keeps its own "unset" behaviour.

Both ``NAME`` and ``NAME_FILE`` non-empty is a compose/launcher skew, not a
choice: the worker refuses to start on it (:func:`refuse_on_conflicts`, run
from ``worker_pool.__main__``). The per-call reader still answers
(``_FILE`` wins) so the refusal is reported once, by the check that owns it.

Slim on purpose: no Fernet, no dotenv loading — those stay in ``secrets.py``.
Importable from a migration, a CLI, and the worker alike.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping

#: Every name the Python side reads through :func:`secret`. Parsed by
#: ``tests/test_file_reader_parity.py`` against the Rust manifest and the
#: compose projection. Add a reader, add the name.
FILE_BACKED_SECRETS: tuple[str, ...] = (
    "NOO_JWT_SECRET",
    "NOO_CLUSTER_SECRET",
    # This container's OWN bus-principal key: worker,
    # trellion and trellion-intel each get the one for their audience. The
    # controller secret is no longer read by any Python process.
    "NOO_BUS_KEY",
    # The browser container's door key: noo-worker signs its
    # browser calls with it; the fleet secret is no longer in this container.
    "NOO_BROWSER_KEY",
    "NOO_NODE_AGENT_TOKEN",
    "NOO_AUDIT_HMAC_KEY",
    "REDIS_PASSWORD",
    "NOO_GATEWAY_KEY",
    "NATS_WORKER_PASSWORD",
    "NOO_APP_DB_PASSWORD",
    "NOO_EVOLVE_DB_PASSWORD",
    "NOO_TRELLION_DB_PASSWORD",
    # Tier-2 provider and channel credentials: delivered
    # as files to noo-worker (the channel ones) and read through this module
    # by ``cloud_providers`` / ``channels.gateway_client`` wherever they run.
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "WHATSAPP_TOKEN",
    "GOOGLE_CHAT_BEARER_TOKEN",
    "GOOGLE_CHAT_CREDENTIALS_JSON",
)

PREFIX = "NOO_SECRET_"
FILE_SUFFIX = "_FILE"


class SecretFileError(RuntimeError):
    """``NAME_FILE`` names a file that cannot be read, or is empty."""

    def __init__(self, name: str, path: str, reason: str) -> None:
        self.name = name
        self.path = path
        self.reason = reason
        super().__init__(
            f"{name}{FILE_SUFFIX} names {path}, which {reason}; "
            "a named secret file must exist, be readable by this process, "
            "and be non-empty"
        )


class SecretConflictError(RuntimeError):
    """Both ``NAME`` and ``NAME_FILE`` are set for one or more names."""

    def __init__(self, names: list[str]) -> None:
        self.names = names
        super().__init__(
            "both NAME and NAME_FILE are set for "
            + ", ".join(names)
            + " — a compose/launcher skew, not a choice; deliver each secret "
            "ONE way (unset the env value, or the _FILE pointer)"
        )


def strip_one_newline(s: str) -> str:
    """Strip exactly one trailing newline (``\\r\\n`` or ``\\n``) — the one an
    editor or ``echo`` adds. Anything else is the value's own."""
    if s.endswith("\r\n"):
        return s[:-2]
    if s.endswith("\n"):
        return s[:-1]
    return s


def read_secret_file(name: str, path: str) -> str:
    """The content of *path* as *name*'s secret. Raises :class:`SecretFileError`
    when unreadable or empty."""
    try:
        # newline="" — no universal-newline translation. Text mode would turn
        # a lone ``\r`` or an embedded ``\r\n`` into ``\n`` (``abc\r`` would
        # lose its ``\r``), so the same file would answer differently here and
        # in the Rust reader, which keeps the bytes. A secret is bytes;
        # :func:`strip_one_newline` is the only thing allowed to trim.
        with open(path, encoding="utf-8", newline="") as fh:
            raw = fh.read()
    except OSError as e:
        raise SecretFileError(name, path, f"cannot be read ({e.strerror or e})") from e
    value = strip_one_newline(raw)
    if not value:
        raise SecretFileError(name, path, "is empty")
    return value


def secret_from(name: str, get: Callable[[str], str | None]) -> str | None:
    """:func:`secret` over an arbitrary lookup (a ``dict.get``), so the
    precedence is testable without touching ``os.environ`` and so
    ``resolve_nats_credentials`` can take it as its ``read`` hook."""
    path = get(name + FILE_SUFFIX) or ""
    if path:
        return read_secret_file(name, path)
    prefixed = get(PREFIX + name) or ""
    if prefixed:
        return prefixed
    return get(name) or None


def secret(name: str, env: Mapping[str, str] | None = None) -> str | None:
    """The secret called *name*, or ``None`` when nothing is configured.
    See the module docs for the order."""
    env = os.environ if env is None else env
    return secret_from(name, env.get)


def secret_or_empty(name: str, env: Mapping[str, str] | None = None) -> str:
    """:func:`secret`, ``""`` when unset — for the ``os.getenv(NAME, "")`` sites."""
    return secret(name, env) or ""


def both_set_conflicts(
    manifest: tuple[str, ...] = FILE_BACKED_SECRETS,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """Names in *manifest* where BOTH ``NAME`` and ``NAME_FILE`` are non-empty."""
    env = os.environ if env is None else env
    return [n for n in manifest if (env.get(n) or "") and (env.get(n + FILE_SUFFIX) or "")]


def refuse_on_conflicts(
    manifest: tuple[str, ...] = FILE_BACKED_SECRETS,
    env: Mapping[str, str] | None = None,
) -> None:
    """Boot-time check: raise :class:`SecretConflictError` on an env/file skew
    and :class:`SecretFileError` on a named file that cannot be read, so a
    process refuses to start with ONE line naming the problem instead of a
    scatter of auth failures later."""
    env = os.environ if env is None else env
    both = both_set_conflicts(manifest, env)
    if both:
        raise SecretConflictError(both)
    for n in manifest:
        secret(n, env)  # raises SecretFileError on a broken file
