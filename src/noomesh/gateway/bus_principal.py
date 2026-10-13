# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Verify the per-message principal on `worker.*` NATS messages.

Python peer of ``gateway-rust/src/bus_principal.rs`` (
R31/R32). The Rust gateway signs a compact HMAC token and attaches it as the
``Noo-Principal`` NATS header on every `worker.*` publish; this module is the
one place the worker decides whether to believe it.

Why a header and not the payload: the payload is the *publisher's* claim
about itself. Before this, ``worker_pool._handle_request`` decoded a message
and dispatched it, and the handlers took ``user_id`` / ``_requester`` out of
the body — so anything that could get a message onto ``worker.tool.generic``
also chose who it was. The bus grant (#100) bounded *which process* may
publish; it cannot say anything about a particular message.

Wire format (see the Rust module for the authoritative description)::

    Noo-Principal: <base64url(claims json, no padding)>.<aud>=<hex mac>[,<aud>=<hex mac>…]
    mac(aud) = hmac-sha256(key(aud), "<aud>.<base64url body>")

One MAC per AUDIENCE. This process is one audience —
``NOO_BUS_AUDIENCE`` (``worker``, ``trellion`` or ``trellion-intel``) — and
holds that audience's key and nothing else (``NOO_BUS_KEY``, a file under
/run/secrets). It checks its own MAC and ignores the others, which it could
not verify anyway. every verifier held
``NOO_CONTROLLER_SECRET``, so a leak from any one container forged principals
for all of them and signed HTTP self-calls too; that format — a single bare
64-hex MAC — is refused here.

The MAC covers the base64url text exactly as received, so we authenticate
the bytes we are about to parse rather than a re-serialisation of them.

Claims: ``sub``, ``kind`` (``user``|``internal``), ``role``, ``scopes``,
``subj`` (the NATS subject — a principal is not replayable onto a different
handler), ``iat``, ``exp``, ``nonce``.

Four things have to hold, and a failure of any one is a refusal, never a
downgrade:

1. this audience's MAC verifies under this process's ``NOO_BUS_KEY``;
2. the claimed subject is the subject the message actually arrived on;
3. ``iat``/``exp`` are within :data:`CLOCK_SKEW_SECS` of now;
4. the nonce has not been seen inside the freshness window.

There is no unsigned mode. The one-release rollout bridge that served an
unsigned message (``NOO_BUS_PRINCIPAL=optional``) is retired; the gateway
refuses to start while a posture row or env value still holds it open
(``gateway-rust/src/posture.rs`` → ``RETIRED_BRIDGES``). See
``docs/operating/runbooks/nats-isolation.md``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import structlog

log = structlog.get_logger(__name__)

HEADER = "Noo-Principal"

#: Freshness slack, in either direction. Matches the Rust signer's TTL, so a
#: token minted at the far edge of a clock disagreement still lands.
CLOCK_SKEW_SECS = 60

#: How long a nonce is remembered. Must be at least the width of the window a
#: replayed token could still pass (`exp` + skew), or the cache would forget
#: a nonce while the token bearing it is still considered fresh.
NONCE_TTL_SECS = 2 * CLOCK_SKEW_SECS + 60

#: Hard cap so a flood of signed messages cannot grow the cache without
#: bound. On overflow the cache is pruned by age first; if that is not enough
#: the OLDEST entries go, which is the safe direction — a forgotten nonce can
#: only be replayed inside its own freshness window.
NONCE_MAX = 50_000


class PrincipalError(Exception):
    """A message that must not be served. ``reason`` is the audit label."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


class Principal:
    """A verified caller. Constructed only by :func:`verify`."""

    __slots__ = ("sub", "kind", "role", "scopes")

    def __init__(self, sub: str, kind: str, role: str, scopes: "list[str]") -> None:
        self.sub = sub
        self.kind = kind
        self.role = role
        self.scopes = scopes

    # ── What the handlers ask it ──────────────────────────────────────

    @property
    def is_user(self) -> bool:
        """A named account. Its identity is the last word on tenancy."""
        return self.kind == "user"

    @property
    def is_internal(self) -> bool:
        """A gateway loop or service acting on its own account."""
        return self.kind == "internal"

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    @property
    def is_admin(self) -> bool:
        """``admin`` comes from the VERIFIED header and nowhere else.

        ``workers/kb.py`` used to read this out of ``params["_requester"]``,
        i.e. out of the message body — so "I am an admin" was a thing the
        publisher said about itself.
        """
        return "admin" in self.scopes

    @property
    def kb_unrestricted(self) -> bool:
        """May read every audience tier in the knowledge base.

        Replaces ``kb.py``'s "no ``_requester`` means unrestricted", which
        made the absence of identity the widest possible identity. Now it is
        a scope, and only named internal actors carry it: the gateway grants
        it to the heartbeat's internal principal, for research and reindex
        actions that run over every audience tier
        (``gateway-rust/src/heartbeat_loop.rs``). That actor is not an admin.
        """
        return self.is_admin or "kb:unrestricted" in self.scopes

    def as_requester(self) -> dict:
        """The ``_requester`` shape the KB handlers already speak."""
        return {"sub": self.sub, "scopes": list(self.scopes), "role": self.role}

    def __repr__(self) -> str:  # pragma: no cover — diagnostics only
        return f"Principal(sub={self.sub!r}, kind={self.kind!r}, scopes={self.scopes!r})"


#: The audiences the gateway signs for (``gateway-rust/src/bus_principal.rs``
#: ``AUDIENCES``; ``tests/test_bus_principal_parity.py`` pins the two).
AUDIENCES = ("worker", "trellion", "trellion-intel")


def _key() -> str:
    """This process's OWN bus key (``NOO_BUS_KEY_FILE`` → /run/secrets).

    Never the controller secret: no Python process holds it since an earlier change, and a verifier holding the signer's secret is what made one leak
    forge principals for every worker.
    """
    from ..secret_env import secret_or_empty

    return secret_or_empty("NOO_BUS_KEY").strip()


def _audience() -> str:
    """Which audience this process is. Not a secret: compose sets it beside
    the key (``worker`` / ``trellion`` / ``trellion-intel``)."""
    import os

    return (os.environ.get("NOO_BUS_AUDIENCE") or "").strip()


def _own_mac(signatures: str, audience: str) -> "str | None":
    """This audience's MAC out of ``aud=hex,aud=hex``; None when absent."""
    for entry in signatures.split(","):
        aud, sep, mac = entry.partition("=")
        if sep and aud == audience:
            return mac
    return None


# ── Nonce cache ───────────────────────────────────────────────────────

_NONCES: "dict[str, float]" = {}


def reset_nonce_cache() -> None:
    """Drop every remembered nonce (tests)."""
    _NONCES.clear()


def _remember_nonce(nonce: str, now: float) -> bool:
    """``True`` if this nonce is new. ``False`` means a replay."""
    if nonce in _NONCES and _NONCES[nonce] > now:
        return False
    if len(_NONCES) >= NONCE_MAX:
        for key in [k for k, exp in _NONCES.items() if exp <= now]:
            del _NONCES[key]
        while len(_NONCES) >= NONCE_MAX:
            del _NONCES[min(_NONCES, key=_NONCES.__getitem__)]
    _NONCES[nonce] = now + NONCE_TTL_SECS
    return True


# ── Verification ──────────────────────────────────────────────────────


def _b64_decode(body: str) -> bytes:
    padding = "=" * (-len(body) % 4)
    return base64.urlsafe_b64decode(body + padding)


def verify_token(token: str, subject: str, *, now: "float | None" = None) -> Principal:
    """Verify one token for one subject, or raise :class:`PrincipalError`.

    Pure over its inputs apart from the nonce cache, so the tests can drive
    the clock rather than sleep.
    """
    key = _key()
    audience = _audience()
    if not key or audience not in AUDIENCES:
        # Not "accept everything": with no key of our own we cannot verify
        # anything, and serving an unverifiable message is exactly what this
        # is for.
        raise PrincipalError(
            "no_key",
            f"this process holds no bus key of its own (NOO_BUS_KEY set: {bool(key)}, "
            f"NOO_BUS_AUDIENCE={audience!r}, expected one of {', '.join(AUDIENCES)}) — it "
            "cannot verify bus principals. Run `noo upgrade --stack` (it mints the bus keys) "
            "or `noo stack restart --force`.",
        )

    body, _, signatures = token.partition(".")
    if not body or not signatures:
        raise PrincipalError("malformed", "principal header is not <body>.<aud>=<mac>[,…]")
    if "=" not in signatures:
        # The pre-702 format: one bare MAC under the shared controller
        # secret. Refused by name so an old gateway mid-roll reads as that.
        raise PrincipalError(
            "legacy_signature",
            "principal is signed in the retired single-secret format — "
            "the gateway is older than this worker; roll them together",
        )

    mac = _own_mac(signatures, audience)
    if mac is None:
        raise PrincipalError("no_audience", f"principal carries no MAC for audience {audience!r}")
    expected = hmac.new(key.encode(), f"{audience}.{body}".encode(), hashlib.sha256).hexdigest()
    # Full width only. The cluster token's 32-char legacy prefix is a
    # compatibility debt (P13) being retired; this format does not inherit it.
    # Bytes, not str (review L7): `compare_digest` raises TypeError on a
    # non-ASCII str, which would turn a forged header into an exception
    # instead of a refusal.
    if len(mac) != 64 or not hmac.compare_digest(mac.encode("utf-8", "replace"), expected.encode()):
        raise PrincipalError("bad_signature", "principal signature does not verify")

    try:
        claims = json.loads(_b64_decode(body))
    except Exception as exc:  # noqa: BLE001 — any decode failure is a refusal
        raise PrincipalError("malformed", f"principal claims are not JSON: {exc}") from exc
    if not isinstance(claims, dict):
        raise PrincipalError("malformed", "principal claims are not an object")

    claimed_subject = str(claims.get("subj") or "")
    if claimed_subject != subject:
        # Signed-but-for-something-else. Without this a principal lifted off
        # `worker.memory.search` would work on `worker.tool.generic` for the
        # next 60 seconds.
        raise PrincipalError(
            "wrong_subject",
            f"principal is signed for {claimed_subject!r}, message arrived on {subject!r}",
        )

    now = time.time() if now is None else now
    try:
        iat = float(claims.get("iat"))
        exp = float(claims.get("exp"))
    except (TypeError, ValueError) as exc:
        raise PrincipalError("malformed", "principal iat/exp are not numbers") from exc
    if now > exp + CLOCK_SKEW_SECS:
        raise PrincipalError("expired", f"principal expired {int(now - exp)}s ago")
    if iat > now + CLOCK_SKEW_SECS:
        raise PrincipalError("not_yet_valid", f"principal issued {int(iat - now)}s in the future")

    nonce = str(claims.get("nonce") or "")
    if not nonce:
        raise PrincipalError("malformed", "principal carries no nonce")
    if not _remember_nonce(nonce, now):
        raise PrincipalError("replay", "principal nonce was already used")

    sub = str(claims.get("sub") or "")
    if not sub:
        raise PrincipalError("malformed", "principal names no subject")
    kind = str(claims.get("kind") or "")
    if kind not in ("user", "internal"):
        raise PrincipalError("malformed", f"principal kind {kind!r} is not user/internal")
    scopes_raw = claims.get("scopes") or []
    if not isinstance(scopes_raw, list):
        raise PrincipalError("malformed", "principal scopes are not a list")
    scopes = [str(s) for s in scopes_raw]
    role = str(claims.get("role") or "user")

    return Principal(sub=sub, kind=kind, role=role, scopes=scopes)


def _header_value(headers) -> "str | None":
    """Read the principal header, case-insensitively.

    NATS headers are transmitted as written and every client in this fleet
    sends `Noo-Principal`, so the exact-match lookup is the one that fires.
    The fallback exists because getting this wrong is not a subtle bug: with
    the gate at `required`, a client that canonicalised the name differently
    would have EVERY message refused, and the failure would read as a total
    outage of the Python surface rather than as a header-case mismatch.
    """
    if not headers:
        return None
    try:
        token = headers.get(HEADER)
        if token:
            return str(token)
        wanted = HEADER.lower()
        for key, value in headers.items():
            if str(key).lower() == wanted and value:
                return str(value)
    except Exception:  # noqa: BLE001 — an exotic header container
        return None
    return None


def verify_message(headers, subject: str, *, now: "float | None" = None) -> Principal:
    """Verify a NATS message's headers.

    Returns the verified principal. Raises :class:`PrincipalError` in every
    failing case — including "no header at all": there is no unsigned mode.
    """
    token = _header_value(headers)
    if not token:
        raise PrincipalError("missing", "message carries no principal header")
    return verify_token(str(token), subject, now=now)


# ── Applying a verified principal to a request body ───────────────────

#: Reserved key: the verified principal, as handlers read it.
PRINCIPAL_KEY = "_principal"


def apply_to_request(request: dict, principal: Principal) -> dict:
    """Overwrite the body's identity claims from the verified header.

    Overwrite, never merge — the body is caller-controlled and the header is
    an authenticated fact, the same rule ``routes/knowledge.rs`` already
    applies to ``_requester`` on the HTTP side.

    The two kinds are treated differently, and the difference is the whole
    tenancy rule:

    * **user** — the header IS the tenant. ``_requester`` is replaced with
      it, and a payload ``user_id`` naming somebody else is refused rather
      than quietly ignored: a caller trying to read another tenant's data is
      an event, not a preference.
    * **internal** — a loop legitimately acts *for* somebody (the heartbeat
      runs a task owned by a user), so a payload ``user_id`` still selects
      the tenant. What it may not do is choose its own authority: scopes come
      from the header, so an internal actor is never an admin because the
      body said so.

    **There is deliberately no "admin acting for another user" on the bus.**
    On the HTTP rail ``auth.scoped_user`` lets Operator+ name somebody else;
    over NATS a `user` principal naming a different ``user_id`` is refused,
    admin or not. No in-tree worker handler needs it — none of the delegated
    subjects reads ``user_id`` at all — and a delegation that exists "just in
    case" is one an attacker can use and nobody is watching. If it is ever
    genuinely needed it should be an ``act_as`` claim the GATEWAY signs, so
    the delegation is authorised where the authorisation lives rather than
    asserted in a body.

    The returned dict carries :data:`PRINCIPAL_KEY`, whose value is a
    :class:`Principal` OBJECT rather than a dict. Nothing in-tree
    re-serialises a whole request — handlers return their own payloads — but
    anything that starts to must strip the key first.
    """
    body = dict(request)
    params = body.get("params")
    has_params = isinstance(params, dict)
    params = dict(params) if has_params else {}

    if principal.is_user:
        for holder in (body, params):
            claimed = holder.get("user_id")
            if claimed and str(claimed) != principal.sub:
                raise PrincipalError(
                    "user_id_mismatch",
                    f"payload user_id {str(claimed)[:64]!r} does not match the signed "
                    f"principal {principal.sub!r}",
                )
        body["user_id"] = principal.sub
        if has_params:
            params["user_id"] = principal.sub

    requester = principal.as_requester()
    body["_requester"] = requester
    if has_params:
        params["_requester"] = requester
        body["params"] = params
    body[PRINCIPAL_KEY] = principal
    if has_params:
        params[PRINCIPAL_KEY] = principal
        body["params"] = params
    return body


def tenant_of(request: dict, params: "dict | None" = None) -> "str | None":
    """The user a data read must be scoped to, from the VERIFIED header.

    This is the R32 fix at the point of use. A ``user`` principal IS the
    tenant, and the payload cannot disagree — :func:`apply_to_request`
    already refused the message if it tried. An ``internal`` principal is a
    loop acting for somebody, so the payload still names the tenant; what it
    could never do is grant itself scopes.

    ``None`` means "nothing decided here" and leaves the caller's existing
    fail-closed resolution (``identity.scope.resolve_scope_user``) in charge,
    which is what keeps a single-account install working.
    """
    principal = of(request) or (of(params) if params else None)
    if principal is not None and principal.is_user:
        return principal.sub
    for holder in (params, request):
        if not holder:
            continue
        claimed = holder.get("user_id")
        if claimed:
            return str(claimed)
    return None


def of(request: dict) -> "Principal | None":
    """The verified principal attached to a request by the worker pool."""
    value = request.get(PRINCIPAL_KEY)
    return value if isinstance(value, Principal) else None
