# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Write-side KB audience clamping for the `ingest` scope.

The read side (`_resolve_kb_roles`) decides what a caller may SEE. This covers
what a caller may TAG, which is a different question with a different answer:
`system` is readable by everyone and writable by nobody but an operator.

Why this matters more than it looks: the clamp in `workers/rag.py::_rag_ingest`
existed before the `ingest` scope and had NEVER executed. Its guard is
`if requester …`, and `routes/knowledge.rs::docs_ingest` — hand-written rather
than built by `delegate_post` — never attached `_requester`. It was correct-
looking dead code, harmless only because `scope_allows` let nobody but
write/admin reach the route, and for them the clamp is a deliberate no-op.
Adding a scope that reaches the route is what makes it load-bearing.
"""
from __future__ import annotations

import pytest

from noomesh.gateway import bus_principal as bp
from noomesh.workers.kb import _resolve_kb_roles as _resolve_kb_roles_real
from noomesh.workers.kb import _writable_kb_roles


def _resolve_kb_roles(params: dict, grants=None):
    """Call the real resolver the way the bus now calls it.

    The read side stopped taking the caller from the message body (an earlier changef R32): ``_resolve_kb_roles`` reads the principal the worker pool
    verified from the signed ``Noo-Principal`` header, and an absent one is a
    refusal rather than "unrestricted". These cases were written against the
    body, so this attaches the principal the header would have carried —
    which keeps every assertion below testing the CLAMP, which is what this
    file is about, rather than the plumbing that delivers the identity.

    `_writable_kb_roles` is unchanged: it already took a requester dict as an
    argument rather than digging it out of a payload.
    """
    requester = params.get("_requester")
    if requester:
        params = {
            **params,
            bp.PRINCIPAL_KEY: bp.Principal(
                sub=requester.get("sub", ""),
                kind="user",
                role=requester.get("role", "user"),
                scopes=list(requester.get("scopes") or []),
            ),
        }
    return _resolve_kb_roles_real(params, grants)

INTERNAL: dict = {}
ADMIN = {"sub": "alice", "scopes": ["admin", "write", "read"]}
OPERATOR = {"sub": "carol", "scopes": ["read", "write"]}
CONTRIB = {"sub": "claude-ext", "scopes": ["read", "ingest"]}
READER = {"sub": "areader", "scopes": ["read"]}


class TestUnrestrictedCallers:
    def test_no_requester_is_unclamped(self):
        """Cluster-HMAC / service-key / internal callers keep today's
        behaviour — the ingest loop and heartbeat tag documents freely."""
        assert _writable_kb_roles(INTERNAL) is None

    def test_admin_is_unclamped(self):
        assert _writable_kb_roles(ADMIN) is None


class TestWriteIsNotAVisibilityTier:
    """`write` grants API access, not KB audience.

    It used to grant both. That made "let them contribute documents" and "let
    them read every other user's private tier" the same grant, which is not a
    tradeoff anyone would choose deliberately if the two were stated
    separately. Only `admin` is unrestricted now.
    """

    def test_operator_is_clamped_on_write(self):
        assert _writable_kb_roles(OPERATOR) == {"company", "user:carol"}

    def test_operator_is_clamped_on_read(self):
        assert _resolve_kb_roles({"_requester": OPERATOR}) is not None

    def test_operator_cannot_tag_system(self):
        assert "system" not in _writable_kb_roles(OPERATOR)

    def test_operator_cannot_read_another_users_tier(self):
        readable = set(_resolve_kb_roles({"_requester": OPERATOR}) or [])
        assert "user:claude-ext" not in readable

    def test_operator_explicit_role_request_is_clamped_not_honoured(self):
        """Asking for someone else's tier by name must not be a way around
        the default — the clamp intersects, it does not defer."""
        got = _resolve_kb_roles(
            {"_requester": OPERATOR, "roles": ["user:alice", "company"]}
        )
        assert got == ["company"]

    def test_operator_reads_identically_to_a_plain_reader(self):
        op = set(_resolve_kb_roles({"_requester": OPERATOR}) or [])
        rd = set(_resolve_kb_roles({"_requester": READER}) or [])
        assert op - {"user:carol"} == rd - {"user:areader"}


class TestContributorAudience:
    def test_can_tag_the_shared_company_tier(self):
        """The point of the feature: a contributed document can land where
        everyone else's does, instead of being trapped in the ingesting
        account's personal tier where the humans would never see it."""
        assert "company" in _writable_kb_roles(CONTRIB)

    def test_can_tag_own_personal_tier(self):
        assert "user:claude-ext" in _writable_kb_roles(CONTRIB)

    def test_cannot_tag_system(self):
        """`system` is where repo runbooks live, so a document wearing it
        reads as authoritative to every user on the deployment. Self-declaring
        that is content injection, not sharing."""
        assert "system" not in _writable_kb_roles(CONTRIB)

    def test_cannot_tag_another_users_tier(self):
        assert "user:alice" not in _writable_kb_roles(CONTRIB)

    def test_granted_teams_are_writable(self):
        """Teams are how org membership attaches to a user, so a member may
        contribute into their team's tier."""
        allowed = _writable_kb_roles(CONTRIB, ["team:research"])
        assert "team:research" in allowed

    def test_a_granted_system_role_is_still_refused(self):
        """Grants come from a DB table an operator edits. Even so, `system`
        does not become writable — the write rule is not "whatever you can
        read"."""
        assert "system" not in _writable_kb_roles(CONTRIB, ["system", "team:x"])

    def test_legacy_generic_user_tier_is_not_writable(self):
        """The bare `user` tier is the pre-roles bucket. Nothing new should be
        born into it."""
        assert "user" not in _writable_kb_roles(CONTRIB, ["user"])


class TestReadWriteAsymmetry:
    def test_system_is_readable_but_not_writable(self):
        """The asymmetry is the design, so state it as a test rather than
        leaving it implied by two separate functions."""
        readable = set(_resolve_kb_roles({"_requester": CONTRIB}) or [])
        writable = _writable_kb_roles(CONTRIB) or set()
        assert "system" in readable
        assert "system" not in writable

    def test_company_is_both(self):
        readable = set(_resolve_kb_roles({"_requester": CONTRIB}) or [])
        assert "company" in readable
        assert "company" in _writable_kb_roles(CONTRIB)


class TestScopeDoesNotWidenReads:
    def test_ingest_scope_does_not_unrestrict_the_kb(self):
        """`ingest` must not behave like `write`.

        `_resolve_kb_roles` returns None — unrestricted — for admin. If
        `ingest` ever joined that branch, a contributor could read the whole
        corpus, which is the escalation the per-user door was built to remove.
        """
        assert _resolve_kb_roles({"_requester": CONTRIB}) is not None

    def test_ingest_scope_reads_identically_to_plain_read(self):
        contrib = set(_resolve_kb_roles({"_requester": CONTRIB}) or [])
        reader = set(_resolve_kb_roles({"_requester": READER}) or [])
        # Same shape; only the personal tier differs by username.
        assert contrib - {"user:claude-ext"} == reader - {"user:areader"}


class TestReadWriteInvariant:
    """The relationship between the two sides, asserted rather than assumed.

    Both now derive from `_kb_audience`, so the only intended difference is
    that reads add `system`. These pin that down: a future change that widens
    what may be WRITTEN fails here instead of shipping quietly.
    """

    CASES = [
        ({"sub": "claude-ext", "scopes": ["read", "ingest"]}, None),
        ({"sub": "carol", "scopes": ["read"]}, ["team:research"]),
        ({"sub": "x", "scopes": ["read"]}, ["team:a", "team:b", "system", "user"]),
        ({"sub": "", "scopes": ["read"]}, None),
        # `write` is inside the invariant now, not exempt from it.
        ({"sub": "carol", "scopes": ["read", "write"]}, None),
        ({"sub": "opr", "scopes": ["read", "write"]}, ["team:research"]),
    ]

    def test_writable_is_always_a_subset_of_readable(self):
        """You may never tag a document into a tier you cannot even see."""
        for requester, grants in self.CASES:
            readable = set(_resolve_kb_roles({"_requester": requester}, grants) or [])
            writable = _writable_kb_roles(requester, grants) or set()
            assert writable <= readable, (
                f"{requester['sub'] or '<anon>'} can write {sorted(writable - readable)} "
                "but cannot read it"
            )

    def test_system_is_the_only_difference(self):
        for requester, grants in self.CASES:
            readable = set(_resolve_kb_roles({"_requester": requester}, grants) or [])
            writable = _writable_kb_roles(requester, grants) or set()
            assert readable - writable == {"system"}, (
                "read and write should differ by exactly `system`; got "
                f"{sorted(readable - writable)}"
            )

    def test_an_admin_stays_unrestricted_on_both_sides(self):
        assert _resolve_kb_roles({"_requester": ADMIN}) is None
        assert _writable_kb_roles(ADMIN) is None

    def test_an_unidentified_reader_is_refused_rather_than_unrestricted(self):
        """The asymmetry that changed, and the reason it changed.

        Reading with no identity used to return `None` — unrestricted, the
        whole corpus — so the ABSENCE of a claim was the widest claim anyone
        could make. It was safe only while the gateway was the sole publisher
        on `worker.>` (#100), which is a property of the bus, not of this
        call. Now a caller proves who it is or gets nothing.

        The WRITE side keeps returning `None` for an unidentified caller, and
        that is not an oversight: `_writable_kb_roles` is handed its
        requester by name, so "no requester" there means an internal caller
        the gateway already authenticated, not an unauthenticated one.
        """
        with pytest.raises(PermissionError):
            _resolve_kb_roles({})
        assert _writable_kb_roles(INTERNAL) is None
