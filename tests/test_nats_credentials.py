# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Which NATS credential the worker presents, and the refusal when it has none.

an earlier change. One shared bus user for the gateway, the workers and
every node makes subject permissions impossible; and an empty user used to
connect ANONYMOUSLY to a server that accepts it, silently removing bus
authentication altogether. an earlier change retired the shared user and its
bridge: the worker's own pair is the only credential it presents.
"""

import pytest

from noomesh.cluster.messaging import (
    ALLOW_ANONYMOUS_VAR,
    NatsCredentialsMissing,
    RETIRED_SHARED_USER_VAR,
    WORKER_PASSWORD_VAR,
    WORKER_USER_VAR,
    INBOX_PREFIX,
    resolve_nats_credentials,
)

#: The retired bridge and the retired password, spelled out rather than
#: imported: the module no longer exports them, and a test that imported
#: them would be the thing keeping them alive.
RETIRED_BRIDGE = "NOO_NATS_LEGACY_SHARED_CREDS"
RETIRED_PASSWORD = "NATS_PASSWORD"


def test_role_pair_wins_over_shared():
    cred = resolve_nats_credentials({
        WORKER_USER_VAR: "worker",
        WORKER_PASSWORD_VAR: "worker-secret",
        RETIRED_SHARED_USER_VAR: "noo",
        RETIRED_PASSWORD: "fleet-secret",
    })
    assert cred == {"user": "worker", "password": "worker-secret", "source": "worker"}


@pytest.mark.parametrize("bridge", ["", "0", "1", "true"])
def test_the_shared_pair_is_refused_whatever_the_retired_bridge_says(bridge):
    """an earlier change: the shared user is retired, and so is its bridge.

    Before the retirement `NOO_NATS_LEGACY_SHARED_CREDS=1` handed back
    ``{"user": "noo", "source": "shared"}`` — the one credential users.conf
    could only grant ``>``/``>``. The server no longer defines that user, so
    there is nothing to bridge to: the refusal is unconditional, and names
    the command that mints the worker's own pair.
    """
    env = {RETIRED_SHARED_USER_VAR: "noo", RETIRED_PASSWORD: "fleet-secret"}
    if bridge:
        env[RETIRED_BRIDGE] = bridge
    with pytest.raises(NatsCredentialsMissing) as exc:
        resolve_nats_credentials(env)
    message = str(exc.value)
    assert "RETIRED" in message, "the refusal must say the shared user is retired"
    assert WORKER_USER_VAR in message, "the refusal must name the pair it wants"
    assert "nats-creds rotate worker" in message, "the refusal must name the fix"
    assert RETIRED_BRIDGE not in message, "the refusal must not offer the retired bridge"


def test_blank_role_user_does_not_fall_through_to_the_shared_pair():
    with pytest.raises(NatsCredentialsMissing):
        resolve_nats_credentials({
            WORKER_USER_VAR: "  ",
            RETIRED_SHARED_USER_VAR: "noo",
            RETIRED_PASSWORD: "fleet-secret",
            RETIRED_BRIDGE: "1",
        })


@pytest.mark.parametrize("env", [
    {},
    {RETIRED_SHARED_USER_VAR: "", RETIRED_PASSWORD: ""},
    {RETIRED_SHARED_USER_VAR: "", RETIRED_PASSWORD: "fleet-secret"},
    {ALLOW_ANONYMOUS_VAR: "0"},
    {ALLOW_ANONYMOUS_VAR: "no"},
])
def test_missing_credentials_refuse_to_connect(env):
    with pytest.raises(NatsCredentialsMissing) as exc:
        resolve_nats_credentials(env)
    message = str(exc.value)
    for var in (WORKER_USER_VAR, ALLOW_ANONYMOUS_VAR):
        assert var in message, f"the refusal must name {var}"


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE"])
def test_escape_hatch_allows_anonymous(value):
    assert resolve_nats_credentials({ALLOW_ANONYMOUS_VAR: value}) is None


def test_escape_hatch_does_not_discard_a_configured_credential():
    cred = resolve_nats_credentials({
        ALLOW_ANONYMOUS_VAR: "1",
        WORKER_USER_VAR: "worker",
        RETIRED_PASSWORD: "fleet-secret",
    })
    assert cred["user"] == "worker"


def test_the_anonymous_hatch_does_not_smuggle_the_shared_pair_in():
    """`NOO_NATS_ALLOW_ANONYMOUS` is not a second spelling of a bridge.

    With the retired shared pair set and only the anonymous hatch on, the
    answer must be "connect anonymously" — never "use `noo`".
    """
    assert resolve_nats_credentials({
        ALLOW_ANONYMOUS_VAR: "1",
        RETIRED_SHARED_USER_VAR: "noo",
        RETIRED_PASSWORD: "fleet-secret",
    }) is None


def test_inbox_prefix_is_a_single_worker_scoped_token():
    assert INBOX_PREFIX == "_INBOX_worker"
    assert "." not in INBOX_PREFIX, "a dot would create a subject hierarchy"


# ── an add-on's own principal (i70 residue) ──────────────────────────────

from noomesh.cluster.messaging import (  # noqa: E402
    ADDON_PASSWORD_VAR,
    ADDON_USER_VAR,
    BUS_AUDIENCE_VAR,
    inbox_prefix_for,
)

_WORKER_PAIR = {WORKER_USER_VAR: "worker", WORKER_PASSWORD_VAR: "wk"}


@pytest.mark.parametrize("audience, user", [("trellion", "trellion"), ("trellion-intel", "trellion_intel")])
def test_an_addon_presents_its_own_principal(audience, user):
    cred = resolve_nats_credentials({
        **_WORKER_PAIR, BUS_AUDIENCE_VAR: audience, ADDON_USER_VAR: user, ADDON_PASSWORD_VAR: "own",
    })
    assert cred == {"user": user, "password": "own", "source": "addon"}
    # Its client inbox is its own, not the worker's.
    assert inbox_prefix_for(cred) == f"_INBOX_{user}"


def test_an_addon_without_its_password_falls_back_to_the_worker_and_says_so():
    # ONE release: the overlay sets NATS_ADDON_USER only when the store holds
    # the add-on's password, so absent means "not migrated yet".
    from structlog.testing import capture_logs

    # The overlay's user is a literal; the password FILE is there only when
    # the store holds it.
    with capture_logs() as logs:
        cred = resolve_nats_credentials({**_WORKER_PAIR, BUS_AUDIENCE_VAR: "trellion", ADDON_USER_VAR: "trellion"})
    assert cred == {"user": "worker", "password": "wk", "source": "worker"}
    assert inbox_prefix_for(cred) == INBOX_PREFIX
    warned = [entry for entry in logs if entry["event"] == "nats_addon_principal_fallback"]
    assert warned and warned[0]["log_level"] == "warning", logs
    assert "NATS_TRELLION_PASSWORD" in warned[0]["message"]


def test_an_inherited_principal_is_never_presented():
    # trellion-intel `extends` trellion; a bundle that predates its own
    # principal inherits trellion's pair. It must present the worker, not
    # trellion (whose grant cannot subscribe intel's subjects anyway).
    from structlog.testing import capture_logs

    with capture_logs() as logs:
        cred = resolve_nats_credentials({
            **_WORKER_PAIR, BUS_AUDIENCE_VAR: "trellion-intel",
            ADDON_USER_VAR: "trellion", ADDON_PASSWORD_VAR: "trellions",
        })
    assert cred["user"] == "worker" and cred["source"] == "worker"
    assert any(entry["event"] == "nats_addon_principal_not_ours" for entry in logs), logs


def test_the_core_worker_says_nothing_about_add_ons():
    from structlog.testing import capture_logs

    with capture_logs() as logs:
        cred = resolve_nats_credentials({**_WORKER_PAIR, BUS_AUDIENCE_VAR: "worker"})
    assert cred["source"] == "worker"
    assert not [entry for entry in logs if entry["event"].startswith("nats_addon")], logs


def test_the_addon_password_is_read_from_its_file(tmp_path):
    f = tmp_path / "nats_addon_password"
    f.write_text("from-file\n")
    cred = resolve_nats_credentials({
        BUS_AUDIENCE_VAR: "trellion", ADDON_USER_VAR: "trellion", ADDON_PASSWORD_VAR + "_FILE": str(f),
    })
    assert cred == {"user": "trellion", "password": "from-file", "source": "addon"}
