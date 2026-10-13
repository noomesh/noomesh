# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""What an add-on's compose env must (and must not) pass through.

History: this file began as "a service that PROVISIONS a role needs that
role's password in its env" — an earlier change had noo-trellion create
`noo_trellion` itself, and three separate outages (033's missing
`NOO_APP_DB_PASSWORD` passthrough crash-looping the gateway, #299; 034's
same lesson; 038's) came from a password that never reached the
provisioner. Role creation is the broker's job since phase A′, and since
an earlier change no add-on DSN carries a password (pgpass files instead), so
that check retired with its subject — see the note below.

What stays: the add-on switch is the `addons:` map in the mounted
noomesh.yaml, and no retired add-on flag comes back as a passthrough.
"""
from __future__ import annotations

from tests._compose_projection import raw_services_union  # base + add-on overlays, as written

# (PROVISIONERS — "service → the role password it needs to CREATE its own
# role" — held one row, trellion, and it went stale: role creation moved to
# the broker in the design, and trellion's memory env says so
# (src/trellion/db/migrations/env.py: "creating the noo_trellion role — the
# broker's job"). the design stopped delivering NOO_TRELLION_DB_PASSWORD
# to noo-trellion, whose DSNs carry no password any more: the roles it logs in
# as read theirs from a pgpass file (tests/test_compose_secret_files.py pins
# the roles to the DSN users). A service that DOES provision a role again
# needs the password through a `_FILE`-aware reader, not this passthrough.)

def _env_keys(service: str) -> set[str]:
    compose = {"services": raw_services_union()}
    env = compose["services"][service]["environment"]
    if isinstance(env, dict):
        return set(env)
    return {entry.split("=", 1)[0] for entry in env}


# The 2026-08-05 failure — `NOO_PRO_ENABLED=1` in `.env`, noo-evolve running,
# and still `provisioned=1 skipped=1` because the flag never reached the
# gateway container — is now structurally impossible rather than guarded: a
# system named after an add-on follows the `addons:` map, and that map is in
# noomesh.yaml, which is MOUNTED into the container. There is no flag to
# forward and therefore no allowlist entry to forget.
#
# What has to stay true is the mount. Without it the gateway falls back to
# every add-on's default polarity, which for the licensed ones is off — the
# same silent skip in a new costume.
def test_the_gateway_mounts_the_config_that_declares_addons():
    compose = {"services": raw_services_union()}
    volumes = compose["services"]["gateway"].get("volumes") or []
    mounted = [v for v in volumes if isinstance(v, str) and "noomesh.yaml" in v]
    assert mounted, (
        "the gateway does not mount noomesh.yaml. The `addons:` map in that "
        "file is the ONE declaration of which add-ons run: the launcher reads "
        "it for compose profiles and the gateway reads it for routing and "
        "refusals. Unmounted, the gateway falls back to default polarity and "
        "every licensed add-on silently reads as off."
    )


def test_no_retired_addon_flag_is_passed_to_any_service():
    """The four retired flags must not come back as a passthrough.

    Re-adding one would recreate the exact bug this replaced: a second
    declaration of the same boolean, able to disagree with the map, with the
    env copy winning inside the container.
    """
    retired = {
        "NOO_PRO_ENABLED",
        "NOO_TRELLION_ENABLED",
        "NOO_TRELLION_INTEL_ENABLED",
        "NOO_VOICE_ENABLED",
    }
    compose = {"services": raw_services_union()}
    offenders = []
    for name, svc in (compose.get("services") or {}).items():
        for key in _env_keys(name) if svc.get("environment") else set():
            if key in retired:
                offenders.append(f"{name}: {key}")
    assert not offenders, (
        "retired add-on flags are being passed into containers: "
        f"{offenders}. Add-ons are declared once, in noomesh.yaml."
    )

