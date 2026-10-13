#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

[ -n "${_NOO_LIB_ADDONS_LOADED:-}" ] && return 0
_NOO_LIB_ADDONS_LOADED=1
# Add-on resolution, shared by noomesh-start.sh and noomesh-rebuild.sh.
#
# These two scripts used to carry this logic twice, and rebuild's own comment
# records what that cost: the copies drifted, rebuild kept gating on a flag
# start.sh had stopped reading, the two disagreed about which container owns
# the memory Alembic env, and the gateway crash-looped on rebuild only.
# "MUST MIRROR noomesh-start.sh EXACTLY" is not a mechanism. This file is.

# ONE declaration: the `addons:` map in noomesh.yaml. It drives BOTH halves —
# the compose profiles/overlays here, and the gateway's routing and refusals
# (it reads the same mounted file). What got deployed and what the gateway
# will route to therefore cannot disagree.
#
# There is no NOO_TRELLION_ENABLED / NOO_PRO_ENABLED /
# NOO_TRELLION_INTEL_ENABLED / NOO_VOICE_ENABLED any more. That boolean used
# to be written down in six places (.env, this script, the onboard wizard,
# addons.rs, the compose passthrough, systems.*.enabled_when) and they could
# disagree — on 2026-08-05 evolve's schema was silently never provisioned
# because one of the six never reached the gateway container.
#
# Read here rather than after lib-config.sh, so the block that decides the
# compose invocation stays where the compose invocation is built. `noo` is
# the primary reader (it already parses this map for itself —
# commands/addons.rs — and is on every host that runs this launcher, being
# what invoked it; see `noo_bin` in lib-config.sh, sourced by every caller
# of this file before it). python3+PyYAML is the fallback for a dev
# checkout with no `noo` binary handy; with neither, each add-on falls back
# to its own polarity, which is the documented default shape.
# Test seam: a caller that sets NOO_ADDON_MAP_OVERRIDE=1 supplies the map
# itself (the CLI's parity test runs where neither noo nor python3-yaml may
# be available). The flag is required so a stale NOO_ADDON_MAP exported in
# an operator's shell can never outvote noomesh.yaml by accident.
if [ "${NOO_ADDON_MAP_OVERRIDE:-}" = 1 ]; then
    NOO_ADDON_MAP="${NOO_ADDON_MAP:-}"
elif [ -f noomesh.yaml ] && _ao_nb="$(noo_bin 2>/dev/null)" \
        && NOO_ADDON_MAP="$("$_ao_nb" config launch-render addons noomesh.yaml 2>/dev/null)"; then
    # (an older noo without the subcommand fails the && and falls through)
    unset _ao_nb
elif [ -f noomesh.yaml ] && command -v python3 >/dev/null 2>&1; then
    NOO_ADDON_MAP=""
    NOO_ADDON_MAP="$(python3 - <<'PYEOF' 2>/dev/null || true
import sys
try:
    import yaml
    doc = yaml.safe_load(open("noomesh.yaml")) or {}
except Exception:
    sys.exit(0)
addons = doc.get("addons")
if isinstance(addons, dict):
    for name, on in addons.items():
        print("%s=%s" % (name, "1" if on else "0"))
PYEOF
)"
elif [ -f noomesh.yaml ]; then
    echo "config: neither the noo CLI nor python3+PyYAML found — addons not read from noomesh.yaml (each add-on falls back to its own default)" >&2
fi

# Add-ons --core-only may defer. trellion is NOT on this list, and the reason
# is about the MAP, not about trellion being special.
#
# The gateway's `check_baseline_tables` preflight requires trellion's four
# tables WHEN THE MAP SAYS TRELLION IS ON — which during onboarding it does,
# seeded from the example. Deferring the container while the declaration says
# enabled would have the gateway correctly demand a schema nobody was asked
# to create, and abort. Deferral has to agree with the declaration.
#
# Turning trellion off is a genuine, bootable configuration (the preflight
# asks for its tables only when it is enabled). It is simply not something
# --core-only can decide on the operator's behalf mid-wizard.
CORE_ONLY_DEFERS="evolve trellion_intel voice"

# addon_on NAME DEFAULT(0|1) — is this add-on switched on?
#
# CORE_ONLY (the launcher's --core-only flag) answers "no" for the deferrable
# add-ons without touching the map. The wizard needs a run that brings up
# base services before it has asked which add-ons the operator wants; making
# that a caller-side override rather than a temporary edit keeps noomesh.yaml
# the one declaration.
# Absent from the map is NOT "off": it is "not stated", which resolves to the
# add-on's own polarity, matching addons::resolve in the gateway.
addon_on() {
    if [ "${CORE_ONLY:-false}" = true ]; then
        case " $CORE_ONLY_DEFERS " in
            *" $1 "*) return 1 ;;
        esac
    fi
    _ao_line="$(printf '%s\n' "$NOO_ADDON_MAP" | grep -E "^$1=" | tail -1)"
    if [ -n "$_ao_line" ]; then
        [ "${_ao_line#*=}" = "1" ]
    else
        [ "$2" = "1" ]
    fi
}

# There is no addon_compose_overlay_args any more: every add-on
# is an OVERLAY, composed by file. Profiles remain for the base's own tiers
# (controller, standalone, gpu-tier*, monitoring…), which are not add-ons.


# The overlay add-ons (trellion, voice, trellion_intel, evolve): echoes `-f <overlay>` pairs
# or nothing. Same contract — append unquoted to COMPOSE_FILES (lib-compose.sh
# is the one caller).
addon_compose_overlay_args() {
    _aco_out=""
    # trellion FIRST: the Intelligent tier's overlay extends its service.
    if addon_on trellion 1; then
        _aco="$(addons_trellion_overlay)"
        [ -n "$_aco" ] && _aco_out="$_aco_out -f $_aco"
    fi
    if addon_on voice 0; then
        _aco="$(addons_voice_overlay)"
        [ -n "$_aco" ] && _aco_out="$_aco_out -f $_aco"
    fi
    if addon_on trellion_intel 0; then
        _aco="$(addons_trellion_intel_overlay)"
        [ -n "$_aco" ] && _aco_out="$_aco_out -f $_aco"
    fi
    if addon_on evolve 0; then
        _aco="$(addons_evolve_overlay)"
        [ -n "$_aco" ] && _aco_out="$_aco_out -f $_aco"
    fi
    printf '%s' "${_aco_out# }"
    return 0
}

# addons_trellion_overlay — the knowledge pack, opt-OUT.
addons_trellion_overlay() {
    _ao_here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ -f "$_ao_here/docker-compose.trellion.yml" ]; then
        printf '%s' "$_ao_here/docker-compose.trellion.yml"
    fi
}

# addons_voice_overlay — noo-whisper + noo-piper, shipped in this tree
#.
addons_voice_overlay() {
    _ao_here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ -f "$_ao_here/docker-compose.voice.yml" ]; then
        printf '%s' "$_ao_here/docker-compose.voice.yml"
    fi
}

# addons_trellion_intel_overlay — the Intelligent tier's overlay, shipped in
# this tree. It EXTENDS the base's trellion service, so
# it is only meaningful beside docker-compose.cluster.yml.
addons_trellion_intel_overlay() {
    _ao_here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ -f "$_ao_here/docker-compose.trellion-intel.yml" ]; then
        printf '%s' "$_ao_here/docker-compose.trellion-intel.yml"
    fi
}

addons_guard_retired_flags() {
    [ -f ".env" ] || return 0
    _retired="$(grep -oE '^[[:space:]]*(NOO_TRELLION_ENABLED|NOO_PRO_ENABLED|NOO_TRELLION_INTEL_ENABLED|NOO_VOICE_ENABLED)=' .env | tr -d ' \t=' | sort -u | tr '\n' ' ')"
    [ -n "$_retired" ] || return 0
    cat >&2 <<EOF

ERROR: .env still carries retired add-on flags: $_retired

Add-ons are declared in noomesh.yaml now — one place, read by both the
launcher and the gateway:

  addons:
    trellion: true
    evolve: true          # if you had NOO_PRO_ENABLED=1
    trellion_intel: true  # if you had NOO_TRELLION_INTEL_ENABLED=1
    voice: true           # if you had NOO_VOICE_ENABLED=1

  noo onboard --only addons     # writes it for you

Then delete those lines from .env. Refusing to start rather than guess which
one you meant — a licensed add-on silently changing state on upgrade is the
failure this avoids.
EOF
    exit 1
}

# warn_retired_env_keys — one WARN line per retired .env key that nothing
# reads any more, naming what replaced it. A warning, not a refusal: these
# keys are inert (compose no longer delivers them), so the stack is correct
# either way — the operator just deserves to know the line does nothing.
warn_retired_env_keys() {
    [ -f ".env" ] || return 0
    _wr_list="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/retired-env-keys"
    [ -f "$_wr_list" ] || return 0
    while IFS='|' read -r _wr_key _wr_note; do
        case "$_wr_key" in ''|'#'*) continue ;; esac
        if grep -qE "^[[:space:]]*${_wr_key}=" .env; then
            echo "WARN: .env sets ${_wr_key}, which is RETIRED and ignored — ${_wr_note}. Run \`noo onboard --only env\` to remove it (it backs up .env first)." >&2
        fi
    done < "$_wr_list"
    return 0
}

# addons_evolve_overlay — echo the evolve compose overlay path, if present.
# The overlay travels with the code: it lives in the
# noo-evolve checkout, and its relative paths still resolve against the
# CALLER's directory, because compose resolves them against the first -f
# file's location.
addons_evolve_overlay() {
    _ao_base="${NOO_EVOLVE_PATH:-../noo-evolve}"
    if [ -f "$_ao_base/docker-compose.evolve.yml" ]; then
        printf '%s' "$_ao_base/docker-compose.evolve.yml"
    elif [ -f "$_ao_base/docker-compose.pro.yml" ]; then
        # The dev overlay's pre-proposal-54 name; a checkout that has not
        # pulled the rename still composes.
        printf '%s' "$_ao_base/docker-compose.pro.yml"
    else
        # No checkout: the PUBLISHED image, through the overlay that ships in
        # this tree. Before this fallback, `addons.evolve: true` with no
        # checkout meant the gateway provisioned the add-on and /health
        # reported it enabled while nothing served it (2026-09-14).
        _ao_here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
        if [ -f "$_ao_here/docker-compose.evolve.yml" ]; then
            printf '%s' "$_ao_here/docker-compose.evolve.yml"
        fi
    fi
}
