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
#
# Every licensed add-on is deferred too (addon_on: anything not trellion),
# without naming one here: they are puzzle pieces core does not list.
CORE_ONLY_DEFERS="voice"
# The add-ons whose overlay ships in this tree. Every other add-on's overlay
# arrives in its own signed bundle (N6): addons/<name>/docker-compose.yml.
CORE_OVERLAY_ADDONS="trellion voice"
# Core add-ons that are a GATEWAY FEATURE FLAG and nothing else: no
# container, no overlay, never a bundle (docs/getting-started/add-ons.md:
# identity is free, `addons.identity (on)`). They are not licensed add-ons,
# so nothing below looks for an overlay for them; addons_report_licensed
# says "gateway feature" instead of the no-overlay warning it printed for
# identity on every start (N6, 2026-10-15). Mirrors the CLI's ADDON_ROWS
# rows that are neither licensed nor a core overlay
# (tests/test_launcher_addon_profiles_parity.py holds the two equal).
GATEWAY_FEATURE_ADDONS="identity"

# addon_on NAME DEFAULT(0|1) — is this add-on switched on?
#
# CORE_ONLY (the launcher's --core-only flag) answers "no" for the deferrable
# add-ons without touching the map. The wizard needs a run that brings up
# base services before it has asked which add-ons the operator wants; making
# that a caller-side override rather than a temporary edit keeps noomesh.yaml
# the one declaration.
# Absent from the map is NOT "off": it is "not stated", which resolves to the
# add-on's own polarity, matching addons::resolve in the gateway.
#
# An add-on the launcher REFUSED this start (lib-dist.sh require_addon_pins:
# its signed pin does not verify for the running stack) is off from then on,
# whatever the map says: its overlay is not composed, its declarations are not
# handed to the gateway, and addons_stop_refused stops a leftover container.
# _NOO_ADDONS_REFUSED is a plain shell variable (never exported, never read
# from the environment), set only by require_addon_pins.
_NOO_ADDONS_REFUSED=""
addon_on() {
    case ",${_NOO_ADDONS_REFUSED}," in
        *",$1,"*) return 1 ;;
    esac
    if [ "${CORE_ONLY:-false}" = true ]; then
        case " $CORE_ONLY_DEFERS " in
            *" $1 "*) return 1 ;;
        esac
        case " $CORE_OVERLAY_ADDONS " in
            *" $1 "*) : ;;
            *) return 1 ;;
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


# The overlay add-ons: echoes `-f <overlay>` pairs or nothing. Same contract —
# append unquoted to COMPOSE_FILES (lib-compose.sh is the one caller).
# The core overlays first (trellion FIRST: a licensed add-on's overlay may
# extend its service), then every other add-on declared ON in the map, by
# name, from addon_overlay. Licensed add-ons default off, so only an explicit
# `<name>: true` composes one.
addon_compose_overlay_args() {
    _aco_out=""
    if addon_on trellion 1; then
        _aco="$(addons_trellion_overlay)"
        [ -n "$_aco" ] && _aco_out="$_aco_out -f $_aco"
    fi
    if addon_on voice 0; then
        _aco="$(addons_voice_overlay)"
        [ -n "$_aco" ] && _aco_out="$_aco_out -f $_aco"
    fi
    for _aco_n in $(addon_licensed_names); do
        addon_on "$_aco_n" 0 || continue
        _aco="$(addon_overlay "$_aco_n")"
        [ -n "$_aco" ] && _aco_out="$_aco_out -f $_aco"
    done
    printf '%s' "${_aco_out# }"
    return 0
}

# addon_licensed_names — every add-on that is not a core overlay add-on nor a
# gateway feature flag (GATEWAY_FEATURE_ADDONS), and that the map names or that has a bundle materialised, one per line, sorted
# (a stable compose order). Never a fixed list: core names no licensed add-on.
addon_licensed_names() {
    _aln_here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    {
        printf '%s\n' "$NOO_ADDON_MAP" | sed -n 's/^\([a-z][a-z0-9_]*\)=.*/\1/p'
        for _aln_d in "$_aln_here"/addons/*/; do
            [ -f "${_aln_d}docker-compose.yml" ] && basename "$_aln_d"
        done
    } | while read -r _aln_n; do
        case " $CORE_OVERLAY_ADDONS " in *" $_aln_n "*) continue ;; esac
        case " $GATEWAY_FEATURE_ADDONS " in *" $_aln_n "*) continue ;; esac
        [ -n "$_aln_n" ] && printf '%s\n' "$_aln_n"
    done | sort -u
    return 0
}

# addon_overlay NAME — the compose overlay for a licensed add-on, or nothing:
#   1. a development checkout of the add-on, when one is there:
#      ${NOO_<NAME>_PATH:-../noo-<name>}/docker-compose.<name>.yml (name with
#      `-` for `_`); it bind-mounts source for live editing;
#   2. its signed bundle: addons/<name>/docker-compose.yml under this install,
#      written by `noo addons enable|upgrade` after verifying the add-on's
#      signed lock (dist starts re-verify the bytes: lib-dist.sh
#      require_addon_pins → `noo addons launch-pins`);
# With neither, nothing is echoed: the caller refuses an enabled add-on
# naming `noo addons upgrade <name>`. (The root docker-compose.<name>.yml an
# earlier CLI shipped is not looked for any more.)
addon_overlay() {
    _ao_name="$1"
    _ao_kebab="$(printf '%s' "$_ao_name" | tr '_' '-')"
    # A hyphenated add-on name (pai-voice) reads NOO_PAI_VOICE_PATH, the same
    # `-` → `_` rule the gateway uses for NOO_<ADDON>_URL; `NOO_PAI-VOICE_PATH`
    # is not a variable name and ${!...} dies on it (2026-10-22).
    _ao_var="NOO_$(printf '%s' "$_ao_name" | tr 'a-z-' 'A-Z_')_PATH"
    _ao_base="${!_ao_var:-../noo-$_ao_kebab}"
    _ao_here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ -f "$_ao_base/docker-compose.$_ao_kebab.yml" ]; then
        printf '%s' "$_ao_base/docker-compose.$_ao_kebab.yml"
    elif [ -f "$_ao_here/addons/$_ao_name/docker-compose.yml" ]; then
        printf '%s' "$_ao_here/addons/$_ao_name/docker-compose.yml"
    fi
    return 0
}

# addon_own_services OVERLAY — the services OVERLAY adds to the stack (its
# `services:` keys that the composed base, $COMPOSE_FILES, does not already
# define): what to stop when the add-on is switched off on a live stack.
# Derived, so core names no add-on service.
addon_own_services() {
    _aos_base="$(docker compose $COMPOSE_FILES config --services 2>/dev/null || true)"
    awk '/^services:[[:space:]]*$/ { s = 1; next }
         s && /^[^[:space:]#]/ { s = 0 }
         s && /^  [A-Za-z0-9][A-Za-z0-9_.-]*:/ { sub(/^  /, ""); sub(/:.*/, ""); print }' "$1" \
        | while read -r _aos_s; do
            printf '%s\n' "$_aos_base" | grep -qx "$_aos_s" || printf '%s\n' "$_aos_s"
        done
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

# addons_report_licensed — one line per gateway feature add-on declared on
# ("gateway feature": it has no overlay to find), then one line per licensed
# add-on declared on, saying
# where its overlay comes from (or that none was found, in which case a dist
# start refuses it in require_addon_pins and a dev start runs without it).
addons_report_licensed() {
    for _arl_n in $GATEWAY_FEATURE_ADDONS; do
        # Only when DECLARED on: an unstated feature add-on is the gateway's
        # default, and the launcher has no business restating it.
        printf '%s\n' "$NOO_ADDON_MAP" | grep -qx "${_arl_n}=1" \
            && echo "Add-on $_arl_n: ENABLED (gateway feature)"
    done
    for _arl_n in $(addon_licensed_names); do
        addon_on "$_arl_n" 0 || continue
        _arl_o="$(addon_overlay "$_arl_n" 2>/dev/null)"
        case "$_arl_o" in
            '') echo "addons.$_arl_n is true but no overlay was found: not in its signed bundle (noo addons upgrade $_arl_n) nor in a development checkout (NOO_$(printf '%s' "$_arl_n" | tr 'a-z-' 'A-Z_')_PATH)" ;;
            */addons/"$_arl_n"/docker-compose.yml) echo "Add-on $_arl_n: ENABLED (its signed bundle, $_arl_o)" ;;
            *) echo "Add-on $_arl_n: ENABLED (via $_arl_o)" ;;
        esac
    done
    return 0
}

# addons_stop_disabled — a licensed add-on switched OFF on a live stack: its
# overlay is not composed, so `up` never touches its containers. Name the
# overlay just to reach them, and stop the services it adds.
addons_stop_disabled() {
    for _asd_n in $(addon_licensed_names); do
        addon_on "$_asd_n" 0 && continue
        # A refused add-on's overlay is never composed, not even to stop it:
        # addons_stop_refused reaches its containers by label instead.
        case ",${_NOO_ADDONS_REFUSED}," in *",$_asd_n,"*) continue ;; esac
        _asd_o="$(addon_overlay "$_asd_n" 2>/dev/null)"
        [ -n "$_asd_o" ] || continue
        _asd_s="$(addon_own_services "$_asd_o" | tr '\n' ' ')"
        [ -n "${_asd_s// /}" ] || continue
        # shellcheck disable=SC2086
        docker compose $COMPOSE_FILES -f "$_asd_o" stop $_asd_s 2>/dev/null || true
    done
    return 0
}

# addons_stop_refused — an add-on the launcher refused this start must not
# keep running from an earlier start (a stale container still holds its
# image, env and service key). Its overlay is NOT composed, not even for
# `stop`: the service names are read from the overlay's text
# (addon_own_services parses it; only the core files are rendered), and the
# containers are found by compose's own labels in this project.
addons_stop_refused() {
    [ -n "${_NOO_ADDONS_REFUSED}" ] || return 0
    _asr_proj="${COMPOSE_PROJECT_NAME:-noomesh}"
    for _asr_n in $(printf '%s' "$_NOO_ADDONS_REFUSED" | tr ',' ' '); do
        _asr_o="$(addon_overlay "$_asr_n" 2>/dev/null)"
        [ -n "$_asr_o" ] || continue
        for _asr_s in $(addon_own_services "$_asr_o"); do
            _asr_ids="$(docker ps -q --filter "label=com.docker.compose.project=${_asr_proj}" \
                --filter "label=com.docker.compose.service=${_asr_s}" 2>/dev/null)"
            [ -n "$_asr_ids" ] || continue
            echo "Stopping ${_asr_s}: add-on ${_asr_n} was refused this start and must not keep running" >&2
            # shellcheck disable=SC2086
            docker stop $_asr_ids >/dev/null 2>&1 || echo "WARNING: could not stop ${_asr_s} (add-on ${_asr_n}); stop it: docker stop ${_asr_ids}" >&2
        done
    done
    return 0
}
