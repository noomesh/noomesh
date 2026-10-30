#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

[ -n "${_NOO_LIB_DIST_LOADED:-}" ] && return 0
_NOO_LIB_DIST_LOADED=1
# lib-dist.sh — THE distribution-mode block, as a sourceable helper.
#
# Finding #43 was `noo stack restart --force` composing WITHOUT the dist
# overlay on a dist install and dying trying to build Dockerfiles the
# install does not ship. The fix was copy-pasted into restart.sh — and the
# #43b sweep (2026-08-27) found the same blindness in every OTHER compose
# consumer: the host-watcher's recreate op (the gateway's own restart
# button), the post-rollback restart-watchdog, bootstrap-standby's postgres
# bring-up, and the model-switch paths. Two hand-maintained copies of the
# block had already drifted; this file is the single one.
#
# Usage:
#   source "$SCRIPTS_DIR/lib-dist.sh"
#   apply_dist_mode "$PROJECT_ROOT"
#   # then: . lib-compose.sh; compose_file_list/compose_file_args append the
#   # overlay LAST when DIST_MODE=1
#
# After apply_dist_mode:
#   DIST_MODE          1 when this is a dist install with the overlay present
#                      and a resolvable image tag, else 0.
#   DIST_COMPOSE_FILE  absolute path to docker-compose.dist.yml (DIST_MODE=1).
#   exported           NOO_IMAGE_PREFIX, NOO_IMAGE_TAG, and the dev-overlay
#                      neutralization vars (DIST_MODE=1 only).
#
# The caller still owns COMPOSE_FILES (string or array — callers differ) and
# still passes --no-build on its up/recreate invocations: the overlay makes
# every first-party service `pull_policy: missing`, and --no-build is the
# belt to that suspender.
#
# Detection is the launcher's: NOO_INSTALL_MODE from the environment, else
# scraped from $PROJECT_ROOT/.env. Tag ladder: $NOO_IMAGE_TAG env → .env →
# newest local stack-v* git tag. A dist install with NO resolvable tag gets
# DIST_MODE=0 plus a loud warning — the caller then behaves exactly as
# before this helper existed (build attempt and all), which is the honest
# failure rather than composing an overlay whose image refs cannot resolve.

apply_dist_mode() {
    local root="${1:-.}"
    DIST_MODE=0
    DIST_COMPOSE_FILE=""

    local mode="${NOO_INSTALL_MODE:-}"
    if [ -z "$mode" ] && [ -f "$root/.env" ]; then
        mode="$(grep -E '^[[:space:]]*NOO_INSTALL_MODE=' "$root/.env" | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    [ "${mode:-dev}" = "dist" ] || return 0
    [ -f "$root/docker-compose.dist.yml" ] || return 0

    local tag="${NOO_IMAGE_TAG:-}"
    if [ -z "$tag" ] && [ -f "$root/.env" ]; then
        tag="$(grep -E '^[[:space:]]*NOO_IMAGE_TAG=' "$root/.env" | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    if [ -z "$tag" ]; then
        tag="$(git -C "$root" tag -l 'stack-v*' 2>/dev/null | sort -V | tail -1)"
        tag="${tag#stack-}"
    fi
    if [ -z "$tag" ]; then
        echo "warning: dist install but no resolvable NOO_IMAGE_TAG — compose may try to build" >&2
        return 0
    fi

    export NOO_IMAGE_PREFIX="${NOO_IMAGE_PREFIX:-$(release_image_namespace)}"
    export NOO_IMAGE_TAG="$tag"
    DIST_COMPOSE_FILE="$root/docker-compose.dist.yml"
    DIST_MODE=1
    # Add-on overlays have no dist row (a row for an uncomposed service is a
    # bare service compose refuses); the ones that build in dev interpolate
    # this instead (docker-compose.trellion.yml).
    export NOO_PULL_POLICY="missing"
    echo "Distribution mode: ON (${NOO_IMAGE_PREFIX}/<service>:${NOO_IMAGE_TAG}, no local build)"

    # Neutralize the dev bind-mounts: the base file overlays the source tree
    # into the containers, which must not happen over released images.
    export NOO_SRC_OVERLAY="./.src-overlay-placeholder"
    export NOO_SRC_OVERLAY_DEST="/tmp/.src-overlay-unused"
    export NOO_UI_STATIC_OVERLAY="./.src-overlay-placeholder"
    export NOO_UI_STATIC_OVERLAY_DEST="/tmp/.ui-static-unused"
    export NOO_UI_INDEX_OVERLAY="./.src-overlay-placeholder"
    export NOO_UI_INDEX_OVERLAY_DEST="/tmp/.ui-index-unused"
    export TRELLION_SRC="./.trellion-src-placeholder"
    export TRELLION_SRC_DEST="/tmp/.trellion-src-unused"
    return 0
}

# secrets_floor [compose-file] — the `x-noo-secrets-floor` stack tag the base
# compose file declares (e.g. `stack-v0.2.79`), or nothing when it declares
# none.
secrets_floor() {
    local compose="${1:-docker-compose.cluster.yml}"
    [ -f "$compose" ] || return 0
    sed -nE 's/^x-noo-secrets-floor:[[:space:]]*"?([^"[:space:]]+)"?[[:space:]]*$/\1/p' "$compose" | head -1
}

# require_secrets_floor <root> <image-tag> — refuse to run this compose file
# against images older than the ones that read its secrets.
#
# docker-compose.cluster.yml delivers every tier-1 secret to the gateway and
# the worker as a FILE (`<NAME>_FILE` → /run/secrets/…) and no longer as a
# plain value. The readers ship in the IMAGES, the compose file ships in the
# CLI's deploy slice, and the two move separately (`noo upgrade --stack`
# refreshes the slice; a pin or a `--tag` chooses the images). New compose on
# an old image is not a degraded start — the gateway boots with no JWT
# secret, no DB password and no NATS credential. So below the floor this
# refuses, loudly, and names the way forward.
#
# Only a version-shaped tag (vX.Y.Z) can be compared; anything else
# (`latest`, a branch build) is refused too, because "unknown" cannot be
# shown to be at or above the floor. Dev mode (images built from this very
# checkout) never calls this.
require_secrets_floor() {
    local root="${1:-.}" tag="${2:-}" floor
    floor="$(secrets_floor "$root/docker-compose.cluster.yml")"
    [ -n "$floor" ] || return 0
    local want="${floor#stack-}"
    local have="${tag#stack-}"
    # A release candidate vX.Y.Z-rc.N (cut on staging, rehearsed before vX.Y.Z
    # is cut on main) carries the code vX.Y.Z ships: judge it as vX.Y.Z.
    if printf '%s' "$have" | grep -qE '^v?[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'; then
        have="v${have#v}"
        have="${have%%-rc.*}"
        if [ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -1)" = "$want" ]; then
            return 0
        fi
    fi
    {
        echo "REFUSING: this compose file needs images at or above ${floor}, and the tag in use is '${tag:-<none>}'."
        echo "  It delivers the gateway's and the worker's secrets as FILES (/run/secrets); an older image"
        echo "  does not read them and would start with no credentials at all."
        echo "  Fix:  noo upgrade --stack            (rolls the images and this file together)"
        echo "   or:  noo stack start --dist --tag ${want}   (or any newer stack tag)"
        echo "  Rolling back below ${want} needs the noo CLI that shipped that release, not this one."
    } >&2
    return 1
}

# ── Licensed add-ons: pinned by their own signed lock, never pulled here ──
#
# The licensed add-ons (trellion-intel, evolve) release from their own
# repositories with their own signed lock; the stack release carries no add-on
# row. `noo addons enable|upgrade` and `noo upgrade --stack` fetch that lock
# from the add-on's registry package, verify it against the entitlement's trust
# anchor, pull every image BY DIGEST (with the controller's registry token, in a
# throwaway docker config) and write the pin to `addons.lock` beside
# `stack.lock`. The launcher only checks: it never pulls an add-on and holds no
# registry credential.
#
# The overlays take their image from NOO_ADDON_IMAGE_<NAME> (the lock's image
# name upper-cased, `-` as `_`: NOO_ADDON_IMAGE_TRELLION_INTEL,
# NOO_ADDON_IMAGE_EVOLVE), which only require_addon_pins sets. There is no
# tag-only path, no prefix fallback and no override variable any more
# (NOO_INTEL_IMAGE, NOO_EVOLVE_IMAGE and their *_PREFIX twins are retired:
# scripts/retired-env-keys).

# _addon_noo — the noo binary, through lib-config.sh's noo_bin when it is
# loaded (it resolves the binary that invoked the launcher), else PATH.
_addon_noo() {
    if declare -F noo_bin >/dev/null 2>&1; then noo_bin; else command -v noo; fi
}

# addon_image_vars <compose args> — the NOO_ADDON_IMAGE_* variables the
# composed overlays (the files named by `-f`) read in an `image:` line. Derived
# from the overlays, so core names no add-on image.
addon_image_vars() {
    local _prev="" _f
    for _f in "$@"; do
        if [ "$_prev" = "-f" ] && [ -f "$_f" ]; then
            grep -oE '^    image:[[:space:]]*\$\{NOO_ADDON_IMAGE_[A-Z0-9_]+' "$_f" | sed 's/.*\${//'
        fi
        _prev="$_f"
    done | sort -u
}

# _addon_composed_names — the add-on keys declared on (the same addon_on
# decisions addon_compose_overlay_args makes, --core-only included): the core
# overlay add-ons, then every licensed one (lib-addons addon_licensed_names).
# An add-on is listed whether or not its overlay was found, so a licensed
# add-on that is on with no bundle materialised is refused by launch-pins
# rather than silently left out of the stack.
_addon_composed_names() {
    local _n
    addon_on trellion 1 && printf '%s\n' trellion
    addon_on voice 0 && printf '%s\n' voice
    for _n in $(addon_licensed_names); do
        addon_on "$_n" 0 && printf '%s\n' "$_n"
    done
    return 0
}

# require_addon_pins — a start or restart runs each composed licensed add-on
# overlay from the image its signed lock pins for THIS tag, present locally by
# digest, or that add-on does not start.
#
# The set looked at is exactly what is composed (addon_compose_overlay_args:
# addon_on, so `--core-only` defers the same add-ons it leaves out of the file
# list). Every NOO_ADDON_IMAGE_* already in the environment is dropped first,
# so an .env line or a shell export can never name an add-on image.
#
# Dist: `noo addons launch-pins --root <install root> <tag> <add-on>...` re-verifies, offline, each
# cached lock against the installed entitlement and answers one line per
# licensed add-on:
#   pin <addon> <VAR> <ref@sha256:…>     export VAR=ref once the image is local
#   refuse <addon> <why>                 REFUSE that add-on, naming it and why
# Then every variable a composed overlay reads must have been exported from
# a pin: an add-on whose lock maps its image to another variable (its overlay
# would render the unpinned sentinel) is refused here, by name. The exports
# are recorded in _ADDON_PINS for dist_assert_addon_refs.
#
# A REFUSED add-on is left out of this start; the core stack and every other
# add-on start (approved 2026-10-24: one stale add-on pin used to refuse every
# restart of the gateway, auth and Postgres). It is never silent:
#   - a `REFUSED add-on <name>: <why>` line and its remedy, on every start;
#   - addon_on answers "off" for it (_NOO_ADDONS_REFUSED), so its overlay,
#     images, env and secrets are not composed, its bundle declarations
#     (system.json, workloads.json) are not handed to the gateway, and
#     addons_stop_refused stops a container left from an earlier start;
#   - it is absent from NOO_ADDONS_VERIFIED, so the gateway's add-on registry
#     refuses its routes (a stale routes.json in the routes volume included)
#     and /health reads `unhealthy` for it; NOO_ADDONS_REFUSED names it, so
#     the systems broker runs no DDL for a `systems:` entry of that name;
#   - the launcher's closing line says which add-ons did NOT start
#     (addons_report_refused).
# What still refuses the WHOLE start: the reader failing or sending a line it
# should never send (unreadable verdict, a non add-on variable), a CLI too old
# to report verdicts while something is refused (the gateway would then load
# a refused built-in add-on as it always did), a composed variable no add-on
# can be blamed for, and everything stack-level (stack.lock, core digests:
# dist_require_lock).
#
# Dist also exports NOO_ADDONS_VERIFIED, from the `verified <addon> <version>
# <stack>` lines of the add-ons that are launched: `name=version@stack,...`,
# or `none`. Dev exports `dev`. The gateway's add-on registry registers an
# add-on only when it is named there. Beside it, NOO_ADDONS_DEV, from the
# `dev <addon> <unix>` lines: `name=<unix expiry>,...` for the add-ons only a
# temporary development key vouches for (i163 part A); the gateway reports
# them as dev and refuses them once that instant passes. Unset when there are
# none.
#
# Dev (not dist): each variable the composed overlays read is set to the dev
# build's name, `${NOO_IMAGE_PREFIX:-noomesh}/<name>:${NOO_IMAGE_TAG:-latest}`.
#
# REFUSE (the whole start) = return 1; both launchers `|| exit 1` before
# anything is pulled or recreated.
_ADDON_PINS=()
# The `decl <addon> <file>` lines launch-pins printed (a declaration file the
# verified lock lists: system.json, workloads.json, routes.json), for
# addon_decls_materialise below. An older noo prints none: nothing is handed
# to the gateway, which then provisions no bundle system (the safe side).
_ADDON_DECLS=()
# `<addon><TAB><why>` per add-on refused this start (addons_report_refused).
_ADDON_REFUSED=()
# The install root this launcher belongs to (scripts/..), fixed when the
# library is sourced. launch-pins reads the pins under it, never the cwd.
_DIST_LIB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"

# _addon_refuse <addon> <why> — leave one add-on out of this start, loudly.
# Once per add-on (the first reason wins).
_addon_refuse() {
    case ",${_NOO_ADDONS_REFUSED:-}," in *",$1,"*) return 0 ;; esac
    _NOO_ADDONS_REFUSED="${_NOO_ADDONS_REFUSED:+${_NOO_ADDONS_REFUSED},}$1"
    _ADDON_REFUSED+=("$1"$'\t'"$2")
    _addon_refused_lines "$1" "$2" >&2
}

# _addon_refused_lines <addon> <why> — the REFUSED line and its remedy.
_addon_refused_lines() {
    echo "REFUSED add-on $1: $2"
    echo "  It is left out of this start and is NOT running; the rest of the stack starts without it."
    case "$2" in
        *"development key"*expired*)
            echo "  Fix:  noo addons trust-key $1 <pubkey> --dev --expires 14d   (renew the dev key; or turn it off: noo addons disable $1)" ;;
        *)
            echo "  Fix:  noo addons upgrade $1   (or turn it off: noo addons disable $1)" ;;
    esac
}

# addons_report_refused — repeat, at the end of a start or restart, every
# add-on refused this start (nothing when none was). Prints to stderr.
addons_report_refused() {
    local _r
    for _r in ${_ADDON_REFUSED[@]+"${_ADDON_REFUSED[@]}"}; do
        _addon_refused_lines "${_r%%$'\t'*}" "${_r#*$'\t'}" >&2
    done
    return 0
}

require_addon_pins() {
    local _v _on _nb _out _kind _addon _rest _var _ref _vars _args _name fail=0
    local _verified=() _pinned=() _dev=() _pinlines=() _decls=() _legacy_cli=0 _p _n _o _l _miss
    for _v in $(compgen -e | grep '^NOO_ADDON_IMAGE_' || true); do unset "$_v"; done
    # The registry verdict is set here and nowhere else: a value inherited from
    # the shell or an .env line is dropped, like the image variables above.
    unset NOO_ADDONS_VERIFIED NOO_ADDONS_DEV NOO_ADDONS_REFUSED
    _NOO_ADDONS_REFUSED=""
    _ADDON_PINS=()
    _ADDON_DECLS=()
    _ADDON_REFUSED=()
    _args="$(addon_compose_overlay_args 2>/dev/null)"
    # shellcheck disable=SC2086
    _vars="$(addon_image_vars $_args)"
    _on="$(_addon_composed_names | tr '\n' ' ')"
    # Nothing to pin: no composed overlay reads an add-on image, and no add-on
    # beyond the core overlays is on (a licensed add-on that is on always goes
    # to launch-pins, which refuses it when its bundle is missing).
    if [ -z "$_vars" ] && [ -z "$(printf '%s' "$_on" | tr ' ' '\n' | grep -vxE 'trellion|voice|' || true)" ]; then
        # Nothing was composed that needs a lock. The gateway's add-on
        # registry still wants the verdict: a dist launcher verified "none",
        # a source checkout is "dev".
        if [ "${DIST_MODE:-0}" = 1 ]; then export NOO_ADDONS_VERIFIED=none; else export NOO_ADDONS_VERIFIED=dev; fi
        return 0
    fi
    if [ "${DIST_MODE:-0}" != 1 ]; then
        for _v in $_vars; do
            _name="$(printf '%s' "${_v#NOO_ADDON_IMAGE_}" | tr 'A-Z_' 'a-z-')"
            export "${_v}=${NOO_IMAGE_PREFIX:-$(local_image_namespace)}/${_name}:${NOO_IMAGE_TAG:-latest}"
        done
        # A source checkout builds its add-on images: there is no signed lock.
        export NOO_ADDONS_VERIFIED=dev
        return 0
    fi
    local _tag="${DIST_TAG:-${NOO_IMAGE_TAG:-}}"
    if ! _nb="$(_addon_noo)" || [ -z "$_nb" ]; then
        echo "REFUSING: add-on overlays are composed (${_on% }) and no noo CLI was found to verify their signed pins." >&2
        return 1
    fi
    # shellcheck disable=SC2086
    if ! _out="$("$_nb" addons launch-pins --root "${PROJECT_ROOT:-$_DIST_LIB_ROOT}" "$_tag" $_on 2>&1)"; then
        {
            echo "REFUSING: the add-on pins could not be read (noo addons launch-pins failed):"
            printf '  %s\n' "$_out"
            echo "  Fix:  noo addons verify"
        } >&2
        return 1
    fi
    # Read every line first; nothing is exported until the refused set is known.
    while read -r _kind _addon _rest; do
        case "$_kind" in verified|dev|pin|decl|refuse)
            # An add-on name goes into the gateway's environment: only a name
            # the gateway accepts (addon_registry::name_ok) is read at all.
            case "$_addon" in
                [a-z]*) case "$_addon" in *[!a-z0-9_-]*) _addon="" ;; esac ;;
                *) _addon="" ;;
            esac
            if [ -z "$_addon" ]; then
                echo "REFUSING: noo addons launch-pins sent a line for something that is not an add-on name: ${_kind} …" >&2
                fail=1; continue
            fi ;;
        esac
        case "$_kind" in
            verified)
                # `verified <addon> <version> <stack>`: the signed lock verified
                # offline and lists this stack. Handed to the gateway below.
                case "$_rest" in
                    *[!-A-Za-z0-9._+\ ]*|"") echo "REFUSING: noo addons launch-pins sent an unreadable verdict for ${_addon}: ${_rest}" >&2; fail=1 ;;
                    *) _verified+=("${_addon}=${_rest%% *}@${_rest#* }") ;;
                esac ;;
            dev)
                # `dev <addon> <unix>`: only a development key vouches for this
                # add-on, until <unix>. Handed to the gateway beside the verdict.
                case "$_rest" in
                    *[!0-9]*|"") echo "REFUSING: noo addons launch-pins sent an unreadable dev expiry for ${_addon}: ${_rest}" >&2; fail=1 ;;
                    *) _dev+=("${_addon}=${_rest}") ;;
                esac ;;
            pin)
                _var="${_rest%% *}"; _ref="${_rest#* }"
                case "$_var" in NOO_ADDON_IMAGE_*) : ;; *)
                    echo "REFUSING: noo addons launch-pins named '${_var}' for ${_addon}, not an add-on image variable" >&2
                    fail=1; continue ;;
                esac
                if ! docker image inspect "$_ref" >/dev/null 2>&1; then
                    # The launcher never pulls an add-on; the CLI pulls it by
                    # digest with the registry token.
                    _addon_refuse "$_addon" "its pinned image is not on this host (${_ref}); the launcher never pulls an add-on"
                    continue
                fi
                _pinlines+=("${_addon} ${_var} ${_ref}") ;;
            decl)
                # `decl <addon> <file>`: a declaration file its verified lock
                # lists. Only the names the gateway reads are kept.
                case "$_rest" in
                    system.json|workloads.json|routes.json) _decls+=("${_addon} ${_rest}") ;;
                esac ;;
            refuse)
                _addon_refuse "$_addon" "${_rest:-no verified pin for ${_tag}}" ;;
        esac
    done <<PINS
$_out
PINS
    [ "$fail" = 0 ] || return 1
    # Each add-on's overlay must find every image variable it reads among the
    # pins of add-ons that are launched; one that does not is refused by name
    # (its lock names its image differently, or it is not licensed here).
    for _n in $_on; do
        case " $CORE_OVERLAY_ADDONS " in *" $_n "*) continue ;; esac
        case ",${_NOO_ADDONS_REFUSED}," in *",$_n,"*) continue ;; esac
        _o="$(addon_overlay "$_n" 2>/dev/null)"
        [ -n "$_o" ] || continue
        for _v in $(addon_image_vars -f "$_o"); do
            _miss=1
            for _p in ${_pinlines[@]+"${_pinlines[@]}"}; do
                case ",${_NOO_ADDONS_REFUSED}," in *",${_p%% *},"*) continue ;; esac
                _p="${_p#* }"
                [ "${_p%% *}" = "$_v" ] && _miss=0
            done
            if [ "$_miss" = 1 ]; then
                _addon_refuse "$_n" "its overlay runs \${${_v}}, and no verified pin supplies it (its signed lock names its image differently, or it is not licensed on this install)"
                break
            fi
        done
    done
    # Export the pins, the declarations and the verdict of the launched add-ons only.
    for _p in ${_pinlines[@]+"${_pinlines[@]}"}; do
        _addon="${_p%% *}"; _p="${_p#* }"; _var="${_p%% *}"; _ref="${_p#* }"
        case ",${_NOO_ADDONS_REFUSED}," in *",${_addon},"*) continue ;; esac
        _pinned+=("$_addon")
        export "${_var}=${_ref}"
        _ADDON_PINS+=("${_var}=${_ref}")
    done
    for _p in ${_decls[@]+"${_decls[@]}"}; do
        case ",${_NOO_ADDONS_REFUSED}," in *",${_p%% *},"*) continue ;; esac
        _ADDON_DECLS+=("$_p")
    done
    # The gateway's add-on registry reads this (gateway-rust/src/addon_registry.rs).
    # A pin with no verdict beside it came from a noo binary older than this
    # launcher: it verified, it just cannot say so. Leave the variable unset
    # (the gateway then loads only the add-ons it already knew and says why)
    # rather than report "none" and refuse a good add-on.
    local _vstr="" _d
    for _d in ${_verified[@]+"${_verified[@]}"}; do
        case ",${_NOO_ADDONS_REFUSED}," in *",${_d%%=*},"*) continue ;; esac
        _vstr="${_vstr:+${_vstr},}${_d}"
    done
    for _p in ${_pinned[@]+"${_pinned[@]}"}; do
        case ",${_vstr}," in *",${_p}="*) : ;; *) _legacy_cli=1 ;; esac
    done
    if [ "$_legacy_cli" = 1 ]; then
        if [ -n "$_NOO_ADDONS_REFUSED" ]; then
            # An unset verdict makes the gateway load the built-in add-ons it
            # already knew, the refused one included: refuse the start instead.
            {
                echo "REFUSING: add-on(s) ${_NOO_ADDONS_REFUSED//,/, } were refused, and this noo CLI does not report verified"
                echo "  add-on locks, so the gateway could not be told to leave them out."
                echo "  Fix:  noo upgrade"
            } >&2
            return 1
        fi
        echo "WARNING: this noo CLI does not report verified add-on locks; the gateway loads only the add-ons it already knew. Run: noo upgrade" >&2
    elif [ -n "$_vstr" ]; then
        export NOO_ADDONS_VERIFIED="$_vstr"
        # Only for add-ons the verdict names: a dev line alone vouches for nothing.
        local _dstr=""
        for _d in ${_dev[@]+"${_dev[@]}"}; do
            case ",${_vstr}," in *",${_d%%=*}="*) _dstr="${_dstr:+${_dstr},}${_d}" ;; esac
        done
        [ -z "$_dstr" ] || export NOO_ADDONS_DEV="$_dstr"
    else
        export NOO_ADDONS_VERIFIED=none
    fi
    # The systems broker reads this: no DDL for a refused add-on's system.
    [ -z "$_NOO_ADDONS_REFUSED" ] || export NOO_ADDONS_REFUSED="$_NOO_ADDONS_REFUSED"
    # Last line of defence: what is composed NOW (refused add-ons are off)
    # must find every image variable it reads. A variable no add-on can be
    # blamed for (a core overlay reading one) refuses the start.
    _args="$(addon_compose_overlay_args 2>/dev/null)"
    # shellcheck disable=SC2086
    for _v in $(addon_image_vars $_args); do
        if [ -z "${!_v:-}" ]; then
            {
                echo "REFUSING: a composed add-on overlay runs \${${_v}}, and no verified pin supplies it."
                echo "  The add-on's signed lock names its image differently from the overlay, or the add-on"
                echo "  is not licensed on this install. The overlay would render its unpinned sentinel."
                echo "  Fix:  noo addons verify"
            } >&2
            fail=1
        fi
    done
    [ "$fail" = 0 ]
}

# addon_services <compose args> — the services whose image an add-on pin
# supplies: every service whose `image:` line reads ${NOO_ADDON_IMAGE_…}, in
# the compose files named by `-f`. Derived from the overlays, so core names no
# add-on service. The dist pull leaves these out (the launcher never pulls an
# add-on) and dist_assert_addon_refs holds them to their pins.
addon_services() {
    local _prev="" _f
    for _f in "$@"; do
        if [ "$_prev" = "-f" ] && [ -f "$_f" ]; then
            awk '
                /^services:[[:space:]]*$/ { in_s = 1; next }
                /^[^[:space:]#]/ { in_s = 0 }
                in_s && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ { svc = $1; sub(/:$/, "", svc) }
                in_s && /^    image:.*\$\{NOO_ADDON_IMAGE_/ { print svc }
            ' "$_f"
        fi
        _prev="$_f"
    done | sort -u
}

# compose_capture <compose args...> - run `docker compose "$@"`, keeping its
# stdout in COMPOSE_OUT and its stderr in COMPOSE_ERR; returns compose's own
# exit status. Callers used to write `2>/dev/null`, which turned a compose
# config error (a missing required variable, a bad overlay) into an empty
# string that every gate then reported as something else (live 2026-10-13,
# pop-os: "could not render the image of add-on service noo-evolve").
COMPOSE_OUT=""; COMPOSE_ERR=""
compose_capture() {
    local _ef _rc
    _ef="$(mktemp)" || { COMPOSE_OUT=""; COMPOSE_ERR="mktemp failed"; return 1; }
    COMPOSE_OUT="$(docker compose "$@" 2>"$_ef")"; _rc=$?
    COMPOSE_ERR="$(cat "$_ef" 2>/dev/null)"
    rm -f "$_ef"
    return "$_rc"
}

# compose_report_error <exit status> - print the last 10 lines of the stderr
# compose_capture kept, indented, plus the exit status. Prints to stderr.
compose_report_error() {
    echo "       docker compose exited with status ${1:-?}; its last output:" >&2
    if [ -n "$COMPOSE_ERR" ]; then
        printf '%s\n' "$COMPOSE_ERR" | tail -n 10 | sed 's/^/         /' >&2
    else
        echo "         (no output on stderr)" >&2
    fi
}

# dist_assert_addon_refs <compose args> — in dist mode, every add-on service
# compose renders must run exactly a pinned reference (one of _ADDON_PINS).
# Refuses with the service and the ref otherwise, and when compose cannot
# render the ref at all: an add-on overlay that resolved to anything but its
# verified pin must never start. Both launchers call it once COMPOSE_FILES is
# known, whether or not they pull.
dist_assert_addon_refs() {
    [ "${DIST_MODE:-0}" = 1 ] || return 0
    local _svc _ref _p _ok _rc _l
    for _svc in $(addon_services "$@"); do
        _rc=0
        _ref=""
        if command -v python3 >/dev/null 2>&1; then
            # The service's OWN image. `config --images <svc>` prints <svc> AND
            # its depends_on chain (5 lines for noo-evolve, the gateway first
            # on compose 5.0.2 and 5.5.1), so its first line is a dependency's
            # image and the pin check would refuse a correct start.
            compose_capture "$@" config --format json || _rc=$?
            if [ "$_rc" -eq 0 ]; then
                _ref="$(printf '%s' "$COMPOSE_OUT" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin)["services"][sys.argv[1]].get("image", ""))
except Exception:
    pass' "$_svc" 2>/dev/null)"
            fi
        else
            # No python3: fall back to `--images`, whose output includes the
            # dependency chain. Accept the line that IS one of the pins; if
            # none is, the first line is reported as the offending ref.
            compose_capture "$@" config --images "$_svc" || _rc=$?
            _ref="$(printf '%s\n' "$COMPOSE_OUT" | head -1)"
            while IFS= read -r _l; do
                for _p in "${_ADDON_PINS[@]+"${_ADDON_PINS[@]}"}"; do
                    [ "${_p#*=}" = "$_l" ] && _ref="$_l"
                done
            done <<IMGS
$COMPOSE_OUT
IMGS
        fi
        if [ "$_rc" -ne 0 ] || [ -z "$_ref" ]; then
            echo "ERROR: compose could not render the image of add-on service ${_svc} - refusing to start it unverified" >&2
            compose_report_error "$_rc"
            echo "       Fix:  the compose files could not be rendered: see the lines above" >&2
            return 1
        fi
        _ok=""
        for _p in "${_ADDON_PINS[@]+"${_ADDON_PINS[@]}"}"; do
            [ "${_p#*=}" = "$_ref" ] && _ok=1
        done
        if [ -z "$_ok" ]; then
            echo "ERROR: add-on service ${_svc} would run ${_ref}, which is not its signed pin for ${DIST_TAG:-this tag} - refusing" >&2
            echo "       Fix:  noo addons upgrade" >&2
            return 1
        fi
    done
    return 0
}

# release_image_namespace — the registry namespace release images are PULLED
# from (`<this>/<service>:<tag>`), the shell twin of
# noo-cli/src/registry.rs::IMAGE_NAMESPACE and node-agent-go/internal/docker/
# registry.go::DefaultImagePrefix. ONE definition per language; the tests in
# tests/test_image_namespace_*.py fail if a literal of it appears anywhere else
# outside internal/, or if the three disagree.
#
# An operator's own NOO_IMAGE_PREFIX always wins over it.
release_image_namespace() { printf 'ghcr.io/noomesh'; }

# local_image_namespace — the namespace a `docker build` in this repo writes to.
#
# ONE definition. It was `pai-assistant` until 2026-09-06, when 10fb1cd1
# renamed it to `noomesh`, and the rename stranded every hand-written copy:
# five scripts kept running containers from the dead name (fixed with
# resolve_release_image below), and `noomesh-clean.sh --images` kept pruning
# `reference=pai-assistant/*`, so it silently removed nothing and left every
# current local image behind. A namespace spelled out in N places is a rename
# with N chances to be missed.
#
# `resolve_release_image` uses this as its dev default, so the builder, the
# runner and the pruner cannot disagree again.
local_image_namespace() { printf 'noomesh'; }

# legacy_image_namespaces — namespaces this repo used to build into.
#
# Kept so cleanup can still find images an older install left on disk. A box
# onboarded before 2026-09-06 has `pai-assistant/*` layers that nothing else
# will ever reference or remove.
legacy_image_namespaces() { printf 'pai-assistant'; }

# resolve_release_image <name> — the image ref for a release-matrix image,
# correct in BOTH dev and dist, printed on stdout.
#
# For scripts that run a throwaway container with `docker run` and therefore
# get no help from compose. Three of them hardcoded
# `pai-assistant/postgres-pgvector:latest`:
# `restore-drill.sh`, `bootstrap-standby.sh` and `pg-upgrade.sh`. That name
# stopped being produced on 2026-09-06, when 10fb1cd1 renamed the local
# namespace to `noomesh/` — so on a dev box they had been reaching for an
# image that only still existed as a stale cached layer, and on a --dist box
# neither name exists at all ("pull access denied"). The backup RESTORE DRILL
# was the casualty: the one command that proves a backup is restorable could
# not start its container on a standalone controller (found 2026-09-12).
#
# Same three-part expression the compose files use, so there is one shape to
# get right:
#   ${NOO_IMAGE_PREFIX:-noomesh}/<name>:${NOO_IMAGE_TAG:-latest}${NOO_IMAGE_DIGEST_<NAME>:-}
#
# `apply_dist_mode` exports prefix and tag on a dist install and returns early
# on a dev one, which is exactly why the defaults are here rather than in the
# caller. Call it first if you want the dist values; this function is correct
# either way.
#
# Digests: only `dist_load_stack_lock` (start and restart) loads `stack.lock` into
# NOO_IMAGE_DIGEST_* vars, so a script that has not been through one of them
# resolves by TAG. That is the right trade for a disposable container — it is
# a read-only consumer of a dump, not a fleet service — and it is stated here
# rather than left to be discovered.
resolve_release_image() {
    local name="$1"
    [ -n "$name" ] || { echo "resolve_release_image: no image name" >&2; return 1; }
    local var="NOO_IMAGE_DIGEST_$(printf '%s' "$name" | tr 'a-z-' 'A-Z_')"
    local digest="${!var:-}"
    printf '%s/%s:%s%s\n' \
        "${NOO_IMAGE_PREFIX:-$(local_image_namespace)}" "$name" "${NOO_IMAGE_TAG:-latest}" "$digest"
}

_DIST_PINS=()
# dist_load_stack_lock TAG - the ONE reader of ./stack.lock (the start
# launcher and the restart both call it; a restart that skipped it recreated
# every core container by TAG, no @sha256, on 0.6.5-rc.1). `noo upgrade
# --stack` fetches the release's signed stack-<tag>.lock, verifies it against
# the release key baked into the CLI, and writes it here as stack.lock. Every
# compose image ref carries `${NOO_IMAGE_DIGEST_<SVC>:-}`, so with the lock
# loaded docker runs `<image>:<tag>@sha256:...` - the tag is a label, the
# digest is what runs. A lock for a DIFFERENT tag is never applied: one tag's
# digests are never pinned onto another. Exports each pin, records it in
# _DIST_PINS, and sets _DIST_LOCK_STATE to loaded | missing | other.
_DIST_LOCK_STATE=missing
dist_load_stack_lock() {
    local line img dig var
    _DIST_LOCK_STATE=missing
    [ -f "stack.lock" ] || return 0
    # The tag binding is the line INSIDE the signed bytes (`# stack <tag>`,
    # released from v0.6.7 on; `noo upgrade --stack` already refused a lock
    # signed for another tag). When it is there it is the only header trusted:
    # the unsigned `# tag` line the CLI also writes is read only for the
    # locks of older releases, which never carried the signed one.
    if grep -q '^# stack ' stack.lock; then
        if ! grep -q "^# stack ${1}\$" stack.lock || grep '^# stack ' stack.lock | grep -qv "^# stack ${1}\$"; then
            _DIST_LOCK_STATE=other
            return 0
        fi
    elif ! grep -q "^# tag ${1}\$" stack.lock; then
        _DIST_LOCK_STATE=other
        return 0
    fi
    while IFS= read -r line; do
        case "$line" in \#*|"") continue ;; esac
        img="${line%%@*}"; dig="${line#*@}"
        # IMAGE rows only. The lock also carries provenance rows —
        # `source:trellion@<git sha>` since #1108 — which are not
        # images, and whose derived name (NOO_IMAGE_DIGEST_SOURCE:…)
        # is not a valid shell identifier. `export` then fails, and
        # under `set -e` that killed every start on stack v0.2.22:
        # the first tag whose lock carried provenance could not boot.
        #
        # Testing the DIGEST is what states the intent — an image
        # row is the one that carries a sha256 digest.
        case "$dig" in sha256:*) : ;; *) continue ;; esac
        var="NOO_IMAGE_DIGEST_$(printf '%s' "$img" | tr 'a-z-' 'A-Z_')"
        # ...and testing the NAME is what makes it safe, because the
        # digest test alone does not close the failure mode it was
        # written for. `export` dies on any name that is not a shell
        # identifier, and `tr` only folds case and hyphens: a colon,
        # a dot or a slash survives it. So a row like
        # `attestation:sbom@sha256:…`, a registry-qualified
        # `ghcr.io/owner/gateway@sha256:…`, or a bare `sha256:x` with
        # no `@` at all (img and dig are then the same string, and it
        # passes the digest test) reproduces v0.2.22 exactly: every
        # start dies under `set -e`.
        #
        # Today's eleven image names are all lowercase and hyphens,
        # so none of that is live — which is precisely the position
        # we were in before #1108 added a row nobody had anticipated.
        # A name we cannot export is a row we do not understand, and
        # the launcher's job is to start the stack, not to adjudicate
        # lock formats. Skip it, say so, and keep booting.
        case "$var" in
            ''|[!A-Z_]*|*[!A-Z0-9_]*)
                echo "stack.lock row '''$line''' does not name an image variable — skipping" >&2
                continue
                ;;
        esac
        export "$var=@$dig"
        _DIST_PINS+=("$var=@$dig")
    done < stack.lock
    _DIST_LOCK_STATE=loaded
}

# dist_require_lock TAG VERB - a recreate under distribution mode runs the
# signed digests or nothing: refuse (exit status 1, saying why and the fix)
# when ./stack.lock is missing or for another tag.
dist_require_lock() {
    case "$_DIST_LOCK_STATE" in
        loaded) return 0 ;;
        other) echo "ERROR: stack.lock is not for ${1} — refusing to $2 by tag (unpinned images)." >&2 ;;
        *) echo "ERROR: no stack.lock for ${1} — refusing to $2 by tag (unpinned images)." >&2 ;;
    esac
    echo "       lay down the signed lock first: noo upgrade --stack --tag ${1}" >&2
    return 1
}

# (Defined here, not in the launcher: the launcher's own guard tests read its
# text for `docker compose` lines before the secrets check.)
# The dist pins - NOO_IMAGE_TAG and the stack.lock digests - are resolved ONCE,
# by dist_load_stack_lock above, which records every digest it exports in
# _DIST_PINS. Every later loader (load_secrets exports unconditionally,
# load_config adds compose_env) can write the same names, and the pull and the
# `up` after it must see the SAME values. `dist_reassert_pins` is the one place
# that restores them: it drops every NOO_IMAGE_DIGEST_* var in the environment
# (a digest is only ever the lock's, never another tag's) and re-exports the
# recorded ones plus the tag. Called once, after the last loader and before the
# pull.
dist_reassert_pins() {
    [ -n "${DIST_TAG:-}" ] || return 0
    local _v _p
    for _v in $(compgen -e | grep '^NOO_IMAGE_DIGEST_' || true); do unset "$_v"; done
    for _p in "${_DIST_PINS[@]+"${_DIST_PINS[@]}"}"; do export "$_p"; done
    export NOO_IMAGE_TAG="$DIST_TAG"
}

# dist_ref_is_stack_versioned NAME TAG - is this ref (already known to sit
# under our image prefix) one the STACK versions, i.e. one whose tag is the
# release tag? Derived, never hand-listed: the name is one the lock for this
# tag pins (every stack image is a lock row, `<name>@sha256:...`), or the tag
# has the shape of a stack tag (`v<major>.<minor>.<patch>[-rc.N]`), which
# keeps the guard live when the lock is absent or for another tag. Anything
# else under the prefix is a third-party or monitoring image a mirror put
# there - `grafana:12-debian13-dev`, `loki:3`, `redis:8.6-debian13-dev`,
# `nats:latest@sha256:...` - whose compose tag is NOT the stack tag, and
# which the pull must fetch as declared.
dist_ref_is_stack_versioned() {
    local _name="$1" _tag="$2" _var _p
    case "$_tag" in v[0-9]*.[0-9]*.[0-9]*) return 0 ;; esac
    _var="NOO_IMAGE_DIGEST_$(printf '%s' "$_name" | tr 'a-z-' 'A-Z_')"
    for _p in "${_DIST_PINS[@]+"${_DIST_PINS[@]}"}"; do
        [ "${_p%%=*}" = "$_var" ] && return 0
    done
    return 1
}

# dist_third_party_row REF - the lock row family (NOO_IMAGE_DIGEST_<X> suffix
# list) for a third-party runtime image the signed lock pins, by the REPOSITORY
# name in the ref; empty for anything else. Mirrors THIRD_PARTY in
# scripts/stack-lock-third-party.py (tests/test_third_party_image_lock.py
# pins the two together). tei has two rows (GPU and cpu- tags).
dist_third_party_row() {
    local _r="${1%%@*}"
    _r="${_r##*/}"
    _r="${_r%%:*}"
    case "$_r" in
        redis) echo REDIS ;;
        nats) echo NATS ;;
        nginx) echo NGINX ;;
        loki) echo LOKI ;;
        prometheus) echo PROMETHEUS ;;
        alertmanager) echo ALERTMANAGER ;;
        grafana) echo GRAFANA ;;
        node-exporter) echo NODE_EXPORTER ;;
        text-embeddings-inference) echo "TEI TEI_CPU" ;;
        vllm-openai) echo VLLM ;;
    esac
}

# dist_assert_third_party_ref REF - a third-party runtime image compose is
# about to pull must be the one the signed lock pins. With a pin loaded for
# its row: the ref must carry a digest, and it must be one of the lock's pins
# (a hand-set override such as VLLM_IMAGE=vllm/vllm-openai:v0.26 of a locked
# repository is refused too: name its digest, or unset it). With no pin for the row (a lock of a release before the
# third-party rows existed, or no lock): warn, never silent, and go on, so a
# roll back to an older stack still starts.
dist_assert_third_party_ref() {
    local _ref="$1" _rows _row _p _dig _ok="" _pinned=""
    _rows="$(dist_third_party_row "$_ref")"
    [ -n "$_rows" ] || return 0
    for _row in $_rows; do
        for _p in "${_DIST_PINS[@]+"${_DIST_PINS[@]}"}"; do
            [ "${_p%%=*}" = "NOO_IMAGE_DIGEST_${_row}" ] && _pinned=1
        done
    done
    if [ -z "$_pinned" ]; then
        echo "WARNING: $_ref is not pinned by stack.lock (a release before the lock carried third-party images?) - pulled by tag" >&2
        return 0
    fi
    case "$_ref" in
        *@sha256:*)
            _dig="@${_ref#*@}"
            for _p in "${_DIST_PINS[@]+"${_DIST_PINS[@]}"}"; do
                [ "${_p#*=}" = "$_dig" ] && _ok=1
            done
            if [ -z "$_ok" ]; then
                echo "ERROR: the pull would fetch $_ref - its digest is not in stack.lock for ${DIST_TAG:-this tag} (an override such as VLLM_IMAGE? name its digest, or unset it); refusing to pull an unpinned image" >&2
                return 1
            fi ;;
        *)
            # Compose renders the digest whenever the lock is loaded, so a
            # digest-less ref here is an override of the locked repository.
            echo "ERROR: the pull would fetch $_ref with no digest, but stack.lock pins it - refusing to pull by tag" >&2
            return 1 ;;
    esac
    return 0
}

# dist_assert_pull_refs - refuse a pull whose first-party refs are not the
# ones the up phase will run. `config --images` is what compose will PULL;
# every STACK-VERSIONED ref under our image prefix must carry DIST_TAG, and
# a digest that is not one of the lock's pins is another release's. Fails
# with the offending ref instead of fetching the wrong images (observed live
# 2026-10-06: a v0.2.91 -> v0.2.93 roll pulled `<svc>:v0.2.91@sha256:...`
# while `up` ran v0.2.93). When compose cannot list images it warns with
# compose's own error and lets the pull proceed.
#
# Only the images the stack versions are held to the stack tag. A
# controller whose NOO_BASE_REGISTRY mirrors the monitoring images under the
# same prefix renders `<prefix>/grafana:12-debian13-dev`, `<prefix>/loki:3`
# and the like; holding those to `:v0.2.94` refused every roll on such a
# box (observed live 2026-10-07, host8, v0.2.93 -> v0.2.94: "the pull would
# fetch .../grafana:12-debian13-dev, but this start runs v0.2.94"). See
# dist_ref_is_stack_versioned for how the set is derived.
#
# The runtime images' own registry (NOO_BASE_REGISTRY, default
# `<prefix>/dhi`, the DHI mirrors) nests UNDER the image prefix. Nothing
# there is a stack image, so a ref under `${NOO_BASE_REGISTRY}/` is not held
# to the stack TAG; it is held to its signed DIGEST pin instead, like every
# other third-party runtime image (dist_assert_third_party_ref).
dist_assert_pull_refs() {
    local _imgs _ref _rest _name _tag _dig _ok _p
    local _rc=0
    compose_capture "$@" config --images || _rc=$?
    _imgs="$COMPOSE_OUT"
    if [ "$_rc" -ne 0 ]; then
        # Not a refusal (the pull itself will fail loudly), but never silent.
        echo "WARNING: compose could not list the images this pull would fetch, so they are not checked" >&2
        compose_report_error "$_rc"
        return 0
    fi
    local _base="${NOO_BASE_REGISTRY:-${NOO_IMAGE_PREFIX:-}/dhi}"
    _base="${_base%/}"
    while IFS= read -r _ref; do
        # Third-party runtime images (redis, nats, loki, vllm, tei ...) sit
        # outside the stack-versioned set, but the signed lock pins them by
        # digest: held to their pins below, wherever their registry is.
        dist_assert_third_party_ref "$_ref" || return 1
        case "$_ref" in "${NOO_IMAGE_PREFIX:-}"/*) : ;; *) continue ;; esac
        if [ -n "$_base" ] && [ "$_base" != "${NOO_IMAGE_PREFIX:-}" ]; then
            case "$_ref" in "$_base"/*) continue ;; esac
        fi
        _rest="${_ref#"${NOO_IMAGE_PREFIX:-}"/}"
        _rest="${_rest%%@*}"
        _name="${_rest%%:*}"
        _tag=""; [ "$_rest" != "$_name" ] && _tag="${_rest#*:}"
        dist_ref_is_stack_versioned "$_name" "$_tag" || continue
        case "$_ref" in
            *":${DIST_TAG}"|*":${DIST_TAG}@sha256:"*) : ;;
            *) echo "ERROR: the pull would fetch $_ref, but this start runs ${DIST_TAG} - refusing to pull the wrong images" >&2
               return 1 ;;
        esac
        case "$_ref" in
            *@sha256:*)
                _dig="@${_ref#*@}"; _ok=""
                for _p in "${_DIST_PINS[@]+"${_DIST_PINS[@]}"}"; do
                    [ "${_p#*=}" = "$_dig" ] && _ok=1
                done
                if [ -z "$_ok" ]; then
                    echo "ERROR: the pull would fetch $_ref - its digest is not in stack.lock for ${DIST_TAG}; refusing to pull the wrong images" >&2
                    return 1
                fi ;;
        esac
    done <<REFS
$_imgs
REFS
    # Add-on refs sit outside NOO_IMAGE_PREFIX, so the loop above never sees
    # them: they are held to their signed pins instead.
    dist_assert_addon_refs "$@" || return 1
    return 0
}

# compose_active_services <compose args> - COMPOSE_OUT = the services the
# files+profiles render. A render failure is reported (compose's own error)
# instead of becoming an empty list that silently skips the GPU/guard
# arithmetic; the launcher goes on with an empty set, as before.
compose_active_services() {
    local _rc=0
    compose_capture "$@" config --services || _rc=$?
    if [ "$_rc" -ne 0 ]; then
        echo "WARNING: compose could not list the stack's services (continuing with none)" >&2
        compose_report_error "$_rc"
        COMPOSE_OUT=""
    fi
    return 0
}

# addon_decls_materialise — hand the gateway what each add-on's signed bundle
# declares beyond its overlay (noomesh-internal i163 E/B): `system.json` (its
# database system), `workloads.json` (its managed workloads) and `routes.json`
# (its HTTP route manifest, 0.6.13), copied into
#   <install root>/.noo-addon-systems/<addon>/system.json
#   <install root>/.noo-addon-workloads/<addon>/workloads.json
#   <install root>/.noo-addon-routes/<addon>/routes.json
# which docker-compose.cluster.yml mounts read-only into the gateway at
# /opt/noo/addon-systems, /opt/noo/addon-workloads and
# /opt/noo/addon-bundle-routes (gateway-rust/src/addon_decls.rs and
# addon_proxy.rs validate them again and read them only for an add-on its
# registry registers). This is how an add-on publishes routes without
# touching a core service: a third-party overlay may not extend the gateway
# or mount a core volume (noo-cli/src/addons/guards.rs). The gateway reads a
# routes.json here BEFORE the older per-add-on volume a shipped add-on's own
# overlay mounts under /opt/noo/addon-routes, so the signed copy wins.
#
# ONLY for add-ons switched on AND verified this start, from the verdict
# require_addon_pins just computed (call it right after, never before):
#   dist  each `decl <addon> <file>` launch-pins printed: the file is listed
#         in the add-on's verified signed lock and was just held to its hash,
#         so an unsigned file left in addons/<name>/ is never copied;
#   dev   (NOO_ADDONS_VERIFIED=dev, a source checkout signs nothing) the files
#         beside each composed add-on's overlay (addon_overlay: its
#         development checkout, else its bundle);
#   anything else (an older noo, `none`, unset) copies nothing.
# Every other add-on's directory is removed, so a switched-off or unverified
# add-on stops declaring (and loses its routes) on this start. The three
# directories keep their inode
# (contents replaced, never the directory), so a gateway bind stays valid.
#
# lib-secrets.sh `_declared_systems` reads the systems directory: it is the
# second source of declared systems (passwords NOO_<ID>_DB_PASSWORD /
# NOO_<ID>_DDL_PASSWORD, minted by `noo addons enable`). load_secrets ran
# before the verdict existed, so when the SET of systems changed here the
# systems-secrets file is derived and written again.
#
# Fails (return 1) only when the directories cannot be written.
addon_decls_materialise() {
    local _root="${PROJECT_ROOT:-$_DIST_LIB_ROOT}" _sys _wl _rt _before _after _plan="" _pair _a _f _src _n _d _keep=" "
    _sys="$_root/.noo-addon-systems"
    _wl="$_root/.noo-addon-workloads"
    _rt="$_root/.noo-addon-routes"
    if ! mkdir -p "$_sys" "$_wl" "$_rt" || ! chmod 0755 "$_sys" "$_wl" "$_rt"; then
        echo "REFUSING: could not create the add-on declaration directories under $_root (.noo-addon-systems, .noo-addon-workloads, .noo-addon-routes)." >&2
        return 1
    fi
    _before="$(cd "$_sys" && ls -1 2>/dev/null | sort | tr '\n' ' ')"
    case "${NOO_ADDONS_VERIFIED:-}" in
        dev)
            for _n in $(addon_licensed_names 2>/dev/null); do
                addon_on "$_n" 0 || continue
                _src="$(addon_overlay "$_n" 2>/dev/null)"
                [ -n "$_src" ] || continue
                _d="$(dirname "$_src")"
                for _f in system.json workloads.json routes.json; do
                    [ -f "$_d/$_f" ] && _plan="${_plan}${_n} ${_f} ${_d}/${_f}"$'\n'
                done
            done ;;
        ''|none) : ;;
        *)
            for _pair in ${_ADDON_DECLS[@]+"${_ADDON_DECLS[@]}"}; do
                _a="${_pair%% *}"
                _f="${_pair#* }"
                case ",${NOO_ADDONS_VERIFIED}," in *",${_a}="*) : ;; *) continue ;; esac
                if command -v addon_on >/dev/null 2>&1; then addon_on "$_a" 0 || continue; fi
                _plan="${_plan}${_a} ${_f} ${_root}/addons/${_a}/${_f}"$'\n'
            done ;;
    esac
    while read -r _a _f _src; do
        [ -n "$_a" ] || continue
        case "$_a" in [a-z]*) : ;; *) continue ;; esac
        case "$_a" in *[!a-z0-9_-]*) continue ;; esac
        case "$_f" in system.json) _d="$_sys/$_a" ;; workloads.json) _d="$_wl/$_a" ;; routes.json) _d="$_rt/$_a" ;; *) continue ;; esac
        [ -f "$_src" ] && [ ! -L "$_src" ] || continue
        case "$_keep" in *" $_f:$_a "*) : ;; *)
            rm -rf "${_d:?}" && mkdir -p "$_d" && chmod 0755 "$_d" || return 1 ;;
        esac
        cp "$_src" "$_d/$_f.tmp.$$" && chmod 0644 "$_d/$_f.tmp.$$" && mv -f "$_d/$_f.tmp.$$" "$_d/$_f" || {
            echo "REFUSING: could not copy ${_a}'s ${_f} into $_d." >&2
            return 1
        }
        _keep="${_keep}${_f}:${_a} "
    done <<PLAN
$_plan
PLAN
    # Drop every add-on directory not copied above.
    for _d in "$_sys"/* "$_wl"/* "$_rt"/*; do
        [ -e "$_d" ] || continue
        _n="$(basename "$_d")"
        case "$_d" in "$_sys"/*) _f=system.json ;; "$_wl"/*) _f=workloads.json ;; *) _f=routes.json ;; esac
        case "$_keep" in *" $_f:$_n "*) : ;; *) rm -rf "${_d:?}" ;; esac
    done
    _after="$(cd "$_sys" && ls -1 2>/dev/null | sort | tr '\n' ' ')"
    if [ "$_before" != "$_after" ] && command -v derive_file_secrets >/dev/null 2>&1 && command -v write_secret_files >/dev/null 2>&1; then
        # The systems-secrets file must carry the new set's passwords.
        derive_file_secrets && write_secret_files || return 1
    fi
    return 0
}

# ── Add-on runtime inputs (noomesh-internal i239 section 10) ────────────────
#
# addon_resources_materialise — every add-on that is on is checked by the CLI
# (its overlay may take only its own secrets, and a third-party add-on may not
# hold a core name: noo-cli/src/addons/guards.rs), and what each add-on's
# signed bundle declares in
# `resources.json` (a gateway URL, a TLS leaf, its outbound key, a shared
# secret, its database URL and files, network names), produced by
# `noo addons launch-resources` and handed over here. Call it right after
# require_addon_pins and BEFORE addon_decls_materialise: an add-on refused
# here must not have its declarations handed to the gateway either.
#
# Core names no add-on and no add-on variable. The CLI writes the files, on
# tmpfs, into <rundir>/<addon>/<generation>/<mount>/ (0400 files under 0700
# directories; NOO_ADDON_RUNDIR, else /run/noo/addons as root, else
# /dev/shm/noo-addons-<uid>), and prints the protocol documented in
# noo-cli/src/commands/addon_resources.rs. This function then:
#   - hands each fresh mount directory to the uid the bundle declares (the
#     secret-file chown helper, _secret_chown_files, when that uid is not
#     ours) and marks the generation complete; a generation that is already
#     complete is reused untouched, so a running add-on keeps its files;
#   - removes older generations;
#   - exports the add-on's variables: mount directories (host paths its
#     overlay bind-mounts read-only) and the non-secret values;
#   - REFUSES the add-on (_addon_refuse: left out of this start, by name;
#     the rest starts) when a resource cannot be produced, naming it;
#   - records the HELD services: a third-party add-on's service that asks
#     for a GPU, the Docker socket or `privileged` is never started
#     (ADDON_HOLD_SCALE, `--scale <service>=0`, on every launcher `up`).
#
# No value is printed: a secret part cannot be declared with an environment
# delivery (the CLI refuses the bundle), and files are never echoed.
ADDON_HOLD_SCALE=""
# "<addon> <service> <why>" per held service.
_ADDON_HELD=()

# _addon_unverify <addon> — take a refused add-on out of the verdict the
# gateway's registry reads (require_addon_pins exported it before this ran).
_addon_unverify() {
    local _d _out=""
    case "${NOO_ADDONS_VERIFIED:-}" in
        dev|''|none) : ;;
        *)
            for _d in $(printf '%s' "$NOO_ADDONS_VERIFIED" | tr ',' ' '); do
                case "$_d" in "$1="*) ;; *) _out="${_out:+${_out},}${_d}" ;; esac
            done
            export NOO_ADDONS_VERIFIED="${_out:-none}" ;;
    esac
    if [ -n "${NOO_ADDONS_DEV:-}" ]; then
        _out=""
        for _d in $(printf '%s' "$NOO_ADDONS_DEV" | tr ',' ' '); do
            case "$_d" in "$1="*) ;; *) _out="${_out:+${_out},}${_d}" ;; esac
        done
        if [ -n "$_out" ]; then export NOO_ADDONS_DEV="$_out"; else unset NOO_ADDONS_DEV; fi
    fi
    export NOO_ADDONS_REFUSED="$_NOO_ADDONS_REFUSED"
}

# _addon_hand_tree <dir> <uid> — chown <dir> and everything under it to
# <uid>, through the secret helper (_secret_chown_files: chown as root, else
# a throwaway container with CAP_CHOWN only). Its manifest sits in <dir>'s
# parent (ours) and holds the uid and paths, never a value.
_addon_hand_tree() {
    local _dir="$1" _uid="$2" _parent _m _rc=0
    # Everything in it already belongs to <uid>: nothing to hand over. (Run
    # as us, find cannot enter a directory of another uid, and says so.)
    if [ -z "$(find "$_dir" ! -uid "$_uid" -print -quit 2>&1)" ]; then return 0; fi
    declare -F _secret_chown_files >/dev/null 2>&1 || return 1
    _parent="$(dirname "$_dir")"
    _m=".chown.$$"
    ( cd "$_parent" && find "$(basename "$_dir")" -print | while IFS= read -r _f; do printf '%s %s\n' "$_uid" "$_f"; done ) > "${_parent:?}/${_m:?}" || return 1
    chmod 0644 "${_parent:?}/${_m:?}" 2>/dev/null || true
    _secret_chown_files "$_parent" "$_m" || _rc=1
    rm -f -- "${_parent:?}/${_m:?}"
    return "$_rc"
}

addon_resources_materialise() {
    local _n _o _args=() _nb _out _rc=0 _kind _addon _rest _var _val _uid _path _h _prefix _bad
    local _envs=() _owns=() _gens=() _stales=() _p _tagargs=()
    ADDON_HOLD_SCALE=""
    _ADDON_HELD=()
    for _n in $(addon_licensed_names); do
        addon_on "$_n" 0 || continue
        case "${NOO_ADDONS_VERIFIED:-}" in
            dev)
                _o="$(addon_overlay "$_n" 2>/dev/null)"
                [ -n "$_o" ] || continue
                _args+=("${_n}=${_o}") ;;
            ''|none) continue ;;
            *)
                case ",${NOO_ADDONS_VERIFIED}," in *",${_n}="*) _args+=("$_n") ;; *) continue ;; esac ;;
        esac
    done
    [ ${#_args[@]} -gt 0 ] || return 0
    _nb="$(_addon_noo 2>/dev/null)" || _nb=""
    [ -n "${DIST_TAG:-${NOO_IMAGE_TAG:-}}" ] && _tagargs=(--tag "${DIST_TAG:-${NOO_IMAGE_TAG:-}}")
    if [ -z "$_nb" ]; then
        _rc=127
        _out="no noo CLI found"
    else
        _out="$("$_nb" addons launch-resources --root "${PROJECT_ROOT:-$_DIST_LIB_ROOT}" ${_tagargs[@]+"${_tagargs[@]}"} \
            --project "${COMPOSE_PROJECT_NAME:-noomesh}" --network "${NOO_CLUSTER_NETWORK:-noo-cluster}" "${_args[@]}" 2>&1)" || _rc=$?
    fi
    if [ "$_rc" != 0 ]; then
        # launch-resources is also where every add-on's overlay is checked
        # against its own secrets (noo-cli addons/guards.rs): without it no
        # add-on was checked, so none starts. Fail closed, by name; core starts.
        for _n in ${_args[@]+"${_args[@]}"}; do
            _n="${_n%%=*}"
            _addon_refuse "$_n" "its overlay's secrets and runtime inputs could not be checked (noo addons launch-resources failed: $(printf '%s' "$_out" | tail -1))"
            _addon_unverify "$_n"
        done
        echo "WARNING: noo addons launch-resources failed, so no add-on was checked and none was started. Fix: noo upgrade" >&2
        return 0
    fi
    while read -r _kind _addon _rest; do
        case "$_kind" in hold|env|mount|own|gen|stale|refuse|notice) : ;; *) continue ;; esac
        case "$_addon" in
            [a-z]*) case "$_addon" in *[!a-z0-9_-]*) _addon="" ;; esac ;;
            *) _addon="" ;;
        esac
        if [ -z "$_addon" ]; then
            echo "REFUSING: noo addons launch-resources sent a line for something that is not an add-on name: ${_kind} …" >&2
            return 1
        fi
        case "$_kind" in
            refuse)
                _addon_refuse "$_addon" "${_rest:-its runtime inputs could not be produced}"
                _addon_unverify "$_addon" ;;
            notice)
                # An optional input that could not be produced: skipped, said.
                echo "NOTE: add-on ${_addon}: ${_rest}" >&2 ;;
            hold)
                case "${_rest%% *}" in
                    [A-Za-z0-9]*) case "${_rest%% *}" in *[!A-Za-z0-9_.-]*) continue ;; esac ;;
                    *) continue ;;
                esac
                _ADDON_HELD+=("$_addon $_rest") ;;
            env|mount)
                _var="${_rest%% *}"
                _val="${_rest#* }"
                [ "$_val" = "$_rest" ] && _val=""
                _prefix="$(printf '%s' "$_addon" | tr 'a-z-' 'A-Z_')_"
                _bad=""
                case "$_var" in ''|*[!A-Z0-9_]*|[!A-Z]*) _bad=1 ;; esac
                case "$_var" in NOO_*|COMPOSE_*|DOCKER_*) _bad=1 ;; esac
                case "$_var" in "$_prefix"?*) : ;; *) _bad=1 ;; esac
                if [ -n "$_bad" ]; then
                    _addon_refuse "$_addon" "noo addons launch-resources named variable '${_var}', which is not one of its own (${_prefix}*)"
                    _addon_unverify "$_addon"
                    continue
                fi
                _envs+=("${_addon}"$'\t'"${_var}"$'\t'"${_val}") ;;
            own)
                _uid="${_rest%% *}"
                _path="${_rest#* }"
                case "$_uid" in
                    ''|0|*[!0-9]*)
                        _addon_refuse "$_addon" "noo addons launch-resources asked to hand its inputs to uid '${_uid}'"
                        _addon_unverify "$_addon"
                        continue ;;
                esac
                _owns+=("$_addon $_uid $_path") ;;
            gen) _gens+=("$_addon $_rest") ;;
            stale) _stales+=("$_addon $_rest") ;;
        esac
    done <<RES
$_out
RES
    # Hand each fresh mount directory to the add-on's uid.
    for _p in ${_owns[@]+"${_owns[@]}"}; do
        _addon="${_p%% *}"; _p="${_p#* }"; _uid="${_p%% *}"; _path="${_p#* }"
        case ",${_NOO_ADDONS_REFUSED}," in *",${_addon},"*) continue ;; esac
        case "$_path" in
            /?*) : ;;
            *) _addon_refuse "$_addon" "its runtime inputs were written to a path that is not absolute"; _addon_unverify "$_addon"; continue ;;
        esac
        if ! _addon_hand_tree "$_path" "$_uid"; then
            _addon_refuse "$_addon" "its runtime inputs could not be handed to uid ${_uid} (${_path})"
            _addon_unverify "$_addon"
        fi
    done
    for _p in ${_gens[@]+"${_gens[@]}"}; do
        _addon="${_p%% *}"; _path="${_p#* }"
        case ",${_NOO_ADDONS_REFUSED}," in *",${_addon},"*) continue ;; esac
        if ! : > "${_path:?}/.complete"; then
            _addon_refuse "$_addon" "its runtime inputs could not be marked complete (${_path})"
            _addon_unverify "$_addon"
        fi
    done
    # Older generations: hand them back to us, then remove them. Not fatal.
    for _p in ${_stales[@]+"${_stales[@]}"}; do
        _path="${_p#* }"
        case "$_path" in /?*/g-?*) : ;; *) continue ;; esac
        _addon_hand_tree "$_path" "$(id -u)" >/dev/null 2>&1 || true
        rm -rf -- "${_path:?}" 2>/dev/null || echo "WARNING: could not remove an older add-on input generation: ${_path}" >&2
    done
    for _p in ${_envs[@]+"${_envs[@]}"}; do
        _addon="${_p%%$'\t'*}"; _p="${_p#*$'\t'}"; _var="${_p%%$'\t'*}"; _val="${_p#*$'\t'}"
        case ",${_NOO_ADDONS_REFUSED}," in *",${_addon},"*) continue ;; esac
        export "${_var}=${_val}"
    done
    for _h in ${_ADDON_HELD[@]+"${_ADDON_HELD[@]}"}; do
        _addon="${_h%% *}"; _p="${_h#* }"
        case ",${_NOO_ADDONS_REFUSED}," in *",${_addon},"*) continue ;; esac
        ADDON_HOLD_SCALE="${ADDON_HOLD_SCALE} --scale ${_p%% *}=0"
        echo "HELD: add-on ${_addon} service ${_p%% *} is not started: it ${_p#* } (an add-on gets no GPU, Docker socket or privileged mode)" >&2
    done
    ADDON_HOLD_SCALE="${ADDON_HOLD_SCALE# }"
    return 0
}

# addon_held_services — the services held this start, one per line.
addon_held_services() {
    local _h _p
    for _h in ${_ADDON_HELD[@]+"${_ADDON_HELD[@]}"}; do
        case ",${_NOO_ADDONS_REFUSED}," in *",${_h%% *},"*) continue ;; esac
        _p="${_h#* }"
        printf '%s\n' "${_p%% *}"
    done
    return 0
}

# addon_drop_held <services, newline separated> — the same list without the
# held services.
addon_drop_held() {
    local _held _s
    _held="$(addon_held_services)"
    printf '%s\n' "$1" | while IFS= read -r _s; do
        [ -n "$_s" ] || continue
        printf '%s\n' "$_held" | grep -qxF -- "$_s" || printf '%s\n' "$_s"
    done
    return 0
}

# addon_refuse_held <name>... — exit status 1, naming each, when a service
# the operator named is held (exactly, or as noo-<name>).
addon_refuse_held() {
    local _n _held _bad=""
    _held="$(addon_held_services)"
    [ -n "$_held" ] || return 0
    for _n in "$@"; do
        if printf '%s\n' "$_held" | grep -qxF -- "$_n" || printf '%s\n' "$_held" | grep -qxF -- "noo-$_n"; then
            _bad="${_bad} ${_n}"
        fi
    done
    [ -z "$_bad" ] && return 0
    echo "REFUSING:${_bad}: an add-on service that asks for a GPU, the Docker socket or privileged mode is never started (add-ons have no GPU reservation path yet)" >&2
    return 1
}
