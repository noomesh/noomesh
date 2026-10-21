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
# digest, or it does not start.
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
#   refuse <addon> <why>                 REFUSE, naming the add-on and why
# Then every variable the composed overlays read must have been exported from
# a pin: a lock whose image name maps to another variable (the overlay would
# render its unpinned sentinel) is refused here, by name. The exports are
# recorded in _ADDON_PINS for dist_assert_addon_refs.
#
# Dist also exports NOO_ADDONS_VERIFIED, from the `verified <addon> <version>
# <stack>` lines: `name=version@stack,...`, or `none`. Dev exports `dev`. The
# gateway's add-on registry registers an add-on only when it is named there.
# Beside it, NOO_ADDONS_DEV, from the `dev <addon> <unix>` lines:
# `name=<unix expiry>,...` for the add-ons only a temporary development key
# vouches for (i163 part A); the gateway reports them as dev and refuses them
# once that instant passes. Unset when there are none.
#
# Dev (not dist): each variable the composed overlays read is set to the dev
# build's name, `${NOO_IMAGE_PREFIX:-noomesh}/<name>:${NOO_IMAGE_TAG:-latest}`.
#
# REFUSE = return 1; both launchers `|| exit 1` before anything is pulled or
# recreated.
_ADDON_PINS=()
# The install root this launcher belongs to (scripts/..), fixed when the
# library is sourced. launch-pins reads the pins under it, never the cwd.
_DIST_LIB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
require_addon_pins() {
    local _v _on _nb _out _kind _addon _rest _var _ref _vars _args _name fail=0
    local _verified=() _pinned=() _dev=() _legacy_cli=0 _p
    for _v in $(compgen -e | grep '^NOO_ADDON_IMAGE_' || true); do unset "$_v"; done
    # The registry verdict is set here and nowhere else: a value inherited from
    # the shell or an .env line is dropped, like the image variables above.
    unset NOO_ADDONS_VERIFIED NOO_ADDONS_DEV
    _ADDON_PINS=()
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
    while read -r _kind _addon _rest; do
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
                _pinned+=("$_addon")
                _var="${_rest%% *}"; _ref="${_rest#* }"
                case "$_var" in NOO_ADDON_IMAGE_*) : ;; *)
                    echo "REFUSING: noo addons launch-pins named '${_var}' for ${_addon}, not an add-on image variable" >&2
                    fail=1; continue ;;
                esac
                if ! docker image inspect "$_ref" >/dev/null 2>&1; then
                    {
                        echo "REFUSING: the ${_addon} add-on is on, and its pinned image is not on this host:"
                        echo "  image:  ${_ref}"
                        echo "  The launcher never pulls an add-on; the CLI pulls it by digest with the registry token."
                        echo "  Fix:  noo addons upgrade ${_addon}"
                    } >&2
                    fail=1; continue
                fi
                export "${_var}=${_ref}"
                _ADDON_PINS+=("${_var}=${_ref}") ;;
            refuse)
                {
                    echo "REFUSING: the ${_addon} add-on is on and has no verified pin for ${_tag}:"
                    echo "  ${_rest}"
                    echo "  Fix:  noo addons upgrade ${_addon}   (or turn it off: noo addons disable ${_addon})"
                } >&2
                fail=1 ;;
        esac
    done <<PINS
$_out
PINS
    [ "$fail" = 0 ] || return 1
    # The gateway's add-on registry reads this (gateway-rust/src/addon_registry.rs).
    # A pin with no verdict beside it came from a noo binary older than this
    # launcher: it verified, it just cannot say so. Leave the variable unset
    # (the gateway then loads only the add-ons it already knew and says why)
    # rather than report "none" and refuse a good add-on.
    local _vstr
    _vstr="$(IFS=,; printf '%s' "${_verified[*]-}")"
    for _p in ${_pinned[@]+"${_pinned[@]}"}; do
        case ",${_vstr}," in *",${_p}="*) : ;; *) _legacy_cli=1 ;; esac
    done
    if [ "$_legacy_cli" = 1 ]; then
        echo "WARNING: this noo CLI does not report verified add-on locks; the gateway loads only the add-ons it already knew. Run: noo upgrade" >&2
    elif [ -n "$_vstr" ]; then
        export NOO_ADDONS_VERIFIED="$_vstr"
        # Only for add-ons the verdict names: a dev line alone vouches for nothing.
        local _dstr="" _d
        for _d in ${_dev[@]+"${_dev[@]}"}; do
            case ",${_vstr}," in *",${_d%%=*}="*) _dstr="${_dstr:+${_dstr},}${_d}" ;; esac
        done
        [ -z "$_dstr" ] || export NOO_ADDONS_DEV="$_dstr"
    else
        export NOO_ADDONS_VERIFIED=none
    fi
    for _v in $_vars; do
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
        ollama) echo OLLAMA ;;
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
