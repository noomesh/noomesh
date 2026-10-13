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

# resolve_intel_image — never let the Intelligent tier strand a pinned stack.
#
# The trellion-intel service has its own image name since noo-cli 0.3.48
#, but stack tags before v0.2.6 never built
# it: a dist install pinned to such a tag with NOO_TRELLION_INTEL_ENABLED=1
# died at pull ("trellion-intel:v0.2.5: not found") on every start/restart
# (host8, 2026-09-02). The image is the SAME build as trellion for those
# tags, so when the dedicated one is absent we point the service at the
# tag's trellion image via NOO_INTEL_IMAGE and say so, naming the tag.
# Cheap: an image already present locally short-circuits; otherwise ONE
# manifest lookup against the registry the pull would hit anyway.
resolve_intel_image() {
    [ "${DIST_MODE:-0}" = 1 ] || return 0
    [ -n "${NOO_INTEL_IMAGE:-}" ] && return 0
    local prefix="${NOO_INTEL_IMAGE_PREFIX:-${NOO_IMAGE_PREFIX}}"
    local want="${prefix}/trellion-intel:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_TRELLION_INTEL:-}"
    # Only an ABSENT image means "this tag predates the dedicated image". A
    # refused credential or an unreachable registry says nothing about the
    # tag, and substituting the public trellion image there would run the
    # licensed tier on an unlicensed build with a note about tag age. Those
    # fall through untouched; require_addon_images reports them.
    _addon_probe "$want"
    case "$_ADDON_PROBE" in
        present|denied|unreachable) return 0 ;;
    esac
    # Absent AND the tag predates v0.2.6 (version-shaped and below it): the
    # fallback is correct. Absent on a newer or non-version tag means the
    # add-on is simply not in this registry (a public install), and running the
    # licensed tier on the public trellion image would hide that, so leave it
    # for require_addon_images to refuse with the licence message.
    local _t="${NOO_IMAGE_TAG#stack-}"
    printf '%s' "$_t" | grep -qE '^v?[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$' || return 0
    _t="v${_t#v}"; _t="${_t%%-rc.*}"
    [ "$_t" != v0.2.6 ] && [ "$(printf '%s\nv0.2.6\n' "$_t" | sort -V | head -1)" = "$_t" ] || return 0
    export NOO_INTEL_IMAGE="${NOO_IMAGE_PREFIX}/trellion:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_TRELLION:-}"
    echo "◦ trellion-intel: stack tag ${NOO_IMAGE_TAG} has no ${want} — running the Intelligent tier on" >&2
    echo "  ${NOO_INTEL_IMAGE} for this start (identical build for that tag). Tags ≥ v0.2.6 ship the" >&2
    echo "  dedicated image: noo upgrade --stack" >&2
    return 0
}

# _addon_probe <image-ref> — classify what the registry says about one image.
# Sets _ADDON_PROBE (one word) and _ADDON_PROBE_LINE (the registry's last line,
# for the message). Never exits non-zero and never prints.
#   present     in the local image store, or `docker manifest inspect` succeeded
#   denied      the registry answered but refused us (unauthorized / forbidden /
#               denied / no credential): the LICENCE gate on a private package
#   notfound    the registry answered and has no such image/tag
#   unreachable no answer (DNS, timeout, refused connection, TLS)
#   unknown     failed in a way none of the above matches (treated as a failure
#               by require_addon_images, as "absent" by resolve_intel_image,
#               which is what it did before this classification existed)
_addon_probe() {
    local ref="$1" out
    _ADDON_PROBE="present"; _ADDON_PROBE_LINE=""
    if docker image inspect "$ref" >/dev/null 2>&1; then
        return 0
    fi
    if out="$(docker manifest inspect "$ref" 2>&1 >/dev/null)"; then
        return 0
    fi
    _ADDON_PROBE_LINE="$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -1)"
    case "$(printf '%s' "$out" | tr 'A-Z' 'a-z')" in
        *unauthorized*|*denied*|*forbidden*|*"authentication required"*|*"401"*|*"403"*|*"requested access"*)
            _ADDON_PROBE="denied" ;;
        *"no such manifest"*|*"manifest unknown"*|*"not found"*|*"404"*|*"name unknown"*)
            _ADDON_PROBE="notfound" ;;
        *"no such host"*|*timeout*|*"timed out"*|*"connection refused"*|*"network is unreachable"*|*"dial tcp"*|*"tls:"*|*"temporary failure"*|*"i/o timeout"*|*"eof"*)
            _ADDON_PROBE="unreachable" ;;
        *)  _ADDON_PROBE="unknown" ;;
    esac
    return 0
}

# _addon_ref <overridevar> <prefixvar> <name> <digestvar> — the reference the
# overlay will run, computed the way its `image:` line does:
#   $<overridevar>  else  ${<prefixvar>:-$NOO_IMAGE_PREFIX}/<name>:$NOO_IMAGE_TAG$<digestvar>
# Echoes it; sets _ADDON_PREFIX to the prefix tried (empty when an override
# supplied the whole reference). Call it WITHOUT a command substitution if
# _ADDON_PREFIX is wanted (a subshell loses it); see require_addon_images.
_addon_ref() {
    local ov="${!1:-}" pf="${!2:-}" dg="${!4:-}"
    if [ -n "$ov" ]; then _ADDON_PREFIX=""; _ADDON_REF="$ov"; return 0; fi
    _ADDON_PREFIX="${pf:-${NOO_IMAGE_PREFIX:-}}"
    _ADDON_REF="${_ADDON_PREFIX}/${3}:${NOO_IMAGE_TAG:-latest}${dg}"
}

# require_addon_images — a dist install that turns an add-on on must either be
# able to pull its image or stop with a message that says what is missing.
#
# The add-ons (trellion-intel, evolve) are LICENSED. Their images are private
# packages; the right to pull one IS the licence gate, and the entitlement
# itself is checked offline elsewhere. A public install has neither the
# entitlement nor a login to that registry, and without this check it reaches
# `compose pull`, retries three times and dies on a bare "pull access denied" /
# "manifest unknown" that names no add-on and no remedy.
#
# Behaviour per input (dist mode only; other modes build from a checkout):
#   add-on switched off ........ not looked at (absent is not failed).
#   image already local ........ passes, no registry call. This is also how a
#                                controller-staged / `docker load`ed image works
#                                on a box with no registry route.
#   add-on image NOT in the lock  (NOO_IMAGE_DIGEST_<NAME> empty): the public
#                                lock carries no add-on rows, so this is the
#                                normal case, not a failure. The tag is probed
#                                instead and the start proceeds UNPINNED, with
#                                one note saying so. It is never silently
#                                treated as pinned.
#   prefix unset ............... the prefix tried is the core one, which holds
#                                no add-on: reported as `notfound`, with the
#                                NOO_<NAME>_IMAGE_PREFIX remedy. (NOO_IMAGE_PREFIX
#                                itself is always set by apply_dist_mode.)
#   registry denied ............ REFUSE. Names the add-on, the image, the prefix,
#                                that add-ons are licensed and pulled from a private
#                                registry, and what to do (entitlement + login).
#   registry unreachable ....... REFUSE with the transport error. Not a licence
#                                problem and the message must not say it is.
#   image not found ............ REFUSE: wrong prefix or tag not yet published.
#   unknown failure ............ REFUSE, quoting the registry's last line.
# REFUSE = return 1; both launchers `|| exit 1`, before anything is recreated.
# A probe is one manifest request, the same one the pull would make.
require_addon_images() {
    [ "${DIST_MODE:-0}" = 1 ] || return 0
    local entry name ov pf dg flag fail=0
    # name|override var|prefix var|digest var|addon_on key
    for entry in \
        "trellion-intel|NOO_INTEL_IMAGE|NOO_INTEL_IMAGE_PREFIX|NOO_IMAGE_DIGEST_TRELLION_INTEL|trellion_intel" \
        "evolve|NOO_EVOLVE_IMAGE|NOO_EVOLVE_IMAGE_PREFIX|NOO_IMAGE_DIGEST_EVOLVE|evolve"; do
        IFS='|' read -r name ov pf dg flag <<<"$entry"
        addon_on "$flag" 0 || continue
        _addon_ref "$ov" "$pf" "$name" "$dg"
        _addon_probe "$_ADDON_REF"
        if [ "$_ADDON_PROBE" = present ]; then
            if [ -z "${!dg:-}" ] && [ -z "${!ov:-}" ]; then
                echo "◦ ${name}: no digest for it in this release lock — running ${_ADDON_REF} by tag, unpinned" >&2
            fi
            continue
        fi
        fail=1
        {
            echo "REFUSING: the ${name} add-on is switched on but its image cannot be pulled."
            echo "  image:  ${_ADDON_REF}"
            if [ -n "$_ADDON_PREFIX" ]; then
                echo "  prefix: ${_ADDON_PREFIX}   (override: ${pf}; the core prefix NOO_IMAGE_PREFIX is the fallback)"
            else
                echo "  source: ${ov} (a full reference you set)"
            fi
            case "$_ADDON_PROBE" in
                denied)
                    echo "  The registry refused us. Add-ons are licensed and pulled from a PRIVATE registry;"
                    echo "  the public stack registry does not carry them and the right to pull is the licence."
                    echo "  Fix:  noo security entitlement install <token>   (no licence: set addons.${flag}: false in noomesh.yaml)"
                    echo "        docker login <registry of ${pf}>   with the credential your licence came with" ;;
                notfound)
                    echo "  The registry has no such image. Add-ons are licensed and are NOT in the public stack"
                    echo "  registry; either ${pf} is unset or wrong, or this tag has no ${name} build yet."
                    echo "  Fix:  set ${pf} to your add-on registry, or addons.${flag}: false in noomesh.yaml" ;;
                unreachable)
                    echo "  The registry could not be reached (a network or TLS problem, not a licence one)."
                    echo "  Fix:  check the route to that registry, or load the image locally, then re-run" ;;
                *)
                    echo "  The registry check failed in a way this launcher cannot classify."
                    echo "  Add-ons are licensed and pulled from a private registry; check ${pf} and your login." ;;
            esac
            if [ -z "${NOO_ENTITLEMENT:-}" ]; then
                echo "  No NOO_ENTITLEMENT is visible to the launcher."
            fi
            if [ -n "$_ADDON_PROBE_LINE" ]; then echo "  registry said: ${_ADDON_PROBE_LINE}"; fi
        } >&2
    done
    [ "$fail" = 0 ]
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
# Digests: `noomesh-start.sh` is the only thing that loads `stack.lock` into
# NOO_IMAGE_DIGEST_* vars, so a script that has not been through the launcher
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

# (Defined here, not in the launcher: the launcher's own guard tests read its
# text for `docker compose` lines before the secrets check.)
# The dist pins - NOO_IMAGE_TAG and the stack.lock digests - are resolved ONCE,
# in the dist block below, which records every digest it exports in
# _DIST_PINS. Every later loader (load_secrets exports unconditionally,
# load_config adds compose_env) can write the same names, and the pull and the
# `up` after it must see the SAME values. `dist_reassert_pins` is the one place
# that restores them: it drops every NOO_IMAGE_DIGEST_* var in the environment
# (a digest is only ever the lock's, never another tag's) and re-exports the
# recorded ones plus the tag. Called once, after the last loader and before the
# pull.
_DIST_PINS=()
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

# dist_assert_pull_refs - refuse a pull whose first-party refs are not the
# ones the up phase will run. `config --images` is what compose will PULL;
# every STACK-VERSIONED ref under our image prefix must carry DIST_TAG, and
# a digest that is not one of the lock's pins is another release's. Fails
# with the offending ref instead of fetching the wrong images (observed live
# 2026-10-06: a v0.2.91 -> v0.2.93 roll pulled `<svc>:v0.2.91@sha256:...`
# while `up` ran v0.2.93). Silent when compose cannot list images; the pull
# then says why.
#
# Only the images the stack versions are held to the stack tag. A
# controller whose NOO_BASE_REGISTRY mirrors the monitoring images under the
# same prefix renders `<prefix>/grafana:12-debian13-dev`, `<prefix>/loki:3`
# and the like; holding those to `:v0.2.94` refused every roll on such a
# box (observed live 2026-10-07, host8, v0.2.93 -> v0.2.94: "the pull would
# fetch .../grafana:12-debian13-dev, but this start runs v0.2.94"). See
# dist_ref_is_stack_versioned for how the set is derived.
dist_assert_pull_refs() {
    local _imgs _ref _rest _name _tag _dig _ok _p
    _imgs="$(docker compose "$@" config --images 2>/dev/null)" || return 0
    while IFS= read -r _ref; do
        case "$_ref" in "${NOO_IMAGE_PREFIX:-}"/*) : ;; *) continue ;; esac
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
    return 0
}
