#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC


# Single-flight across every compose-mutating entry point (an earlier change —
# the 2026-07-31 outage was two recreate paths interleaving).
source "$(dirname "${BASH_SOURCE[0]}")/lib-compose-lock.sh"
acquire_compose_lock || exit 1
# Restart Mesh services


# fu 46: derive the per-instance namespace (project, container prefix,
# network, ports) before any compose invocation — stop/status/logs must
# address the same project start created.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-instance.sh"
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-ui.sh"


# Auto-include override file if it exists (user directory mounts)

# Resolve the cluster-plane bind address (auto-detect tailnet IP) before up.
# shellcheck source=scripts/lib-bind-addr.sh
_LIBDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$_LIBDIR/lib-bind-addr.sh"
resolve_bind_addr || exit 1   # an unset NOO_BIND_MODE is a refusal (lib-bind-addr.sh); no set -e here, so check it
resolve_location
# Load secrets (no-op unless NOO_SECRETS_BACKEND=sops; fails closed on decrypt error).
source "$_LIBDIR/lib-secrets.sh"
load_secrets || { echo "aborting: secrets load failed" >&2; exit 1; }
require_core_secrets || exit 1
# Deployment config: noomesh.yaml `compose_env:` -> environment, so
# compose can interpolate ${VAR} from something other than .env.
# Non-fatal: config has compose-side defaults, and a missing knob must
# not block a launch the way a missing credential does.
source "$_LIBDIR/lib-config.sh"
# The add-on decision, from the SAME helper start.sh and rebuild.sh use.
# `secrets rotate` runs this script with --force; a restart that cannot see
# the add-on profiles recreates every core consumer and leaves the add-ons
# on the old secrets (noo-trellion-intel, 2026-09-14 → 18).
source "$_LIBDIR/lib-addons.sh"
load_config || echo "warning: config load reported problems (continuing)" >&2
# Stuck-in-Created self-heal for recreates (the 2026-08-20 74-min wedge).
source "$_LIBDIR/lib-created-guard.sh"
source "$_LIBDIR/lib-stuck-container.sh"
# Refuse an `up` whose bind-mount sources are missing or the wrong type.
source "$_LIBDIR/lib-bind-sources.sh"
# Refuse ANY restart while an enabled system lacks its credentials: even a
# plain `compose restart` brings the gateway back reading noomesh.yaml, and
# it will not start without them.
check_system_credentials || exit 1
# Refuse ANY restart of an install whose secrets sit in plaintext .env
#.
check_secrets_at_rest || exit 1

# ── Distribution overlay (first-contact finding #43, unified in #43b) ───
# Restart must speak dist too: without this, `restart --force` on a dist/
# standalone install rendered compose WITHOUT docker-compose.dist.yml and
# tried to BUILD images from Dockerfiles the install does not ship
# ("open Dockerfile.sandbox: no such file", live 2026-08-25). The block
# itself now lives in lib-dist.sh, shared with every other compose consumer.
source "$_LIBDIR/lib-dist.sh"
apply_dist_mode "."
# Same floor as noomesh-start.sh --dist: this compose file delivers the
# gateway's and worker's secrets as files, which an image below
# x-noo-secrets-floor does not read. `secrets rotate` runs this script too.
if [ "${DIST_MODE:-0}" = 1 ]; then
    require_secrets_floor "." "$NOO_IMAGE_TAG" || exit 1
    # The signed digests, exactly as noomesh-start.sh loads them (one reader,
    # lib-dist.sh). Without this `restart --force` recreated every core
    # container by TAG - `gateway:v0.6.5-rc.1`, `ollama/ollama:0.40.5`, no
    # @sha256 (0.6.5-rc.1 rehearsal). dist_reassert_pins drops any stale
    # NOO_IMAGE_DIGEST_* load_secrets exported above.
    DIST_TAG="$NOO_IMAGE_TAG"
    dist_load_stack_lock "$DIST_TAG"
    dist_reassert_pins
fi
# A recreate under distribution mode runs the lock's digests or refuses; a
# plain `compose restart` keeps the containers' images and needs no lock.
restart_require_lock() {
    [ "${DIST_MODE:-0}" = 1 ] || return 0
    dist_require_lock "$DIST_TAG" "recreate"
}
# Licensed add-ons run only their signed, local pins for this tag (see
# lib-dist.sh require_addon_pins); restart never pulls one either.
require_addon_pins || exit 1
# The verified add-ons' bundle declarations, for the gateway (lib-dist.sh).
addon_decls_materialise || exit 1

DEFAULT_PROFILE="controller"

# Map service names to required Docker Compose profiles
service_profile() {
    case $1 in
        vllm)       echo "gpu-tier1" ;;
        airllm)     echo "gpu-tier1" ;;
        llamacpp)   echo "gpu-tier2" ;;
        ollama)     echo "gpu-tier2" ;;
        tei)        echo "controller" ;;
        tei-gpu)    echo "gpu-tier2" ;;
        # whisper / piper: the voice OVERLAY — no profile.
        # trellion: the trellion OVERLAY — no profile.
        # licensed add-ons: OVERLAYS from their signed bundles — visible
        # whenever the add-on is on, no profile to map.
        *)          echo "" ;;
    esac
}

# Detect GPU tier: Tier 1 (>=10GB VRAM), Tier 2 (4-10GB), or none
detect_gpu_tier() {
    if ! command -v nvidia-smi &>/dev/null; then
        echo ""
        return
    fi
    local vram_mb
    vram_mb=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')
    # Guard (same as noomesh-rebuild.sh): nvidia-smi can print an error to
    # stdout ("Failed to initialize NVML: ..."), which would reach the
    # arithmetic below and abort the script. Only a purely numeric value is
    # a VRAM reading; anything else means "no usable GPU here".
    if ! [[ "$vram_mb" =~ ^[0-9]+$ ]] || [ "$vram_mb" = "0" ]; then
        echo ""
        return
    fi
    local vram_gb=$(( vram_mb / 1024 ))
    if [ "$vram_gb" -ge 10 ]; then
        echo "gpu-tier1"
    elif [ "$vram_gb" -ge 4 ]; then
        echo "gpu-tier2"
    else
        echo ""
    fi
}

PROFILE=""
SERVICES=()
FORCE_RECREATE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            PROFILE="${1#*=}"
            shift
            ;;
        --force)
            FORCE_RECREATE=true
            shift
            ;;
        *)
            SERVICES+=("$1")
            shift
            ;;
    esac
done

if [ -z "$PROFILE" ]; then
    # Same resolution as noomesh-start.sh: the persisted install profile
    # (NOO_DEFAULT_PROFILE in .env, written by onboard) wins over the
    # controller default. Without this, `noo stack restart` on a
    # standalone box ran with the controller profile (host8 2026-09-02:
    # the standalone OLLAMA_URL default never fired on restart).
    if [ -z "${NOO_DEFAULT_PROFILE:-}" ] && [ -f ".env" ]; then
        NOO_DEFAULT_PROFILE="$(grep -E '^[[:space:]]*NOO_DEFAULT_PROFILE=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    if [ -z "${NOO_DEFAULT_PROFILE:-}" ] && [ -f ".noo-standalone" ]; then
        NOO_DEFAULT_PROFILE="standalone"
    fi
    PROFILE="${NOO_DEFAULT_PROFILE:-$DEFAULT_PROFILE}"
fi
# A licensed add-on is an overlay, not a profile — restart must carry it or a
# rotation recreates the stack without it and leaves the old one running.
# The file list has ONE home. Evaluated here, after
# dist mode and the add-on map are both known.
. "$_LIBDIR/lib-compose.sh"
. "$_LIBDIR/lib-restart.sh"
COMPOSE_FILES="$(compose_file_args .)"

# Standalone: the single ollama-embed serves chat too (gateway static
# fallback, stack-v0.2.5). An install whose .env predates that (0.3.31
# wrote none) must not fall to the compose default `stunnel-ollama`, which
# does not exist on this profile — default it HERE, where the profile is
# known, so every existing install converges on its next start.
#
# The door is the stunnel-ollama-embed sidecar (mTLS, client certificate
# required), never the container's plain :11434. An .env written before
# the sidecar carries the plaintext literal in up to three variables;
# an exported value beats .env in compose interpolation, so rewrite the
# exact legacy literal here (loudly) until `noo onboard --only env`
# converges the file. Anything else the operator set is left alone.
if { [ "$PROFILE" = "standalone" ] || [ -f ".noo-standalone" ]; }; then
    if [ -z "${OLLAMA_URL:-}" ]; then
        export OLLAMA_URL="https://noo-stunnel-ollama-embed:11434"
    fi
    for _v in OLLAMA_URL PAGEINDEX_EMBEDDING_URL; do
        _cur="$(eval "printf '%s' \"\${$_v:-}\"")"
        if [ -z "$_cur" ] && [ -f ".env" ]; then
            _cur="$(grep -E "^[[:space:]]*$_v=" .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
        fi
        if [ "$_cur" = "http://ollama-embed:11434" ]; then
            echo "WARN: $_v=http://ollama-embed:11434 is the plaintext door; using https://noo-stunnel-ollama-embed:11434 (run: noo onboard --only env)" >&2
            export "$_v=https://noo-stunnel-ollama-embed:11434"
        fi
    done
    unset _v _cur
fi

# Build profile args, auto-detecting GPU profiles from service names
PROFILE_ARGS="--profile $PROFILE"
# Every add-on is an OVERLAY in COMPOSE_FILES (lib-compose.sh); there are no
# add-on profiles left to select.

# Auto-detect GPU tier on controller and add the inference profile
if [ "$PROFILE" = "controller" ]; then
    GPU_TIER=$(detect_gpu_tier)
    if [ -n "$GPU_TIER" ]; then
        PROFILE_ARGS="$PROFILE_ARGS --profile $GPU_TIER"
    fi
fi

for svc in "${SERVICES[@]}"; do
    p=$(service_profile "$svc")
    if [ -n "$p" ]; then
        PROFILE_ARGS="$PROFILE_ARGS --profile $p"
    fi
done
# Profiles the operator enabled in COMPOSE_PROFILES (compose ignores that
# variable beside our own --profile flags; lib-config.sh).
PROFILE_ARGS="$PROFILE_ARGS $(operator_profile_args)"
derive_profile_env
# Every add-on service compose renders must run exactly its verified pin
# (require_addon_pins above exported them); empty render = refusal. Dist only.
# Rendered with the SAME --profile flags `up` gets: without them compose can
# reject the whole project (a COMPOSE_PROFILES profile whose service depends
# on one only the launcher's own profile defines).
# shellcheck disable=SC2086
dist_assert_addon_refs $COMPOSE_FILES $PROFILE_ARGS || exit 1

if [ ${#SERVICES[@]} -eq 0 ]; then
    ui_phase "Stack"
    ui_step "Restarting all services (profile $PROFILE)"
    # The gateway's own dirs on noo-data (uid 65532), as noomesh-start.sh
    # makes them: a restart can be the first start of a new gateway image.
    noo_prepare_gateway_data_dirs
    if [ "$FORCE_RECREATE" = true ]; then
        # Same service arithmetic as noomesh-start.sh: the profile's set,
        # minus the GPU-only exporter when this daemon has no NVIDIA
        # runtime (it carries the standalone profile since fleet logging
        # phase 0; on a CPU box `up` left it Created with "could not select
        # device driver nvidia" and the guard below called it DOWN —
        # 2026-09-29 upgrade rehearsal), minus the containerised agent.
        # shellcheck disable=SC2086
        compose_active_services $COMPOSE_FILES $PROFILE_ARGS
        ACTIVE_SVCS="$COMPOSE_OUT"
        GPU_SCALE=""
        if ! docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; then
            if printf '%s\n' "$ACTIVE_SVCS" | grep -qx nvidia-exporter; then
                GPU_SCALE="--scale nvidia-exporter=0"
                ACTIVE_SVCS="$(printf '%s\n' "$ACTIVE_SVCS" | grep -vx nvidia-exporter)"
                echo "  (no nvidia container runtime — skipping noo-nvidia-exporter)"
            fi
        fi
        AGENT_SCALE=""
        if printf '%s\n' "$ACTIVE_SVCS" | grep -qx node-agent; then
            AGENT_SCALE="--scale node-agent=0"
            ACTIVE_SVCS="$(printf '%s\n' "$ACTIVE_SVCS" | grep -vx node-agent)"
        fi
        restart_require_lock || exit 1
        # shellcheck disable=SC2086
        check_bind_sources --no-deps $ACTIVE_SVCS || exit 1
        noo_compose_up_isolating_stuck compose $COMPOSE_FILES $PROFILE_ARGS up -d --no-build --force-recreate $GPU_SCALE $AGENT_SCALE || _up_rc=$?
        if [ "${_up_rc:-0}" -ne 0 ] && [ "${_up_rc:-0}" -ne "$NOO_EXIT_STACK_PARTIAL" ]; then exit "$_up_rc"; fi
        # The guard only heals services this invocation manages; a Created
        # container outside that set (a stale leftover, or the scaled-out
        # exporter) is removed, not started.
        NOO_CREATED_GUARD_SERVICES="$(printf '%s\n' "$ACTIVE_SVCS" | tr '\n' ' ')" \
            noo_created_guard $(docker compose $COMPOSE_FILES $PROFILE_ARGS ps -aq)
        [ "${_up_rc:-0}" -eq "$NOO_EXIT_STACK_PARTIAL" ] && exit "$NOO_EXIT_STACK_PARTIAL"
    else
        docker compose $COMPOSE_FILES $PROFILE_ARGS restart || {
            _rc=$?
            ui_close_failed "compose failed (exit $_rc) restarting the stack"
            exit "$_rc"
        }
    fi
else
    ui_phase "Stack"
    # Names resolve against the services compose renders for THIS profile and
    # overlay set; the status table's spelling (evolve) and add-on keys work,
    # an unknown name is a refusal that lists the valid ones.
    # shellcheck disable=SC2086
    if ! VALID_SVCS="$(restart_valid_services $COMPOSE_FILES $PROFILE_ARGS)"; then
        _rc=$?
        ui_close_failed "could not list the compose services"
        compose_report_error "$_rc"
        exit 1
    fi
    # shellcheck disable=SC2086
    restart_resolve_all "$VALID_SVCS" $COMPOSE_FILES $PROFILE_ARGS -- "${SERVICES[@]}" || exit 1
    SERVICES=("${RESOLVED_SERVICES[@]}")
    if printf '%s\n' "${SERVICES[@]}" | grep -qx gateway; then
        noo_prepare_gateway_data_dirs
    fi
    ui_step "Restarting ${SERVICES[*]}"
    if [ "$FORCE_RECREATE" != true ]; then
        # A plain restart keeps the old image: after `noo addons upgrade` the
        # pin moved but the container did not. Recreate those (--no-deps).
        # shellcheck disable=SC2086
        DRIFTED="$(restart_image_drift $COMPOSE_FILES $PROFILE_ARGS -- "${SERVICES[@]}" | tr '\n' ' ')"
        if [ -n "${DRIFTED// /}" ]; then
            ui_note "pin moved: ${DRIFTED% }still on an older image - recreating instead of restarting"
            FORCE_RECREATE=true
        fi
    fi
    RESTART_RC=0
    if [ "$FORCE_RECREATE" = true ]; then
        # --no-deps: "restart THESE" must not recreate half the stack via
        # depends_on; --no-build: a restart never compiles anything.
        restart_require_lock || exit 1
        check_bind_sources --no-deps "${SERVICES[@]}" || exit 1
        docker compose $COMPOSE_FILES $PROFILE_ARGS up -d --no-build --no-deps --force-recreate "${SERVICES[@]}" || RESTART_RC=$?
        if [ "$RESTART_RC" -eq 0 ]; then
            NOO_CREATED_GUARD_SERVICES="${SERVICES[*]}" \
                noo_created_guard $(docker compose $COMPOSE_FILES $PROFILE_ARGS ps -aq "${SERVICES[@]}")
        fi
    else
        docker compose $COMPOSE_FILES $PROFILE_ARGS restart "${SERVICES[@]}" || RESTART_RC=$?
    fi
    if [ "$RESTART_RC" -ne 0 ]; then
        ui_close_failed "compose failed (exit $RESTART_RC) restarting ${SERVICES[*]}"
        echo "       valid services: $(printf '%s\n' "$VALID_SVCS" | tr '\n' ' ')" >&2
        exit "$RESTART_RC"
    fi
fi

ui_close_done "Services restarted"
ui_note "noo stack status shows the containers"
