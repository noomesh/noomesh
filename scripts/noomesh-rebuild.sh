#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Rebuild and restart Mesh services

set -e

# Single-flight across every compose-mutating entry point (an earlier change —
# the 2026-07-31 outage was two recreate paths interleaving).
source "$(dirname "${BASH_SOURCE[0]}")/lib-compose-lock.sh"
# Presentation helpers (ui_step/ui_kv/…) follow
# noo-cli/CLI_STYLE_GUIDE.md. Sourced HERE, before ANY caller: the
# dist/digest block and the rebuild EXIT trap both call ui_* well
# above where this used to sit, and under `set -e` an undefined
# helper is exit 127 (host8, 2026-09-03: `noo upgrade --all` died
# with "ui_kv: command not found" the moment a stack.lock existed).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-ui.sh"
acquire_compose_lock || exit 1


# Cleanup runs on EXIT regardless of build success/failure. Failed builds
# leave orphaned cache layers behind (each retry of a 14GB pip step stacks
# another 14GB), so the cleanup is more important on failure than success.
_cleanup_build_artifacts() {
    local code=$?
    echo ""
    # Dangling images (untagged leftovers from previous builds) — always safe.
    docker image prune -f 2>/dev/null || true

    if [ "$code" -ne 0 ]; then
        # FAILED build: nuke ALL build cache. Failed builds leave orphaned
        # cache layers behind (each retry of a 14GB pip/cargo step stacks
        # another 14GB), so the aggressive `-a` is justified here.
        ui_step "Pruning build artifacts (build failed — full clean)"
        docker builder prune -af 2>/dev/null || true
    else
        # SUCCESS: keep recent cache (esp. deps-base, ~5GB site-packages)
        # so the next no-op rebuild is ~30s instead of ~12min. Bound the
        # cache size so it can't grow unbounded across many rebuilds.
        # Override floor with NOO_BUILD_CACHE_KEEP (e.g. "30GB").
        local keep="${NOO_BUILD_CACHE_KEEP:-20GB}"
        ui_step "Pruning build artifacts (keeping up to $keep)"
        # buildx renamed --keep-storage to --reserved-space (same meaning:
        # disk always allowed to keep for cache). The old name still works on
        # buildx >= 0.31 but prints a deprecation warning on every rebuild,
        # and will eventually stop working.
        #
        # Detected rather than pinned, because this script runs on the
        # controller, on the self-hosted CI runner, and on worker hosts —
        # which do not upgrade together. `2>/dev/null` on the prune itself
        # would have hidden a hard failure of the old flag just as it hid the
        # warning, so the choice is made before the call, not discovered by it.
        local keep_flag="--keep-storage"
        if docker builder prune --help 2>/dev/null | grep -q -- '--reserved-space'; then
            keep_flag="--reserved-space"
        fi
        docker builder prune -f "$keep_flag" "$keep" 2>/dev/null || true
    fi
    # Orphaned anonymous volumes (created by failed/recreated containers
    # that never got `docker compose down -v`'d). Named volumes are protected.
    docker volume prune -f 2>/dev/null || true
    # Truncate live container logs that have already grown past the per-file
    # cap. Compose's logging.options.max-size only kicks in for *new* writes;
    # existing oversized files don't auto-rotate. Zero anything > 60MB so
    # the underlying filesystem can reclaim the space on next compact.
    if command -v find >/dev/null 2>&1; then
        find /var/lib/docker/containers -maxdepth 2 -name '*-json.log' \
             -size +60M -exec sh -c '> "$1"' _ {} \; 2>/dev/null || true
    fi
}
trap _cleanup_build_artifacts EXIT


# fu 46: derive the per-instance namespace (project, container prefix,
# network, ports) before any compose invocation — stop/status/logs must
# address the same project start created.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-instance.sh"

DEFAULT_PROFILE="controller"

# Auto-include override file if it exists (user directory mounts)

# ── Persisted install mode (warn on build, refuse the recreate) ────────
# Rebuild is inherently a DEV operation: it compiles images from the local
# source tree. On a dist install (NOO_INSTALL_MODE=dist in .env) a bare
# `noo stack start` deploys the released GHCR images, so nothing built here
# is used until the mode changes or a one-off `noo stack start --dev`.
# Building ahead of a mode switch is legitimate — warn, don't block. What
# is NOT legitimate is this script's Step 3 then recreating the LIVE stack
# under dev image names and live dev bind-mounts (#43b): on dist, the
# recreate is refused below, not just warned about.
DIST_ACTIVE=0
if [ -z "${NOO_INSTALL_MODE:-}" ] && [ -f ".env" ]; then
    NOO_INSTALL_MODE="$(grep -E '^[[:space:]]*NOO_INSTALL_MODE=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
fi
if [ "${NOO_INSTALL_MODE:-dev}" = "dist" ]; then
    DIST_ACTIVE=1
    echo "WARNING: NOO_INSTALL_MODE=dist — this install runs released images."
    echo "         Images rebuilt here will NOT be used until you run"
    echo "         'noo stack start --dev' (one-off) or change NOO_INSTALL_MODE in .env."
fi

# ── Add-ons ────────────────────────────────────────────────────────────
# Same `addons:` map, same code as noomesh-start.sh — sourced, not mirrored.
# The comment below used to say "MUST MIRROR noomesh-start.sh EXACTLY", and
# the paragraph after it documents what happened when it did not.
# `noo_bin` only (function def, no side effects) — lib-addons.sh below needs
# it, and this script's own `load_config` (via lib-config.sh) is sourced
# later. Sourcing twice is harmless — see noomesh-start.sh's comment.
. "$(dirname "$0")/lib-config.sh"
. "$(dirname "$0")/lib-addons.sh"
addons_guard_retired_flags
warn_retired_env_keys

if addon_on evolve 0; then
    PRO_COMPOSE="$(addons_evolve_overlay)"
    if [ -n "$PRO_COMPOSE" ]; then
        # `--profile pro` now comes from addon_compose_overlay_args (one home).
        echo "Add-on evolve: ENABLED (noo-evolve via $PRO_COMPOSE)"
    else
        echo "addons.evolve is true but no evolve compose overlay was found (set NOO_EVOLVE_PATH to the noo-evolve checkout) — starting without it"
    fi
fi

# ── Trellion worker pool (always on) ───────────────────────────────────
# The add-on decision itself now comes from lib-addons.sh, shared with
# noomesh-start.sh, because "MUST MIRROR noomesh-start.sh EXACTLY" is what
# this comment used to say and the copies drifted anyway: rebuild kept gating
# on a flag start.sh had stopped reading, the two disagreed about which
# container owns the memory Alembic env, and the disagreement stayed silent
# until the gateway restarted.
#
# The three exports below are still this file's own and still not optional.
#
# Concretely, on a .env without the obsolete flag (which start.sh actively
# invites, since it prints "NOO_TRELLION_ENABLED is obsolete and ignored"):
# rebuild leaves NOO_MIGRATIONS_ENVS unset -> the entrypoint resolves it to
# "all" -> the mesh env is handed to the Rust runner -> what remains is
# "memory" -> memory_cfg() does `import trellion.db`, which the gateway
# image deliberately does not carry -> ImportError -> exit 1 -> crash loop.
# `noo stack start` was fine throughout, so this reproduces only on rebuild.
#
# The three knobs are not optional; see the same block in start.sh for what
# each one does.
export NOO_WORKER_SUPERVISOR="external"
# NOO_MCP_GATEWAY_HOST_PORT: owned by lib-instance.sh since the MCP hub
# cutover (gateway holds host 3100). The stale 3199 export that used to
# sit here would have re-parked the LIVE MCP door on every rebuild and
# collided with trellion's parked mapping.
export NOO_MIGRATIONS_ENVS="${NOO_MIGRATIONS_ENVS:-mesh}"
# Trellion add-on — the same `addon_on` the launcher uses, from lib-addons.sh.
TRELLION_ON=""
if addon_on trellion 1; then
    TRELLION_ON=1
    echo "Trellion add-on: enabled (also rebuilding the noo-trellion image)"
else
    # worker rides the controller profile (phase 5). The overlay is not
    # composed when the add-on is off, so a container from a previous
    # ENABLED run is not touched by `up` — opting out on a live stack must
    # actively stop it (live rehearsal round 2, 2026-08-13).
    TRELLION_STOP_ON_OFF=1
    echo "Trellion add-on: DISABLED (building the slim noo-worker instead)"
fi

# Trellion Intelligent tier — same contract as noomesh-start.sh
#: opt-in, default OFF. No image of its own to rebuild
# (it runs the trellion image with NOO_WORKER_SURFACES=ml-intel); the
# switch only decides whether the profile is selected so the container
# gets recreated alongside the rest.
# Resolved through the shared helper, like trellion above. This block used
# to parse NOO_TRELLION_INTEL_ENABLED out of .env by hand — a flag
# addons_guard_retired_flags refuses to START on — so rebuild always saw the
# intel add-on as OFF while start saw the noomesh.yaml declaration.
# Since an earlier change the tier is an OVERLAY composed by lib-compose.sh
# when the add-on is on; nothing to select here beyond the opt-out stop.
if ! addon_on trellion_intel 0; then
    TRELLION_INTEL_STOP_ON_OFF=1
fi

# ── Voice switch (STT + TTS) ───────────────────────────────────────────
# Mirrors noomesh-start.sh: when the opt-in voice containers (whisper STT
# + piper TTS) are enabled, rebuilds must build those images too. Their
# OVERLAY is composed by lib-compose.sh, so compose can
# see them; provider selection stays in NOO_STT_* / NOO_TTS_*.
VOICE_ON=""
if addon_on voice 0; then
    VOICE_ON=1
    echo "Voice: ENABLED (also rebuilding the noo-whisper + noo-piper images)"
else
    VOICE_STOP_ON_OFF=1
fi

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ui_phase "Rebuild"

GATEWAY_ENGINE="${GATEWAY_ENGINE:-rust}"
NODE_ENGINE="${NODE_ENGINE:-go}"

# Sync local Python dependencies if running in a venv or editable install
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Resolve the cluster-plane bind address (auto-detect tailnet IP) before any up.
# shellcheck source=scripts/lib-bind-addr.sh
source "$SCRIPT_DIR/lib-bind-addr.sh"
resolve_bind_addr
resolve_location
# Load secrets (no-op unless NOO_SECRETS_BACKEND=sops; fails closed on decrypt error).
source "$SCRIPT_DIR/lib-secrets.sh"
load_secrets || { echo "aborting: secrets load failed" >&2; exit 1; }
# Deployment config: noomesh.yaml `compose_env:` -> environment, so
# compose can interpolate ${VAR} from something other than .env.
# Non-fatal: config has compose-side defaults, and a missing knob must
# not block a launch the way a missing credential does.
source "$SCRIPT_DIR/lib-config.sh"
load_config || echo "warning: config load reported problems (continuing)" >&2
# Refuse an `up` whose bind-mount sources are missing or the wrong type.
source "$SCRIPT_DIR/lib-bind-sources.sh"
# ...and a start whose enabled systems lack their credentials.
check_system_credentials || exit 1
# ...and an install whose secrets sit in plaintext .env.
check_secrets_at_rest || exit 1

if [ -f "$PROJECT_ROOT/pyproject.toml" ]; then
    ui_step "Syncing local Python dependencies"
    pip install -q -e "$PROJECT_ROOT" 2>/dev/null && \
        ui_done "Local deps synced" || \
        ui_warned "Local dep sync skipped (no writable Python env)"
fi

# Custom services (ones we build from source)
CUSTOM_SERVICES="gateway node-agent nvidia-exporter postgres"
if [ -n "$TRELLION_ON" ]; then
    CUSTOM_SERVICES="$CUSTOM_SERVICES trellion"
fi
if [ -n "$VOICE_ON" ]; then
    CUSTOM_SERVICES="$CUSTOM_SERVICES whisper piper"
fi

# Map service names to required Docker Compose profiles
service_profile() {
    case $1 in
        vllm)         echo "gpu-tier1" ;;
        vllm-secondary) echo "vllm-secondary" ;;
        airllm)       echo "gpu-tier1" ;;
        llamacpp)     echo "gpu-tier2" ;;
        ollama)       echo "gpu-tier2" ;;
        tei)          echo "controller" ;;
        tei-gpu)      echo "gpu-tier2" ;;
        *)            echo "" ;;
    esac
}

# Detect GPU tier: Tier 1 (>=10GB VRAM), Tier 2 (4-10GB), or none
detect_gpu_tier() {
    # Method 1: nvidia-smi on host
    if command -v nvidia-smi &>/dev/null; then
        local vram_mb
        vram_mb=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')
        # Guard: nvidia-smi can print an error to stdout (e.g. "Failed to
        # initialize NVML: GPU access blocked by the operating system") which
        # would otherwise reach the arithmetic below and abort the script with
        # a syntax error. Only treat a purely-numeric value as a VRAM reading;
        # anything else falls through to the container-based detection.
        if [[ "$vram_mb" =~ ^[0-9]+$ ]] && [ "$vram_mb" != "0" ]; then
            local vram_gb=$(( vram_mb / 1024 ))
            if [ "$vram_gb" -ge 10 ]; then
                echo "gpu-tier1"
                return
            elif [ "$vram_gb" -ge 4 ]; then
                echo "gpu-tier2"
                return
            fi
        fi
    fi
    # Method 2: infer from running/existing GPU backend containers
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^noo-vllm$'; then
        echo "gpu-tier1"
        return
    fi
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qE '^noo-(ollama|llamacpp)$'; then
        echo "gpu-tier2"
        return
    fi
    echo ""
}

# Detect running COMPOSE-OWNED GPU backend containers to include in rebuild.
# Placement-managed backends (node-agent reconciler, no compose config-hash
# label) must NOT be dragged into compose's up — the two owners then race
# over the container name and the rebuild dies on the conflict (PR #67).
detect_running_backends() {
    local backends=""
    for svc in vllm ollama llamacpp airllm; do
        if docker inspect "noo-${svc}" \
            --format '{{index .Config.Labels "com.docker.compose.config-hash"}}' \
            2>/dev/null | grep -q .; then
            backends="$backends $svc"
        fi
    done
    echo "$backends"
}

# Parse arguments
PROFILE=""
EXTRA_PROFILES=()
SERVICES=()
PULL_IMAGES=true
START_STACK=true
NO_CACHE=""

# The file list has ONE home.
. "$(dirname "$0")/lib-compose.sh"
COMPOSE_FILES="$(compose_file_args .)"
# Composed add-on overlays read NOO_ADDON_IMAGE_<NAME> (no tag fallback):
# a rebuild is a dev start, so they get the dev build's names here
# (lib-dist.sh require_addon_pins; DIST_MODE is never 1 in a rebuild).
DIST_MODE=0 require_addon_pins || exit 1

while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            # Known extra profiles are additive (don't replace base profile)
            case "$2" in
                vllm-secondary|ollama|llamacpp|gpu-tier2)
                    EXTRA_PROFILES+=("$2") ;;
                *)
                    PROFILE="$2" ;;
            esac
            shift 2
            ;;
        --profile=*)
            _prof="${1#*=}"
            case "$_prof" in
                vllm-secondary|ollama|llamacpp|gpu-tier2)
                    EXTRA_PROFILES+=("$_prof") ;;
                *)
                    PROFILE="$_prof" ;;
            esac
            shift
            ;;
        --no-pull)
            PULL_IMAGES=false
            shift
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --quick|-q)
            # Quick mode: just restart gateway to pick up mounted source changes
            # No Docker build needed — source is volume-mounted at ./src:/app/src
            ui_step "Quick restart (no build)"
            docker compose $COMPOSE_FILES restart gateway
            ui_done "Gateway restarted — picked up source changes"
            echo ""
            ui_note "for auto-reload on save, set DEV_MODE=true in .env"
            exit 0
            ;;
        --no-start)
            START_STACK=false
            shift
            ;;
        all)
            # "all" means all custom services
            SERVICES=($CUSTOM_SERVICES)
            shift
            ;;
        *)
            SERVICES+=("$1")
            shift
            ;;
    esac
done

# Default to all custom services + any running GPU backends
if [ ${#SERVICES[@]} -eq 0 ]; then
    RUNNING_BACKENDS=$(detect_running_backends)
    SERVICES=($CUSTOM_SERVICES $RUNNING_BACKENDS)
    ui_kv "Scope" "custom services + running backends"
fi

# Default profile
if [ -z "$PROFILE" ]; then
    PROFILE="$DEFAULT_PROFILE"
fi

# Auto-detect extra profiles needed for requested services
PROFILE_ARGS="--profile $PROFILE"

# Auto-detect GPU tier on controller and add the inference profile
if [ "$PROFILE" = "controller" ]; then
    GPU_TIER=$(detect_gpu_tier)
    if [ -n "$GPU_TIER" ]; then
        PROFILE_ARGS="$PROFILE_ARGS --profile $GPU_TIER"
        if [ "$GPU_TIER" = "gpu-tier1" ]; then
            ui_kv "GPU" "${GPU_TIER} — tier 1 (>=10GB VRAM) → GPU monitoring + TEI (CPU)"
        else
            ui_kv "GPU" "${GPU_TIER} — tier 2 (4-10GB VRAM) → Ollama + TEI (CPU)"
        fi
        echo "  LLM backends are placement-managed: noo cluster place <node> vllm <model>"
    else
        ui_kv "GPU" "none detected → TEI (CPU) only, inference via cloud fallback"
    fi
fi

# Append extra profiles (--profile vllm-secondary, etc.)
for ep in "${EXTRA_PROFILES[@]}"; do
    PROFILE_ARGS="$PROFILE_ARGS --profile $ep"
done
# Profiles the operator enabled in COMPOSE_PROFILES (lib-config.sh).
PROFILE_ARGS="$PROFILE_ARGS $(operator_profile_args)"
derive_profile_env

for svc in ${SERVICES[@]}; do
    p=$(service_profile "$svc")
    if [ -n "$p" ]; then
        PROFILE_ARGS="$PROFILE_ARGS --profile $p"
    fi
done

# evolve profile (set by the addons map above; empty when off)



# Auto-adjust GPU memory when colocating multiple inference backends.
# Counts active GPU profiles and splits memory proportionally.
GPU_BACKENDS=1  # primary vLLM always counts
if echo "$PROFILE_ARGS" | grep -q "vllm-secondary"; then
    GPU_BACKENDS=$((GPU_BACKENDS + 1))
fi
# Ollama manages its own GPU memory but still needs headroom
if echo "$PROFILE_ARGS" | grep -q "gpu-tier2\|ollama"; then
    GPU_BACKENDS=$((GPU_BACKENDS + 1))
fi

if [ $GPU_BACKENDS -gt 1 ]; then
    # Split GPU: primary gets 50%, secondaries share the rest
    PRIMARY_UTIL="0.50"
    PRIMARY_CTX=4096
    ui_kv "GPU colocate" "${GPU_BACKENDS} backends sharing the GPU"
    echo "  Primary vLLM: ${PRIMARY_UTIL} GPU util, ${PRIMARY_CTX} max context"
    if echo "$PROFILE_ARGS" | grep -q "vllm-secondary"; then
        echo "  Secondary vLLM: ${VLLM2_GPU_MEM_UTIL:-0.35} GPU util (${VLLM2_MODEL:-not set})"
    fi
    export GPU_MEM_UTIL="$PRIMARY_UTIL"
    export VLLM_MAX_MODEL_LEN="$PRIMARY_CTX"
fi

ui_kv "Services" "${SERVICES[*]}"
ui_kv "Profiles" "${PROFILE_ARGS}"
echo ""

# Step 1: Pull latest official images
if [ "$PULL_IMAGES" = true ]; then
    echo ""
    ui_step "Pulling official images"
    docker compose $COMPOSE_FILES $PROFILE_ARGS pull --ignore-pull-failures --ignore-buildable
    echo ""
fi

# Step 2: Separate buildable vs pre-built services
BUILD_SERVICES=()
PULL_SERVICES=()
for svc in ${SERVICES[@]}; do
    if echo "$CUSTOM_SERVICES" | grep -qw "$svc"; then
        BUILD_SERVICES+=("$svc")
    else
        PULL_SERVICES+=("$svc")
    fi
done

# Does anything in this build set sit on top of the shared Python bases?
#
# Two tiers since an earlier change: deps-core (non-ML — sandbox and worker
# FROM it) and deps-base (ML — FROM deps-core, trellion
# FROMs it). A deps-base consumer therefore needs BOTH built, in order.
#
# Computed HERE, before the headroom gate, because both decisions depend on
# it: the headroom gate's whole premise is "a deps-base rebuild is the memory
# hog" (torch/CUDA resolution lives in the ML tier — a deps-core build is a
# light pip install), so if deps-base is not going to be built, killing vLLM
# to make room for it is pure waste — which is the exact mistake the headroom
# comment already records having made once.
#
# Expressed as CONSUMERS, not as service names. Trellion is the only one this
# script can currently build (sandbox and worker are not in
# CUSTOM_SERVICES, and sandbox-base is FROM python:3.12-slim), but adding
# either to CUSTOM_SERVICES later must not silently reintroduce a skip.
# Keep in step with the Dockerfiles:
#   grep -l '^FROM ${DEPS_CORE}\|^FROM ${DEPS_BASE}' docker/Dockerfile.*
DEPS_CORE_CONSUMERS="sandbox worker"
DEPS_BASE_CONSUMERS="trellion"
_needs_deps_core=0
_needs_deps_base=0
for _svc in "${BUILD_SERVICES[@]}"; do
    if echo " $DEPS_CORE_CONSUMERS " | grep -qw "$_svc"; then
        _needs_deps_core=1
    fi
    if echo " $DEPS_BASE_CONSUMERS " | grep -qw "$_svc"; then
        # deps-base is FROM deps-core, so its consumers need both tiers.
        _needs_deps_base=1
        _needs_deps_core=1
    fi
done

# Build custom images
if [ ${#BUILD_SERVICES[@]} -gt 0 ]; then
    # Free build headroom by removing local inference backends BEFORE building
    # — but ONLY when a build genuinely risks OOM. The memory hog is the
    # deps-base rebuild (torch/CUDA, ~8GB peak); with a loaded vLLM (~4.5GB
    # RAM) on a 15GB WSL2 VM that OOMs the whole VM (2026-07-11: three
    # rebuilds died this way). A gateway/sandbox/node-agent build with a
    # CACHED deps-base only runs a Rust/Go compile (~2-4GB) that fits
    # alongside vLLM — killing the backend there was pure waste (every gchat
    # test tonight cycled vLLM for a build that didn't need the room).
    #
    # Gate: remove only when (a) an inference image is itself being built, or
    # (b) deps-base will do a heavy (re)build — approximated as image ABSENT
    # or --no-cache — or (c) free RAM measured WITH backends still loaded is
    # below the build peak (direct "will a build fit alongside vLLM?" probe).
    # Force either way: NOO_REBUILD_KEEP_BACKENDS=1 keeps,
    # NOO_REBUILD_FREE_BACKENDS=1 removes. REMOVE not stop — BackendManager
    # raw-`docker run` containers (no compose labels) would squat the name.
    _need_headroom=0
    _reason=""
    if echo " ${BUILD_SERVICES[*]} " | grep -qE ' (vllm|llamacpp|airllm|ollama|deps-base)'; then
        _need_headroom=1; _reason="inference/deps-base image in build set"
    # The next two reasons are ONLY about deps-base, so they are moot when
    # nothing in this build set is FROM it — a gateway-only build does not
    # touch deps-base at all now, and killing vLLM "in case deps-base
    # rebuilds" would be the same waste this gate was written to stop.
    elif [ "$_needs_deps_base" = "1" ] && [ -n "${NO_CACHE:-}" ]; then
        _need_headroom=1; _reason="--no-cache (deps-base will rebuild)"
    elif [ "$_needs_deps_base" = "1" ] && \
         ! docker image inspect pai-assistant/deps-base:latest >/dev/null 2>&1; then
        _need_headroom=1; _reason="deps-base image absent (first heavy build)"
    else
        # deps-base cached → only the ~4GB Rust/Go compile remains. Keep
        # backends if free RAM already covers it alongside the loaded model.
        _free_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
        _floor=${NOO_REBUILD_MIN_FREE_MB:-4500}
        if [ "${_free_mb:-0}" -lt "$_floor" ]; then
            _need_headroom=1; _reason="low free RAM ${_free_mb}MB < ${_floor}MB floor"
        fi
    fi
    if [ "${NOO_REBUILD_KEEP_BACKENDS:-0}" = "1" ]; then _need_headroom=0; _reason="NOO_REBUILD_KEEP_BACKENDS=1"; fi
    if [ "${NOO_REBUILD_FREE_BACKENDS:-0}" = "1" ]; then _need_headroom=1; _reason="NOO_REBUILD_FREE_BACKENDS=1"; fi

    if [ "$_need_headroom" = "1" ]; then
        RUNNING_BACKENDS=$(docker ps --format '{{.Names}}' 2>/dev/null \
            | grep -E '^noo-(vllm|ollama|llamacpp)' || true)
        if [ -n "$RUNNING_BACKENDS" ]; then
            ui_step "Removing inference backends for build headroom ($_reason): $RUNNING_BACKENDS"
            echo "   (they come back via the reconciler / on the next inference request)"
            echo "$RUNNING_BACKENDS" | xargs -r docker rm -f >/dev/null 2>&1 || true
        fi
    else
        ui_done "Keeping inference backends up (${_reason:-deps-base cached, ample RAM})"
    fi

    echo ""
    ui_step "Building custom images: ${BUILD_SERVICES[*]}"
    # Bust Rust/Go source cache: write a hash file into the source dirs so the
    # COPY layer sees a changed file even when WSL2/NTFS checksums are stale.
    SOURCE_HASH=$(find gateway-rust/src -name '*.rs' -exec md5sum {} + 2>/dev/null | sort | md5sum | cut -c1-12)
    echo "${SOURCE_HASH:-$(date +%s)}" > gateway-rust/src/.build-hash 2>/dev/null || true
    GO_HASH=$(find node-agent-go -name '*.go' -exec md5sum {} + 2>/dev/null | sort | md5sum | cut -c1-12)
    echo "${GO_HASH:-$(date +%s)}" > node-agent-go/.build-hash 2>/dev/null || true

    # Build the shared Python deps-base FIRST — but ONLY when something in
    # this build set is actually FROM it.
    #
    # WHICH QUESTION THIS ASKS MATTERS. It is NOT "has deps-base changed?" —
    # that stays BuildKit's call, always, for the reason in the next
    # paragraph. It is "does anything we are building use deps-base at all?"
    # When the answer is yes, the build below is invoked exactly as before and
    # BuildKit decides; only a build set with NO consumer skips it.
    #
    # The distinction is the whole point. A previous version of this block
    # tried to second-guess BuildKit by checking pyproject.toml mtime. That
    # heuristic missed changes to noo-trellion source (a sibling repo, COPY'd
    # in via `--build-context trellion=...`) and silently skipped deps-base
    # rebuilds when only trellion changed — a real prod outage on 2026-04-29.
    # Nothing here revisits that: if trellion is in the build set, deps-base
    # is built unconditionally and BuildKit does the thinking.
    #
    # What changed is the gateway. It used to be FROM deps-base; since
    # an earlier change it is FROM dhi.io/rust -> dhi.io/python and carries
    # no Python dependency stack at all. So `noo stack rebuild gateway` was
    # building a multi-GB Python/CUDA base that the thing being built has not
    # used since. The comment here still claimed the gateway was downstream of
    # it, which is how it survived that change.
    #
    # The list is deliberately expressed as CONSUMERS rather than "trellion",
    # even though trellion is the only one this script can currently build
    # (sandbox and worker are not in CUSTOM_SERVICES; sandbox-base
    # is FROM python:3.12-slim). Adding either to CUSTOM_SERVICES later must
    # not silently reintroduce the skip. Keep in step with the Dockerfiles:
    #   grep -l '^FROM ${DEPS_CORE}\|^FROM ${DEPS_BASE}' docker/Dockerfile.*
    #
    # Order matters: deps-core first (deps-base is FROM it). Compose does
    # not order builds by FROM — this script is what does.
    if [ "$_needs_deps_core" = "1" ]; then
        ui_step "Ensuring deps-core is current (BuildKit handles the cache)"
        docker compose $COMPOSE_FILES --profile build-only build ${NO_CACHE:-} deps-core
    else
        ui_note "skipping deps-core — nothing in this build set is FROM it" \
             "(${BUILD_SERVICES[*]})"
    fi
    if [ "$_needs_deps_base" = "1" ]; then
        ui_step "Ensuring deps-base is current (BuildKit handles the cache)"
        docker compose $COMPOSE_FILES --profile build-only build ${NO_CACHE:-} deps-base
    else
        ui_note "skipping deps-base — nothing in this build set is FROM it" \
             "(${BUILD_SERVICES[*]})"
    fi

    # Sandbox-capability base image (noo-sandbox-base:latest) — default
    # container.image for capability manifests. Cheap (python:3.12-slim +
    # non-root user); BuildKit no-ops when unchanged. Ship to workers with
    # `noo cluster sync-images`.
    ui_step "Ensuring sandbox-base is current"
    docker compose $COMPOSE_FILES --profile build-only build ${NO_CACHE:-} sandbox-base

    # --parallel builds independent services concurrently. Combined with the
    # uv + cargo cache mounts in the Dockerfiles + the shared deps-base,
    # source-only rebuilds drop from minutes to seconds.
    docker compose $COMPOSE_FILES build --parallel ${NO_CACHE:-} ${BUILD_SERVICES[@]}
    # Cleanup happens via the EXIT trap (handles both success and failure).
    echo ""
fi

# Show disk usage summary
echo ""
ui_step "Docker disk usage"
docker system df 2>/dev/null
echo ""

# Pull latest for pre-built services (vllm, ollama, etc.)
if [ ${#PULL_SERVICES[@]} -gt 0 ]; then
    ui_step "Pulling latest images for ${PULL_SERVICES[*]}"
    docker compose $COMPOSE_FILES $PROFILE_ARGS pull ${PULL_SERVICES[@]} 2>/dev/null || true
    echo ""
fi

# Step 3: Restart services
if [ "$START_STACK" = true ] && [ "$DIST_ACTIVE" = 1 ]; then
    # #43b: recreating here would put the whole stack on dev image names
    # with live dev bind-mounts, silently replacing the released deploy.
    echo ""
    echo "NOO_INSTALL_MODE=dist — images were (re)built but the running stack was NOT touched."
    echo "To run what you just built:   noo stack start --dev   (one-off)"
    echo "To redeploy released images:  noo stack restart --force <service>"
    START_STACK=false
fi
if [ "$START_STACK" = true ]; then
    ui_phase "Stack"
    ui_step "Starting the full stack"

    # Force recreate the requested services. (The ngrok sidecar used to be
    # recreated alongside the gateway; it no longer exists — access is
    # tailnet/LAN only.)
    RECREATE_SERVICES="${SERVICES[@]}"

    echo "Recreating services: ${RECREATE_SERVICES}"
    # shellcheck disable=SC2086
    check_bind_sources ${RECREATE_SERVICES} || exit 1
    docker compose $COMPOSE_FILES $PROFILE_ARGS up -d --force-recreate ${RECREATE_SERVICES}

    # Opt-out enforcement — same as noomesh-start.sh.
    if [ "${TRELLION_STOP_ON_OFF:-}" = "1" ]; then
        docker compose $COMPOSE_FILES -f "$(addons_trellion_overlay)" stop trellion 2>/dev/null || true
    fi
    if [ "${TRELLION_INTEL_STOP_ON_OFF:-}" = "1" ]; then
        docker compose $COMPOSE_FILES -f "$(addons_trellion_intel_overlay)" stop trellion-intel 2>/dev/null || true
    fi
    if [ "${VOICE_STOP_ON_OFF:-}" = "1" ]; then
        docker compose $COMPOSE_FILES -f "$(addons_voice_overlay)" stop whisper piper 2>/dev/null || true
    fi

    # Ensure all other services in the active profiles are running.
    # --scale node-agent=0 for the same reason as noomesh-start.sh: the
    # containerised agent cannot work post-fu-43 and its :8081 collides with
    # the host agent, killing this blanket `up` partway through. Only the
    # BLANKET up is scaled — an explicit `noo stack rebuild node-agent` above
    # still honours a deliberate request for the containerised shape.
    echo "Ensuring all services are running..."
    check_bind_sources --skip node-agent || exit 1
    docker compose $COMPOSE_FILES $PROFILE_ARGS up -d --scale node-agent=0

    # Pre-pull Ollama inference model if Ollama is running
    if docker ps --format '{{.Names}}' | grep -q '^noo-ollama$'; then
    # Default gemma4:e2b, announced when it fires (see
    # noomesh-start.sh). Only for installs
    # that already have SOME chat model loaded (embedders do not count) — a fresh container (nothing
    # pulled yet, e.g. an onboard that skipped the model step) gets no
    # surprise multi-GB download; see noomesh-start.sh for the same fix.
    if [ -z "${OLLAMA_MODEL:-}" ]; then
        if docker exec noo-ollama ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' \
            | grep -vE "^(${PAGEINDEX_EMBEDDING_MODEL:-}|${EMBEDDING_MODEL:-})$|embed|harrier|minilm|bge" | grep -q .; then
            OLLAMA_MODEL="gemma4:e2b"
            ui_note "no OLLAMA_MODEL declared — using the default (gemma4:e2b)"
        else
            ui_note "no chat model installed — skipping the default pull; pick one: noo models recommended / noo models pull <model>"
        fi
    fi
    if [ -n "${OLLAMA_MODEL:-}" ] && ! docker exec noo-ollama ollama list 2>/dev/null | grep -q "$OLLAMA_MODEL"; then
            echo ""
            ui_step "Pulling inference model $OLLAMA_MODEL into Ollama (background)"
            docker exec noo-ollama ollama pull "$OLLAMA_MODEL" &
            OLLAMA_PULL_PID=$!
        fi
    fi

    # Wait for vLLM to be healthy (model download + load + compile)
    if docker ps --format '{{.Names}}' | grep -q '^noo-vllm$'; then
        echo ""
        ui_step "Waiting for vLLM to load the model (2–5 min)"
        VLLM_DEADLINE=$((SECONDS + 600))  # 10 min max (includes potential model download)
        VLLM_READY=false
        # The listener is always TLS and requires a client certificate
        # (--ssl-cert-reqs 2); the image carries python3, not curl — the
        # old `curl -sfk` could never have answered. Probe from inside with
        # the container's own leaf, CA-verified (a self-check, nothing granted).
        VLLM_PROBE="import ssl,urllib.request; ctx=ssl.create_default_context(cafile='/app/pki/ca.crt'); ctx.load_cert_chain('/app/pki/services/vllm/service.crt','/app/pki/services/vllm/service.key'); urllib.request.urlopen('https://localhost:8000/health',context=ctx,timeout=5)"

        while [ $SECONDS -lt $VLLM_DEADLINE ]; do
            # Check container is still running (not crash-looping)
            if ! docker ps --format '{{.Names}}' | grep -q '^noo-vllm$'; then
                ui_warned "vLLM container stopped — checking its logs"
                docker logs noo-vllm --tail 10 2>&1 | grep -iE "error|ValueError|killed|OOM" || true
                ui_note "fix the issue and rebuild, or check: docker logs noo-vllm"
                break
            fi

            # Probe health endpoint
            if docker exec noo-vllm python3 -c "$VLLM_PROBE" >/dev/null 2>&1; then
                VLLM_READY=true
                break
            fi

            # Show progress from vLLM logs (loading shards, compiling, etc.)
            PROGRESS=$(docker logs noo-vllm --tail 3 2>&1 | grep -oE '(Loading.*\|.*Completed|Dynamo|torch.compile|Starting vLLM|INFO.*Serving)' | tail -1)
            if [ -n "$PROGRESS" ]; then
                ui_note "${PROGRESS}"
            fi
            sleep 10
        done

        if [ "$VLLM_READY" = true ]; then
            # Warm up with a short inference request so first real chat isn't slow
            ui_done "vLLM healthy — warming up"
            VLLM_MODEL="${VLLM_MODEL:-$(grep '^VLLM_MODEL=' .env 2>/dev/null | cut -d= -f2)}"
            VLLM_WARM="import ssl,json,urllib.request; ctx=ssl.create_default_context(cafile='/app/pki/ca.crt'); ctx.load_cert_chain('/app/pki/services/vllm/service.crt','/app/pki/services/vllm/service.key'); body=json.dumps({'model':'${VLLM_MODEL}','messages':[{'role':'user','content':'hi'}],'max_tokens':1}).encode(); urllib.request.urlopen(urllib.request.Request('https://localhost:8000/v1/chat/completions',data=body,headers={'Content-Type':'application/json'}),context=ctx,timeout=120)"
            docker exec noo-vllm python3 -c "$VLLM_WARM" \
                >/dev/null 2>&1 && \
                ui_done "vLLM warm and ready" || \
                ui_warned "Warmup request failed (the model may still be compiling CUDA graphs)"
        elif [ $SECONDS -ge $VLLM_DEADLINE ]; then
            ui_warned "vLLM still loading after 10 min — continuing in the background"
            ui_note "check progress: docker logs -f noo-vllm"
        fi
    fi

    # Step 3b: Post-startup image cleanup
    # Now that all containers are running, remove images not used by any container.
    # Docker protects images referenced by running containers, so this is safe.
    echo ""
    IMAGES_BEFORE=$(docker images --format '{{.Size}}' | wc -l)
    DISK_BEFORE=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1)
    ui_step "Removing unused images (keeping running containers' images and base images)"
    # Exclude images labeled `noo.image.keep=true` (e.g. deps-base) — those
    # are build-only base images that no container runs from directly, so
    # plain `image prune -a` would incorrectly nuke them and force a
    # 5-minute bootstrap on the next rebuild.
    PRUNED=$(docker image prune -a -f --filter "label!=noo.image.keep=true" 2>/dev/null | tail -1)
    IMAGES_AFTER=$(docker images --format '{{.Size}}' | wc -l)
    DISK_AFTER=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1)
    ui_kv "Images" "${IMAGES_BEFORE} → ${IMAGES_AFTER}  $(ui_muted "${PRUNED}")"
    ui_kv "Image disk" "${DISK_BEFORE:-?} → ${DISK_AFTER:-?}"

    ui_close_done "Rebuild complete — full stack running"
else
    ui_close_done "Build complete (not started: --no-start)"
fi

# Step 4: Show logs for rebuilt services
ui_phase "Recent logs"
for service in ${SERVICES[@]}; do
    echo ""
    printf '  %s\n' "$(ui_muted "$service")"
    docker compose $COMPOSE_FILES logs --tail=20 $service
done

# Step 5: the container table is `noo stack status` now.
echo ""
ui_note "noo stack status shows the containers"

# Wait for background model pull if it was started (max 10 minutes)
if [ -n "${OLLAMA_PULL_PID:-}" ]; then
    echo ""
    ui_step "Waiting for the Ollama model pull to finish (up to 10 min)"
    PULL_DEADLINE=$((SECONDS + 600))
    PULL_OK=false
    while kill -0 $OLLAMA_PULL_PID 2>/dev/null; do
        if [ $SECONDS -ge $PULL_DEADLINE ]; then
            ui_warned "Model pull still running after 10 min — continuing in the background"
            ui_note "check progress: docker exec noo-ollama ollama list"
            break
        fi
        sleep 5
    done
    if ! kill -0 $OLLAMA_PULL_PID 2>/dev/null; then
        wait $OLLAMA_PULL_PID 2>/dev/null && PULL_OK=true
        if [ "$PULL_OK" = true ]; then
            ui_done "Inference model ready"
        else
            ui_warned "Model pull failed (will retry on next start)"
        fi
    fi
fi

ui_phase "Endpoints"
print_service_urls full

echo ""
ui_rule
ui_guide_cmd "noo stack status" "containers, health and ports in one table"
ui_guide_cmd "noo stack logs -f [service]" "follow logs; omit the service for all of them"
ui_guide_cmd "noo stack restart [service]" "restart one service or the whole stack"
ui_guide_cmd "noo stack stop" "stop everything, data volumes kept"
