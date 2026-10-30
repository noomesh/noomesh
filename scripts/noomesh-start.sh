#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Start Noomesh cluster services

set -e

# Single-flight across every compose-mutating entry point (an earlier change —
# the 2026-07-31 outage was two recreate paths interleaving).
source "$(dirname "${BASH_SOURCE[0]}")/lib-compose-lock.sh"
# require_addon_pins (licensed add-ons run only their signed, local pins).
source "$(dirname "${BASH_SOURCE[0]}")/lib-dist.sh"
# Presentation helpers (ui_step/ui_kv/…) follow
# noo-cli/CLI_STYLE_GUIDE.md. Sourced HERE, before ANY caller: the
# dist/digest block and the rebuild EXIT trap both call ui_* well
# above where this used to sit, and under `set -e` an undefined
# helper is exit 127 (host8, 2026-09-03: `noo upgrade --all` died
# with "ui_kv: command not found" the moment a stack.lock existed).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-ui.sh"
# `noo_bin` only (function def, no side effects) — needed by the override
# regen below and by lib-addons.sh, both of which run before `load_config`
# is called further down. Sourcing twice is harmless: lib-config.sh has no
# top-level side effects outside its functions.
. "$(dirname "${BASH_SOURCE[0]}")/lib-config.sh"
acquire_compose_lock || exit 1


DEFAULT_PROFILE="controller"

# ── Distribution mode ──────────────────────────────────────────────────
# Parsed BEFORE the main arg loop because it changes which compose files we
# layer. `--dist` runs the stack from the published GHCR images instead of
# building from the local source tree (see docker-compose.dist.yml).
# `--tag vX.Y.Z` picks the release; default = newest stack-v* tag in the repo.
# `--dev` forces a build-from-source run for THIS invocation only — the
# one-off override for installs whose persisted mode is dist (below).
DIST=false
DIST_TAG=""
EXPLICIT_TAG=""
FORCE_DEV=false
# --core-only: bring up the base stack WITHOUT any add-on profile or overlay,
# whatever the `addons:` map says. One-shot instruction from the caller, not a
# declaration — the map stays the single source of truth and this does not
# write to it.
#
# The onboarding wizard uses it for its Service Setup step, which runs BEFORE
# the operator has been asked which add-ons they want. Without it a fresh
# install pulls and starts trellion (~4.5 GB, opt-out so on by default) four
# steps before the question, and stops it again if they say no.
CORE_ONLY=false
_argv=()
while [ $# -gt 0 ]; do
    case "$1" in
        --dist)      DIST=true; shift ;;
        --dev)       FORCE_DEV=true; shift ;;
        --core-only) CORE_ONLY=true; shift ;;
        --tag)       DIST_TAG="$2"; EXPLICIT_TAG=1; shift 2 ;;
        --tag=*)     DIST_TAG="${1#*=}"; EXPLICIT_TAG=1; shift ;;
        *)           _argv+=("$1"); shift ;;
    esac
done
set -- "${_argv[@]+"${_argv[@]}"}"

if [ "$DIST" = true ] && [ "$FORCE_DEV" = true ]; then
    echo "ERROR: --dev and --dist are mutually exclusive." >&2
    echo "       --dist runs the published images; --dev builds from source." >&2
    exit 1
fi

# ── Persisted install mode ─────────────────────────────────────────────
# `noo onboard` records the dev-vs-dist answer as NOO_INSTALL_MODE in .env
# (a bootstrap flag, read here before anything else loads). `dist` makes a
# bare start behave exactly like `--dist`; absent or `dev` keeps today's
# build-from-source behavior. Explicit flags always win: --dist forces
# dist, --dev forces source, and --build implies a dev run (it is already
# mutually exclusive with --dist below).
if [ "$DIST" != true ] && [ "$FORCE_DEV" != true ]; then
    _has_build=false
    for _a in ${_argv[@]+"${_argv[@]}"}; do
        [ "$_a" = "--build" ] && _has_build=true
    done
    if [ "$_has_build" != true ]; then
        if [ -z "${NOO_INSTALL_MODE:-}" ] && [ -f ".env" ]; then
            NOO_INSTALL_MODE="$(grep -E '^[[:space:]]*NOO_INSTALL_MODE=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
        fi
        if [ "${NOO_INSTALL_MODE:-dev}" = "dist" ]; then
            DIST=true
            echo "Install mode: dist (persisted in .env) — starting from released images; use --dev for a one-off source run."
        fi
    fi
fi

# Regenerate docker-compose.override.yml from noomesh.yaml (user directory
# mounts). Moved into `regen_compose_override` in lib-config.sh (sourced
# above, and before this point unconditionally) so it can be exercised by
# a test without sourcing this whole script — see that function's own
# comment for the mount/precedence/fallback rules.
regen_compose_override

# Auto-include override file if it exists (user directory mounts)

# ── Add-ons ────────────────────────────────────────────────────────────
# ONE declaration: the `addons:` map in noomesh.yaml. Shared with
# noomesh-rebuild.sh via lib-addons.sh so the two commands cannot drift —
# see that file for the incident the rule comes from.
. "$(dirname "$0")/lib-addons.sh"
addons_guard_retired_flags
warn_retired_env_keys


# Licensed add-ons (every add-on whose overlay is not in this tree): each
# overlay arrives in the add-on's signed bundle, addons/<name>/docker-compose.yml
# (N6), or from a development checkout. lib-addons.sh addon_overlay.
addons_report_licensed

# ── Trellion worker pool (always on) ───────────────────────────────────
# The Python worker pool ALWAYS runs as its own noo-trellion container.
# It used to be opt-in via NOO_TRELLION_ENABLED, with the gateway spawning
# and supervising the pool as a child process when the switch was off.
#
# That in-process path is gone. It forced the gateway image to
# carry trellion's whole dependency tree — 2724 MB of nvidia, 1072 MB of
# torch, 689 MB of triton — in a process that runs no models. Removing it is
# what lets the image drop that weight.
#
# The trade, stated plainly: a single-container mesh is no longer a
# supported shape. These knobs move together and are no longer
# optional — running the gateway without noo-trellion leaves every worker.*
# delegation to degrade per-capability.
#   addons.trellion (noomesh.yaml, default on) → the trellion overlay
#                               (docker-compose.trellion.yml) is composed in;
#                               there is no compose profile for it
#   NOO_WORKER_SUPERVISOR     → the gateway never spawns a pool
#   NOO_MCP_GATEWAY_HOST_PORT → the gateway's host :3100 (Rust /mcp door; + the
#                               instance port offset; exported by
#                               lib-instance.sh) so noo-trellion owns the
#                               host MCP port
#   NOO_MIGRATIONS_ENVS       → memory alembic runs in noo-trellion; the
#                               gateway applies mesh only
export NOO_WORKER_SUPERVISOR="external"
export NOO_MIGRATIONS_ENVS="${NOO_MIGRATIONS_ENVS:-mesh}"
# ── Trellion add-on switch ─────────────────────────────────────────────
# The switch is `addons.trellion` in noomesh.yaml (read by addon_on in
# lib-addons.sh). The old NOO_TRELLION_ENABLED env flag is retired and
# lib-addons.sh refuses to start while it is still set in .env. Default ON:
#   ON  → composes its overlay, docker-compose.trellion.yml (the ML pack, surfaces=ml since the
#         phase-5 flip; the slim noo-worker always rides the controller
#         profile and serves the four core subjects either way)
#   OFF → trellion simply not started; the gateway's degradation
#         contract (phase 3) answers every knowledge surface honestly. The
#         gateway reads the same noomesh.yaml declaration, so containers and
#         behavior cannot disagree.
if ! addon_on trellion 1; then
    # worker rides the controller profile (phase 5). The overlay is not
    # composed when the add-on is off, so a container from a previous
    # ENABLED run is not touched by `up` — opting out on a live stack must
    # actively stop it (live rehearsal round 2, 2026-08-13).
    TRELLION_STOP_ON_OFF=1
    ui_warned "trellion add-on disabled — slim noo-worker serves the core surfaces"
    ui_note "knowledge features (RAG/memory/recall/graph) answer 503 by design"
fi

# ── Voice / STT switch ─────────────────────────────────────────────────
# Single switch for the opt-in voice containers (noo-whisper STT +
# noo-piper TTS). `addons: {voice: true}` in noomesh.yaml composes their
# OVERLAY (docker-compose.voice.yml via lib-compose.sh; an earlier change phase
# D), so the containers survive `noo stack start` and a reboot. Provider selection
# stays in NOO_STT_* / NOO_TTS_* (the gateway defaults to
# https://noo-whisper:8000 and https://noo-piper:8000 (mTLS), wire format "openai" for
# both); this switch only decides whether the containers are deployed.
#
# `voice` is in the same map but is NOT in the gateway's add-on table: it
# deploys containers and gates no gateway route, so there is nothing for
# addons.rs to refuse. The map is "what this install runs"; the table is the
# subset the gateway itself gates.
if addon_on voice 0; then
    echo "Add-on voice: ENABLED (noo-whisper STT + noo-piper TTS; provider config stays in NOO_STT_* / NOO_TTS_*)"
else
    # Same leftover-container rule as trellion: `up` never touches a service
    # it was not shown, so opting out on a live stack must stop it.
    VOICE_STOP_ON_OFF=1
fi

# ── Distribution overlay ───────────────────────────────────────────────
# Layered LAST so its `pull_policy: missing` wins over the base file's
# `pull_policy: build` (compose merges later -f files over earlier ones).
if [ "$DIST" = true ]; then
    # Checked here, before any side effects (pip install, secret load, pull).
    for _a in ${_argv[@]+"${_argv[@]}"}; do
        if [ "$_a" = "--build" ]; then
            echo "ERROR: --build and --dist are mutually exclusive." >&2
            echo "       --dist runs the published images; --build compiles from source." >&2
            exit 1
        fi
    done
    if [ ! -f "docker-compose.dist.yml" ]; then
        echo "ERROR: --dist requires docker-compose.dist.yml (not found)." >&2
        exit 1
    fi

    # Tag resolution, in order: explicit --tag → NOO_IMAGE_TAG from the
    # environment or .env (a STANDALONE install has no .git — `noo onboard
    # --standalone` seeds the tag its binary was released with) → the newest
    # local stack-v* git tag (checkout installs; reproducible rather than
    # chasing a floating :latest).
    if [ -z "$DIST_TAG" ] && [ -n "${NOO_IMAGE_TAG:-}" ]; then
        DIST_TAG="$NOO_IMAGE_TAG"
    fi
    if [ -z "$DIST_TAG" ] && [ -f ".env" ]; then
        DIST_TAG="$(grep -E '^[[:space:]]*NOO_IMAGE_TAG=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    if [ -z "$DIST_TAG" ]; then
        DIST_TAG="$(git tag -l 'stack-v*' 2>/dev/null | sort -V | tail -1)"
        DIST_TAG="${DIST_TAG#stack-}"
    fi
    if [ -z "$DIST_TAG" ]; then
        echo "ERROR: --dist could not resolve a release tag (no stack-v* tags and no NOO_IMAGE_TAG)." >&2
        echo "       Pass one explicitly (noo stack start --dist --tag v0.1.8)" >&2
        echo "       or set NOO_IMAGE_TAG in .env (standalone installs)." >&2
        exit 1
    fi
    # The compose file's secret wiring needs images that read /run/secrets
    # (x-noo-secrets-floor) — refuse an older tag here, before any side
    # effect, rather than start a gateway with no credentials.
    require_secrets_floor "." "$DIST_TAG" || exit 1

    export NOO_IMAGE_PREFIX="${NOO_IMAGE_PREFIX:-$(release_image_namespace)}"
    export NOO_IMAGE_TAG="$DIST_TAG"
    DIST_MODE=1
    DIST_COMPOSE_FILE="docker-compose.dist.yml"

    echo "Distribution mode: ON"
    echo "  Images: ${NOO_IMAGE_PREFIX}/<service>:${NOO_IMAGE_TAG} (pull-only, no local build)"

    # Digest pins from the signed stack.lock (lib-dist.sh dist_load_stack_lock;
    # a lock for another tag is never applied).
    dist_load_stack_lock "$DIST_TAG"
    case "$_DIST_LOCK_STATE" in
        loaded) ui_kv "Digests" "pinned from stack.lock $(ui_muted "(signed release stack-${DIST_TAG})")" ;;
        other) ui_kv "Digests" "stack.lock is for another tag — pulling ${DIST_TAG} by tag $(ui_muted "(noo upgrade --stack refreshes the lock)")" ;;
    esac

    # ── Promotion guardrails (2026-08-28 incident: a plain start silently
    # DOWNGRADED v0.1.91 → v0.1.75 because the yaml's pinned NOO_IMAGE_TAG
    # was never bumped — explicit --tag runs don't touch it). Two rules:
    #   1. explicit --tag PERSISTS to noomesh.yaml, so the pin follows
    #      every deliberate deploy instead of lying in wait;
    #   2. a pinned tag older than the newest stack-v* release warns
    #      loudly with the exact promote command (the pin still wins —
    #      pinning is deliberate; being silently stale is not).
    NEWEST_STACK="$(git tag -l 'stack-v*' 2>/dev/null | sort -V | tail -1)"
    NEWEST_STACK="${NEWEST_STACK#stack-}"
    if [ -n "$EXPLICIT_TAG" ] && [ -f "noomesh.yaml" ]; then
        if CUR_PIN="$(config_compose_env_get noomesh.yaml NOO_IMAGE_TAG)"; then
            if [ "$CUR_PIN" != "$DIST_TAG" ]; then
                config_compose_env_set noomesh.yaml NOO_IMAGE_TAG "${DIST_TAG}"
                ui_kv "Promoted" "noomesh.yaml NOO_IMAGE_TAG ${CUR_PIN:-unset} → ${DIST_TAG}"
            fi
        fi
    elif [ -n "$NEWEST_STACK" ] && [ "$DIST_TAG" != "$NEWEST_STACK" ]; then
        if [ "$(printf '%s\n%s\n' "$DIST_TAG" "$NEWEST_STACK" | sort -V | tail -1)" = "$NEWEST_STACK" ]; then
            ui_warned "Pinned tag ${DIST_TAG} is older than the newest release (${NEWEST_STACK})" >&2
            echo "    Promote with: noo stack start --dist --tag ${NEWEST_STACK}" >&2
        fi
    fi
    # Config-plane guard: on a checkout install the tag's home is
    # noomesh.yaml compose_env — a copy in .env silently shadows every
    # promotion (the two-homes failure class from CLAUDE.md).
    if [ -d ".git" ] && [ -f ".env" ] && grep -qE '^[[:space:]]*NOO_IMAGE_TAG=' .env; then
        ui_warned "NOO_IMAGE_TAG is set in .env — on a checkout install it belongs" >&2
        echo "    ONLY in noomesh.yaml compose_env (the .env copy shadows promotions)." >&2
    fi

    # fu 47: dist mode runs PURE IMAGE CODE. The dev overlays (trellion
    # ./src:/app/src, the gateway dashboard assets) are neutralized by
    # repointing their DEST at scratch paths — the released image's baked
    # code is the truth, and behavior no longer depends on the host
    # checkout's git state (the 2026-08-09 saga shipped three releases
    # whose Python fixes never ran because a stale mount won silently).
    export NOO_SRC_OVERLAY="./.src-overlay-placeholder"
    export NOO_SRC_OVERLAY_DEST="/tmp/.src-overlay-unused"
    export NOO_UI_STATIC_OVERLAY="./.src-overlay-placeholder"
    export NOO_UI_STATIC_OVERLAY_DEST="/tmp/.ui-static-unused"
    export NOO_UI_INDEX_OVERLAY="./.src-overlay-placeholder"
    export NOO_UI_INDEX_OVERLAY_DEST="/tmp/.ui-index-unused"
    export TRELLION_SRC="./.trellion-src-placeholder"
    export TRELLION_SRC_DEST="/tmp/.trellion-src-unused"

    # An add-on overlay cannot have a dist row (a row for a service the
    # overlay did not compose is a bare service compose refuses), so the
    # overlays that build in dev interpolate `pull_policy:
    # ${NOO_PULL_POLICY:-build}` instead — docker-compose.trellion.yml,
    # an earlier change. lib-dist.sh exported this from the day the
    # interpolation landed; THIS block, the launcher's own dist path and the
    # one every `noo stack start` / `noo upgrade --stack` takes, did not. So
    # the fallback won: compose resolved `build` for trellion and tried to
    # build it, dying on `failed to get build context trellion: stat
    # <home>/trellion: no such file or directory` — a standalone
    # controller has no sibling source checkout. Live on a standalone
    # controller rolling v0.2.72, 2026-09-23, with the image already pulled
    # and sitting on disk.
    export NOO_PULL_POLICY="missing"

    # The core GHCR packages are PUBLIC: no login is needed to pull them. A
    # registry login matters only for licensed add-ons (trellion-intel,
    # evolve), which are private packages whose access is granted with the
    # entitlement; if one of those is denied, compose reports it with its own
    # error. Absent login is therefore a note here, never a failure. If the
    # images are already local, pull_policy `missing` never contacts the
    # registry at all (air-gapped / pre-seeded installs).
    if ! grep -q 'ghcr.io' "${DOCKER_CONFIG:-$HOME/.docker}/config.json" 2>/dev/null; then
        if docker image inspect "${NOO_IMAGE_PREFIX}/gateway:${NOO_IMAGE_TAG}" >/dev/null 2>&1; then
            echo "  (no ghcr.io login, but images for ${NOO_IMAGE_TAG} are present locally — continuing pull-free)"
            DIST_PULL_FREE=true
        else
            echo "  (no ghcr.io login — the core images are public and pull anonymously; licensed add-ons need GHCR access granted with the entitlement)"
        fi
    fi
fi

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Map service names to required Docker Compose profiles
service_profile() {
    case $1 in
        vllm)         echo "gpu-tier1" ;;
        vllm-secondary) echo "vllm-secondary" ;;
        airllm)       echo "gpu-tier1" ;;
        llamacpp)     echo "llamacpp" ;;   # own profile — gpu-tier2 no longer includes it (no-GGUF restart loop)
        ollama)       echo "gpu-tier2" ;;
        tei)          echo "controller" ;;
        tei-gpu)      echo "gpu-tier2" ;;
        *)            echo "" ;;
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

ui_phase "Stack"

# Ensure local Python dependencies are current
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# fu 46: per-instance namespace (project, prefix, network, ports).
. "$SCRIPT_DIR/lib-instance.sh"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -f "$PROJECT_ROOT/pyproject.toml" ]; then
    # [trellion]: noo-trellion is an extra since an earlier change (it is
    # not in the gateway image any more). The host venv is the editable
    # install the Python tests and tooling use (there is no Python CLI).
    pip install -q -e "$PROJECT_ROOT[trellion]" 2>/dev/null || true
fi

# Resolve the cluster-plane bind address (auto-detects the tailnet IP when
# NOO_BIND_MODE=tailnet) so compose publishes ports on the right interface.
# shellcheck source=scripts/lib-bind-addr.sh
source "$SCRIPT_DIR/lib-bind-addr.sh"
resolve_bind_addr
resolve_location
# Load secrets (no-op unless NOO_SECRETS_BACKEND=sops; fails closed on decrypt error).
source "$SCRIPT_DIR/lib-secrets.sh"
load_secrets || { echo "aborting: secrets load failed" >&2; exit 1; }
require_core_secrets || exit 1
require_bus_keys || exit 1
require_audit_key || exit 1
# NATS runs ONE config (monitoring/nats/nats-tls.conf, mTLS). The selector
# that could pick a plaintext `nats.conf` is gone from compose, so a .env
# that still sets NOO_NATS_CONFIG would be silently ignored — and a value
# naming the old plaintext file is a box someone once downgraded on purpose.
# Refuse, and say what to remove. Empty and the TLS file's own name are inert.
_nats_cfg="${NOO_NATS_CONFIG:-}"
if [ -z "$_nats_cfg" ] && [ -f ".env" ]; then
    _nats_cfg="$(grep -E '^[[:space:]]*NOO_NATS_CONFIG=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
fi
case "$_nats_cfg" in
    ""|nats-tls.conf) ;;
    *)
        echo "FATAL: NOO_NATS_CONFIG=$_nats_cfg — NATS runs the mTLS config only (nats-tls.conf)." >&2
        echo "       The plaintext nats.conf and the config selector were removed; this value" >&2
        echo "       would be ignored silently. Remove the NOO_NATS_CONFIG line from .env (or the" >&2
        echo "       environment) and start again." >&2
        exit 1 ;;
esac
unset _nats_cfg
# Deployment config: noomesh.yaml `compose_env:` -> environment, so
# compose can interpolate ${VAR} from something other than .env.
# Non-fatal: config has compose-side defaults, and a missing knob must
# not block a launch the way a missing credential does.
source "$SCRIPT_DIR/lib-config.sh"
load_config || echo "warning: config load reported problems (continuing)" >&2
# ── Data-root guard ─────────────────────
# The compose file has no fallback for NOO_DATA_ROOT: it refuses to render
# without one, because a guessed root would bind-mount directories Docker
# creates EMPTY. The onboard storage step always writes it, so reaching this
# means it was skipped; say so before compose's own error does.
_data_root="${NOO_DATA_ROOT:-}"
if [ -z "$_data_root" ] && [ -f ".env" ]; then
    _data_root="$(grep -E '^[[:space:]]*NOO_DATA_ROOT=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
fi
# The sensitive state set (redis, grafana, ...) lives under NOO_STATE_ROOT,
# which defaults to the data root (i10a); the re-own below follows it.
_state_root="$(noo_state_root)"
if [ -z "$_data_root" ]; then
    ui_warned "NOO_DATA_ROOT is not set — compose will refuse to start"
    ui_note "pin one path: run 'noo onboard --only storage', or set NOO_DATA_ROOT in .env"
fi

# ── redis/grafana data re-owned to 65532 (i64) ────────────────────────
# Done immediately before `up`, after the running service is stopped, and
# verified afterwards: reown_nonroot_dirs (lib-reown.sh). It used to run HERE,
# minutes before `up`, while the old root container kept rewriting its files
# through the pull — the 0.6.3 -> 0.6.4 redis crash loop on a root-owned
# appendonlydir/appendonly.aof.manifest (2026-10-16).

# ── HF_CACHE_DIR must be an HF_HOME, not a bare hub archive ───────────
# HF_CACHE_DIR is bound to /root/.cache/huggingface for the vLLM-family
# backends and to /hf-store for the weight cache, whose nginx serves
# /hf-store/hub/. So it must be the directory that CONTAINS hub/.
#
# An operator pointed it at a bare hub archive — models--* at the top level,
# no hub/ — and nothing served. Every layer failed politely: nginx 404s a
# directory it cannot alias, the node's preseed reports "list …: HTTP 404",
# the backends find no models where they look. Not one of them says "wrong
# level", and the stack starts perfectly either way.
#
# Detect it here, where the answer is one `test`. Deliberately a WARNING and
# not a refusal: everything except model preseeding still works, and the
# cost of being wrong about someone's unusual layout should not be a stack
# that will not boot.
_hf_dir="${HF_CACHE_DIR:-}"
if [ -z "$_hf_dir" ] && [ -f ".env" ]; then
    _hf_dir="$(grep -E '^[[:space:]]*HF_CACHE_DIR=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
fi
[ -n "$_hf_dir" ] || _hf_dir="${_data_root:-/mnt/d/pai}/hf-cache"
# The `models--*` test is what separates "wrong level" from "nothing here
# yet": an empty or absent directory is a normal fresh install and says
# nothing, so it must stay silent or the warning becomes noise.
if [ -d "$_hf_dir" ] && [ ! -d "$_hf_dir/hub" ] &&    [ -n "$(find "$_hf_dir" -maxdepth 1 -name 'models--*' -print -quit 2>/dev/null)" ]; then
    ui_warned "HF_CACHE_DIR looks like a bare hub archive: $_hf_dir"
    ui_note "it holds models--* directly, but HF_CACHE_DIR must CONTAIN hub/ (it is an HF_HOME)"
    ui_note "the weight cache serves \$HF_CACHE_DIR/hub, so /hf/ will 404 and every node's preseed will fail"
    ui_note "fix: mkdir -p '$_hf_dir/hub' && mv '$_hf_dir'/models--* '$_hf_dir/hub'/"
    ui_note "see docs/models/weight-cache.md"
fi
unset _hf_dir
# _data_root stays set: the re-own (reown_nonroot_dirs, i64/i100) runs just
# before each `up`, far below, and reads it. 0.6.4/0.6.5-rc.1 unset it HERE,
# so both `if [ -n "$_data_root" ]` guards were false and the re-own never
# ran (the rc.1 rehearsal: redis crash-looped on the seeded root-owned AOF
# manifest). tests/test_launcher_reown_nonroot_dirs.py runs the real script.
# The dist-tag RESOLUTION is authoritative — re-assert it after every env
# source has loaded. The sops store can carry a STALE NOO_IMAGE_TAG (the
# wizard encrypts the whole .env, pin included) and load_secrets exports
# unconditionally, which stomped the resolved tag: the hotfix banner said
# v0.1.76 while compose deployed v0.1.75 (live 2026-08-23, first-contact
# finding #31 — the declaration-beats-config rule, violated by our own
# launcher).
if [ -n "${DIST_TAG:-}" ]; then
    dist_reassert_pins
    # A licensed add-on that is on runs only the image its signed lock pins
    # for THIS tag, already local by digest (the CLI pulled it). No pin, a
    # pin that no longer verifies, or the image missing: refused HERE, naming
    # the add-on and `noo addons upgrade`, before anything is pulled or
    # recreated. The launcher never pulls an add-on. Off add-ons are not
    # looked at.
    # An add-on whose pin does not verify for this tag is left out of the
    # start (REFUSED, by name, with its remedy); the rest starts.
    DIST_MODE=1 require_addon_pins || exit 1
else
    # A dev start: composed add-on overlays run the dev build's names.
    DIST_MODE=0 require_addon_pins || exit 1
fi
# Their declared runtime inputs (resources.json): written to tmpfs, handed
# to the uid each bundle declares, exported; an add-on whose input cannot be
# produced is refused by name, and GPU/Docker-socket services are held
# (lib-dist.sh). Before the declarations, so a refused add-on declares nothing.
addon_resources_materialise || exit 1
# What the verified add-ons' signed bundles declare beyond their overlays
# (system.json, workloads.json) goes to the gateway's read-only directories,
# for exactly the add-ons the verdict above names (lib-dist.sh).
addon_decls_materialise || exit 1
# Stuck-in-Created self-heal for recreates (the 2026-08-20 74-min wedge).
source "$SCRIPT_DIR/lib-created-guard.sh"
source "$SCRIPT_DIR/lib-stuck-container.sh"
# Refuse an `up` whose bind-mount sources are missing or the wrong type
# (Docker would invent root-owned directories for them — 2026-09-29).
source "$SCRIPT_DIR/lib-bind-sources.sh"
# Hand redis/grafana data to uid 65532 right before `up` (i64), verified.
source "$SCRIPT_DIR/lib-reown.sh"

# <MODELS_DIR>/voice/{whisper,piper}: the voice add-on's read-only model
# mounts (docker-compose.voice.yml, i105). Same resolution as compose and
# `noo models pull`: MODELS_DIR, else <data root>/models.
noo_voice_model_dirs() {
    local models="${MODELS_DIR:-}"
    if [ -z "$models" ] && [ -f ".env" ]; then
        models="$(grep -E '^[[:space:]]*MODELS_DIR=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    [ -n "$models" ] || { [ -n "$_data_root" ] && models="$_data_root/models"; }
    [ -n "$models" ] || return 0
    mkdir -p "$models/voice/whisper" "$models/voice/piper" 2>/dev/null || \
        echo "NOTE: could not create $models/voice/{whisper,piper} (the voice add-on's model mounts); run: noo models pull whisper:base" >&2
    return 0
}
# An enabled system without its credentials is a gateway crash-loop once
# `up` runs — refuse before pulling or recreating anything.
check_system_credentials || exit 1
# A plaintext-.env install is refused before anything is pulled or
# recreated; the message names the sops remedy.
check_secrets_at_rest || exit 1
# An install whose state lives on the encrypted volume (i10a) is refused
# while that volume is not open: the services would start on an empty dir.
source "$SCRIPT_DIR/lib-state-volume.sh"
check_state_volume_open || exit 1
# ...and a start whose data root is not on the filesystem it was recorded on
# (a missing data disk must never let postgres initialise an empty database).
source "$SCRIPT_DIR/lib-data-root-mount.sh"
check_data_root_mount || exit 1

# Parse arguments
PROFILE=""
EXTRA_PROFILES=()
# Dist mode always refreshes from the registry, so it implies --pull —
# EXCEPT in pull-free mode (no registry login, all images pre-seeded:
# sandbox rehearsals, air-gapped installs), where a forced pull would die
# on the first third-party registry needing auth (dhi.io monitoring
# images) despite every image already being present.
if [ "$DIST" = true ] && [ "${DIST_PULL_FREE:-false}" != true ]; then PULL=true; else PULL=false; fi
BUILD=false
SERVICES=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            case "$2" in
                vllm-secondary|ollama|llamacpp|gpu-tier2|monitoring)
                    EXTRA_PROFILES+=("$2") ;;
                *)
                    PROFILE="$2" ;;
            esac
            shift 2
            ;;
        --profile=*)
            _prof="${1#*=}"
            case "$_prof" in
                vllm-secondary|ollama|llamacpp|gpu-tier2|monitoring)
                    EXTRA_PROFILES+=("$_prof") ;;
                *)
                    PROFILE="$_prof" ;;
            esac
            shift
            ;;
        --pull)
            PULL=true
            shift
            ;;
        --build)
            BUILD=true
            shift
            ;;
        *)
            SERVICES+=("$1")
            shift
            ;;
    esac
done

# Determine what to start
if [ ${#SERVICES[@]} -eq 0 ]; then
    # No specific services - start full stack
    if [ -z "$PROFILE" ]; then
        # A standalone install (noo onboard --standalone, fu67) persists its
        # profile via NOO_DEFAULT_PROFILE in .env, so a bare `noo stack
        # start` day-2 doesn't silently switch to the controller profile
        # (which names the containerised agent and no ollama-embed). The
        # monitoring set is in BOTH profiles since 2026-09-28; it used to be
        # controller-only, so this exact relaunch dropped it on every
        # standalone roll. Same read-don't-source pattern as
        # NOO_INSTALL_MODE above.
        if [ -z "${NOO_DEFAULT_PROFILE:-}" ] && [ -f ".env" ]; then
            NOO_DEFAULT_PROFILE="$(grep -E '^[[:space:]]*NOO_DEFAULT_PROFILE=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
        fi
        PROFILE="${NOO_DEFAULT_PROFILE:-$DEFAULT_PROFILE}"
    fi

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

    # Auto-detect GPU tier on controller and add the inference profile
    PROFILE_ARGS="--profile $PROFILE"
    if [ "$PROFILE" = "controller" ]; then
        GPU_TIER=$(detect_gpu_tier)
        if [ -n "$GPU_TIER" ]; then
            PROFILE_ARGS="$PROFILE_ARGS --profile $GPU_TIER"
            ui_kv "Profiles" "${PROFILE}, ${GPU_TIER}"
            if [ "$GPU_TIER" = "gpu-tier1" ]; then
                ui_kv "Controller GPU" "tier 1 (>=10GB VRAM) → Ollama (vLLM by placement)"
            else
                ui_kv "Controller GPU" "tier 2 (4-10GB VRAM) → Ollama"
            fi
        else
            ui_kv "Profile" "${PROFILE}"
            ui_kv "Controller GPU" "none detected → Ollama on CPU (or a cloud model, if a key is configured)"
        fi
    else
        ui_kv "Profile" "${PROFILE}"
    fi
    # Append extra profiles (--profile vllm-secondary, etc.)
    for ep in "${EXTRA_PROFILES[@]}"; do
        PROFILE_ARGS="$PROFILE_ARGS --profile $ep"
    done
    # Profiles the operator enabled in COMPOSE_PROFILES (embed-cpu, sensors):
    # compose would ignore that variable beside our own --profile flags.
    _op_profiles="$(operator_profile_args)"
    derive_profile_env
    if [ -n "$_op_profiles" ]; then
        PROFILE_ARGS="$PROFILE_ARGS $_op_profiles"
        ui_kv "Extra profiles" "$(printf '%s' "$_op_profiles" | sed 's/--profile //g') (COMPOSE_PROFILES)"
    fi
    # evolve profile (set by the addons map above; empty when off)

    # Indented through the same helper as the rows above it. A bare `echo`
    # landed hard against the left margin in the middle of an aligned block,
    # which is what made the roll output look ragged (operator, 2026-09-13).
    ui_note "includes gateway, node-agent, NATS, postgres and supporting services"
    echo ""

    # Auto-adjust GPU memory when colocating multiple inference backends
    GPU_BACKENDS=1
    if echo "$PROFILE_ARGS" | grep -q "vllm-secondary"; then GPU_BACKENDS=$((GPU_BACKENDS + 1)); fi
    if echo "$PROFILE_ARGS" | grep -q "gpu-tier2\|ollama"; then GPU_BACKENDS=$((GPU_BACKENDS + 1)); fi
    if [ $GPU_BACKENDS -gt 1 ]; then
        ui_kv "GPU colocate" "${GPU_BACKENDS} backends sharing the GPU (primary vLLM at 50%)"
        export GPU_MEM_UTIL=0.50
        export VLLM_MAX_MODEL_LEN=4096
    fi

    # Only pull if explicitly requested
    # noo-cluster is declared `external:` in the compose file (worker
    # networks predate compose's name pin and must never be recreated), so
    # the launcher owns creating it on the controller. Every existing host
    # inherited the network from history; a truly fresh machine could not
    # `up` at all without this (sandbox rehearsal 2026-08-06, defect #13).
    docker network create "${NOO_CLUSTER_NETWORK:-noo-cluster}" --driver bridge 2>/dev/null || true

    # The gateway runs as nonroot (uid 65532) and creates its own dirs on
    # the noo-data volume (/data/ingest, /data/audit-archive), whose root is
    # owned by whoever first wrote it: make them and hand them to 65532 first
    # (lib-instance.sh noo_prepare_gateway_data_dirs; same throwaway-container
    # pattern as the wizard's ensure_dir_ownership, no sudo needed).
    noo_prepare_gateway_data_dirs

    # noomesh.yaml must be WRITABLE BY THE GATEWAY, not just readable.
    # `noo config set` and every dashboard settings write go through the
    # gateway, which runs as uid 65532 and sees this file through a bind
    # mount. The file is created by the operator (uid 1000, mode 0644), so
    # on a dist install every config write answered
    #   500 Failed to open config lock /app/noomesh.yaml.lock: Permission denied
    # and the operator edited the yaml by hand instead (§3f R47).
    #
    # `chgrp` on the HOST is not an option: it needs the launching user to be
    # a member of gid 65532, which on most boxes they are not — the same wall
    # lib-secrets.sh documents for the Google key. So the same throwaway root
    # container as the block above does it, through the same bind mount the
    # gateway will use. The operator keeps ownership and write access; only
    # the group changes.
    #
    # Not fatal: a gateway that cannot write its config still serves
    # everything else, and the failure is now legible (the gateway's 500
    # names this command). Silence on success — one more line on every start
    # is not worth it.
    if [ -f noomesh.yaml ]; then
        if ! docker run --rm -v "$PWD/noomesh.yaml":/f alpine \
                sh -c 'chgrp 65532 /f && chmod 660 /f' 2>/dev/null; then
            echo "NOTE: could not make noomesh.yaml group-writable by the gateway (gid 65532) — \
'noo config set' and dashboard settings writes will fail with a permission error. To fix: \
docker run --rm -v \"\$PWD/noomesh.yaml\":/f alpine sh -c 'chgrp 65532 /f && chmod 660 /f'" >&2
        fi
    fi

# The file list has ONE home: base, GPU overlay,
# override, add-on overlays, then dist last so pinned image refs win.
. "$(dirname "$0")/lib-compose.sh"
COMPOSE_FILES="$(compose_file_args .)"
compose_gpu_notice
# Every add-on service compose renders must run exactly its verified pin,
# whether or not this start pulls (empty render = refusal). Dist only.
if [ -n "${DIST_TAG:-}" ]; then
    # shellcheck disable=SC2086
    DIST_MODE=1 dist_assert_addon_refs $COMPOSE_FILES $PROFILE_ARGS || exit 1
fi
# Before the pull loop (and every later `docker compose`): no v2 plugin is a
# prerequisite failure, not a pull failure — exit, never retry.
require_compose_v2 || exit 1

    if [ "$PULL" = true ]; then
        echo ""
        ui_step "Pulling images"
        if [ "$DIST" = true ]; then
            # Dist mode must pull the first-party images too. They still carry
            # `build:` blocks (kept for schema validity), so --ignore-buildable
            # would skip exactly the images we came for. Failures are fatal
            # here: a half-pulled dist stack would silently fall back to
            # whatever stale local image happened to match the tag.
            #
            # Add-on services are never pulled here: their images are pinned
            # by the add-on's own signed lock and were pulled by digest by the
            # CLI (`noo addons enable|upgrade`, `noo upgrade --stack`) with the
            # registry token the launcher does not hold. require_addon_pins
            # has already refused a start whose add-on image is not local.
            # The set is derived from the overlays (addon_services), so core
            # names no add-on service.
            # shellcheck disable=SC2086
            compose_active_services $COMPOSE_FILES $PROFILE_ARGS
            _dist_services="$(printf '%s\n' "$COMPOSE_OUT" \
                | grep -vxF -f <(addon_services $COMPOSE_FILES; echo '#none#') || true)"
            # Up to three attempts: GHCR blob downloads over IPv6 timed out
            # twice on host8 (2026-09-03), each time on the largest layer,
            # and each re-run resumed from the layers already on disk. A
            # transient must not surface as a failed start.
            # The pull must fetch what `up` will run: same tag, same lock
            # digests (re-asserted after the last env loader above). Checked
            # against compose's own rendering before a byte is downloaded.
            # shellcheck disable=SC2086
            dist_assert_pull_refs $COMPOSE_FILES $PROFILE_ARGS || exit 1
            _attempt=1
            _pull_err="$(mktemp)"
            # Off a terminal compose's output is teed to a file so a failed
            # attempt can show its LAST line, the real reason, instead of a
            # guess. On a terminal it draws in place (see compose_pull).
            # shellcheck disable=SC2086
            until { _pull_rc=0; compose_pull "$_pull_err" $COMPOSE_FILES $PROFILE_ARGS pull $_dist_services || _pull_rc=$?; [ "$_pull_rc" -eq 0 ]; }; do
                _pull_why="$(last_error_line "$_pull_err")"
                if [ "$_attempt" -ge 3 ]; then
                    if [ "$_pull_rc" -eq 125 ]; then
                        # 125 = docker/compose itself refused the command (bad
                        # flag, no plugin, bad config): not the network.
                        echo "ERROR: compose refused the pull (exit 125) — this is not a registry or network failure" >&2
                    else
                        echo "ERROR: image pull failed 3 times (exit $_pull_rc) — check the registry login and network, then re-run" >&2
                    fi
                    [ -n "$_pull_why" ] && echo "       last line from compose: $_pull_why" >&2
                    rm -f "$_pull_err"
                    exit 1
                fi
                ui_warned "pull failed (attempt $_attempt/3) — retrying in 15s; finished layers are kept" >&2
                [ -n "$_pull_why" ] && ui_note "$_pull_why" >&2
                _attempt=$((_attempt + 1))
                sleep 15
            done
            rm -f "$_pull_err"
        else
            docker compose $COMPOSE_FILES $PROFILE_ARGS pull --ignore-pull-failures --ignore-buildable
        fi
        echo ""
    fi

    # Build if requested (for custom images like node-agent)
    # A dist run must never compile: every image is pulled by digest from the
    # signed lock. This is the belt to `pull_policy: missing`'s suspender, and
    # it is what the overlay comments have claimed since an earlier change — the
    # claim was simply never true of this script. With it, a dist start whose
    # image is genuinely absent fails saying so instead of quietly building a
    # different artefact from whatever source happens to be on the host.
    BUILD_FLAG=""
    if [ "$DIST" = true ]; then
        BUILD_FLAG="--no-build"
    fi
    if [ "$BUILD" = true ] && [ "$DIST" = true ]; then
        echo "ERROR: --build and --dist are mutually exclusive." >&2
        echo "       --dist runs the published images; --build compiles from source." >&2
        exit 1
    fi
    if [ "$BUILD" = true ]; then
        ui_step "Building custom images"
        BUILD_FLAG="--build"
    fi

    # Fail closed on the Grafana admin password when a grafana-bearing profile
    # is being started (no admin/admin default). This check lives HERE
    # instead of a compose `:?` guard because compose interpolates required
    # vars file-wide on ANY operation — a `:?` guard broke worker-node
    # node-agent recreates where grafana never runs. `standalone` bears
    # grafana too (2026-09-28); onboard mints GRAFANA_PASSWORD on every
    # install shape, so an install that reaches here without one is an
    # install to repair, not to start.
    if echo "$PROFILE_ARGS" | grep -qE "controller|monitoring|standalone"; then
        for _reqvar in GRAFANA_PASSWORD NOO_JWT_SECRET REDIS_PASSWORD POSTGRES_PASSWORD; do
            _val="${!_reqvar:-$(grep -E "^${_reqvar}=" .env 2>/dev/null | head -1 | cut -d= -f2-)}"
            if [ -z "$_val" ]; then
                echo "ERROR: ${_reqvar} must be set (no insecure default) to start the ${PROFILE} profile." >&2
                echo "       Add ${_reqvar}=<value> to .env and retry." >&2
                exit 1
            fi
            # Blank was the only thing this refused, so the two files that
            # SHIPPED a value — .env.example's `changeme` and
            # cluster-init.sh's `admin` — sailed through it, and the
            # documented setup path produced a Grafana admin login that is
            # written down in the repo (§3f R28). A placeholder is not a
            # weaker secret than blank; it is a published one.
            case "$(printf '%s' "$_val" | tr '[:upper:]' '[:lower:]')" in
                changeme|change-me|admin|password|secret|dev-secret-change-in-production|test|example)
                    echo "ERROR: ${_reqvar} is set to the placeholder '${_val}'." >&2
                    echo "       That value is published in this repository — every install that" >&2
                    echo "       copied .env.example shares it. Generate a real one:" >&2
                    echo "         noo security generate-secret" >&2
                    echo "       and set ${_reqvar} in .env (or re-run 'noo onboard', which mints it)." >&2
                    exit 1
                    ;;
            esac
        done
    fi

    # GPU-less machine: noo-nvidia-exporter (controller profile) carries a
    # hard nvidia device reservation, and compose ABORTS the entire up on
    # "could not select device driver nvidia" — a CPU-only (tier 3)
    # controller could never start at all (sandbox --dist rehearsal).
    # --scale <svc>=0 skips just that service.
    # A --scale flag naming a service OUTSIDE the active profiles makes
    # compose ERROR "no such service" and set -e kills the launcher BEFORE
    # `up` starts anything (first-contact finding #12: the standalone
    # profile has no nvidia-exporter, and a GPU box without the container
    # toolkit walked straight into it). Scale only what the profile runs.
    # shellcheck disable=SC2086
    compose_active_services $COMPOSE_FILES $PROFILE_ARGS
    ACTIVE_SVCS="$COMPOSE_OUT"
    GPU_SCALE=""
    if ! docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; then
        if printf '%s\n' "$ACTIVE_SVCS" | grep -qx nvidia-exporter; then
            GPU_SCALE="--scale nvidia-exporter=0"
            # Out of the guard's set too: a Created exporter from an earlier
            # run is then removed, not `docker start`-ed and called DOWN.
            ACTIVE_SVCS="$(printf '%s\n' "$ACTIVE_SVCS" | grep -vx nvidia-exporter)"
        fi
        echo "  (no nvidia container runtime — skipping noo-nvidia-exporter)"
    fi

    # The containerised node-agent CANNOT WORK: an earlier change removed
    # docker.sock from the service (#705) and made the agent refuse to start
    # without a Docker API (#706). The host-native agent
    # (`noo cluster agent-host`) is the only working shape.
    #
    # 768c78b applied this to cluster-init.sh and the executor revive path
    # but not here, so the launcher an operator actually runs still tried to
    # create it — and it publishes :8081, which the host agent already owns.
    # Result: `up` dies on a bind error PARTWAY THROUGH, leaving the stack
    # half-recreated (observed 2026-08-17; noo-node-agent left in `Created`).
    #
    # --scale (not a profile edit) mirrors cluster-init.sh deliberately: the
    # service stays declared as the reference shape, so anyone who wants the
    # containerised form can still ask for it by name.
    AGENT_SCALE=""
    if printf '%s\n' "$ACTIVE_SVCS" | grep -qx node-agent; then
        AGENT_SCALE="--scale node-agent=0"
    fi
    # An add-on service that asks for a GPU, the Docker socket or privileged
    # mode is never started (lib-dist.sh addon_resources_materialise).
    ACTIVE_SVCS="$(addon_drop_held "$ACTIVE_SVCS")"

    # fu 46 phase 3: refuse the start BEFORE compose moves anything when a
    # foreign process/instance owns this instance's host ports — otherwise
    # `up` dies halfway on a bind error with some containers already
    # recreated.
    if echo "$PROFILE_ARGS" | grep -q "controller"; then
        noo_check_port_collisions || exit 1
    fi

    # redis/grafana run as uid 65532 (i64): re-own their data NOW, with the old
    # container stopped, and refuse the start if anything is still not 65532 (lib-reown.sh).
    # Before the bind-source check, which stays the last thing before `up`
    # and so sees the final ownership.
    reown_stop_service() { docker compose $COMPOSE_FILES $PROFILE_ARGS stop "$1" >/dev/null 2>&1; }
    if [ -n "$_data_root" ]; then
        # shellcheck disable=SC2046  # one service name per word
        reown_nonroot_dirs "${_state_root:-$_data_root}" $(printf '%s\n' "$ACTIVE_SVCS" | grep -xE 'redis|grafana' || true) || exit 1
    fi
    reown_ollama_stores "$ACTIVE_SVCS" || exit 1
    # The voice add-on mounts the controller's staged models read-only
    # (<MODELS_DIR>/voice/{whisper,piper}, i105). `noo models pull` and
    # `noo addons enable voice` create them; make sure they exist even when
    # nothing is staged yet, so the containers start and name the missing
    # model instead of the bind check refusing the whole stack.
    if printf '%s\n' "$ACTIVE_SVCS" | grep -qxE 'whisper|piper'; then
        noo_voice_model_dirs
    fi
    # Every bind source of what this `up` starts must already exist, with
    # the right type — else refuse NOW, before anything is recreated
    # (lib-bind-sources.sh). $ACTIVE_SVCS is that set, minus the scaled-out
    # exporter; the agent is scaled out below the same way.
    _bind_skip=""
    [ -n "$AGENT_SCALE" ] && _bind_skip="--skip node-agent"
    # Retired services (config/retired-services.txt): remove a stale container of
    # one BEFORE the up, one line each; nothing else is removed (186b step 4).
    compose_remove_retired .
    # shellcheck disable=SC2086
    check_bind_sources --no-deps $_bind_skip $ACTIVE_SVCS || exit 1
    # Start all services with profile(s)
    # --force-recreate handles re-provisioning where stale containers may exist
    # An unkillable leftover container (lib-stuck-container.sh) must not
    # abort the whole `up`: everything else is started and the launcher
    # exits $NOO_EXIT_STACK_PARTIAL (75) after the guard below has run.
    noo_compose_up_isolating_stuck compose $COMPOSE_FILES $PROFILE_ARGS up -d --force-recreate $BUILD_FLAG $GPU_SCALE $AGENT_SCALE $ADDON_HOLD_SCALE || _up_rc=$?
    if [ "${_up_rc:-0}" -ne 0 ] && [ "${_up_rc:-0}" -ne "$NOO_EXIT_STACK_PARTIAL" ]; then exit "$_up_rc"; fi
    # Report, never reap: a container no compose file of this install declares
    # (186b). Exit status unchanged; `--remove-orphans` is not passed to any `up`.
    compose_report_undeclared .
    # $ACTIVE_SVCS (computed above) is the service set THIS invocation
    # manages — tell the guard so a stale, out-of-profile Created
    # container (e.g. noo-ollama left by an earlier `noo models switch`
    # while running the `standalone` profile) is removed, not `docker
    # start`-ed as if it were the wedge this guard exists for.
    NOO_CREATED_GUARD_SERVICES="$ACTIVE_SVCS" noo_created_guard $(docker compose $COMPOSE_FILES $PROFILE_ARGS ps -aq)
    [ "${_up_rc:-0}" -eq "$NOO_EXIT_STACK_PARTIAL" ] && exit "$NOO_EXIT_STACK_PARTIAL"

    # Opt-out enforcement: stop a leftover trellion from a previous
    # enabled run — `up` above ignores unselected profiles entirely.
    if [ "${TRELLION_STOP_ON_OFF:-}" = "1" ]; then
        docker compose $COMPOSE_FILES -f "$(addons_trellion_overlay)" stop trellion 2>/dev/null || true
    fi
    # Licensed add-ons switched off: stop the services their overlay adds.
    # Add-ons refused this start (require_addon_pins): a container left from
    # an earlier start must not keep running. Only services an add-on OWNS
    # are stopped; a core service found stopped afterwards fails the start.
    addons_stop_leftovers addons_stop_disabled addons_stop_refused || exit 1
    if [ "${VOICE_STOP_ON_OFF:-}" = "1" ]; then
        docker compose $COMPOSE_FILES -f "$(addons_voice_overlay)" stop whisper piper 2>/dev/null || true
    fi
else
    # Specific services requested — auto-detect profiles
    PROFILE_ARGS=""
    if [ -n "$PROFILE" ]; then
        PROFILE_ARGS="--profile $PROFILE"
    fi
    for svc in "${SERVICES[@]}"; do
        p=$(service_profile "$svc")
        if [ -n "$p" ]; then
            PROFILE_ARGS="$PROFILE_ARGS --profile $p"
        fi
    done
    # A named service behind an operator profile (ollama-embed-cpu) needs it too.
    PROFILE_ARGS="$PROFILE_ARGS $(operator_profile_args)"
    derive_profile_env

    # Auto-adjust GPU memory when colocating backends
    if echo "$PROFILE_ARGS" | grep -q "vllm-secondary"; then
        ui_kv "GPU colocate" "reducing primary vLLM to 50% GPU"
        export GPU_MEM_UTIL=0.50
        export VLLM_MAX_MODEL_LEN=4096
    fi

    ui_kv "Services" "${SERVICES[*]}"
    if [ -n "$PROFILE_ARGS" ]; then
        echo "Profiles: $PROFILE_ARGS"
    fi

    # redis/grafana re-owned (lib-reown.sh) before the bind-source check,
    # which stays last before `up`. Only the named services: re-owning (and so stopping) one this start
    # does not bring back up would leave it down.
    reown_stop_service() { docker compose $COMPOSE_FILES $PROFILE_ARGS stop "$1" >/dev/null 2>&1; }
    if [ -n "$_data_root" ]; then
        # shellcheck disable=SC2046
        reown_nonroot_dirs "${_state_root:-$_data_root}" $(printf '%s\n' "${SERVICES[@]}" | grep -xE 'redis|grafana' || true) || exit 1
    fi
    reown_ollama_stores "$(printf '%s\n' "${SERVICES[@]}")" || exit 1
    if printf '%s\n' "${SERVICES[@]}" | grep -qxE 'whisper|piper'; then
        noo_voice_model_dirs
    fi
    addon_refuse_held "${SERVICES[@]}" || exit 1
    check_bind_sources "${SERVICES[@]}" || exit 1
    docker compose $COMPOSE_FILES $PROFILE_ARGS up -d "${SERVICES[@]}"
    NOO_CREATED_GUARD_SERVICES="${SERVICES[*]}" noo_created_guard $(docker compose $COMPOSE_FILES $PROFILE_ARGS ps -aq "${SERVICES[@]}")
fi

# Pre-pull the Ollama inference model if Ollama is running. Default
# gemma4:e2b (by design: US-origin, matching the
# NOO_MODEL_ORIGINS=us default; there is no silent fallback model) — and when the default is what fires, SAY so.
# Standalone runs its single ollama as `noo-ollama-embed`; a failed or
# skipped model step there never self-healed because only `noo-ollama` was
# looked for.
OLLAMA_CTR=""
for _c in noo-ollama noo-ollama-embed; do
    if docker ps --format '{{.Names}}' | grep -q "^${_c}\$"; then OLLAMA_CTR="$_c"; break; fi
done
if [ -n "$OLLAMA_CTR" ]; then
    if [ -z "${OLLAMA_MODEL:-}" ]; then
        # No chat model is declared. An OLD install that already has one
        # loaded (it relied on this same implicit default before
        # OLLAMA_MODEL existed) keeps working exactly as before. A
        # genuinely fresh container — nothing pulled yet, e.g. a
        # `--skip-model` onboard — gets no surprise multi-GB download
        # (2026-09-28 rehearsal: --skip-model still pulled a chat model
        # here even though the model step never ran).
        if docker exec "$OLLAMA_CTR" ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' \
            | grep -vE "^(${PAGEINDEX_EMBEDDING_MODEL:-}|${EMBEDDING_MODEL:-})$|embed|harrier|minilm|bge" | grep -q .; then
            OLLAMA_MODEL="gemma4:e2b"
            ui_note "no OLLAMA_MODEL declared — using the default (gemma4:e2b); set it in .env to change"
        else
            ui_note "no chat model installed — skipping the default pull; pick one: noo models recommended / noo models pull <model>"
        fi
    fi
    if [ -n "${OLLAMA_MODEL:-}" ] && ! docker exec "$OLLAMA_CTR" ollama list 2>/dev/null | grep -q "$OLLAMA_MODEL"; then
        ui_step "Pulling inference model $OLLAMA_MODEL into $OLLAMA_CTR (background)"
        docker exec "$OLLAMA_CTR" ollama pull "$OLLAMA_MODEL" &
        OLLAMA_PULL_PID=$!
    fi
fi

if [ -n "${NOO_ADDONS_REFUSED:-}" ]; then
    # Never a plain "started": the outcome names what did NOT start.
    ui_close_warned "Services started WITHOUT add-on(s) ${NOO_ADDONS_REFUSED//,/, }: refused, NOT running"
    addons_report_refused
else
    ui_close_done "Services started"
fi
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
            ui_note "check progress: docker exec $OLLAMA_CTR ollama list"
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
print_service_urls

echo ""
ui_rule
ui_guide_cmd "noo stack status" "containers, health and ports in one table"
ui_guide_cmd "noo stack logs -f [service]" "follow logs; omit the service for all of them"
ui_guide_cmd "noo stack restart [service]" "restart one service or the whole stack"
ui_guide_cmd "noo stack stop" "stop everything, data volumes kept"
