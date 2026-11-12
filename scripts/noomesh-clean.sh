#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Clean up ALL Mesh containers, volumes, images, and caches


# fu 46: derive the per-instance namespace (project, container prefix,
# network, ports) before any compose invocation — stop/status/logs must
# address the same project start created.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-instance.sh"
# local_image_namespace / legacy_image_namespaces — the single definition of
# which namespaces this repo builds into (see the --images block below).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-dist.sh"


# Auto-include override file if it exists (user directory mounts)
# The file list has ONE home: this now composes the
# add-on overlays too, so an add-on container is stopped/cleaned/logged as
# part of its own stack rather than treated as an orphan of it.
. "$(dirname "$0")/lib-compose.sh"
COMPOSE_FILES="$(compose_file_args .)"

# Paths
WIN_HF_CACHE="/mnt/c/Users/${USER}/.cache/huggingface/hub"
# The data root comes from the environment or .env, never a default: deep
# clean WIPES postgres/redis/nats under it, so a guessed root could wipe the
# wrong install's data. Empty means "not set" and is refused.
_REPO_ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
DATA_ROOT="${NOO_DATA_ROOT:-}"
if [ -z "$DATA_ROOT" ] && [ -f "$_REPO_ROOT/.env" ]; then
    DATA_ROOT="$(grep -E '^NOO_DATA_ROOT=' "$_REPO_ROOT/.env" | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
fi

# The sensitive state set (postgres, redis, nats) lives under NOO_STATE_ROOT,
# which defaults to the data root (i10a). Same empty-means-refused rule.
STATE_ROOT="${NOO_STATE_ROOT:-}"
if [ -z "$STATE_ROOT" ] && [ -f "$_REPO_ROOT/.env" ]; then
    STATE_ROOT="$(grep -E '^NOO_STATE_ROOT=' "$_REPO_ROOT/.env" | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
fi
STATE_ROOT="${STATE_ROOT:-$DATA_ROOT}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-ui.sh"

# --- Helpers ---
bytes_to_human() {
    local bytes=$1
    if (( bytes >= 1073741824 )); then
        echo "$(( bytes / 1073741824 )) GB"
    elif (( bytes >= 1048576 )); then
        echo "$(( bytes / 1048576 )) MB"
    else
        echo "$(( bytes / 1024 )) KB"
    fi
}

disk_free() {
    df --output=avail -B1 "$1" 2>/dev/null | tail -1 | tr -d ' '
}

ui_phase "Clean"
echo ""

REMOVE_VOLUMES=false
REMOVE_IMAGES=false
PRUNE_CACHE=false
CLEAN_HF=false
DEEP_CLEAN=false
ASSUME_YES=false

# Prompt for a destructive sub-step, unless -y/--yes was passed.
# Usage: if confirm "Remove X?"; then ...
confirm() {
    if [ "$ASSUME_YES" = true ]; then
        echo "  $1 (y/N) y  [--yes]"
        return 0
    fi
    # No terminal to ask on: refuse, never block on a read nobody answers.
    # The same rule and words as the CLI's confirm_prompt (noo stack clean
    # refuses before this script runs); this covers the script run directly.
    if [ ! -t 0 ]; then
        echo "confirmation required: pass --yes (stdin is not a TTY; refusing to block on: $1)" >&2
        exit 2
    fi
    local REPLY
    read -p "  $1 (y/N) " -r REPLY
    [[ "$REPLY" =~ ^[Yy]$ ]]
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--volumes)
            REMOVE_VOLUMES=true
            shift
            ;;
        --images)
            REMOVE_IMAGES=true
            shift
            ;;
        --cache)
            PRUNE_CACHE=true
            shift
            ;;
        --hf-cache)
            CLEAN_HF=true
            shift
            ;;
        --deep)
            REMOVE_VOLUMES=true
            REMOVE_IMAGES=true
            PRUNE_CACHE=true
            CLEAN_HF=true
            DEEP_CLEAN=true
            shift
            ;;
        --all)
            REMOVE_VOLUMES=true
            REMOVE_IMAGES=true
            PRUNE_CACHE=true
            CLEAN_HF=true
            shift
            ;;
        -y|--yes)
            ASSUME_YES=true
            shift
            ;;
        -h|--help)
            echo "Usage: noo stack clean [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --volumes   Remove Docker volumes (preserves postgres, redis & hf-cache)"
            echo "  --images        Remove locally built images (noomesh/* and legacy namespaces)"
            echo "  --cache         Prune Docker build cache"
            echo "  --hf-cache      Remove Windows HuggingFace cache (models live on D:)"
            echo "  --deep          All of the above + unused images + certs/secrets (with confirmation)"
            echo "                  Postgres & Redis volumes are prompted individually"
            echo "  --all           --volumes + --images + --cache (keeps data dirs, PKI, secrets; NOT --deep)"
            echo "  -y, --yes       Auto-confirm every prompt (unattended)"
            echo "  -h, --help      Show this help"
            echo ""
            echo "Default (no flags): stops containers, removes orphans, prunes dangling images"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Refuse a deep clean with no data root BEFORE anything is stopped or removed.
if [ "$DEEP_CLEAN" = true ] && [ -z "$DATA_ROOT" ]; then
    ui_warned "NOO_DATA_ROOT is not set (environment or .env) — refusing --deep, nothing was changed"
    ui_note "set NOO_DATA_ROOT to this install's data root, then re-run --deep"
    exit 1
fi

# i677 #20: docker must ANSWER before anything is removed. A shell outside
# the docker group (or a daemon that is down) fails every docker call; read
# as "nothing there", the clean would go on to remove the PKI, the secrets
# and the data dirs while the stack runs. Not installed at all is a positive
# answer: what is on disk is still cleaned. `noo stack clean` refuses the
# same way before it runs this script; this covers the script run directly.
# Reachable means the daemon answered with its version: an exit 0 with an
# empty version is not an answer (Docker 28.0.4, a shell without the group:
# rc.2 install matrix). Same rule as noo's docker_access.
_docker_down() { # why docker did not answer; nothing when it did, or is not installed
    command -v docker >/dev/null 2>&1 || return 0
    local f v rc e
    f="$(mktemp)"
    v="$(docker info --format '{{.ServerVersion}}' 2>"$f")" && rc=0 || rc=$?
    e="$(grep -m1 -v '^[[:space:]]*$' "$f" 2>/dev/null)"; rm -f "$f"
    if [ "$rc" != 0 ]; then
        printf '%s' "${e:-docker info reported no server version: the daemon did not answer}"
    fi
}
_docker_why="$(_docker_down)"
if [ -n "$_docker_why" ]; then
    echo "cannot reach docker ($_docker_why): nothing was removed" >&2
    echo "  run it from a shell where \`docker ps\` works (after joining the docker group: a new terminal, or \`newgrp docker\`)," >&2
    echo "  or as root: sudo noo stack clean (with the same flags)" >&2
    exit 1
fi

# Record starting disk space
C_FREE_BEFORE=$(disk_free /mnt/c)
D_FREE_BEFORE=$(disk_free /mnt/d 2>/dev/null)

# Stop all profiles

ui_step "Stopping all profiles"
ALL_PROFILES="standalone controller worker monitoring vllm vllm-secondary ollama llamacpp airllm cpu gpu-tier1 gpu-tier2"
for profile in $ALL_PROFILES; do
    docker compose $COMPOSE_FILES --profile "$profile" down 2>/dev/null
done

# Remove any orphaned containers that belong to this compose project
ui_step "Removing orphaned containers"
docker compose $COMPOSE_FILES ps -a --format "{{.Names}}" | xargs -r docker rm -f 2>/dev/null

# The RAM copies of the containers' secrets (lib-secrets.sh write_secret_files).
# shellcheck source=lib-secrets.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-secrets.sh" 2>/dev/null && remove_secret_files || true

# --- Always: prune build cache (biggest space saver, safe to do) ---
echo ""
ui_step "Pruning the Docker build cache"
BUILD_CACHE_BEFORE=$(docker system df --format '{{.BuildCache}}' 2>/dev/null | head -1)
docker builder prune -f 2>/dev/null
# `docker builder prune` and the daemon.json builder GC only ever touch the
# DEFAULT builder. Every docker-container buildx builder (e.g. the
# noo-multiarch one used for arm64 node-agent images) is a separate BuildKit
# instance with its own state volume that nothing reclaims automatically.
# On 2026-07-26 buildx_buildkit_noo-multiarch0_state had grown to 20.7 GB
# unnoticed. Prune each non-default builder explicitly.
# NB: parse the table, not `--format '{{.Name}}'` — the latter flattens
# builders together with their node rows (noo-multiarch AND noo-multiarch0),
# and a node name is not a valid --builder ("no builder ... found").
# Builders are the non-indented rows; `default*` carries a current-marker.
for _builder in $(docker buildx ls 2>/dev/null \
                    | awk 'NR>1 && /^[^[:space:]]/ {gsub(/\*$/,"",$1); print $1}' \
                    | grep -v '^default$' | sort -u); do
    docker buildx prune -f --builder "$_builder" >/dev/null 2>&1 \
        && ui_note "pruned buildx builder ${_builder}"
done
ui_done "Build cache pruned"

# --- Always: remove dangling images (untagged leftovers) ---
ui_step "Removing dangling images"
docker image prune -f 2>/dev/null
ui_done "Dangling images removed"

# --- Volumes: this install's compose project, and nothing else ---
# The project is the `name:` the compose files declare (noomesh), or
# noo-<instance> for a named instance (lib-instance.sh's noo_instance_env,
# run when it was sourced above).
clean_project() {
    printf '%s\n' "${COMPOSE_PROJECT_NAME:-noomesh}"
}

# The volumes whose com.docker.compose.project label IS this project, by
# docker's exact label filter. Never a name glob: a box can run several
# stacks (another instance, a dev checkout, someone else's compose project).
# The old `name=pai-assistant` filter matched no volume at all after the
# project rename, so --volumes/--deep removed nothing (i677a).
stack_volumes() {
    docker volume ls --filter "label=com.docker.compose.project=$1" --format '{{.Name}}'
    # The one volume the launcher created outside compose, so it has no
    # project label on every existing install: <project>_noo-data, by its
    # EXACT name (docker volume names are global; this one is ours). i677.
    if docker volume inspect "$1_noo-data" >/dev/null 2>&1 \
        && [ -z "$(docker volume inspect -f '{{index .Labels "com.docker.compose.project"}}' "$1_noo-data" 2>/dev/null)" ]; then
        printf '%s\n' "$1_noo-data"
    fi
}

# plan_volumes DEEP VOLUME... -> one "<action> <volume>" line each:
#   keep    hf-cache always; postgres-data/redis-data/noo-data without --deep
#   ask     postgres-data/redis-data/noo-data on --deep (asked one by one)
#   remove  everything else of this project
# noo-data is stateful (the gateway's ingest, audit archive and digest
# cache), and on a legacy install it is a plain volume whose data lives
# INSIDE docker: it is never in the bulk removal (i677 #20).
plan_volumes() {
    local deep="$1" vol; shift
    for vol in "$@"; do
        case "$vol" in
            *hf-cache*) echo "keep $vol" ;;
            *postgres-data*|*redis-data*|*_noo-data)
                if [ "$deep" = true ]; then echo "ask $vol"; else echo "keep $vol"; fi ;;
            *) echo "remove $vol" ;;
        esac
    done
}

# print_plan ASSUME_YES < plan lines: what WILL happen, shown before any
# prompt or removal. Under -y the stateful volumes are removed without a
# question, so the plan says so ("by -y") before it happens: that is the one
# irreversible line of the clean.
print_plan() {
    local yes="$1" act vol
    while read -r act vol; do
        case "$act" in
            remove) echo "  remove  $vol" ;;
            keep)   echo "  keep    $vol" ;;
            ask)
                if [ "$yes" = true ]; then
                    echo "  remove  $vol (stateful, by -y: ALL of its data)"
                else
                    echo "  ask     $vol (stateful)"
                fi ;;
        esac
    done
}

if [ "$REMOVE_VOLUMES" = true ]; then
    echo ""
    PROJECT="$(clean_project)"
    # shellcheck disable=SC2046  # volume names have no spaces
    PLAN="$(plan_volumes "$DEEP_CLEAN" $(stack_volumes "$PROJECT"))"
    ui_step "Volumes of compose project $(ui_emph "$PROJECT") (this install only)"
    if [ -z "$PLAN" ]; then
        ui_note "none"
    else
        # Listed BEFORE anything is asked or removed.
        printf '%s\n' "$PLAN" | print_plan "$ASSUME_YES"
    fi
    TO_REMOVE="$(printf '%s\n' "$PLAN" | awk '$1=="remove"{print $2}')"
    if [ -n "$TO_REMOVE" ] && confirm "Remove the $(printf '%s\n' "$TO_REMOVE" | wc -l | tr -d ' ') volume(s) marked remove?"; then
        for vol in $TO_REMOVE; do
            docker volume rm "$vol" >/dev/null 2>&1 && echo "  Removed $vol"
        done
    fi
    for vol in $(printf '%s\n' "$PLAN" | awk '$1=="ask"{print $2}'); do
        echo ""
        ui_warned "Stateful volume: $(ui_emph "$vol")"
        case "$vol" in
            *postgres-data*) ui_note "$(ui_bad "removing this deletes ALL conversation history, knowledge base, user accounts, and scheduled tasks")" ;;
            *redis-data*)    ui_note "$(ui_bad "removing this clears the LLM response cache and all active sessions")" ;;
            *_noo-data)      ui_note "$(ui_bad "removing this deletes the gateway's ingest staging, audit archive and digest cache (on an install from 0.6.10 on, the data itself lives inside this volume)")" ;;
        esac
        if confirm "Remove $vol?"; then
            docker volume rm "$vol" >/dev/null 2>&1 && ui_done "Removed $vol" && TO_REMOVE="$TO_REMOVE $vol"
        else
            ui_note "kept $vol"
        fi
    done
    # Re-list: a volume this run agreed to remove and that is still there is
    # a failure, never "complete" (a verdict must see what it vouches for).
    STILL=""
    for vol in $TO_REMOVE; do
        stack_volumes "$PROJECT" | grep -qx "$vol" && STILL="$STILL $vol"
    done
    if [ -n "$STILL" ]; then
        ui_close_failed "volume(s) still present after removal:$STILL" "docker volume rm$STILL"
        exit 1
    fi
    ui_done "Volume cleanup complete"
fi

# --- Bind-mounted data directories (deep clean only) ---
# The stateful "volumes" are bind mounts onto the host storage root
# (NOO_DATA_ROOT in .env, NOO_STATE_ROOT for the state set; postgres may be
# redirected via NOO_PG_DATA).
# `docker volume rm` above removes only the volume RECORD — the host
# directory keeps every byte, and the next `up` recreates the volume
# pointing at the same populated dir. This is what turned the 2026-08-06
# "fresh install" into an onboard onto the old database. Wiping is done
# through a throwaway container because the files are owned by container
# uids (postgres runs as 70) and the host user has no sudo path here.
if [ "$DEEP_CLEAN" = true ]; then
    REPO_ROOT="$_REPO_ROOT"
    PG_DATA=""
    if [ -f "$REPO_ROOT/.env" ]; then
        PG_DATA=$(grep -E '^NOO_PG_DATA=' "$REPO_ROOT/.env" | tail -1 | cut -d= -f2-)
    fi
    [ -n "$PG_DATA" ] || PG_DATA="$STATE_ROOT/postgres"

    wipe_data_dir() {
        local dir="$1" label="$2" chown_to="$3"
        [ -d "$dir" ] || return 0
        if [ -z "$(ls -A "$dir" 2>/dev/null)" ]; then
            return 0
        fi
        echo ""
        ui_warned "Data directory not empty: $(ui_emph "$dir") ($label)"
        if [ "$label" = "postgres" ]; then
            ui_note "$(ui_bad "wiping this deletes ALL conversation history, knowledge base, user accounts, and scheduled tasks — the database itself, not just the Docker volume record")"
        fi
        if confirm "Wipe contents of $dir?"; then
            # find -mindepth 1 keeps the mount dir itself; chown makes the
            # empty dir writable by the service uid so the next init works.
            if docker run --rm -v "$dir":/wipe alpine sh -c \
                "find /wipe -mindepth 1 -exec rm -rf {} + 2>/dev/null; chown $chown_to /wipe"; then
                ui_done "Wiped $dir"
            else
                ui_failed "Failed to wipe $dir — remove its contents manually before the next onboard, or it will not be a fresh install"
            fi
        else
            ui_note "kept $dir — the next onboard will run against this data"
        fi
    }

    # uids match what each image runs as (observed on a live install):
    # chainguard postgres = 70, chainguard redis = 65532 (nonroot),
    # nats = host uid 1000.
    wipe_data_dir "$PG_DATA"          "postgres" "70:70"
    wipe_data_dir "$STATE_ROOT/redis"  "redis"    "65532:65532"
    wipe_data_dir "$STATE_ROOT/nats"   "nats"     "1000:1000"
fi

if [ "$REMOVE_IMAGES" = true ]; then
    echo ""
    # The namespace comes from lib-dist.sh, not from a literal here. This
    # filter read `reference=pai-assistant/*` until 2026-09-12 — a namespace
    # this repo stopped building into on 2026-09-06 — so `--images` matched
    # nothing, removed nothing, and printed "Custom images removed". A cleanup
    # that reports success having done nothing is worse than one that fails:
    # the operator moves on believing the disk is reclaimed. Tracker R42.
    #
    # Legacy namespaces are included deliberately: a box onboarded before the
    # rename has layers under the old name that nothing else will ever
    # reference, so this is the only thing that will ever remove them.
    ui_step "Removing locally built images"
    _clean_removed=0
    for _ns in "$(local_image_namespace)" $(legacy_image_namespaces); do
        _found="$(docker image ls --filter "reference=${_ns}/*" --format '{{.Repository}}:{{.Tag}}' 2>/dev/null)"
        [ -n "$_found" ] || continue
        _n="$(printf '%s\n' "$_found" | grep -c .)"
        ui_note "${_ns}/*: ${_n} image(s)"
        printf '%s\n' "$_found" | xargs -r docker image rm 2>/dev/null || true
        _clean_removed=$((_clean_removed + _n))
    done
    if [ "$_clean_removed" -gt 0 ]; then
        ui_done "Removed ${_clean_removed} locally built image(s)"
    else
        # Say which namespaces were searched. "Nothing to remove" is a fine
        # outcome; "nothing matched and you cannot tell whether that is right"
        # is how the last four years of stale layers accumulated.
        ui_note "no locally built images found under $(local_image_namespace)/* or $(legacy_image_namespaces)/*"
    fi
fi

if [ "$DEEP_CLEAN" = true ]; then
    echo ""
    ui_step "Removing all unused images (keeps running containers' images)"
    docker image prune -a -f 2>/dev/null
    ui_done "Unused images removed"

    # --- PKI certificates ---
    PKI_DIR="$(dirname "$(dirname "$(readlink -f "$0")")")/pki"
    if [ -d "$PKI_DIR" ]; then
        echo ""
        ui_warned "PKI certificates found at $PKI_DIR"
        ui_note "removing them forces re-generation on the next noo onboard; every node and browser that trusted the old CA must re-trust"
        if confirm "Remove PKI certificates?"; then
            # Auto-untrust old CA from OS trust store before deleting files
            if command -v noo &>/dev/null; then
                ui_step "Removing the old CA from the OS trust store"
                noo security untrust-ca "$PKI_DIR/ca.crt" --yes 2>/dev/null || true
            else
                ui_note "run noo security untrust-ca to remove the old CA from browsers"
            fi
            rm -rf "$PKI_DIR"
            ui_done "PKI certificates removed — they regenerate on the next setup"
        else
            ui_note "kept PKI certificates"
        fi
    fi

    # --- Secrets ---
    SECRETS_DIR="$(dirname "$(dirname "$(readlink -f "$0")")")/secrets"
    if [ -d "$SECRETS_DIR" ]; then
        echo ""
        ui_warned "Secrets found at $SECRETS_DIR"
        ui_note "$(ui_bad "removing them invalidates all existing sessions, cluster auth tokens, and the admin password")"
        ui_note "new secrets are generated on the next noo onboard"

        # Detect non-Mesh files that should NOT be auto-deleted
        MESH_SECRETS="admin_password.txt jwt_secret.txt agent_review_key.txt controller_secret.txt cluster_secret.txt redis_password.txt nats_password.txt node_agent_token.txt postgres_password.txt mcp_token.txt nats_gateway_password.txt nats_worker_password.txt noo_app_db_password.txt noo_trellion_db_password.txt noo_trellion_ddl_password.txt noo_evolve_db_password.txt age_backup_passphrase.txt backup_passphrase.txt"
        OTHER_FILES=""
        for f in "$SECRETS_DIR"/*; do
            [ -f "$f" ] || continue
            fname="$(basename "$f")"
            is_mesh=false
            for m in $MESH_SECRETS; do
                [ "$fname" = "$m" ] && is_mesh=true && break
            done
            if [ "$is_mesh" = false ]; then
                OTHER_FILES="$OTHER_FILES $fname"
            fi
        done

        if [ -n "$OTHER_FILES" ]; then
            ui_note "non-Mesh files detected (preserved):"
            for f in $OTHER_FILES; do
                ui_note "  $f"
            done
        fi

        if confirm "Remove Mesh-generated secrets?"; then
            # Only delete Mesh-generated secrets, preserve everything else
            for m in $MESH_SECRETS; do
                rm -f "$SECRETS_DIR/$m"
            done
            ui_done "Mesh secrets removed — they regenerate on the next setup"
            if [ -n "$OTHER_FILES" ]; then
                ui_note "preserved:$OTHER_FILES"
            fi
        else
            ui_note "kept secrets"
        fi
    fi
fi

if [ "$CLEAN_HF" = true ]; then
    echo ""
    if [ -d "$WIN_HF_CACHE" ]; then
        # Check if models exist on D: before deleting C: copies
        if [ -n "$DATA_ROOT" ] && [ -d "$DATA_ROOT/hf-cache" ] && [ "$(ls -A "$DATA_ROOT/hf-cache" 2>/dev/null)" ]; then
            HF_SIZE=$(du -sb "$WIN_HF_CACHE" 2>/dev/null | cut -f1)
            ui_step "Cleaning the Windows HuggingFace cache"
            ui_note "models verified under the data root ($DATA_ROOT/hf-cache)"
            ui_note "removing $WIN_HF_CACHE ($(bytes_to_human ${HF_SIZE:-0}))"
            rm -rf "$WIN_HF_CACHE"
            ui_done "Windows HF cache removed"
        else
            ui_warned "Skipping Windows HF cache removal — no models found under the data root"
            ui_note "set NOO_DATA_ROOT and copy models to \$NOO_DATA_ROOT/hf-cache first, then re-run"
        fi
    else
        ui_note "no Windows HF cache found at $WIN_HF_CACHE"
    fi
fi

# --- Space report ---
ui_phase "Disk space"
C_FREE_AFTER=$(disk_free /mnt/c)
if [ -n "$C_FREE_BEFORE" ] && [ -n "$C_FREE_AFTER" ]; then
    C_FREED=$(( C_FREE_AFTER - C_FREE_BEFORE ))
    if (( C_FREED > 0 )); then
        ui_kv "C: drive" "$(ui_good "$(bytes_to_human $C_FREED) freed")  $(ui_muted "now $(bytes_to_human $C_FREE_AFTER) available")"
    else
        ui_kv "C: drive" "$(bytes_to_human $C_FREE_AFTER) available"
    fi
fi
if [ -d "/mnt/d" ]; then
    D_FREE_AFTER=$(disk_free /mnt/d)
    ui_kv "D: drive" "$(bytes_to_human ${D_FREE_AFTER:-0}) available"
fi

ui_close_done "Clean complete"

echo ""
ui_rule
ui_guide_cmd "noo stack start" "start fresh on the existing images"
ui_guide_cmd "noo stack rebuild" "rebuild the custom images first, then start"
ui_guide_cmd "noo stack clean --deep" "also remove all unused images and caches"
ui_guide_cmd "noo stack clean --help" "every option, including what is preserved by default"
