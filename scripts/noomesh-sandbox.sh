#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# noo stack sandbox — a throwaway full-stack Mesh, fully isolated from the
# live system.
#
# Isolation model: docker-in-docker. One privileged container runs its own
# inner Docker daemon; the repo (committed files only, via git archive), the
# static `noo` binary, and pre-seeded images go inside. Everything a
# rehearsal does — onboard, .env, secrets, PKI, compose project, data dirs —
# lives and dies inside the container. There is NO code path from the
# sandbox to the live postgres, the live CA, the live compose project, or
# the tailnet (nothing is published; the inner daemon's ports stay inner).
#
# Why DinD and not `compose -p` namespacing: the primary use is the
# FRESH-INSTALL rehearsal, and `noo onboard` legitimately writes the repo
# .env, secrets/, pki/ and starts the default compose project — namespacing
# would need every one of those paths threaded through the wizard. A fresh
# inner machine needs none of that, and doubles as the zero-Python
# bootstrap proof (only the Rust `noo` goes in).
#
# Guarantees: never the live postgres (roles are
# cluster-global only WITHIN one postgres), never the live CA
# or sops file (nothing secret enters: git archive excludes untracked
# files), inner /var/lib/docker on a named volume so image storage lands on
# the volume disk, not the small containerd disk (docker-two-disk split).
#
# Usage:
#   noo stack sandbox up [--fresh]     create + seed (idempotent; --fresh recreates)
#   noo stack sandbox status           container + inner stack state
#   noo stack sandbox run <cmd...>     run a command inside (e.g. `run noo onboard --ci`)
#   noo stack sandbox rehearse [--dist [TAG]]   fresh-install acceptance; --dist
#                                      = pull-only from the published GHCR
#                                      images (track 4), default newest tag
#   noo stack sandbox down [--keep-data]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# release_image_namespace — the one declared home of the registry namespace.
# shellcheck source=lib-dist.sh
. "$REPO_ROOT/scripts/lib-dist.sh"
NAME="noomesh-sandbox"
VOL="noomesh-sandbox-docker"
DIND_IMAGE="${NOO_SANDBOX_DIND_IMAGE:-docker:27-dind}"
APP_DIR="/opt/pai-assistant"

# Presentation via the shared launcher palette (CLI_STYLE_GUIDE §5).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-ui.sh"

die() { ui_failed "$*"; exit 1; }
info() { ui_step "$*"; }
ok() { ui_done "$*"; }

running() { [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = "true" ]; }

# Exec inside the sandbox. -i only (no -t): callable from scripts/agents.
# NOO_REPO_ROOT pins the checkout explicitly (the binary also finds it by
# cwd-walk since the first rehearsal exposed the ~/pai-assistant fallback).
sx() { docker exec -e HOME=/root -e NOO_REPO_ROOT="$APP_DIR" -w "$APP_DIR" "$NAME" "$@"; }

# Last-resort seed: flatten the image via `docker export` (reads the UNPACKED
# snapshot, which exists whenever a container can run — unlike `docker save`,
# which needs the original compressed blobs and emits a manifest-only tar
# once they are content-GC'd) and `docker import` inside with the config
# reconstructed. Loses layer history, keeps runtime behavior. This is what
# rescues dhi.io images: their blobs are GC'd on the host AND the inner
# daemon has no registry auth to pull them.
seed_via_export() {
    local img="$1" cid changes
    cid="$(docker create "$img" 2>/dev/null)" || return 1
    changes="$(docker inspect "$cid" --format '{{json .Config}}' | python3 -c '
import json, shlex, sys
c = json.load(sys.stdin)
out = []
for e in c.get("Env") or []:
    out += ["-c", "ENV " + e]
for key, word in (("User", "USER"), ("WorkingDir", "WORKDIR"), ("StopSignal", "STOPSIGNAL")):
    if c.get(key):
        out += ["-c", word + " " + c[key]]
for p in c.get("ExposedPorts") or {}:
    out += ["-c", "EXPOSE " + p]
for v in c.get("Volumes") or {}:
    out += ["-c", "VOLUME " + v]
for key, word in (("Entrypoint", "ENTRYPOINT"), ("Cmd", "CMD")):
    if c.get(key):
        out += ["-c", word + " " + json.dumps(c[key])]
print(" ".join(shlex.quote(a) for a in out))
')" || { docker rm -f "$cid" >/dev/null 2>&1; return 1; }
    if ! docker export "$cid" | docker exec -i "$NAME" sh -c 'cat > /var/lib/docker/.seed.tar'; then
        docker rm -f "$cid" >/dev/null 2>&1
        return 1
    fi
    docker rm -f "$cid" >/dev/null 2>&1
    docker exec "$NAME" sh -c "docker import $changes /var/lib/docker/.seed.tar '$img' >/dev/null"
}

cmd_up() {
    local fresh=false
    [ "${1:-}" = "--fresh" ] && fresh=true
    if running; then
        if [ "$fresh" = true ]; then
            info "Recreating sandbox (--fresh)..."
            docker rm -f "$NAME" >/dev/null
            docker volume rm "$VOL" >/dev/null 2>&1 || true
        else
            # Idempotent top-up: refresh the staged tree from the current
            # commit and re-seed any images that failed or appeared since.
            info "Sandbox already running — refreshing source tree + image seed..."
            git -C "$REPO_ROOT" archive --format=tar HEAD | docker exec -i "$NAME" tar -x -C "$APP_DIR"
            seed_images
            ok "Sandbox ready. 'noo stack sandbox status' to inspect."
            return 0
        fi
    else
        docker rm -f "$NAME" >/dev/null 2>&1 || true
    fi

    info "Starting inner Docker daemon ($DIND_IMAGE)..."
    # DOCKER_TLS_CERTDIR= disables the dind TLS bootstrap — the inner daemon
    # listens on a unix socket only; nothing is published to the host.
    #
    # NOO_SANDBOX_PUBLISH (optional, e.g. 127.0.0.1:18080:8080) forwards a
    # host port to the inner gateway so a human can open the sandbox
    # dashboard in a browser — the 22-tab visual check for --dist
    # rehearsals. Loopback-only by convention; the sandbox must never be
    # reachable from the LAN or tailnet.
    local publish=()
    [ -n "${NOO_SANDBOX_PUBLISH:-}" ] && publish=(-p "$NOO_SANDBOX_PUBLISH")
    docker run -d --privileged --name "$NAME" \
        -v "$VOL":/var/lib/docker \
        -e DOCKER_TLS_CERTDIR= \
        "${publish[@]}" \
        "$DIND_IMAGE" >/dev/null

    info "Waiting for inner daemon..."
    local i=0
    until docker exec "$NAME" docker info >/dev/null 2>&1; do
        i=$((i+1)); [ "$i" -gt 30 ] && die "inner docker daemon did not come up"
        sleep 1
    done

    info "Installing base tools (bash, git, curl)..."
    docker exec "$NAME" apk add --no-cache bash git curl >/dev/null

    info "Staging the committed source tree at $APP_DIR ..."
    # git archive = committed files only. The live .env, secrets/, pki/ and
    # data can never leak in; the sandbox is a fresh customer checkout.
    docker exec "$NAME" mkdir -p "$APP_DIR"
    git -C "$REPO_ROOT" archive --format=tar HEAD | docker exec -i "$NAME" tar -x -C "$APP_DIR"
    # A fresh checkout is not a git repo after archive; onboard prereqs and
    # scripts expect one.
    sx git init -q
    sx git add -A
    sx git -c user.email=sandbox@mesh -c user.name=sandbox commit -qm "sandbox seed" >/dev/null

    info "Installing the noo binary (static — the zero-Python bootstrap path)..."
    local noo_bin
    noo_bin="$(command -v noo)" || die "no noo binary on PATH to copy in"
    docker cp "$noo_bin" "$NAME:/usr/local/bin/noo"

    info "Seeding images from the host daemon (skips the in-sandbox build)..."
    seed_images

    ok "Sandbox up. Next:"
    echo "  noo stack sandbox rehearse            # scripted fresh-install acceptance"
    echo "  noo stack sandbox run noo onboard --ci --skip-model --skip-channels"
    echo "  noo stack sandbox run bash            # poke around"
    echo "  noo stack sandbox down                # leave no trace"
}

seed_images() {
    # Everything the controller profile resolves that the HOST already has —
    # generic, so new services are picked up automatically. Missing ones
    # simply pull/build inside instead.
    local seeded=0 img
    while IFS= read -r img; do
        [ -n "$img" ] || continue
        if docker image inspect "$img" >/dev/null 2>&1; then
            if ! docker exec "$NAME" docker image inspect "$img" >/dev/null 2>&1; then
                echo "  -> $img"
                # Spool inside /var/lib/docker (the named volume): keeps
                # multi-GB transfers off the small container-layer disk
                # (docker two-disk split on this host). Best-effort per
                # image: a host image whose blobs were content-GC'd emits a
                # manifest-only tar that cannot load (seen live with a
                # months-old dhi alertmanager) — the sandbox just pulls or
                # builds that one itself instead.
                if docker save "$img" | docker exec -i "$NAME" sh -c 'cat > /var/lib/docker/.seed.tar' \
                    && docker exec "$NAME" sh -c 'docker load -i /var/lib/docker/.seed.tar >/dev/null'; then
                    seeded=$((seeded+1))
                elif seed_via_export "$img"; then
                    # Host blobs content-GC'd (docker save = manifest-only
                    # tar) — flattened export/import instead. Layer history
                    # is lost; runtime behavior is preserved.
                    echo "     (flattened via export — host blobs were GC'd)"
                    seeded=$((seeded+1))
                else
                    ui_warned "seed failed — sandbox will try to pull/build it itself"
                fi
                docker exec "$NAME" rm -f /var/lib/docker/.seed.tar
            fi
        fi
    done < <(cd "$REPO_ROOT" && . scripts/lib-compose.sh && docker compose $(compose_file_args .) --profile controller config --images 2>/dev/null | sort -u)
    ok "$seeded image(s) seeded"
}

cmd_status() {
    if ! running; then
        echo "sandbox: not running"
        return 1
    fi
    echo "sandbox: running ($(docker inspect -f '{{.State.StartedAt}}' "$NAME"))"
    echo "inner containers:"
    sx docker ps --format '  {{.Names}}\t{{.Status}}' 2>/dev/null || echo "  (inner daemon not responding)"
}

cmd_run() {
    running || die "sandbox is not running — 'noo stack sandbox up' first"
    [ "$#" -gt 0 ] || die "usage: noo stack sandbox run <cmd...>"
    # Allocate a tty when we have one (interactive bash), stay exec-safe when not.
    if [ -t 0 ] && [ -t 1 ]; then
        docker exec -it -e HOME=/root -e NOO_REPO_ROOT="$APP_DIR" -w "$APP_DIR" "$NAME" "$@"
    else
        sx "$@"
    fi
}

# Seed the PUBLISHED GHCR images for a --dist rehearsal. Pulled on the
# HOST (which holds the GHCR login; the inner daemon deliberately has no
# credentials) and loaded inner under their ghcr.io names, which is what
# docker-compose.dist.yml resolves with pull_policy: missing.
seed_dist_images() {
    local tag="$1" img
    for img in gateway trellion node-agent postgres-pgvector sandbox nvidia-exporter; do
        local ref="$(release_image_namespace)/$img:$tag"
        if docker exec "$NAME" docker image inspect "$ref" >/dev/null 2>&1; then
            continue
        fi
        echo "  -> $ref"
        docker pull -q "$ref" >/dev/null || die "host pull failed for $ref — is this machine logged into GHCR with read:packages?"
        docker save "$ref" | docker exec -i "$NAME" sh -c 'cat > /var/lib/docker/.seed.tar'
        docker exec "$NAME" sh -c 'docker load -i /var/lib/docker/.seed.tar >/dev/null && rm -f /var/lib/docker/.seed.tar'
    done
}

cmd_rehearse() {
    running || die "sandbox is not running — 'noo stack sandbox up' first"
    # `rehearse --dist [TAG]`: the track-4 shape — configure fresh via
    # onboard (no service start), then stand the stack up PULL-ONLY from
    # the published images, exactly as a customer install would.
    local dist=false dist_tag=""
    if [ "${1:-}" = "--dist" ]; then
        dist=true
        dist_tag="${2:-$(git -C "$REPO_ROOT" tag -l 'stack-v*' | sed 's/^stack-//' | sort -V | tail -1)}"
        [ -n "$dist_tag" ] || die "no stack-v* tag found and none given"
    fi
    info "== Fresh-install acceptance rehearsal (inside the sandbox) =="
    info "-- 0/4 reset to pristine (fresh customer machine; seeded images kept)"
    # Rehearsals must be repeatable: strip everything a previous run created
    # (state files, inner containers+volumes, data dirs, sops key) so the
    # wizard's fresh path — not its idempotent re-run guard — is what runs.
    # Brute force, not `compose down` — down without every profile listed
    # skips profiled services and leaves the previous round's containers
    # alive (learned in rehearsal round 8).
    sx bash -c '
        docker ps -aq | xargs -r docker rm -f >/dev/null 2>&1
        docker volume ls -q | xargs -r docker volume rm -f >/dev/null 2>&1
        rm -rf .env secrets pki .sops.yaml .sops.yaml.bak docker-compose.override.yml /root/noo /root/.config/sops /root/.config/mesh
        [ -d noomesh.yaml ] && rm -rf noomesh.yaml; rm -f noomesh.yaml
    '
    if [ "$dist" = true ]; then
        info "-- 1/4 seed published images ($dist_tag) + onboard --ci + start --dist"
        seed_dist_images "$dist_tag"
        sx noo onboard --ci --skip-services --skip-model --skip-channels
        sx bash scripts/noomesh-start.sh --dist --tag "$dist_tag"
    else
        info "-- 1/4 onboard --ci (zero-Python bootstrap; tailscale absent → LAN-only)"
        sx noo onboard --ci --skip-model --skip-channels
    fi
    info "-- 2/4 stack health"
    sx noo stack status || true
    info "-- 3/4 schema plane"
    sx noo db status || true
    sx noo db verify-plane || true
    info "-- 4/4 gateway health endpoint"
    sx curl -kfsS https://localhost:8080/health && echo || sx curl -fsS http://localhost:8080/health && echo || true
    ok "Rehearsal sequence finished — review output above."
}

cmd_down() {
    local keep=false
    [ "${1:-}" = "--keep-data" ] && keep=true
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [ "$keep" = true ]; then
        ok "Sandbox container removed; volume $VOL kept (--keep-data)."
    else
        docker volume rm "$VOL" >/dev/null 2>&1 || true
        ok "Sandbox removed — no trace left."
    fi
}

case "${1:-}" in
    up)       shift; cmd_up "$@";;
    status)   cmd_status;;
    run)      shift; cmd_run "$@";;
    rehearse) shift; cmd_rehearse "$@";;
    down)     shift; cmd_down "$@";;
    *)
        echo "usage: noo stack sandbox up [--fresh] | status | run <cmd...> | rehearse | down [--keep-data]" >&2
        exit 2
        ;;
esac
