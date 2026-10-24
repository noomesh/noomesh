#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# The film studio: shoot the onboarding film in a throwaway "stranger" box.
#
#   scripts/demo/studio.sh up                  # make the box (Ubuntu 24.04 + its own Docker)
#   scripts/demo/studio.sh record [--smoke] [--speed N]   # film it; GIF + MP4 land in demo-out/
#   scripts/demo/studio.sh shell               # look around inside the box
#   scripts/demo/studio.sh status
#   scripts/demo/studio.sh down                # delete the box and its Docker volume
#   scripts/demo/studio.sh cache up|down|purge|status   # a pull-through cache of ghcr.io (see below)
#
# Two containers do the work. The BOX is a clean Ubuntu 24.04 with its own
# Docker engine (Docker-in-Docker), host name node-1 and a user named "you", so
# nothing the film shows is a real name, and the stack the film onboards lives
# and dies inside it. The RECORDER is the vhs container; it types into the box
# with `docker exec`, so vhs, Chromium and ffmpeg never touch the box. The
# recorder script (record-onboarding.sh) does the masking, the leak check and
# the failed-step check exactly as it does on a bare machine.
#
# What it costs: the box is --privileged (it runs a Docker engine), holds the
# stack's images (about 10 GB, in a named volume) and gets a memory cap
# (NOO_STUDIO_MEM, default 10g). The chat step in the film runs a model on the
# box's CPU and is slow. Do not shoot on a machine that is busy serving
# inference; `up` refuses when free memory is below the cap.
#
# The real film fetches the install URL anonymously, so it needs the public
# release. `record --smoke` needs nothing public and proves the whole chain.
#
# The CACHE (optional): `cache up` runs a pull-through cache of ghcr.io on this
# host (the registry image in proxy mode, its blobs in a named volume that
# survives `down`). A box made while the cache runs resolves ghcr.io to the
# cache and trusts the cache's own throwaway CA for that name, so every pull
# the film shows is a real `docker pull ghcr.io/...` whose bytes come over the
# LAN after the first fill. Nothing else changes in the box: Docker Engine
# mirrors only Docker Hub (`registry-mirrors`), and ignores containerd's
# hosts.toml for other registries, so answering AS ghcr.io is the one
# transparent route. The stack's lock pins every image by digest, so a cached
# image cannot differ from the public one. The install itself (`curl | sh`
# from the release repo) is not cached. `cache purge` deletes the blobs.
#
# Environment (all optional):
#   NOO_STUDIO_MEM          box memory cap                       (default 10g)
#   NOO_STUDIO_CPUS         box CPU cap                          (default 4)
#   NOO_STUDIO_REC_MEM      recorder memory cap                  (default 6g)
#   NOO_STUDIO_VHS_IMAGE    recorder image   (default ghcr.io/charmbracelet/vhs:latest)
#   NOO_STUDIO_BASE_IMAGE   box base image (systemd + Docker go on top) (default ubuntu:24.04)
#   NOO_STUDIO_CACHE_IMAGE  pull-through cache image             (default registry:3)
#   NOO_DEMO_INSTALL_URL, NOO_DEMO_MASK_NAMES, NOO_DEMO_CLI_VERSION   passed through to the recorder
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BOX=noo-demo-box
REC=noo-demo-recorder
VOL=noo-demo-docker
# containerd's own root: with Docker as a systemd unit, dockerd uses the
# containerd.io service (not an embedded one under /var/lib/docker), and its
# snapshots cannot live on the box's overlay rootfs (overlay on overlay: every
# container create failed with "failed to mount /tmp/containerd-mount…",
# take 8). A second volume, removed with the first.
CONTAINERD_VOL=noo-demo-containerd
MEM="${NOO_STUDIO_MEM:-10g}"
CPUS="${NOO_STUDIO_CPUS:-4}"
BASE_IMAGE="${NOO_STUDIO_BASE_IMAGE:-ubuntu:24.04}"
VHS_IMAGE="${NOO_STUDIO_VHS_IMAGE:-ghcr.io/charmbracelet/vhs:latest}"
CACHE=noo-demo-cache
CACHE_VOL=noo-demo-cache
CACHE_NET=noo-demo
# registry:3 (distribution 3.x): registry:2 is built on go1.20 and its upstream
# dial to ghcr.io failed blobs with HTTP/2 PROTOCOL_ERROR (2026-10-23).
CACHE_IMAGE="${NOO_STUDIO_CACHE_IMAGE:-registry:3}"
CACHE_DIR="$ROOT/demo-out/cache"   # the cache's throwaway CA and its ghcr.io leaf (git-ignored)
CACHE_UPSTREAM=https://ghcr.io

die() { echo "ERROR: $*" >&2; exit 1; }
need_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || die "docker is not available to this user"; }
# `--type container` everywhere: `docker inspect NAME` also matches a VOLUME of
# that name, and the cache volume IS called noo-demo-cache (2026-10-24: a seeded
# volume made `cache up` refuse "not the studio's cache").
box_exists() { docker inspect --type container "$BOX" >/dev/null 2>&1; }
box_is_ours() { [ "$(docker inspect --type container -f '{{index .Config.Labels "noo-demo-box"}}' "$BOX" 2>/dev/null)" = "1" ]; }
box_running() { [ "$(docker inspect --type container -f '{{.State.Running}}' "$BOX" 2>/dev/null)" = "true" ]; }
cache_exists() { docker inspect --type container "$CACHE" >/dev/null 2>&1; }
cache_is_ours() { [ "$(docker inspect --type container -f '{{index .Config.Labels "noo-demo-cache"}}' "$CACHE" 2>/dev/null)" = "1" ]; }
cache_running() { cache_is_ours && [ "$(docker inspect --type container -f '{{.State.Running}}' "$CACHE" 2>/dev/null)" = "true" ]; }
cache_ip() { docker inspect --type container -f "{{(index .NetworkSettings.Networks \"$CACHE_NET\").IPAddress}}" "$CACHE" 2>/dev/null; }
# The cache answers AS ghcr.io, so it needs a certificate for that name. A
# throwaway CA of its own signs it; the box trusts that CA (system store and
# /etc/docker/certs.d/ghcr.io) and nothing else does. Keys never leave demo-out/.
cache_certs() {
  command -v openssl >/dev/null 2>&1 || die "openssl is needed to make the cache's certificate"
  mkdir -p "$CACHE_DIR"; chmod 700 "$CACHE_DIR"
  [ -s "$CACHE_DIR/ca.crt" ] && [ -s "$CACHE_DIR/ghcr.crt" ] && [ -s "$CACHE_DIR/ghcr.key" ] && return 0
  (
    cd "$CACHE_DIR"
    umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -keyout ca.key -out ca.crt -subj "/CN=noo demo cache (throwaway CA)" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout ghcr.key -out ghcr.csr -subj "/CN=ghcr.io" >/dev/null 2>&1
    printf 'subjectAltName=DNS:ghcr.io\nextendedKeyUsage=serverAuth\n' > ghcr.ext
    openssl x509 -req -in ghcr.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
      -extfile ghcr.ext -out ghcr.crt >/dev/null 2>&1
    rm -f ghcr.csr ghcr.ext ca.srl
    chmod 644 ca.crt ghcr.crt
  ) || die "could not make the cache's certificate"
}

# "10g" / "512m" -> MiB
to_mib() {
  case "$1" in
    *[gG]) echo $(( ${1%[gG]} * 1024 )) ;;
    *[mM]) echo "${1%[mM]}" ;;
    *) die "NOO_STUDIO_MEM must look like 10g or 512m (got '$1')" ;;
  esac
}

# Public base images need no login; a stale login in ~/.docker/config.json makes
# the pull fail ("personal access token is expired"). Pull anonymously.
pull_anon() {
  local d; d="$(mktemp -d)"; echo '{}' > "$d/config.json"
  DOCKER_CONFIG="$d" docker pull -q "$1" >/dev/null || { rm -rf "$d"; die "cannot pull $1"; }
  rm -rf "$d"
}
ensure_image() { docker image inspect "$1" >/dev/null 2>&1 || pull_anon "$1"; }

# The box image: the base plus systemd as init, Docker from Docker's apt
# repository, and the film's user. Built once on this host (cached by Docker's
# build cache; `docker rmi` it to rebuild) so a new box boots in seconds. The
# film starts from "Docker is installed"; it never shows this.
BOX_IMAGE="noo-demo-box:base"
build_box_image() {
  docker build -q -t "$BOX_IMAGE" --build-arg "BASE=$BASE_IMAGE" -f - "$ROOT/scripts/demo" >/dev/null <<'DOCKERFILE' || die "could not build $BOX_IMAGE"
ARG BASE=ubuntu:24.04
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update -qq \
 && apt-get install -y -qq systemd systemd-sysv dbus ca-certificates curl gnupg perl sudo iproute2 >/dev/null \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && . /etc/os-release \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list \
 && apt-get update -qq \
 && apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash you && usermod -aG docker you \
 && echo 'you ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/you && chmod 440 /etc/sudoers.d/you \
 && systemctl enable docker >/dev/null 2>&1 \
 && systemctl mask getty@tty1.service tmp.mount >/dev/null 2>&1 \
 && mkdir -p /var/lib/systemd/linger && touch /var/lib/systemd/linger/you
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKERFILE
}

# box_wait_booted: systemd reports the box up and docker.service answers.
box_wait_booted() {
  local i
  for i in $(seq 1 90); do
    if docker exec "$BOX" systemctl is-system-running >/dev/null 2>&1 || [ "$(docker exec "$BOX" systemctl is-system-running 2>/dev/null)" = degraded ]; then
      # logind lingers `you` (touched at build): the user manager must be up so
      # `systemctl --user` works for the film's shell, as after a real login.
      docker exec "$BOX" docker info >/dev/null 2>&1 \
        && docker exec "$BOX" systemctl is-active "user@$(docker exec "$BOX" id -u you)" >/dev/null 2>&1 && return 0
    fi
    sleep 2
  done
  docker exec "$BOX" systemctl --failed --no-pager 2>&1 | head -20 >&2
  return 1
}

cmd_up() {
  need_docker
  box_exists && die "$BOX already exists; '$0 down' first for a clean one"
  local want avail
  want="$(to_mib "$MEM")"
  avail="$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)"
  [ "$avail" -ge "$want" ] || die "only ${avail} MiB free and the box is capped at ${want} MiB; free memory or lower NOO_STUDIO_MEM (this machine may be serving inference)"
  ensure_image "$BASE_IMAGE"
  build_box_image
  docker volume create "$VOL" >/dev/null
  docker volume create "$CONTAINERD_VOL" >/dev/null
  # With the cache up, the box is born on the cache's network with ghcr.io
  # pointing at it; the CA is installed once Docker is in. Without it, the
  # box is exactly a stranger's machine on the default network.
  local via_cache=() cache_ip=""
  if cache_running; then
    cache_ip="$(cache_ip)"
    [ -n "$cache_ip" ] || die "the cache runs but has no address on network $CACHE_NET; '$0 cache down' and 'cache up'"
    via_cache=(--network "$CACHE_NET" --add-host "ghcr.io:$cache_ip")
  fi
  # systemd is PID 1 (see build_box_image): /run and /run/lock are tmpfs as on
  # a booted machine, the cgroup namespace is the box's own, and the stop
  # signal is systemd's. /tmp stays on the rootfs: tmp.mount is masked in the
  # image, because a tmpfs systemd mounts inside the box is invisible to
  # `docker cp`, which the recorder uses to collect the logs from /tmp/demo. dockerd is then docker.service, not a hand-started
  # daemon, and the host node agent and noo-hostd the film installs run as
  # units, as they do on a real Ubuntu box.
  docker run -d --name "$BOX" --hostname node-1 --label noo-demo-box=1 \
    --privileged --cgroupns=private --memory "$MEM" --cpus "$CPUS" \
    --tmpfs /run --tmpfs /run/lock -e container=docker \
    "${via_cache[@]}" \
    -v "$VOL":/var/lib/docker -v "$CONTAINERD_VOL":/var/lib/containerd "$BOX_IMAGE" >/dev/null
  echo "box created; booting systemd and Docker inside it ..."
  box_wait_booted || { echo "the box did not boot; it is left for inspection ('$0 down' removes it)" >&2; exit 1; }
  if [ -n "$cache_ip" ]; then
    # Trust the cache's CA for ghcr.io: the system store (anything in the box
    # that fetches from ghcr.io over TLS) and Docker's per-registry store.
    docker cp "$CACHE_DIR/ca.crt" "$BOX":/usr/local/share/ca-certificates/noo-demo-cache.crt
    docker exec -u root "$BOX" sh -c 'update-ca-certificates >/dev/null 2>&1 && install -d -m 755 /etc/docker/certs.d/ghcr.io && cp /usr/local/share/ca-certificates/noo-demo-cache.crt /etc/docker/certs.d/ghcr.io/ca.crt' \
      || die "could not install the cache's CA in the box"
    # Prove the box reaches the cache as ghcr.io before anyone films a pull.
    docker exec -u root "$BOX" curl -fsS -o /dev/null -w '%{http_code}' https://ghcr.io/v2/ 2>/dev/null | grep -qE '^(200|401)$' \
      || die "the box cannot reach the cache as ghcr.io (https://ghcr.io/v2/ did not answer 200 or 401)"
  fi
  # prove the stranger's view before declaring it ready
  docker exec -u you "$BOX" sh -c 'docker info >/dev/null 2>&1 || sg docker -c "docker info >/dev/null"' \
    || die "the box's own Docker does not answer for user 'you'"
  echo "box ready: host $(docker exec "$BOX" hostname), user you, systemd $(docker exec "$BOX" systemctl is-system-running 2>/dev/null || echo '?'), own Docker engine ($(docker exec "$BOX" docker --version))"
  [ -z "$cache_ip" ] || echo "ghcr.io in the box is the cache ($CACHE at $cache_ip); the first pull of each image fills it"
  echo "next: $0 record --smoke   (then, once the release is public: $0 record)"
}

cmd_record() {
  need_docker
  box_exists || die "no box; run '$0 up' first"
  box_is_ours || die "container $BOX is not a film box (no label noo-demo-box=1); refusing to use it"
  box_running || die "the box is stopped; '$0 down' and '$0 up' for a fresh one"
  docker exec -u root "$BOX" sh -c 'docker info >/dev/null 2>&1' || docker exec -u root "$BOX" systemctl start docker
  ensure_image "$VHS_IMAGE"
  docker rm -f "$REC" >/dev/null 2>&1 || true
  mkdir -p "$ROOT/demo-out"
  # The recorder drives the box through the host's Docker socket (so it can
  # `docker exec` into the box); that socket is root on this host, and this
  # container is ours and short-lived. The host's docker CLI is mounted in.
  local passenv=() v
  for v in NOO_DEMO_INSTALL_URL NOO_DEMO_MASK_NAMES NOO_DEMO_CLI_VERSION; do
    [ -z "${!v:-}" ] || passenv+=(-e "$v=${!v}")
  done
  # The recorder is capped: vhs's render is the memory peak of a take, and an
  # uncapped one took a 19 GiB WSL2 host down twice (2026-10-23). The GIF is
  # no longer rendered by vhs at all (record-onboarding.sh makes it from the
  # MP4, streaming), so the cap is a backstop, not the budget.
  docker run --rm --name "$REC" --cpus 2 --memory "${NOO_STUDIO_REC_MEM:-6g}" \
    -v "$ROOT":/work -w /work \
    -v "$(command -v docker)":/usr/local/bin/docker:ro \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e NOO_DEMO_BOX="$BOX" "${passenv[@]}" \
    --entrypoint bash "$VHS_IMAGE" -c '
      scripts/demo/record-onboarding.sh "$@"; rc=$?
      chown -R "'"$(id -u):$(id -g)"'" demo-out 2>/dev/null || true
      exit $rc' _ "$@"
}

cmd_down() {
  need_docker
  docker rm -f "$REC" >/dev/null 2>&1 || true
  if box_exists; then
    box_is_ours || die "container $BOX is not a film box (no label noo-demo-box=1); not removing it"
    docker rm -f "$BOX" >/dev/null
    echo "removed $BOX"
  fi
  if docker volume inspect "$VOL" >/dev/null 2>&1; then docker volume rm "$VOL" >/dev/null && echo "removed volume $VOL"; fi
  if docker volume inspect "$CONTAINERD_VOL" >/dev/null 2>&1; then docker volume rm "$CONTAINERD_VOL" >/dev/null && echo "removed volume $CONTAINERD_VOL"; fi
  echo "studio is down"
}

cmd_status() {
  need_docker
  if box_exists; then
    echo "box: $(docker inspect --type container -f '{{.State.Status}}' "$BOX") (host $(docker exec "$BOX" hostname 2>/dev/null || echo '?'))"
    docker exec -u you "$BOX" sh -c 'command -v noo >/dev/null 2>&1 && echo "noo installed: $(noo --version 2>&1 | head -1)" || echo "noo: not installed (clean)"' 2>/dev/null || true
  else
    echo "box: none"
  fi
  docker volume inspect "$VOL" >/dev/null 2>&1 && echo "volume: $VOL ($(docker run --rm -v "$VOL":/v --entrypoint du "$BASE_IMAGE" -sh /v 2>/dev/null | cut -f1))" || echo "volume: none"
}

cmd_cache_up() {
  need_docker
  if cache_exists; then
    cache_is_ours || die "container $CACHE is not the studio's cache (no label noo-demo-cache=1); refusing to use it"
    cache_running || docker start "$CACHE" >/dev/null
    echo "cache up: $CACHE at $(cache_ip) on network $CACHE_NET (volume $CACHE_VOL)"
    return 0
  fi
  cache_certs
  docker network inspect "$CACHE_NET" >/dev/null 2>&1 || docker network create "$CACHE_NET" >/dev/null
  docker volume create "$CACHE_VOL" >/dev/null
  ensure_image "$CACHE_IMAGE"
  # Proxy mode: a pull of a name the cache has not seen is fetched from the
  # upstream (anonymously; public images only) and kept. :443 with the ghcr.io
  # leaf, because the box reaches it under that name.
  docker run -d --name "$CACHE" --label noo-demo-cache=1 --network "$CACHE_NET" --restart unless-stopped \
    -v "$CACHE_VOL":/var/lib/registry -v "$CACHE_DIR":/certs:ro \
    -e REGISTRY_PROXY_REMOTEURL="$CACHE_UPSTREAM" \
    -e REGISTRY_HTTP_ADDR=:443 \
    -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/ghcr.crt \
    -e REGISTRY_HTTP_TLS_KEY=/certs/ghcr.key \
    "$CACHE_IMAGE" >/dev/null
  local i
  for i in $(seq 1 30); do
    docker exec "$CACHE" sh -c 'nc -z 127.0.0.1 443' >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$CACHE" sh -c 'nc -z 127.0.0.1 443' >/dev/null 2>&1 || { docker logs "$CACHE" 2>&1 | tail -5 >&2; die "the cache did not start listening on :443"; }
  echo "cache up: $CACHE at $(cache_ip) on network $CACHE_NET, proxying $CACHE_UPSTREAM into volume $CACHE_VOL"
  echo "next: $0 up   (a box made now pulls ghcr.io through the cache)"
}

cmd_cache_down() {
  need_docker
  if cache_exists; then
    cache_is_ours || die "container $CACHE is not the studio's cache (no label noo-demo-cache=1); not removing it"
    box_exists && echo "note: the box resolves ghcr.io to this cache; its pulls fail until 'cache up' (same address) or a fresh box" >&2
    docker rm -f "$CACHE" >/dev/null
    echo "removed $CACHE (the blobs stay in volume $CACHE_VOL; 'cache purge' deletes them)"
  else
    echo "cache: none"
  fi
}

cmd_cache_purge() {
  cmd_cache_down
  if docker volume inspect "$CACHE_VOL" >/dev/null 2>&1; then docker volume rm "$CACHE_VOL" >/dev/null && echo "removed volume $CACHE_VOL"; fi
  rm -rf "$CACHE_DIR" && echo "removed the cache's certificates"
  docker network inspect "$CACHE_NET" >/dev/null 2>&1 && docker network rm "$CACHE_NET" >/dev/null 2>&1 && echo "removed network $CACHE_NET"
  echo "cache is gone"
}

cmd_cache_status() {
  need_docker
  if cache_exists; then
    echo "cache: $(docker inspect --type container -f '{{.State.Status}}' "$CACHE") at $(cache_ip) on network $CACHE_NET$(cache_is_ours || echo ' (NOT the studio'"'"'s: no label)')"
  else
    echo "cache: none"
  fi
  docker volume inspect "$CACHE_VOL" >/dev/null 2>&1 && echo "volume: $CACHE_VOL ($(docker run --rm -v "$CACHE_VOL":/v --entrypoint du "$BASE_IMAGE" -sh /v 2>/dev/null | cut -f1))" || echo "volume: none"
  if box_exists; then
    docker exec "$BOX" grep -q '^[0-9.]* *ghcr.io$' /etc/hosts 2>/dev/null && echo "box: ghcr.io goes through the cache" || echo "box: ghcr.io is the real one"
  fi
}

cmd_cache() {
  local verb="${1:-}"; [ $# -eq 0 ] || shift
  case "$verb" in
    up) cmd_cache_up ;;
    down) cmd_cache_down ;;
    purge) cmd_cache_purge ;;
    status) cmd_cache_status ;;
    *) die "unknown cache command '$verb' (up | down | purge | status)" ;;
  esac
}

cmd_shell() {
  need_docker; box_exists || die "no box; run '$0 up' first"; box_is_ours || die "not a film box"
  exec docker exec -it -u you -w /home/you "$BOX" bash -l
}

sub="${1:-}"; [ $# -eq 0 ] || shift
case "$sub" in
  up) cmd_up ;;
  record) cmd_record "$@" ;;
  down) cmd_down ;;
  status) cmd_status ;;
  shell) cmd_shell ;;
  cache) cmd_cache "$@" ;;
  -h|--help|"") awk 'NR>=4 { if (/^set -euo pipefail/) exit; print }' "$0"; [ -n "$sub" ] || exit 2 ;;
  *) die "unknown command '$sub' (up | record | down | status | shell | cache)" ;;
esac
