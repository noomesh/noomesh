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
# Environment (all optional):
#   NOO_STUDIO_MEM          box memory cap                       (default 10g)
#   NOO_STUDIO_CPUS         box CPU cap                          (default 4)
#   NOO_STUDIO_VHS_IMAGE    recorder image   (default ghcr.io/charmbracelet/vhs:latest)
#   NOO_STUDIO_BASE_IMAGE   box base image                       (default ubuntu:24.04)
#   NOO_DEMO_INSTALL_URL, NOO_DEMO_MASK_NAMES   passed through to the recorder
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BOX=noo-demo-box
REC=noo-demo-recorder
VOL=noo-demo-docker
MEM="${NOO_STUDIO_MEM:-10g}"
CPUS="${NOO_STUDIO_CPUS:-4}"
BASE_IMAGE="${NOO_STUDIO_BASE_IMAGE:-ubuntu:24.04}"
VHS_IMAGE="${NOO_STUDIO_VHS_IMAGE:-ghcr.io/charmbracelet/vhs:latest}"

die() { echo "ERROR: $*" >&2; exit 1; }
need_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || die "docker is not available to this user"; }
box_exists() { docker inspect "$BOX" >/dev/null 2>&1; }
box_is_ours() { [ "$(docker inspect -f '{{index .Config.Labels "noo-demo-box"}}' "$BOX" 2>/dev/null)" = "1" ]; }
box_running() { [ "$(docker inspect -f '{{.State.Running}}' "$BOX" 2>/dev/null)" = "true" ]; }

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

cmd_up() {
  need_docker
  box_exists && die "$BOX already exists; '$0 down' first for a clean one"
  local want avail
  want="$(to_mib "$MEM")"
  avail="$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)"
  [ "$avail" -ge "$want" ] || die "only ${avail} MiB free and the box is capped at ${want} MiB; free memory or lower NOO_STUDIO_MEM (this machine may be serving inference)"
  ensure_image "$BASE_IMAGE"
  docker volume create "$VOL" >/dev/null
  docker run -d --name "$BOX" --hostname node-1 --label noo-demo-box=1 \
    --privileged --cgroupns=private --memory "$MEM" --cpus "$CPUS" \
    -v "$VOL":/var/lib/docker "$BASE_IMAGE" sleep infinity >/dev/null
  echo "box created; installing Docker inside it (a few minutes) ..."
  # Provision as root. Docker's official apt repository; the film starts from "Docker is installed".
  docker exec -i -u root "$BOX" bash -s <<'PROVISION' || { echo "provisioning failed; the box is left for inspection ('$0 down' removes it)" >&2; exit 1; }
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg perl sudo iproute2 >/dev/null
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
# the user the film runs as: generic name, ordinary sudo, in the docker group
id you >/dev/null 2>&1 || useradd -m -s /bin/bash you
usermod -aG docker you
echo 'you ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/you
chmod 440 /etc/sudoers.d/you
# Docker-in-Docker needs the container's cgroup tree split before dockerd starts.
cat > /usr/local/bin/start-dockerd <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  mkdir -p /sys/fs/cgroup/init
  xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
  sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
fi
nohup dockerd > /var/log/dockerd.log 2>&1 &
for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done
echo "dockerd did not come up; see /var/log/dockerd.log" >&2
exit 1
EOS
chmod 755 /usr/local/bin/start-dockerd
/usr/local/bin/start-dockerd
PROVISION
  # prove the stranger's view before declaring it ready
  docker exec -u you "$BOX" sh -c 'docker info >/dev/null 2>&1 || sg docker -c "docker info >/dev/null"' \
    || die "the box's own Docker does not answer for user 'you'"
  echo "box ready: host $(docker exec "$BOX" hostname), user you, own Docker engine ($(docker exec "$BOX" docker --version))"
  echo "next: $0 record --smoke   (then, once the release is public: $0 record)"
}

cmd_record() {
  need_docker
  box_exists || die "no box; run '$0 up' first"
  box_is_ours || die "container $BOX is not a film box (no label noo-demo-box=1); refusing to use it"
  box_running || die "the box is stopped; '$0 down' and '$0 up' for a fresh one"
  docker exec -u root "$BOX" sh -c 'docker info >/dev/null 2>&1' || docker exec -u root "$BOX" /usr/local/bin/start-dockerd
  ensure_image "$VHS_IMAGE"
  docker rm -f "$REC" >/dev/null 2>&1 || true
  mkdir -p "$ROOT/demo-out"
  # The recorder drives the box through the host's Docker socket (so it can
  # `docker exec` into the box); that socket is root on this host, and this
  # container is ours and short-lived. The host's docker CLI is mounted in.
  local passenv=() v
  for v in NOO_DEMO_INSTALL_URL NOO_DEMO_MASK_NAMES; do
    [ -z "${!v:-}" ] || passenv+=(-e "$v=${!v}")
  done
  docker run --rm --name "$REC" --cpus 2 \
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
  echo "studio is down"
}

cmd_status() {
  need_docker
  if box_exists; then
    echo "box: $(docker inspect -f '{{.State.Status}}' "$BOX") (host $(docker exec "$BOX" hostname 2>/dev/null || echo '?'))"
    docker exec -u you "$BOX" sh -c 'command -v noo >/dev/null 2>&1 && echo "noo installed: $(noo --version 2>&1 | head -1)" || echo "noo: not installed (clean)"' 2>/dev/null || true
  else
    echo "box: none"
  fi
  docker volume inspect "$VOL" >/dev/null 2>&1 && echo "volume: $VOL ($(docker run --rm -v "$VOL":/v --entrypoint du "$BASE_IMAGE" -sh /v 2>/dev/null | cut -f1))" || echo "volume: none"
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
  -h|--help|"") sed -n '4,38p' "$0"; [ -n "$sub" ] || exit 2 ;;
  *) die "unknown command '$sub' (up | record | down | status | shell)" ;;
esac
