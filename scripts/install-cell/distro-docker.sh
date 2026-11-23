#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# The distro engine a stranger gets from `apt install docker.io`, not the
# runner image's docker-ce/moby. ONE home for both users: run.sh's
# DOCKER=distro cells and the upgrade job's `distro` leg (install-matrix.yml).
# Run as root (`sudo bash distro-docker.sh`). Removes the image's engine
# packages, installs Ubuntu's docker.io + docker-compose-v2, and FAILs by name
# unless the engine now running is the docker.io package's.
set -u
systemctl stop docker.socket docker.service containerd.service 2>/dev/null
engines="$(dpkg-query -W -f "\${Package}\n" "docker-ce*" "docker-buildx-plugin" "docker-compose-plugin" "containerd.io" "moby-*" 2>/dev/null | sort -u | tr "\n" " ")"
echo "image engine packages: ${engines:-none}"
[ -z "${engines// /}" ] || DEBIAN_FRONTEND=noninteractive apt-get remove -y -q $engines >/dev/null || { echo "could not remove the image engine"; exit 1; }
apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2 >/dev/null || { echo "apt could not install docker.io docker-compose-v2"; exit 1; }
systemctl enable --now docker.service >/dev/null 2>&1
usermod -aG docker "${SUDO_USER:-runner}" 2>/dev/null
t=0; until docker info >/dev/null 2>&1 || [ $t -ge 60 ]; do sleep 2; t=$((t+2)); done
pkg="$(dpkg-query -W -f "\${Version}" docker.io 2>/dev/null)"
# What the archive offers (the first run, 2026-11-13, found 29.1.3 on
# 22.04, not the 27.x assumed): a future pin can only pick from these.
apt-cache madison docker.io 2>/dev/null | head -6 | sed "s/^/available: /"
echo "docker.io package: ${pkg:-NOT INSTALLED}"
docker version 2>&1 | sed -n "/^Server/,\$p" | head -8
docker compose version 2>&1 | head -1
left="$(dpkg-query -W -f "\${Package} \${Status}\n" "docker-ce" "moby-engine" 2>/dev/null | grep -c " installed$")"
srv="$(docker version --format "{{.Server.Version}}" 2>/dev/null)"
echo "engine: server ${srv:-none}, from docker.io ${pkg:-none}, image engines still installed: $left"
[ -n "$pkg" ] && [ -n "$srv" ] && [ "$left" = 0 ] || { echo "DISTRO-DOCKER FAIL: the engine running is not Ubuntu docker.io"; exit 1; }
