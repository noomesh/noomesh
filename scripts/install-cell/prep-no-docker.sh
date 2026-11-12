#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# prep-no-docker.sh: the install matrix's `docker: none` prep (i677).
#
# A hosted runner ships Docker and Compose. A stranger's fresh Ubuntu box does
# not. This removes them (packages, daemon, socket, CLI plugins, apt sources,
# the docker group) and then PROVES they are gone, so the onboard that follows
# meets the box a stranger has. Getting Docker back is not done here: whatever
# the wizard or the docs tell a stranger to do about it is part of the run.
#
# Called by run.sh as a plain executable with OUT/CELL/... in the environment.
set -uo pipefail
# shellcheck source=scripts/install-cell/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

meta limits "docker removed before the run (the runner image ships it; a stranger's box does not)"

step remove-docker 600 -- sudo bash -c '
set -u
systemctl stop docker.socket docker.service containerd.service 2>/dev/null || true
systemctl disable docker.socket docker.service containerd.service 2>/dev/null || true
pkgs="$(dpkg-query -W -f="\${Package} \${Status}\n" 2>/dev/null \
    | awk "\$NF==\"installed\" && \$1 ~ /^(docker|moby|containerd|runc)/ {print \$1}" | sort -u | tr "\n" " ")"
echo "installed docker packages: ${pkgs:-none}"
if [ -n "$pkgs" ]; then
    DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $pkgs >/dev/null 2>&1; echo "purge rc=$?"
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq >/dev/null 2>&1 || true
fi
rm -f /usr/local/bin/docker /usr/local/bin/docker-compose /usr/bin/docker-compose
rm -rf /usr/libexec/docker /usr/local/lib/docker /usr/lib/docker/cli-plugins /etc/docker
rm -f /etc/apt/sources.list.d/*docker* /etc/apt/sources.list.d/*moby* /etc/apt/keyrings/docker* /usr/share/keyrings/docker*
rm -rf /var/lib/docker /var/lib/containerd /run/docker.sock /var/run/docker.sock
getent group docker >/dev/null && groupdel docker && echo "docker group removed"
rm -rf "/home/${SUDO_USER:-runner}/.docker"
echo done
'

# The proof: each line must read "absent". Anything else stops the cell, since
# a run on a box that still has Docker measures the wrong thing.
step prove-no-docker 60 -- bash -c '
hash -r
bad=0
say() { echo "$1: $2"; [ "$2" = absent ] || bad=1; }
say "docker binary"   "$(command -v docker >/dev/null 2>&1 && echo "present ($(command -v docker))" || echo absent)"
say "docker compose"  "$(docker compose version >/dev/null 2>&1 && echo present || echo absent)"
say "docker-compose"  "$(command -v docker-compose >/dev/null 2>&1 && echo present || echo absent)"
say "docker.service"  "$(systemctl is-active docker.service 2>/dev/null | grep -qx active && echo active || echo absent)"
say "docker socket"   "$([ -S /var/run/docker.sock ] && echo present || echo absent)"
say "docker group"    "$(getent group docker >/dev/null && echo present || echo absent)"
say "docker packages" "$(dpkg-query -W -f="\${Package} \${Status}\n" 2>/dev/null | awk "\$NF==\"installed\" && \$1 ~ /^(docker|moby|containerd)/" | grep -q . && echo present || echo absent)"
echo "git: $(git --version 2>/dev/null || echo absent) (left as is: Ubuntu server ships it; i677-3 is measured by a checkout-less onboard)"
exit $bad
' || exit 1
exit 0
