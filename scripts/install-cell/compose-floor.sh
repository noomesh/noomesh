#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# The lowest supported Compose (operator, 2026-11-21: Docker Engine 28 and
# Compose 2.33 are the supported minimums). The upgrade job's `compose-floor`
# leg runs the runner's docker-ce engine with THIS pinned Compose plugin, not
# the newer one the image ships. Run as root (`sudo bash compose-floor.sh`).
#
# The URL and the sha256 are both pinned; the sha256 is the one docker/compose
# publishes for the asset (v2.33.1's docker-compose-linux-x86_64.sha256 and its
# checksums.txt agree). The download is verified BEFORE it is installed: a
# mismatch exits 1 and installs nothing.
#
# Installed in two places, so every way the cell invokes docker finds it:
#   $HOME/.docker/cli-plugins/docker-compose  (the runner user; searched first)
#   /usr/local/lib/docker/cli-plugins/docker-compose  (system-wide: covers the
#     `sudo -n docker` fallback, where HOME is root's)
# Both come before the image's /usr/libexec and /usr/lib plugin dirs.
set -u
COMPOSE_VERSION="2.33.1"
COMPOSE_URL="https://github.com/docker/compose/releases/download/v2.33.1/docker-compose-linux-x86_64"
COMPOSE_SHA256="3efda1ad6caed49dedd5644cadbf7e0c9cc3d74d8844ca5237b6a43ac1ef1a46"
# COMPOSE_URL_OVERRIDE: tests only (a file:// or local path stand-in)
COMPOSE_URL="${COMPOSE_URL_OVERRIDE:-$COMPOSE_URL}"

who="${SUDO_USER:-runner}"
uhome="$(getent passwd "$who" | cut -d: -f6)"
[ -n "$uhome" ] || { echo "COMPOSE-FLOOR FAIL: no home for user $who"; exit 1; }
tmp="$(mktemp -d)" || exit 1
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/docker-compose" "$COMPOSE_URL" || { echo "COMPOSE-FLOOR FAIL: could not download $COMPOSE_URL"; exit 1; }
got="$(sha256sum "$tmp/docker-compose" | cut -d' ' -f1)"
if [ "$got" != "$COMPOSE_SHA256" ]; then
    echo "COMPOSE-FLOOR FAIL: sha256 mismatch for $COMPOSE_URL: got $got, pinned $COMPOSE_SHA256; nothing installed"
    exit 1
fi
echo "compose $COMPOSE_VERSION sha256 verified: $got"
install -D -m 0755 "$tmp/docker-compose" /usr/local/lib/docker/cli-plugins/docker-compose || exit 1
install -d -o "$who" -m 0755 "$uhome/.docker" "$uhome/.docker/cli-plugins" || exit 1
install -o "$who" -m 0755 "$tmp/docker-compose" "$uhome/.docker/cli-plugins/docker-compose" || exit 1
# what each invocation path now reports
u="$(sudo -n -u "$who" -H docker compose version --short 2>&1 | head -1)"
r="$(docker compose version --short 2>&1 | head -1)"
echo "docker compose version: user $who: ${u:-none}; root: ${r:-none}"
[ "${u#v}" = "$COMPOSE_VERSION" ] && [ "${r#v}" = "$COMPOSE_VERSION" ] \
    || { echo "COMPOSE-FLOOR FAIL: docker compose does not report the pinned $COMPOSE_VERSION"; exit 1; }
