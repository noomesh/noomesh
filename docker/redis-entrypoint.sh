#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Redis entrypoint — keeps the password OFF the command line.
#
# Why this file exists (tracker R27): redis used to be started with
#   command: [--requirepass, "${REDIS_PASSWORD}"]
# in docker-compose.cluster.yml. Compose interpolates that at up-time, so the
# real password ended up in the container's Config.Cmd — readable by anyone who
# can run `docker inspect noo-redis` or read /proc/<pid>/cmdline, which on this
# box is every local user in the docker group and every process in the
# container. It also landed in `docker compose config` output, which operators
# paste into issues.
#
# So: the password arrives as an environment variable (never interpolated into
# a compose command line), this script writes it into a 0600 config file that
# exists only inside the container's own tmpfs-ish /tmp, and redis-server is
# exec'd with the CONFIG FILE as its single argument. Nothing sensitive appears
# in argv, at any layer.
#
# Fail-closed: an empty REDIS_PASSWORD would DISABLE redis auth entirely, so
# this refuses to start rather than come up open. The old compose had a
# `__MISSING_REDIS_PASSWORD_SET_ENV__` placeholder for the same reason; a
# refusal with a readable message beats a container that boots with a password
# nobody knows.
set -eu

# File delivery (an earlier change / the file-backed-secrets plan): when
# REDIS_PASSWORD_FILE names a file, the password is its content, minus one
# trailing newline. Both set is a compose/launcher skew — one of them is
# stale and nothing says which — so refuse rather than pick. Same rule as
# the gateway's `secret_env` and the worker's `noomesh.secret_env`.
if [ -n "${REDIS_PASSWORD_FILE:-}" ]; then
    if [ -n "${REDIS_PASSWORD:-}" ]; then
        echo "redis-entrypoint: both REDIS_PASSWORD and REDIS_PASSWORD_FILE are set — REFUSING to start." >&2
        echo "  Deliver the password ONE way: unset the env value, or the _FILE pointer." >&2
        exit 1
    fi
    if [ ! -r "$REDIS_PASSWORD_FILE" ]; then
        echo "redis-entrypoint: REDIS_PASSWORD_FILE names $REDIS_PASSWORD_FILE, which cannot be read — REFUSING to start." >&2
        exit 1
    fi
    # $(cat) strips every trailing newline; the password cannot end in one
    # anyway (redis reads requirepass to end of line).
    REDIS_PASSWORD=$(cat "$REDIS_PASSWORD_FILE")
fi

if [ -z "${REDIS_PASSWORD:-}" ]; then
    echo "redis-entrypoint: REDIS_PASSWORD is empty — REFUSING to start." >&2
    echo "  An empty requirepass disables redis authentication. Set REDIS_PASSWORD" >&2
    echo "  in the environment (it lives in secrets/env.sops; \`noo stack start\`" >&2
    echo "  loads it) and recreate this container." >&2
    exit 1
fi

CONF="${REDIS_CONF_PATH:-/tmp/redis-noo.conf}"
# umask before the redirect, not chmod after: chmod after creation leaves a
# window in which the file holding the password is world-readable.
umask 077
: > "$CONF"

cat >> "$CONF" <<CONFEOF
appendonly yes
requirepass ${REDIS_PASSWORD}
CONFEOF

# TLS is not optional on the controller and there is no switch here to make it
# optional: the plain port is disabled and client certificates are mandatory.
# Cert material comes from the read-only /tls bind. (The retired NOO_REDIS_TLS
# never gated the server; no client reads it either, 1242 finding 2.)
cat >> "$CONF" <<CONFEOF
tls-port 6379
port 0
tls-cert-file /tls/services/redis/service.crt
tls-key-file /tls/services/redis/service.key
tls-ca-cert-file /tls/ca.crt
tls-auth-clients yes
CONFEOF

# Any extra flags passed as CMD are appended after the config file, which is
# how redis-server itself layers overrides. Nothing in this repo passes any.
exec redis-server "$CONF" "$@"
