#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# lib-instance.sh — per-instance namespace derivation.
#
# One instance = one checkout + one NOO_INSTANCE name. This function turns
# that single name (plus a single NOO_PORT_OFFSET) into everything compose
# needs: project name, container-name prefix, network name, and the full
# set of host-port variables. Sourced by every lifecycle script that runs
# `docker compose` — stop/status/logs must address the SAME project the
# start script created, or they silently operate on the wrong instance.
#
# Migration contract: absent NOO_INSTANCE — or the default
# value `mesh` — is byte-identical to the pre-namespacing behavior:
# directory-derived compose project, `noo-*` container names, the
# `noo-cluster` network, stock ports. No live install is ever renamed.
#
# Port scheme: a single NOO_PORT_OFFSET,
# not nine per-port knobs. The launcher does the arithmetic because
# compose interpolation cannot; each derived var still has a compose-side
# `:-default` so worker nodes and bare recreates behave unchanged.
# POSTGRES_PORT / NOO_MODEL_CACHE_PORT existed
# as knobs before this file; an explicit value always wins over the offset.

# ── a named instance must never share the default data root ─────────
#
# Everything above namespaces the CONTROL plane (project, containers, ports,
# volume OBJECTS). It does not touch the DATA plane: every stateful compose
# volume is a driver_opts device-bind under NOO_DATA_ROOT, so two instances
# with one root share postgres/redis/nats FILES. An instance-scoped
# onboard that reused the default root would open the default install's live
# postgres data dir and replay WAL under its running postmaster.
#
# Onboarded instances get an auto-suffixed root (onboard/steps.rs). This
# guard is the belt for every OTHER path — hand-set env, an old .env, a
# launcher run that never saw onboard: if the resolved root does not carry
# this instance's own directory segment, REFUSE to continue.
#
# NOO_INSTANCE_UNSAFE_DATA_ROOT=1 is the forensics escape hatch (e.g.
# stopping/removing a misconfigured instance's containers requires the
# launchers to run). It exists to be typed deliberately, never defaulted.
# noo_data_root / noo_state_root — the two roots, resolved the way the compose
# file resolves them (environment first, then .env; the state root falls back
# to the data root, exactly `${NOO_STATE_ROOT:-${NOO_DATA_ROOT}}`). The state
# root holds the SENSITIVE state set (postgres, redis, nats, prometheus,
# grafana, loki, noo-data); models / hf-cache / ollama / images always stay
# under the data root. Unset NOO_STATE_ROOT == no change (i10a). Print nothing
# when neither is set; callers decide whether that is fatal.
_noo_env_value() {  # <KEY>: environment, else the last KEY= line in .env
    local _v="${!1:-}"
    if [ -z "$_v" ] && [ -f ".env" ]; then
        _v="$(grep -E "^[[:space:]]*$1=" .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    printf '%s' "$_v"
}
noo_data_root() { _noo_env_value NOO_DATA_ROOT; }
noo_state_root() {
    local _s
    _s="$(_noo_env_value NOO_STATE_ROOT)"
    if [ -n "$_s" ]; then printf '%s' "$_s"; else noo_data_root; fi
}

noo_instance_guard_data_root() {
    [ "${NOO_INSTANCE_UNSAFE_DATA_ROOT:-}" = "1" ] && return 0
    local root="${NOO_DATA_ROOT:-}"
    if [ -z "$root" ] && [ -f ".env" ]; then
        root="$(grep -E '^[[:space:]]*NOO_DATA_ROOT=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    root="${root:-/var/lib/noo}"  # the standard default (data-root policy)
    case "$root" in
        *"/instances/${NOO_INSTANCE}"|*"/instances/${NOO_INSTANCE}/"*) ;;
        *) _noo_instance_guard_fail "$root"; exit 1 ;;
    esac
    # A separately-set state root holds postgres/redis/nats too (i10a): it must
    # be instance-scoped as well, or two instances share one database.
    local sroot
    sroot="$(_noo_env_value NOO_STATE_ROOT)"
    if [ -n "$sroot" ]; then
        case "$sroot" in
            *"/instances/${NOO_INSTANCE}"|*"/instances/${NOO_INSTANCE}/"*) ;;
            *) _noo_instance_guard_fail "$sroot"; exit 1 ;;
        esac
    fi
    return 0
}
_noo_instance_guard_fail() {
    local root="$1"
    echo "FATAL: instance '${NOO_INSTANCE}' would use data root '${root}'," >&2
    echo "which is not instance-scoped (…/instances/${NOO_INSTANCE}). Every" >&2
    echo "stateful volume device-binds under that root, so this instance" >&2
    echo "would OPEN ANOTHER INSTALL'S DATABASES." >&2
    echo "Set NOO_DATA_ROOT=<root>/instances/${NOO_INSTANCE}, or re-run" >&2
    echo "'noo onboard' which scopes it automatically. To operate on a" >&2
    echo "misconfigured instance's CONTAINERS only (stop/clean), set" >&2
    echo "NOO_INSTANCE_UNSAFE_DATA_ROOT=1 deliberately." >&2
    exit 1
}

noo_instance_env() {
    # Bootstrap plane: like NOO_INSTALL_MODE, these are needed before any
    # config file is chosen, so .env is their sanctioned home.
    if [ -z "${NOO_INSTANCE:-}" ] && [ -f ".env" ]; then
        NOO_INSTANCE="$(grep -E '^[[:space:]]*NOO_INSTANCE=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    if [ -z "${NOO_PORT_OFFSET:-}" ] && [ -f ".env" ]; then
        NOO_PORT_OFFSET="$(grep -E '^[[:space:]]*NOO_PORT_OFFSET=' .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    case "${NOO_PORT_OFFSET:-}" in
        ''|*[!0-9]*) NOO_PORT_OFFSET=0 ;;
    esac
    export NOO_PORT_OFFSET

    if [ -n "${NOO_INSTANCE:-}" ] && [ "$NOO_INSTANCE" != "mesh" ]; then
        export NOO_INSTANCE
        export COMPOSE_PROJECT_NAME="noo-${NOO_INSTANCE}"
        export NOO_CONTAINER_PREFIX="noo-${NOO_INSTANCE}"
        export NOO_CLUSTER_NETWORK="noo-${NOO_INSTANCE}-cluster"
        noo_instance_guard_data_root
    else
        # Default instance: DO NOT set COMPOSE_PROJECT_NAME — the
        # directory-derived project is what owns every existing volume
        # (pai-assistant_noo-data); overriding it would orphan them.
        export NOO_CONTAINER_PREFIX="${NOO_CONTAINER_PREFIX:-noo}"
        export NOO_CLUSTER_NETWORK="${NOO_CLUSTER_NETWORK:-noo-cluster}"
    fi

    local o="$NOO_PORT_OFFSET"
    export NOO_PORT_GATEWAY="$((8080 + o))"
    # Trellion's retired hub mapping parks at 3199 (compose cannot
    # conditionally remove a mapping). Nothing publishes 3100 any more:
    # the gateway's plain-HTTP operator-door listener was removed in
    # stack-v0.2.41; the door is /mcp/operator on NOO_PORT_GATEWAY.
    export NOO_PORT_MCP="$((3199 + o))"
    export NOO_PORT_NATS="$((4222 + o))"
    export NOO_PORT_NATS_MON="$((8222 + o))"
    export NOO_PORT_NATS_CLUSTER="$((6222 + o))"
    export NOO_PORT_NODE_AGENT="$((8081 + o))"
    export NOO_PORT_PROMETHEUS="$((9090 + o))"
    export NOO_PORT_ALERTMANAGER="$((9093 + o))"
    export NOO_PORT_GRAFANA="$((3000 + o))"
    export NOO_PORT_NODE_EXPORTER="$((9100 + o))"
    export NOO_PORT_NVIDIA_EXPORTER="$((9400 + o))"
    export POSTGRES_PORT="${POSTGRES_PORT:-$((5433 + o))}"
    export NOO_MODEL_CACHE_TLS_PORT="${NOO_MODEL_CACHE_TLS_PORT:-$((8443 + o))}"
}

# fu 46 phase 3 — refuse to start when another instance (or any foreign
# service) already owns this instance's host ports. Without this, compose
# `up` fails halfway with a raw bind error AFTER some containers are
# already recreated — the collision must be caught before anything moves.
#
# A port counts as OURS when a running container carrying our
# NOO_CONTAINER_PREFIX publishes it (a restart of a live stack re-binds
# the same ports — that is normal, not a collision). Only the
# always-published controller ports are checked; profile-gated ones
# (grafana, prometheus) are skipped so an operator's own grafana on :3000
# does not block a stack that never publishes it.
#
# Callers: noomesh-start.sh, controller path only. NOT invoked at
# source time — stop/status/logs source this lib too and must never
# refuse anything.
noo_check_port_collisions() {
    command -v ss >/dev/null 2>&1 || return 0  # no ss → skip, compose will report
    local busy="" p owned
    # NOO_PORT_NODE_AGENT is deliberately ABSENT. The host-native agent owns
    # :8081 and no container publishes it, so a listener there is the NORMAL
    # state — checking it would make this function refuse every controller
    # start. The launchers `--scale node-agent=0` instead, so :8081 is not a
    # port this instance binds at all. Do not "fix" this by adding it.
    for p in "$NOO_PORT_GATEWAY" "$POSTGRES_PORT" "$NOO_PORT_NATS" \
             "$NOO_PORT_NATS_MON" "$NOO_PORT_MCP" "$NOO_MODEL_CACHE_PORT" "$NOO_MODEL_CACHE_TLS_PORT"; do
        ss -ltnH "sport = :$p" 2>/dev/null | grep -q . || continue
        owned="$(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null \
            | grep -E "^${NOO_CONTAINER_PREFIX}-" | grep -c ":${p}->" || true)"
        [ "${owned:-0}" -gt 0 ] && continue
        busy="$busy $p"
    done
    if [ -n "$busy" ]; then
        echo "ERROR: host port(s)$busy already in use, and not by this instance (${NOO_INSTANCE:-mesh})." >&2
        echo "       Another Mesh instance or an unrelated service owns them." >&2
        echo "       Either stop the conflicting service, or give this instance its own" >&2
        echo "       port range: set NOO_PORT_OFFSET in .env (e.g. 1000 -> gateway :$((8080 + 1000)))" >&2
        echo "       and NOO_INSTANCE for a side-by-side deployment. See docs/getting-started/multi-instance.md." >&2
        return 1
    fi
    return 0
}

# The compose-project data volume: noomesh_noo-data for the default
# instance, noo-galaxy_noo-data for instance `galaxy`. The project is the
# `name:` the compose files declare (noomesh), NOT the cwd: on a dist
# install the cwd is the install root (~/.noo), and basename-of-$PWD built
# ".noo_noo-data", an invalid volume name (docker exit 125, rc.4 rehearsal).
# Instances override it via COMPOSE_PROJECT_NAME (noo_instance_env above).
noo_data_volume() {
    printf '%s_noo-data\n' "${COMPOSE_PROJECT_NAME:-noomesh}"
}

# The directories the gateway (nonroot, uid 65532) creates under /data on
# the noo-data volume, made and handed to 65532 before it starts. The volume
# root stays owned by whoever first wrote it (onboard's `subdir_owner` leaves
# noo-data with the operator, on purpose: host tooling reads it), so the
# gateway's own create_dir_all of a NEW top-level dir fails EACCES:
#   - ingest/{working,archive}: Drive/folder ingest staging (live 2026-08-08,
#     Drive->KB ingestion silently broken, one warn per file per tick);
#   - audit-archive: the agent-mail archive (gateway-rust
#     agent_mail_archive.rs) and audit retention export
#     (`${NOO_DATA_DIR}/audit-archive`). 0.6.10-rc.3 rehearsal: "cannot
#     create /data/audit-archive: Permission denied" on every host.
# A throwaway root container through the same volume: no sudo, idempotent,
# never touches anything outside these dirs. Not fatal (no docker, no
# alpine), but never silent: a failed prep prints a WARNING with docker's
# own error, and the gateway then names the directory it could not create.
# Pinned by tests/test_gateway_data_dirs_prepared.py.
NOO_GATEWAY_DATA_DIRS="ingest audit-archive"
noo_prepare_gateway_data_dirs() {
    local vol out
    vol="$(noo_data_volume)"
    if ! out="$(docker run --rm -v "$vol":/d alpine \
        sh -c 'mkdir -p /d/ingest/working /d/ingest/archive /d/audit-archive && chown -R 65532:65532 /d/ingest /d/audit-archive' \
        2>&1)"; then
        echo "WARNING: could not prepare the gateway's data dirs on volume '$vol'" >&2
        echo "         (the gateway may fail with 'Permission denied' on /data/audit-archive):" >&2
        printf '%s\n' "$out" | sed 's/^/         /' >&2
    fi
    return 0
}

noo_instance_env
