#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# lib-reown.sh — hand <data root>/redis and <data root>/grafana to uid 65532
# (i64) before the `up` that starts them as that uid.
#
# Before i64 both ran as the DHI -dev images' root, so on an upgraded install
# the files they wrote (redis: appendonlydir/, dump.rdb; grafana: grafana.db,
# plugins/, png/) are root-owned and the new uid cannot open them.
#
# The first version (0.6.4) re-owned these near the TOP of the launcher,
# minutes before `up`, while the OLD root container was still running through
# the image pull. Whatever that container rewrote in the window — redis
# replaces appendonlydir/appendonly.aof.manifest by rename on every AOF
# rewrite, dump.rdb on every save and at shutdown — came back root-owned, the
# probe had already said "nothing to do", and the new redis crash-looped once
# a minute on "can't open the AOF manifest file ... Permission denied"
# (controller, 0.6.3 -> 0.6.4, 2026-10-16). Nothing checked afterwards.
#
# So, per service, immediately before `up`:
#   1. probe: list every path not 65532:65532 (none -> nothing to do, silent)
#   2. stop the running service, so nothing writes root-owned files again
#   3. chown -R 65532:65532
#   4. VERIFY: probe again; anything left refuses the start, naming the paths
#      and the manual command, instead of starting a service that cannot read
#      its own data.
# The work runs in a throwaway alpine container (no sudo), the same pattern
# as the ingest dir. NOO_REOWN_CMD replaces that runner (tests): it is called
# as `$NOO_REOWN_CMD <host dir> <sh snippet>` and must run the snippet with
# $D set to the directory. The caller may define `reown_stop_service <svc>`.

NOO_REOWN_UID=65532

# shellcheck disable=SC2016  # $D expands inside the runner, not here
_REOWN_PROBE='find "$D" \( ! -user 65532 -o ! -group 65532 \) -print'
# shellcheck disable=SC2016
_REOWN_CHOWN='chown -R 65532:65532 "$D"'

_reown_run() {  # <host dir> <snippet>
    if [ -n "${NOO_REOWN_CMD:-}" ]; then
        # shellcheck disable=SC2086  # a command line, split on purpose
        $NOO_REOWN_CMD "$1" "$2"
    else
        docker run --rm -e D=/d -v "$1":/d alpine sh -c "$2"
    fi
}

# Container paths (/d/...) back to host paths for the operator.
_reown_host_paths() {  # <host dir>  (stdin: paths)
    sed -e "s#^/d/#$1/#" -e "s#^/d\$#$1#"
}

# reown_nonroot_path <host dir | docker volume> <service>
# One directory (or named volume: `docker run -v` takes either) that is not
# <state root>/<service>: ollama's store is OLLAMA_DATA_DIR, and the embedders'
# is a named volume. Same probe -> stop -> chown -R -> verify as below; the
# hardened ollama image (docker/Dockerfile.ollama) runs as 65532 and its store
# was written by the old root image. chown only: nothing is deleted or moved.
reown_nonroot_path() {
    local dir="$1" svc="$2" found n left
    if ! found="$(_reown_run "$dir" "$_REOWN_PROBE" 2>/dev/null)"; then
        echo "NOTE: could not inspect ownership under $dir (throwaway alpine container failed); $svc runs as uid $NOO_REOWN_UID and \
may fail with 'permission denied'. To fix: sudo chown -R $NOO_REOWN_UID:$NOO_REOWN_UID $dir" >&2
        return 0
    fi
    [ -n "$found" ] || return 0
    n="$(printf '%s\n' "$found" | wc -l | tr -d ' ')"
    if declare -F reown_stop_service >/dev/null; then
        reown_stop_service "$svc" || true
    fi
    _reown_run "$dir" "$_REOWN_CHOWN" >/dev/null 2>&1 || true
    if ! left="$(_reown_run "$dir" "$_REOWN_PROBE" 2>/dev/null)"; then
        left="(could not re-inspect $dir)"
    fi
    if [ -n "$left" ]; then
        echo "ERROR: $svc runs as uid $NOO_REOWN_UID but these paths under $dir are still not $NOO_REOWN_UID:$NOO_REOWN_UID:" >&2
        printf '%s\n' "$left" | _reown_host_paths "$dir" | sed -n '1,5s/^/         /p' >&2
        echo "       refusing to start $svc on data it cannot read. To fix:" >&2
        echo "         sudo chown -R $NOO_REOWN_UID:$NOO_REOWN_UID $dir" >&2
        return 1
    fi
    echo "re-owned $n path(s) under $dir to $NOO_REOWN_UID"
}

# reown_nonroot_dirs <state root> <service>...
# Each service's data lives at <state root>/<service> (the state root is
# NOO_STATE_ROOT, defaulting to the data root; i10a). Returns 1 (after
# printing why) when a directory is still not wholly 65532:65532.
reown_nonroot_dirs() {
    local root="$1"; shift
    local svc dir found n left
    for svc in "$@"; do
        dir="$root/$svc"
        [ -d "$dir" ] || continue
        if ! found="$(_reown_run "$dir" "$_REOWN_PROBE" 2>/dev/null)"; then
            echo "NOTE: could not inspect ownership under $dir (throwaway alpine container failed); $svc runs as uid $NOO_REOWN_UID (i64) and \
may fail with 'permission denied'. To fix: sudo chown -R $NOO_REOWN_UID:$NOO_REOWN_UID $dir" >&2
            continue
        fi
        [ -n "$found" ] || continue
        n="$(printf '%s\n' "$found" | wc -l | tr -d ' ')"
        if declare -F reown_stop_service >/dev/null; then
            reown_stop_service "$svc" || true
        fi
        _reown_run "$dir" "$_REOWN_CHOWN" >/dev/null 2>&1 || true
        if ! left="$(_reown_run "$dir" "$_REOWN_PROBE" 2>/dev/null)"; then
            left="(could not re-inspect $dir)"
        fi
        if [ -n "$left" ]; then
            echo "ERROR: $svc runs as uid $NOO_REOWN_UID but these paths under $dir are still not $NOO_REOWN_UID:$NOO_REOWN_UID:" >&2
            printf '%s\n' "$left" | _reown_host_paths "$dir" | sed -n '1,5s/^/         /p' >&2
            echo "       refusing to start $svc on data it cannot read. To fix:" >&2
            echo "         sudo chown -R $NOO_REOWN_UID:$NOO_REOWN_UID $dir" >&2
            echo "       then start again (noo stack start)." >&2
            return 1
        fi
        echo "re-owned $n path(s) under $dir to $NOO_REOWN_UID"
    done
    return 0
}

# reown_ollama_stores <newline-separated active services>
# The compose ollama services run the hardened image (uid 65532): re-own their
# stores (ollama: OLLAMA_DATA_DIR or <data root>/ollama; the embedders: the
# ollama-embed-data named volume, shared by ollama-embed and ollama-embed-cpu).
reown_ollama_stores() {
    local active="$1" root vol
    if printf '%s\n' "$active" | grep -qx 'ollama'; then
        root="${OLLAMA_DATA_DIR:-${NOO_DATA_ROOT:-${_data_root:-}}/ollama}"
        if [ -n "$root" ] && [ -d "$root" ]; then
            reown_nonroot_path "$root" ollama || return 1
        fi
    fi
    if printf '%s\n' "$active" | grep -qxE 'ollama-embed|ollama-embed-cpu'; then
        vol="$(docker volume ls -q 2>/dev/null | grep -E '(^|_)ollama-embed-data$' | head -1 || true)"
        if [ -n "$vol" ]; then
            # one volume, two services: stop the cpu twin by hand, the helper stops the other
            if declare -F reown_stop_service >/dev/null && printf '%s\n' "$active" | grep -qx 'ollama-embed-cpu'; then
                reown_stop_service ollama-embed-cpu || true
            fi
            reown_nonroot_path "$vol" ollama-embed || return 1
        fi
    fi
    return 0
}
