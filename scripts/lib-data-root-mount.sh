#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# lib-data-root-mount.sh — refuse to start the stack when the data root is not
# on the filesystem it was recorded on.
#
# THE INCIDENT (2026-10-24, the production controller): the data NVMe dropped
# off the bus. Postgres' data directory is a docker named volume that
# device-binds ${NOO_DATA_ROOT}/postgres. Had the box rebooted with the drive
# absent, the mountpoint would have been an empty directory on the ROOT disk,
# docker would have created the missing bind source there, and postgres'
# entrypoint would have run initdb into it: a brand-new empty database, the
# gateway up on it, silent data loss and split brain.
#
# The identity of the filesystem the data root lives on (its UUID; the mount
# source + target when the filesystem has no UUID) is recorded in
# .noo-data-root-id beside .env, on first launch (or when an upgraded install
# first meets this check and looks healthy), and compared at EVERY launch,
# before compose starts anything. This file is the one home of that
# criterion: the launchers, hostd's boot restore and `noo cluster verify
# --controller` all run it, none restates it.
#
#   check_data_root_mount        launcher form. 0 = may start (records the
#                                identity when none is recorded yet),
#                                1 = refused, reason on stderr. Never creates
#                                the directory.
#   data_root_mount_boot_guard   hostd's boot form: the same check, and on a
#                                refusal it STOPS the stack's containers
#                                (postgres first) and writes the reason to
#                                .noo-data-root-refused. 0 ok, 1 refused.
#   data_root_mount_report       read-only (never records, never stops):
#                                prints one evidence line on stdout. 0 = on
#                                its recorded filesystem, 3 = refused,
#                                4 = nothing recorded yet (not applicable).
#
# Escape hatch for a DELIBERATE move (new disk, new data root):
# NOO_DATA_ROOT_RERECORD=1 re-records the identity from what is mounted now,
# provided the data root exists and is readable. It is a typed, one-shot
# override, never a default.
#
# The record file path is NOO_DATA_ROOT_ID_FILE, default ./.noo-data-root-id
# (the launchers' and hostd's cwd is the install root). Tests:
# tests/test_data_root_mount_guard.py.

DRM_RECORD_FILE_DEFAULT=".noo-data-root-id"
DRM_REFUSED_FILE_DEFAULT=".noo-data-root-refused"
DRM_RUNBOOK="docs/operating/runbooks/data-root-recovery.md"

_drm_env() {  # <KEY>: environment first, else the last KEY= line in ./.env
    local _v="${!1:-}"
    if [ -z "$_v" ] && [ -f ".env" ]; then
        _v="$(grep -E "^[[:space:]]*$1=" .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    printf '%s' "$_v"
}

_drm_record_file() { printf '%s' "${NOO_DATA_ROOT_ID_FILE:-$DRM_RECORD_FILE_DEFAULT}"; }
_drm_refused_file() { printf '%s' "${NOO_DATA_ROOT_REFUSED_FILE:-$DRM_REFUSED_FILE_DEFAULT}"; }

_drm_timeout() {  # run a command under `timeout` when there is one: a dying disk can hang a listing
    if command -v timeout >/dev/null 2>&1; then timeout "${NOO_DATA_ROOT_PROBE_TIMEOUT:-20}" "$@"; else "$@"; fi
}

_drm_get() {  # <key> <file>: value of key= in the record
    [ -f "$2" ] || return 0
    grep -E "^$1=" "$2" | tail -1 | cut -d= -f2-
}

_drm_prefix() {
    local _p _i
    _p="$(_drm_env NOO_CONTAINER_PREFIX)"
    if [ -z "$_p" ]; then
        _i="$(_drm_env NOO_INSTANCE)"
        if [ -n "$_i" ] && [ "$_i" != "mesh" ]; then _p="noo-$_i"; else _p="noo"; fi
    fi
    printf '%s' "$_p"
}

# The postgres data dir, the way the compose volume resolves it:
# ${NOO_PG_DATA:-${NOO_STATE_ROOT:-${NOO_DATA_ROOT}}/postgres}
_drm_pgdir() {
    local _pg _st
    _pg="$(_drm_env NOO_PG_DATA)"
    if [ -n "$_pg" ]; then printf '%s' "$_pg"; return; fi
    _st="$(_drm_env NOO_STATE_ROOT)"
    printf '%s/postgres' "${_st:-$1}"
}

# Fields of the filesystem holding <path>. findmnt -T names the mount that
# contains the path, so a data root that is just a directory on the root disk
# reports the root disk's identity.
_drm_field() {  # <FIELD> <path>
    _drm_timeout findmnt -n -o "$1" -T "$2" 2>/dev/null | head -1 | tr -d '\r' | sed 's/[[:space:]]*$//'
}

# Evaluate. Sets DRM_VERDICT (ok | record | refuse | skip) and DRM_MSG, and the
# DRM_NOW_* identity. Never writes, never creates, never stops anything.
_drm_evaluate() {
    DRM_VERDICT="ok"; DRM_MSG=""; DRM_KIND=""
    DRM_NOW_UUID=""; DRM_NOW_SOURCE=""; DRM_NOW_TARGET=""; DRM_NOW_FSTYPE=""; DRM_PG_INIT_NOW=""
    local root rec rec_root kind e
    root="$(_drm_env NOO_DATA_ROOT)"
    root="${root%/}"
    if [ -z "$root" ]; then
        DRM_VERDICT="skip"; DRM_MSG="NOO_DATA_ROOT is not set (the launcher says so itself)"; return 0
    fi
    rec="$(_drm_record_file)"
    rec_root="$(_drm_get data_root "$rec")"
    kind="$(_drm_get id_kind "$rec")"

    if ! command -v findmnt >/dev/null 2>&1; then
        DRM_VERDICT="skip"; DRM_MSG="no findmnt on this host: the data root's filesystem was not checked"; return 0
    fi

    if [ ! -d "$root" ]; then
        DRM_VERDICT="refuse"
        DRM_MSG="the data root $root does not exist"
        _drm_explain "$root" "$rec" "$rec_root" "$kind"; return 0
    fi
    if ! e="$(_drm_timeout ls -A "$root" 2>&1 >/dev/null)"; then
        DRM_VERDICT="refuse"
        DRM_MSG="the data root $root cannot be read (${e:-listing timed out or failed})"
        _drm_explain "$root" "$rec" "$rec_root" "$kind"; return 0
    fi

    DRM_NOW_UUID="$(_drm_field UUID "$root")"
    DRM_NOW_SOURCE="$(_drm_field SOURCE "$root")"
    DRM_NOW_TARGET="$(_drm_field TARGET "$root")"
    DRM_NOW_FSTYPE="$(_drm_field FSTYPE "$root")"
    if [ -z "$DRM_NOW_UUID" ] && [ -z "$DRM_NOW_SOURCE" ] && [ -z "$DRM_NOW_TARGET" ]; then
        DRM_VERDICT="refuse"
        DRM_MSG="findmnt could not say which filesystem holds $root (the mount table is unreadable)"
        _drm_explain "$root" "$rec" "$rec_root" "$kind"; return 0
    fi

    local pgdir
    pgdir="$(_drm_pgdir "$root")"
    [ -f "$pgdir/PG_VERSION" ] && DRM_PG_INIT_NOW="1"

    if [ ! -f "$rec" ]; then
        # An install that predates this check, or its first launch. Record
        # only what looks healthy: the root exists and lists (above). A fresh
        # install has an empty postgres dir; there is nothing to lose yet.
        DRM_VERDICT="record"
        DRM_MSG="no filesystem recorded for $root yet"
        return 0
    fi

    local bad=""
    if [ "$rec_root" != "$root" ]; then
        bad="the recorded data root is ${rec_root:-<none>}, this launch uses $root"
    elif [ "$kind" = "uuid" ]; then
        local want; want="$(_drm_get uuid "$rec")"
        if [ "$DRM_NOW_UUID" != "$want" ]; then
            bad="the filesystem UUID is ${DRM_NOW_UUID:-<none>}, recorded $want"
        fi
    else
        if [ "$DRM_NOW_SOURCE" != "$(_drm_get source "$rec")" ] || [ "$DRM_NOW_TARGET" != "$(_drm_get target "$rec")" ]; then
            bad="mounted from ${DRM_NOW_SOURCE:-?} at ${DRM_NOW_TARGET:-?}, recorded $(_drm_get source "$rec") at $(_drm_get target "$rec") (this filesystem has no UUID, so source+target are the identity)"
        fi
    fi
    if [ -n "$bad" ]; then
        DRM_VERDICT="refuse"
        DRM_MSG="the data root $root is not on its recorded filesystem: $bad"
        _drm_explain "$root" "$rec" "$rec_root" "$kind"; return 0
    fi

    # Belt and braces: postgres was initialised here before (the record says
    # so), and its data dir is now empty. Never let it initdb again.
    if [ -n "$(_drm_get postgres_initialised "$rec")" ]; then
        if [ ! -d "$pgdir" ] || [ -z "$(_drm_timeout ls -A "$pgdir" 2>/dev/null)" ]; then
            DRM_VERDICT="refuse"; DRM_KIND="pg"
            DRM_MSG="postgres was initialised on this install (since $(_drm_get postgres_initialised "$rec")) but its data directory $pgdir is empty or missing; starting would initialise a NEW EMPTY database"
            _drm_explain "$root" "$rec" "$rec_root" "$kind"; return 0
        fi
    fi
    DRM_VERDICT="ok"
    DRM_MSG="$root is on its recorded filesystem ($(_drm_describe_now))"
    return 0
}

_drm_describe_now() {
    if [ -n "$DRM_NOW_UUID" ]; then
        printf 'UUID %s, %s at %s' "$DRM_NOW_UUID" "${DRM_NOW_SOURCE:-?}" "${DRM_NOW_TARGET:-?}"
    else
        printf 'no UUID; %s at %s' "${DRM_NOW_SOURCE:-?}" "${DRM_NOW_TARGET:-?}"
    fi
}

# Expected vs found, for the message. Reads the record; never prints secrets.
_drm_explain() {  # <root> <rec> <rec_root> <kind>
    local exp="nothing is recorded yet"
    if [ -f "$2" ]; then
        if [ "$4" = "uuid" ]; then
            exp="UUID $(_drm_get uuid "$2") ($(_drm_get source "$2") mounted at $(_drm_get target "$2"), $(_drm_get fstype "$2"))"
        else
            exp="$(_drm_get source "$2") mounted at $(_drm_get target "$2") (no UUID; source+target recorded)"
        fi
    fi
    local found="not mounted anywhere we could read"
    if [ -n "$DRM_NOW_SOURCE$DRM_NOW_TARGET$DRM_NOW_UUID" ]; then
        found="$(_drm_describe_now)"
        if [ "$DRM_NOW_TARGET" = "/" ]; then found="$found: the ROOT filesystem — the data disk is not mounted"; fi
    fi
    DRM_EXPECTED="$exp"; DRM_FOUND="$found"
}

_drm_refusal_text() {
    local root; root="$(_drm_env NOO_DATA_ROOT)"
    printf '%s\n' \
"REFUSED: not starting — $DRM_MSG." \
"  expected: ${DRM_EXPECTED:-the filesystem recorded in $(_drm_record_file)}" \
"  found:    ${DRM_FOUND:-see above}" \
"  Started now, postgres would find an empty directory and initialise a NEW EMPTY database, and the gateway would come up on it." \
"  Nothing was created, changed or started. The data root was NOT created." \
"  check:    findmnt -T ${root:-<data root>};  lsblk -f;  dmesg | grep -i -E 'nvme|ext4|I/O error'" \
"  recovery: $DRM_RUNBOOK — bring the disk back first. If the disk was replaced or the root moved ON PURPOSE:" \
"            NOO_DATA_ROOT_RERECORD=1 noo stack start   (re-records the identity once)"
}

_drm_write_record() {  # writes the record from DRM_NOW_*; keeps an existing initialised marker
    local rec tmp init kind
    rec="$(_drm_record_file)"
    init="$(_drm_get postgres_initialised "$rec")"
    [ -z "$init" ] && [ -n "$DRM_PG_INIT_NOW" ] && init="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [ -n "$DRM_NOW_UUID" ]; then kind="uuid"; else kind="mount"; fi
    tmp="$rec.tmp.$$"
    {
        echo "# written by scripts/lib-data-root-mount.sh — the filesystem the data root lives on."
        echo "# launchers and hostd refuse to start the stack when it is not mounted here."
        echo "data_root=$(_drm_env NOO_DATA_ROOT | sed 's:/*$::')"
        echo "id_kind=$kind"
        echo "uuid=$DRM_NOW_UUID"
        echo "source=$DRM_NOW_SOURCE"
        echo "target=$DRM_NOW_TARGET"
        echo "fstype=$DRM_NOW_FSTYPE"
        echo "recorded_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        if [ -n "$init" ]; then echo "postgres_initialised=$init"; fi
    } > "$tmp" 2>/dev/null && mv -f "$tmp" "$rec" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; return 1; }
    return 0
}

# Both forms share this: evaluate, act on record/rerecord, return 0/1.
_drm_run() {
    _drm_evaluate
    case "$DRM_VERDICT" in
        skip)
            [ -n "$DRM_MSG" ] && case "$DRM_MSG" in no\ findmnt*) echo "WARNING: $DRM_MSG" >&2 ;; esac
            return 0 ;;
        record)
            if _drm_write_record; then
                echo "NOTE: recorded the filesystem under the data root ($(_drm_describe_now)) in $(_drm_record_file); every later launch refuses if the data root is not on it." >&2
            else
                echo "WARNING: could not write $(_drm_record_file): the data root's filesystem is not being tracked" >&2
            fi
            return 0 ;;
        refuse)
            if [ "${NOO_DATA_ROOT_RERECORD:-}" = "1" ] && [ "$DRM_KIND" != "pg" ] && [ -d "$(_drm_env NOO_DATA_ROOT)" ] \
               && [ -n "$DRM_NOW_SOURCE$DRM_NOW_UUID" ] && _drm_timeout ls -A "$(_drm_env NOO_DATA_ROOT)" >/dev/null 2>&1; then
                # Re-record only a data root that exists and lists; the postgres
                # belt still applies afterwards on the next launch.
                if _drm_write_record; then
                    echo "NOTE: NOO_DATA_ROOT_RERECORD=1 — re-recorded the data root's filesystem ($(_drm_describe_now))." >&2
                    return 0
                fi
            fi
            _drm_refusal_text >&2
            return 1 ;;
        *)
            # ok: remember that postgres has been initialised here, so a
            # later empty data dir is refused rather than re-initialised.
            if [ -n "$DRM_PG_INIT_NOW" ] && [ -z "$(_drm_get postgres_initialised "$(_drm_record_file)")" ]; then
                _drm_write_record || true
            fi
            return 0 ;;
    esac
}

check_data_root_mount() {
    _drm_run
}

data_root_mount_boot_guard() {
    local rc=0 refused prefix pg n names
    _drm_run || rc=$?
    refused="$(_drm_refused_file)"
    if [ "$rc" -eq 0 ]; then
        rm -f "$refused" 2>/dev/null || true
        return 0
    fi
    # dockerd restarted the containers at boot without a launcher. Stop them,
    # postgres first, before another second of initdb; never start anything.
    prefix="$(_drm_prefix)"
    pg="${prefix}-postgres"
    names="$(docker ps --format '{{.Names}}' --filter "name=^${prefix}-" 2>/dev/null || true)"
    if printf '%s\n' "$names" | grep -qx "$pg"; then
        docker stop "$pg" >/dev/null 2>&1 || echo "boot-restore: could not stop $pg" >&2
    fi
    for n in $names; do
        [ "$n" = "$pg" ] && continue
        docker stop "$n" >/dev/null 2>&1 || echo "boot-restore: could not stop $n" >&2
    done
    {
        echo "at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "stopped: ${names:-none running}"
        _drm_refusal_text
    } > "$refused" 2>/dev/null || true
    return 1
}

data_root_mount_report() {
    _drm_evaluate
    case "$DRM_VERDICT" in
        skip) echo "$DRM_MSG"; return 4 ;;
        record) echo "no filesystem recorded yet for $(_drm_env NOO_DATA_ROOT) (the next launch records it); mounted now: $(_drm_describe_now)"; return 4 ;;
        refuse) echo "$DRM_MSG — expected ${DRM_EXPECTED:-?}; found ${DRM_FOUND:-?}"; return 3 ;;
        *) echo "$DRM_MSG"; return 0 ;;
    esac
}
