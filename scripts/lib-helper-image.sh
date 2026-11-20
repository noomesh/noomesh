#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# The throwaway "helper" container the launcher scripts run (chown a data dir,
# chgrp noomesh.yaml, wipe a dir). It used to be Docker Hub's `alpine` by tag,
# so a default install contacted Docker Hub on every start. It is now the
# nginx image a default install pulls anyway (the `model-cache` service), from
# our ghcr.io mirror, BY DIGEST, with the entrypoint replaced by the one
# binary the job needs. noo-cli does the same in noo-cli/src/helper_image.rs;
# this file mirrors it and tests/test_helper_image_shell.py proves they agree.
#
#   helper_image_ref           repo:tag@digest. repo:tag from the compose
#                              `model-cache` image line, digest from the
#                              host's stack.lock `nginx@sha256:` row, else the
#                              compose default digest. No second copy.
#   helper_job_caps JOB        the capabilities JOB gets: the SAME table as
#                              JOB_CAPS in helper_image.rs (parity-tested).
#   helper_ensure_present      docker image inspect; pull by digest if absent.
#   helper_argv JOB ENTRYPOINT MOUNT   sets the HELPER_ARGV array: `docker`'s
#                              arguments up to and including the image.
#   helper_run JOB ENTRYPOINT MOUNT [ARGS...]   docker "${HELPER_ARGV[@]}" ARGS
#
# Every run: --rm --pull never --network none --read-only --cap-drop ALL
# (+ the job's caps) --security-opt no-new-privileges --entrypoint. Never
# --privileged. HELPER_IMAGE_OVERRIDE (an operator's own image, e.g.
# NOO_SECRET_CHOWN_IMAGE) replaces the reference and nothing else.
# NOO_STACK_LOCK / NOO_HELPER_COMPOSE point the readers elsewhere (tests).

[ -n "${_NOO_HELPER_LIB:-}" ] && return 0
_NOO_HELPER_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

helper_job_caps() {  # JOB -> caps, one per line (mirror of JOB_CAPS)
    case "$1" in
        touch)         printf '%s\n' DAC_OVERRIDE ;;
        chown)         printf '%s\n' CHOWN ;;
        du)            printf '%s\n' DAC_READ_SEARCH ;;
        secrets-chown) printf '%s\n' CHOWN DAC_READ_SEARCH ;;
        chgrp-file)    printf '%s\n' CHOWN FOWNER ;;
        data-dirs)     printf '%s\n' CHOWN DAC_OVERRIDE ;;
        reown)         printf '%s\n' CHOWN DAC_OVERRIDE ;;
        wipe)          printf '%s\n' CHOWN DAC_OVERRIDE ;;
        *) echo "helper: no capability row for job '$1'" >&2; return 1 ;;
    esac
}

helper_image_ref() {
    local compose="${NOO_HELPER_COMPOSE:-$_NOO_HELPER_LIB/../docker-compose.cluster.yml}"
    local lock="${NOO_STACK_LOCK:-$_NOO_HELPER_LIB/../stack.lock}"
    local line repo_tag def digest
    # The compose model-cache line is the source of truth (its registry and
    # namespace included): it is found by its digest variable, never by a
    # typed-out namespace (tests/test_image_namespace_declarations.py).
    # EXACTLY one line, or a refusal with the reason: never the first of
    # several (the source of truth must be unambiguous). A line without the
    # digest default does not match, so a tag-only reference is refused too.
    local lines n
    lines="$(grep -E '^[[:space:]]*image:[[:space:]]*[^$[:space:]]+/nginx:[^$[:space:]]+\$\{NOO_IMAGE_DIGEST_NGINX:-@sha256:[0-9a-f]{64}\}[[:space:]]*$' "$compose" 2>/dev/null)"
    n="$(printf '%s' "$lines" | grep -c . )"
    if [ "$n" -ne 1 ]; then
        echo "helper: expected exactly one pinned nginx image line (with \${NOO_IMAGE_DIGEST_NGINX:-@sha256:...}) in $compose, found $n" >&2
        return 1
    fi
    line="$lines"
    line="${line#*image:}"; line="${line// /}"
    repo_tag="${line%%\$\{*}"
    def="${line#*NOO_IMAGE_DIGEST_NGINX:-}"; def="${def%\}}"
    digest="$def"
    if [ -f "$lock" ]; then
        local row
        row="$(grep -E '^nginx@sha256:[0-9a-f]{64}[[:space:]]*$' "$lock" | head -1)"
        [ -n "$row" ] && digest="@${row#nginx@}" && digest="${digest%%[[:space:]]*}"
    fi
    printf '%s%s\n' "$repo_tag" "$digest"
}

_helper_image() {
    if [ -n "${HELPER_IMAGE_OVERRIDE:-}" ]; then printf '%s\n'  "$HELPER_IMAGE_OVERRIDE"; else helper_image_ref; fi
}

helper_ensure_present() {
    local image
    image="$(_helper_image)" || return 1
    docker image inspect "$image" >/dev/null 2>&1 && return 0
    docker pull -q "$image" >/dev/null
}

helper_argv() {  # JOB ENTRYPOINT MOUNT
    local job="$1" ep="$2" mount="$3" image cap caps
    image="$(_helper_image)" || return 1
    caps="$(helper_job_caps "$job")" || return 1
    HELPER_ARGV=(run --rm --pull never --network none --read-only --cap-drop ALL)
    for cap in $caps; do HELPER_ARGV+=(--cap-add "$cap"); done
    HELPER_ARGV+=(--security-opt no-new-privileges --entrypoint "$ep" -v "$mount" "$image")
}

helper_run() {  # JOB ENTRYPOINT MOUNT [ARGS...]
    local job="$1" ep="$2" mount="$3"
    shift 3
    helper_argv "$job" "$ep" "$mount" || return 1
    docker "${HELPER_ARGV[@]}" "$@"
}
