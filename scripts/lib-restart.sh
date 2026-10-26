# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# lib-restart.sh - name resolution and exit status for `noo stack restart
# <name>...` (noomesh-restart.sh). Sourced after lib-ui.sh and lib-compose.sh.
#
# Live finding 2026-10-14 (pop-os): `noo stack restart evolve` printed
# "Restarting evolve", compose said "no such service: evolve", and the launcher
# still closed with "Services restarted" and exit 0. Two defects:
#   1. compose's exit status was never read for a named service;
#   2. `noo stack status` shows the container name minus its `noo-` prefix
#      ("evolve"), while the compose service is `noo-evolve`. The names the
#      operator can SEE must work.
#
# A name resolves, first match wins, to compose service(s):
#   1. a compose service of that exact name           gateway   -> gateway
#   2. the key of a licensed add-on that is on: every service its overlay
#      OWNS (lib-addons.sh addon_own_services; a core service it extends is
#      never one), so `noo stack restart <add-on> --force` (re)starts that
#      add-on's services and nothing else (i239 section 10)
#   3. `noo-<name>`: the status table's spelling      evolve    -> noo-evolve
#   4. an add-on key from an overlay's x-noo-addon    trellion_intel -> the
#      services of its `containers:` list (a container noo-X is the service
#      noo-X or X)
# Anything else is refused, naming the valid services.

# restart_valid_services <compose args> - one compose service name per line.
# Returns compose's status; the error text is left in COMPOSE_ERR.
restart_valid_services() {
    compose_capture "$@" config --services || return $?
    printf '%s\n' "$COMPOSE_OUT" | sed '/^$/d' | sort -u
}

# restart_addon_containers <addon key> <compose args> - the `containers:` of
# the overlay whose x-noo-addon names this add-on (read per file; compose merges
# x- keys, so its projection shows only the last overlay's block).
restart_addon_containers() {
    local _key="$1"; shift
    local _prev="" _f
    for _f in "$@"; do
        if [ "$_prev" = "-f" ] && [ -f "$_f" ]; then
            awk -v key="$_key" '
                /^x-noo-addon:[[:space:]]*$/ { in_b = 1; next }
                /^[^[:space:]#]/ { in_b = 0 }
                in_b && /^  addon:/ { v = $2; gsub(/["\047]/, "", v); hit = (v == key) }
                in_b && hit && /^  containers:/ {
                    s = $0; sub(/^  containers:[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
                    gsub(/[ \t"\047]/, "", s); n = split(s, a, ",")
                    for (i = 1; i <= n; i++) if (a[i] != "") print a[i]
                }' "$_f"
        fi
        _prev="$_f"
    done
}

# restart_resolve_name <name> <valid services, newline separated> <compose args>
# Prints the compose service(s) for NAME, one per line; returns 1 if none.
restart_resolve_name() {
    local _name="$1" _valid="$2"; shift 2
    local _c _s _found=""
    if printf '%s\n' "$_valid" | grep -qx -- "$_name"; then
        printf '%s\n' "$_name"; return 0
    fi
    if declare -F addon_licensed_names >/dev/null 2>&1 \
            && addon_licensed_names | grep -qxF -- "$_name" && addon_on "$_name" 0; then
        _c="$(addon_overlay "$_name" 2>/dev/null)"
        if [ -n "$_c" ]; then
            # The services its overlay OWNS: its `services:` keys that no
            # other composed file defines (an extended core service is not
            # its own). With no other file read, it owns nothing.
            local _core="" _prev="" _f
            for _f in "$@"; do
                if [ "$_prev" = "-f" ] && [ "$_f" != "$_c" ] && [ -f "$_f" ]; then
                    _core="${_core}$(_compose_service_keys "$_f")"$'\n'
                fi
                _prev="$_f"
            done
            if [ -n "${_core//[[:space:]]/}" ]; then
                for _s in $(_compose_service_keys "$_c" | sort -u); do
                    printf '%s\n' "$_core" | grep -qxF -- "$_s" && continue
                    if printf '%s\n' "$_valid" | grep -qx -- "$_s"; then
                        printf '%s\n' "$_s"; _found=1
                    fi
                done
            fi
            [ -n "$_found" ] && return 0
        fi
    fi
    if printf '%s\n' "$_valid" | grep -qx -- "noo-$_name"; then
        printf '%s\n' "noo-$_name"; return 0
    fi
    for _c in $(restart_addon_containers "$_name" "$@"); do
        for _s in "$_c" "${_c#noo-}"; do
            if printf '%s\n' "$_valid" | grep -qx -- "$_s"; then
                printf '%s\n' "$_s"; _found=1; break
            fi
        done
    done
    [ -n "$_found" ]
}

# restart_resolve_all <valid services> <compose args> -- <name>...
# Fills RESOLVED_SERVICES (deduplicated). Prints a refusal listing the valid
# names and returns 1 if any name is unknown.
RESOLVED_SERVICES=()
restart_resolve_all() {
    local _valid="$1"; shift
    local _cargs=() _names=() _n _out _s _bad=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do _cargs+=("$1"); shift; done
    shift
    _names=("$@")
    RESOLVED_SERVICES=()
    for _n in "${_names[@]}"; do
        if _out="$(restart_resolve_name "$_n" "$_valid" "${_cargs[@]}")"; then
            while IFS= read -r _s; do
                case " ${RESOLVED_SERVICES[*]-} " in *" $_s "*) ;; *) RESOLVED_SERVICES+=("$_s") ;; esac
            done <<EOF2
$_out
EOF2
        else
            _bad+=("$_n")
        fi
    done
    if [ ${#_bad[@]} -gt 0 ]; then
        ui_failed "unknown service: ${_bad[*]}"
        echo "       valid services: $(printf '%s\n' "$_valid" | tr '\n' ' ')" >&2
        ui_note "see the running names: noo stack status" >&2
        return 1
    fi
    return 0
}

# restart_image_drift <compose args> -- <service>...
# Prints the services whose RUNNING container is not on the image compose now
# resolves for them (an add-on pin moved by `noo addons upgrade`; a restart
# keeps the old image). Services with no container, or an image not present
# locally, are not drift.
restart_image_drift() {
    local _cargs=() _s _ref _want _cid _have
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do _cargs+=("$1"); shift; done
    shift
    compose_capture "${_cargs[@]}" config --format json || return 0
    local _json="$COMPOSE_OUT"
    command -v python3 >/dev/null 2>&1 || return 0
    for _s in "$@"; do
        _ref="$(printf '%s' "$_json" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin)["services"][sys.argv[1]].get("image", ""))
except Exception:
    pass' "$_s" 2>/dev/null)"
        [ -n "$_ref" ] || continue
        _want="$(docker image inspect --format '{{.Id}}' "$_ref" 2>/dev/null)" || continue
        _cid="$(docker compose "${_cargs[@]}" ps -q "$_s" 2>/dev/null | head -1)"
        [ -n "$_cid" ] || continue
        _have="$(docker inspect --format '{{.Image}}' "$_cid" 2>/dev/null)" || continue
        [ -n "$_want" ] && [ -n "$_have" ] && [ "$_want" != "$_have" ] && printf '%s\n' "$_s"
    done
    return 0
}
