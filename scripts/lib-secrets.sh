#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Secrets loading for the cluster launch path.
#
# Default (NOO_SECRETS_BACKEND unset or "env"): NO-OP — compose reads the
# plaintext .env exactly as today. Opt in with NOO_SECRETS_BACKEND=sops to
# source SOPS+age-encrypted secrets at launch instead, so nothing sensitive
# sits in plaintext at rest. Fails CLOSED: if the backend is `sops` but decrypt
# can't happen, the launch aborts rather than silently degrading to plaintext.
#
# Setup: run scripts/noo-secrets-sops-init.sh once (installs sops/age, generates
# the age key, encrypts .env → secrets/env.sops). See
# docs/security/secrets.md.
#
# Source this, then call `load_secrets` before `docker compose ... up`.

# secrets_backend [env-file] — which store is authoritative here: `env` or `sops`.
#
# Split out of `load_secrets` on 2026-09-12 so it can be answered WITHOUT
# loading anything. Any tool that writes a secret has to know which store owns
# it, and the only way to ask used to be to call `load_secrets`, which exports
# ~30 values and materialises files — so `noo-backup-rotate-passphrase.sh`
# didn't ask. It assumed `.env` was the plaintext source and re-encrypted
# env.sops FROM it, which on a sops-first install (where `.env` holds two
# bootstrap flags) would have replaced the whole store with those two flags and
# written both passphrases in plaintext. Caught in dry-run on the live
# controller, 2026-09-12; tracker R42.
#
# ONE definition, because a second copy of this precedence is the drift bug:
# a writer that disagrees with the launcher about which store is authoritative
# writes to the one nobody reads.
# This library is sourced by scripts that do and do not carry the shared UI
# helpers (noomesh-start.sh has them; restore-drill.sh and noo-host-watcher.sh
# do not). Calling an undefined function under `set -e` would abort a restore
# drill over a formatting helper, so define a plain-indent fallback when the
# real one is absent.
if ! declare -F ui_note >/dev/null 2>&1; then
    ui_note() { printf '    %s\n' "$*"; }
fi

secrets_backend() {
    local env_file="${1:-.env}"
    local backend="${NOO_SECRETS_BACKEND:-}"
    # The launcher scripts don't `source .env`, so fall back to reading the flag
    # straight from it — this is what makes `NOO_SECRETS_BACKEND=sops` set in
    # .env actually activate SOPS (otherwise the operator would have to export it
    # in every shell). Mirrors the NOO_INSTALL_MODE pattern in noomesh-start.sh.
    if [ -z "$backend" ] && [ -f "$env_file" ]; then
        backend="$(grep -E '^[[:space:]]*NOO_SECRETS_BACKEND=' "$env_file" | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    printf '%s' "${backend:-env}"
}

# Put sops on PATH if it is in a known install dir. Shared with
# secrets_sops_path_repair's caller in _load_secrets_sops; see the long comment
# there for why a systemd/cron PATH makes this necessary.
secrets_sops_path_repair() {
    if ! command -v sops >/dev/null 2>&1; then
        local _d
        for _d in "$HOME/.local/bin" /usr/local/bin; do
            if [ -x "$_d/sops" ]; then
                export PATH="$_d:$PATH"
                return 0
            fi
        done
    fi
}

load_secrets() {
    local backend
    backend="$(secrets_backend .env)"
    case "$backend" in
        env|"")
            # plaintext .env — compose reads it natively. The launchers refuse
            # this install before any compose command (check_secrets_at_rest,
            # below); the other callers of load_secrets are not launchers.
            :
            ;;
        sops)
            _load_secrets_sops || return 1
            ;;
        *)
            echo "ERROR: unknown NOO_SECRETS_BACKEND='$backend' (expected env|sops)" >&2
            return 1
            ;;
    esac
    derive_file_secrets
    # The `file:` secrets compose bind-mounts (read-only services refuse
    # `environment:` ones). Fails CLOSED: a launch whose secret files could
    # not be put in RAM must not reach `docker compose up`.
    write_secret_files
}

# check_secrets_at_rest — refuse to START an install whose secrets sit in
# plaintext `.env`. Every launcher calls it once, beside
# check_system_credentials, before its first compose command:
#   check_secrets_at_rest || exit 1
#     0  NOO_SECRETS_BACKEND is sops, secrets/env.sops exists and `.env` holds
#        no secret-class value — or the check could not run (said loudly; an
#        older `noo` without the verb must not block a start)
#     1  refused: the reason (key NAMES only) and the remedy are on stderr —
#        `noo onboard --reconfigure --only secrets --secrets-backend sops`,
#        then `noo security secrets tidy`
# The criterion is NOT restated here: it is `noo config launch-check
# secrets-at-rest` (noo-cli/src/commands/plaintext_env.rs), the same
# classifier `cluster verify --controller`, `security scan` and `upgrade
# --stack` apply. tests/test_launcher_secrets_at_rest.py holds each launcher
# to the call.
check_secrets_at_rest() {
    local _nb _rc
    if ! command -v noo_bin >/dev/null 2>&1 || ! _nb="$(noo_bin 2>/dev/null)"; then
        echo "WARNING: no noo binary found — secrets at rest NOT checked before start" >&2
        return 0
    fi
    _rc=0
    "$_nb" config launch-check secrets-at-rest . || _rc=$?
    case "$_rc" in
        0) return 0 ;;
        3) return 1 ;;
        *)
            echo "WARNING: '$_nb config launch-check secrets-at-rest' could not run (exit $_rc; an older noo?) — secrets at rest NOT checked" >&2
            return 0 ;;
    esac
}

# ── File-backed delivery (2026-09-29, RAM files 2026-10-19) ─────────────────
# docker-compose.cluster.yml hands every tier-1 secret to noomesh's own
# containers as a FILE: /run/secrets/<target>, bind-mounted from a top-level
# `secrets:` entry whose source is `file: ${NOO_SECRET_RUNDIR}/<name>`. The
# gateway, worker(s) and trellion run `read_only: true`, and compose REFUSES
# an `environment:`-sourced secret on a read-only service ("cannot create
# secret ... in read-only service ...: `file` is the sole supported option"),
# so the launcher writes the files itself, to a directory on tmpfs
# (`write_secret_files` below): mode 0400, owned by the uid of the container
# that reads each one, removed by `noo stack stop`. They live in RAM only:
# nothing plaintext reaches a disk, and nothing is copied into a container's
# writable layer (the old `environment:` delivery was: the audit's LOW).
# tests/test_compose_secret_files.py (G4) and tests/test_secret_rundir.py
# hold the rules: no redirection into the checkout's secrets/, and the only
# writes are into the tmpfs-checked rundir.

# The pgpass bodies the launcher derives: which DRIVER reads the file, then
# `role:VAR` pairs — one line per role that container logs in as, the
# password read from VAR. Host, port and database are the compose DSNs'
# (`postgres:5432/noomesh`). The onboard wizard's compose wrapper
# (noo-cli/src/onboard/sh.rs `PGPASS_ROLES`) derives the same bodies for its
# own compose calls; tests/test_compose_secret_files.py pins the two
# declarations together.
#
# The driver matters because the two disagree about the PASSWORD field:
# libpq parses it like every other field — it ends at an unescaped `:`, and
# `\:` / `\\` are de-escaped — while sqlx 0.8.6 (options/pgpass.rs,
# `Some(line.to_owned())`) takes the rest of the line verbatim. Measured
# against a live postgres 2026-09-29 with the password `ab:cd\ef`: libpq
# logged in ONLY from `ab\:cd\\ef`, sqlx ONLY from the raw line. So the
# gateway's body (sqlx) is written raw and the others' (libpq) escaped.
#
# The add-ons are libpq too — psycopg in noo-trellion /
# noo-trellion-intel (noomesh's and trellion's engines) and in noo-evolve.
# trellion's covers the three roles its DSNs log in as; intel inherits it.
NOO_PGPASS_ROLES_GATEWAY="sqlx noo:POSTGRES_PASSWORD noo_app:NOO_APP_DB_PASSWORD"
NOO_PGPASS_ROLES_WORKER="libpq noo_app:NOO_APP_DB_PASSWORD"
NOO_PGPASS_ROLES_TRELLION="libpq noo_app:NOO_APP_DB_PASSWORD noo_trellion:NOO_TRELLION_DB_PASSWORD noo_trellion_ddl:NOO_TRELLION_DDL_PASSWORD"
NOO_PGPASS_ROLES_EVOLVE="libpq noo_evolve:NOO_EVOLVE_DB_PASSWORD noo_evolve_ddl:NOO_EVOLVE_DDL_PASSWORD"

# file_secret_sources [compose-file] — the VARIABLE each top-level compose
# secret is sourced from, one per line: `environment: VAR` (an add-on overlay
# not yet moved to files) or `x-noo-source: VAR` (the `file:` form). Read from the file itself so the list
# has one home: the compose declaration. The add-on overlays beside it
# (docker-compose.<addon>.yml) declare their own top-level secrets (compose
# merges them across `-f` files), so every `docker-compose.*.yml` next to the
# base is read too — a source exported for an overlay that is not composed is
# inert, and one missed for an overlay that IS composed stops compose
# creating that service ("required by secret … is not set"). A licensed
# add-on's overlay arrives in its signed bundle and sits under
# addons/<name>/docker-compose.yml below the base (N6), so those are read too.
file_secret_sources() {
    local compose="${1:-docker-compose.cluster.yml}" f
    [ -f "$compose" ] || return 0
    for f in "$compose" "$(dirname "$compose")"/docker-compose.*.yml "$(dirname "$compose")"/addons/*/docker-compose.yml; do
        [ -f "$f" ] || continue
        _file_secret_sources_one "$f"
    done | awk '!seen[$0]++'
}

_file_secret_sources_one() {
    awk '
        /^secrets:[[:space:]]*$/ { inblk = 1; next }
        inblk && /^[^[:space:]#]/ { inblk = 0 }
        inblk && /^[[:space:]]+environment:[[:space:]]*[A-Z_][A-Z0-9_]*[[:space:]]*$/ { print $2 }
        inblk && /^[[:space:]]+x-noo-source:[[:space:]]*[A-Z_][A-Z0-9_]*[[:space:]]*$/ { print $2 }
    ' "$1"
}

# _dotenv_has KEY — is KEY assigned in ./.env (compose's own fallback)?
_dotenv_has() {
    [ -f .env ] && grep -qE "^[[:space:]]*${1}=" .env
}

# _secret_value KEY — KEY from this process's environment, else from ./.env
# (the plaintext backend, where compose reads the file itself). Printed on
# stdout for a command substitution; never logged.
_secret_value() {
    local k="$1" v
    if [ -n "${!k+x}" ]; then
        printf '%s' "${!k}"
        return 0
    fi
    _dotenv_has "$k" || return 0
    v="$(grep -E "^[[:space:]]*${k}=" .env | tail -1)"
    v="${v#*=}"
    v="${v%$'\r'}"
    case "$v" in
        \"*\") v="${v#\"}"; v="${v%\"}" ;;
        \'*\') v="${v#\'}"; v="${v%\'}" ;;
    esac
    printf '%s' "$v"
}

# _pgpass_body <sqlx|libpq> role:VAR ... — a pgpass file body, one line per
# role whose password is non-empty, the password written the way that driver
# reads it (see NOO_PGPASS_ROLES_* above).
_pgpass_body() {
    local driver="$1" pair role var pw body=""
    shift
    for pair in "$@"; do
        role="${pair%%:*}"
        var="${pair#*:}"
        pw="$(_secret_value "$var")"
        [ -n "$pw" ] || continue
        if [ "$driver" = libpq ]; then
            pw="${pw//\\/\\\\}"
            pw="${pw//:/\\:}"
        fi
        body="${body}postgres:5432:noomesh:${role}:${pw}"$'\n'
    done
    printf '%s' "$body"
}

# _declared_systems — every declared system, one line each:
#   <name> <enabled_when var or -> <password_env> <ddl_password_env>
# The ONE place the launcher learns which systems exist. Today the source is
# the `systems:` manifest in ./noomesh.yaml, read by `noo config launch-render
# systems` (the CLI's own parser, the one `noo systems` and the pre-`up`
# credential check use; no second YAML reader here). A further source (an
# add-on bundle's system fragment) appends its lines here and nothing
# downstream changes: not compose, not the gateway's lookup.
_declared_systems() {
    local nb="" rc=0 out
    [ -f noomesh.yaml ] || return 0
    if command -v noo_bin >/dev/null 2>&1; then
        nb="$(noo_bin 2>/dev/null)" || nb=""
    elif [ -n "${NOO_CLI_BIN:-}" ] && [ -x "$NOO_CLI_BIN" ]; then
        nb="$NOO_CLI_BIN"
    else
        nb="$(command -v noo 2>/dev/null)" || nb=""
    fi
    if [ -n "$nb" ]; then
        out="$("$nb" config launch-render systems noomesh.yaml 2>/dev/null)" || rc=$?
    else
        rc=127
    fi
    if [ "$rc" != 0 ]; then
        # Silent only when nothing is declared: a manifest this launcher could
        # not read is a system whose flag and passwords will not arrive.
        if grep -qE '^systems:' noomesh.yaml; then
            echo "WARNING: could not list the declared systems (noo config launch-render systems: exit $rc; an older noo?)." >&2
            echo "         A system no compose line names will not receive its flag or passwords; the gateway skips it and says so." >&2
        fi
        return 0
    fi
    printf '%s\n' "$out"
}

# _systems_secrets_body [compose-file] — the body of the gateway's ONE
# systems-secrets file (compose secret noo_systems_secrets, pointer
# NOO_SYSTEMS_SECRETS_FILE): `KEY=VALUE` per line for each declared system's
# `enabled_when` flag and its two role-password variables, the value from
# this process's environment (the store's decrypt) or ./.env, exactly as
# every other file-backed secret takes it. Skipped: a variable a compose
# secret already delivers by name (`x-noo-source:`, e.g. trellion's and
# evolve's passwords), one with no value, and a repeat. A name that is not an
# env-var name, or a value with a newline (the format has no quoting), is
# refused with a warning naming the VARIABLE — never the value.
_systems_secrets_body() {
    local compose="${1:-docker-compose.cluster.yml}" named name flag pw ddl k v body="" seen=" "
    named=" $(file_secret_sources "$compose" | tr '\n' ' ') "
    while read -r name flag pw ddl; do
        [ -n "$name" ] || continue
        for k in "$flag" "$pw" "$ddl"; do
            [ -n "$k" ] && [ "$k" != - ] || continue
            if ! [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
                echo "WARNING: system $name names '$k', which is not an environment variable name — not delivered" >&2
                continue
            fi
            case "$named$seen" in *" $k "*) continue ;; esac
            seen="$seen$k "
            v="$(_secret_value "$k")"
            [ -n "$v" ] || continue
            case "$v" in
                *$'\n'*)
                    echo "WARNING: $k (system $name) holds a multi-line value, which the systems file cannot carry — not delivered" >&2
                    continue ;;
            esac
            body="${body}${k}=${v}"$'\n'
        done
    done <<EOF
$(_declared_systems)
EOF
    printf '%s' "$body"
}

# derive_file_secrets [compose-file] — make every file-backed secret's source
# variable exist in this process, deriving the two pgpass bodies. Called by
# `load_secrets`, so every launcher and noo-hostd (which runs through
# lib-secrets) gets it.
#
# Every source variable must be SET for compose to create the service that
# uses it ("required by secret … is not set" otherwise). A value the store
# does not hold is exported EMPTY: compose then creates the container with no
# file, and the service's `${NAME:+/run/secrets/…}` pointer stays unset, so an
# optional secret reads as unset. A variable ./.env assigns is left for
# compose to read from the file, exactly as before.
derive_file_secrets() {
    local compose="${1:-docker-compose.cluster.yml}" v
    [ -f "$compose" ] || return 0
    export NOO_PGPASS_GATEWAY NOO_PGPASS_WORKER NOO_PGPASS_TRELLION NOO_PGPASS_EVOLVE
    # shellcheck disable=SC2086  # word-splitting the role list is the point
    NOO_PGPASS_GATEWAY="$(_pgpass_body $NOO_PGPASS_ROLES_GATEWAY)"
    # shellcheck disable=SC2086
    NOO_PGPASS_WORKER="$(_pgpass_body $NOO_PGPASS_ROLES_WORKER)"
    # shellcheck disable=SC2086
    NOO_PGPASS_TRELLION="$(_pgpass_body $NOO_PGPASS_ROLES_TRELLION)"
    # shellcheck disable=SC2086
    NOO_PGPASS_EVOLVE="$(_pgpass_body $NOO_PGPASS_ROLES_EVOLVE)"
    export NOO_SYSTEMS_SECRETS
    NOO_SYSTEMS_SECRETS="$(_systems_secrets_body "$compose")"
    for v in $(file_secret_sources "$compose"); do
        if [ -n "${!v+x}" ]; then
            export "${v?}"
        elif ! _dotenv_has "$v"; then
            export "$v="
        fi
    done
}

# ── RAM-backed secret files ──────────────────────────────────────────────────

# secret_rundir — where the secret files go, as a path. NOO_SECRET_RUNDIR wins
# (tests, and an operator who wants another tmpfs). Otherwise:
#   root:      /run/noo/secrets   (systemd's /run is tmpfs on every Linux box)
#   non-root:  /dev/shm/noo-secrets-<uid>
# A controller's launcher runs as the OPERATOR, not root: `noo stack start`
# is the operator's shell and noo-hostd is installed as a USER unit (its
# install.go default: it needs the operator's docker group and age key). Root
# only appears for a `sudo noo ...` or a system-unit hostd, hence the root
# default. For the operator the obvious home would be $XDG_RUNTIME_DIR, and it
# is NOT used first because /run/user/<uid> is unmounted when the last session
# ends unless linger is on, and a container's restart policy (a crash, a
# daemon restart) re-resolves its bind sources: a vanished source is a service
# that cannot come back until someone re-runs the launcher. /dev/shm lives
# until reboot regardless of sessions. XDG_RUNTIME_DIR is the fallback for a
# host without /dev/shm.
secret_rundir() {
    if [ -n "${NOO_SECRET_RUNDIR:-}" ]; then
        printf '%s' "$NOO_SECRET_RUNDIR"
    elif [ "$(id -u)" = 0 ]; then
        printf '%s' /run/noo/secrets
    elif [ -d /dev/shm ] && [ -w /dev/shm ]; then
        printf '/dev/shm/noo-secrets-%s' "$(id -u)"
    elif [ -n "${XDG_RUNTIME_DIR:-}" ]; then
        printf '%s/noo/secrets' "$XDG_RUNTIME_DIR"
    else
        printf '/dev/shm/noo-secrets-%s' "$(id -u)"
    fi
}

# _secret_compose_files [compose-file] — the base plus every overlay beside it
# and every licensed add-on's overlay (the same set file_secret_sources reads).
_secret_compose_files() {
    local compose="${1:-docker-compose.cluster.yml}" f
    for f in "$compose" "$(dirname "$compose")"/docker-compose.*.yml "$(dirname "$compose")"/addons/*/docker-compose.yml; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done | awk '!seen[$0]++'
}

# _secret_file_plan <compose-file>... — one line per top-level secret that is
# sourced from `file: ${NOO_SECRET_RUNDIR...}/<name>`:
#   <name> <SOURCE_VAR> <owner uid>
# SOURCE_VAR is the `x-noo-source:` extension on the same entry (compose
# ignores `x-` keys). OWNER is the uid every service that takes the secret
# runs as, read from the services' own `uid:` (so the compose file is the one
# home of that fact): the single non-zero uid among them, or 0 when only
# root containers take it. A container running as root reads a file owned by
# 65532 through the default CAP_DAC_OVERRIDE (tests/test_secret_rundir.py
# holds: no root consumer of a shared secret drops it). Two different
# non-zero uids cannot be served by one file and print CONFLICT as the owner;
# a file: entry with no x-noo-source prints NOSOURCE.
_secret_file_plan() {
    awk '
        FNR == 1 { insec = 0; cur = "" }
        /^secrets:[[:space:]]*$/ { insec = 1; cur = ""; next }
        insec && /^[^[:space:]#]/ { insec = 0; cur = "" }
        insec && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ { cur = $1; sub(/:$/, "", cur); next }
        insec && cur != "" && /^[[:space:]]+file:/ && /NOO_SECRET_RUNDIR/ { order[++n] = cur; next }
        insec && cur != "" && /^[[:space:]]+x-noo-source:/ { v = $2; gsub(/["\047]/, "", v); src[cur] = v; next }
        !insec && /source:[[:space:]]*[A-Za-z0-9_.-]+/ && /uid:/ {
            line = $0
            match(line, /source:[[:space:]]*[A-Za-z0-9_.-]+/)
            s = substr(line, RSTART, RLENGTH); sub(/^source:[[:space:]]*/, "", s)
            match(line, /uid:[[:space:]]*"?[0-9]+/)
            u = substr(line, RSTART, RLENGTH); sub(/^uid:[[:space:]]*"?/, "", u)
            if (u != "0") { if (nz[s] == "") nz[s] = u; else if (nz[s] != u) conflict[s] = 1 }
        }
        END {
            for (i = 1; i <= n; i++) {
                k = order[i]
                if (done[k]++) continue
                o = (k in conflict) ? "CONFLICT" : ((nz[k] != "") ? nz[k] : "0")
                sv = src[k]
                if (sv == "") { sv = "-"; o = "NOSOURCE" }
                print k, sv, o
            }
        }
    ' "$@"
}

# _secret_rundir_prepare <dir> - create the directory 0700, own it, and prove
# it is RAM. Refuses (return 1, reason and remedy on stderr) when it is a
# symlink, belongs to someone else, or sits on a disk filesystem: a plaintext
# secret on disk is exactly what this exists to prevent.
_secret_rundir_prepare() {
    local d="$1" fstype owner
    if [ -L "$d" ]; then
        echo "ERROR: $d is a symlink - refusing to put secrets behind it." >&2
        echo "       Remove it, or point NOO_SECRET_RUNDIR at a directory on tmpfs." >&2
        return 1
    fi
    if ! (umask 077; mkdir -p "$d") 2>/dev/null; then
        echo "ERROR: cannot create the secret directory $d." >&2
        echo "       Set NOO_SECRET_RUNDIR to a directory you can create on tmpfs (e.g. /dev/shm/noo-secrets-$(id -u))." >&2
        return 1
    fi
    owner="$(stat -c %u "$d" 2>/dev/null || true)"
    if [ "$owner" != "$(id -u)" ]; then
        echo "ERROR: $d is owned by uid ${owner:-?}, not by uid $(id -u) - refusing to write secrets into it." >&2
        echo "       Remove it (or choose another NOO_SECRET_RUNDIR) and start again." >&2
        return 1
    fi
    chmod 0700 "$d" 2>/dev/null || true
    fstype="$(stat -f -c %T "$d" 2>/dev/null || true)"
    case "$fstype" in
        tmpfs|ramfs) return 0 ;;
    esac
    echo "ERROR: the secret directory $d is on a '${fstype:-unknown}' filesystem, not RAM." >&2
    echo "       noomesh writes the secret files the containers read only to tmpfs, so no plaintext" >&2
    echo "       secret ever reaches a disk. Fix: set NOO_SECRET_RUNDIR to a directory on tmpfs" >&2
    echo "       (check with: stat -f -c %T <dir> - it must print tmpfs), e.g. /dev/shm/noo-secrets-$(id -u)." >&2
    return 1
}

# _secret_tmp_cleanup <dir> - remove this process's temp files and manifest.
_secret_tmp_cleanup() {
    local d="${1:?}" f
    for f in "$d"/.$$.* "$d"/.chown.$$; do
        [ -e "$f" ] && rm -f "$f"
    done
    return 0
}

# _secret_chown_files <dir> <manifest> - hand each file in the manifest
# ("<uid> <name>" per line) to its uid. As root: chown. Otherwise the same
# throwaway-container pattern as lib-reown.sh and the ingest dir (no sudo, the
# operator is in the docker group): a root-in-container `chown` over a bind of
# the directory, with nothing but CAP_CHOWN (+ read/search to get at the
# 0700 directory), no network and a read-only rootfs. The container sees the
# MANIFEST (uids and file names), never a secret value. NOO_SECRET_CHOWN_CMD
# replaces it (tests): called as `$NOO_SECRET_CHOWN_CMD <dir> <manifest>`.
_secret_chown_files() {
    local d="$1" m="$2" uid name
    if [ -n "${NOO_SECRET_CHOWN_CMD:-}" ]; then
        # shellcheck disable=SC2086  # a command line, split on purpose
        $NOO_SECRET_CHOWN_CMD "$d" "$m"
        return $?
    fi
    if [ "$(id -u)" = 0 ]; then
        while read -r uid name; do
            chown "$uid:$uid" -- "$d/$name" || return 1
        done < "$d/$m"
        return 0
    fi
    if ! command -v docker >/dev/null 2>&1; then
        echo "ERROR: cannot hand the secret files to the containers' uids: docker is not on PATH and this is not root." >&2
        return 1
    fi
    # The docker CLI gets a MINIMAL environment: this process holds the
    # decrypted store (and, mid-launch, a stale image pin from it that the
    # launcher re-asserts later); a `docker run` that only chowns files needs
    # none of it, only the way to reach the daemon.
    # shellcheck disable=SC2016  # expands inside the container
    env -i PATH="$PATH" HOME="${HOME:-/}" ${DOCKER_HOST:+DOCKER_HOST="$DOCKER_HOST"} ${DOCKER_CONFIG:+DOCKER_CONFIG="$DOCKER_CONFIG"} \
        ${DOCKER_CONTEXT:+DOCKER_CONTEXT="$DOCKER_CONTEXT"} ${DOCKER_TLS_VERIFY:+DOCKER_TLS_VERIFY="$DOCKER_TLS_VERIFY"} \
        ${DOCKER_CERT_PATH:+DOCKER_CERT_PATH="$DOCKER_CERT_PATH"} ${XDG_RUNTIME_DIR:+XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR"} \
        docker run --rm --network none --read-only --cap-drop ALL --cap-add CHOWN --cap-add DAC_READ_SEARCH \
        --security-opt no-new-privileges -v "$d":/d "${NOO_SECRET_CHOWN_IMAGE:-alpine}" \
        sh -c 'cd /d && while read -r u f; do chown "$u:$u" -- "$f" || exit 1; done < "$1"' sh "$m" >/dev/null
}

# _secret_form_conflicts <compose-file>... - overlays that still source a
# top-level secret from `environment:` while extending a service or declaring
# `read_only: true`. The stack's trellion service is read-only and compose
# refuses an environment-sourced secret on a read-only service, which a service
# that `extends` it inherits: such an overlay is a container compose will fail
# to create halfway through `up`, after the rest of the stack was already
# replaced. Static approximation (the base files are read-only themselves and
# use `file:`); compose still refuses the exact case at create. Prints
# "<file> <secret>" per conflict.
_secret_form_conflicts() {
    local f
    for f in "$@"; do
        awk -v file="$f" '
            /^secrets:[[:space:]]*$/ { insec = 1; cur = ""; next }
            insec && /^[^[:space:]#]/ { insec = 0 }
            insec && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ { cur = $1; sub(/:$/, "", cur); next }
            insec && cur != "" && /^[[:space:]]+environment:/ { envsec[++n] = cur; next }
            /^[[:space:]]+extends:/ { ext = 1 }
            /^[[:space:]]+read_only:[[:space:]]*true/ { ro = 1 }
            END { if (ext || ro) for (i = 1; i <= n; i++) print file, envsec[i] }
        ' "$f"
    done
}

# write_secret_files [compose-file] - write every `file:` secret the compose
# files declare into secret_rundir, then export NOO_SECRET_RUNDIR for compose.
#
#   absent    no `file:` secret in the compose files (an older compose): nothing
#             written, nothing exported, return 0. That compose reads
#             `environment:` sources, which derive_file_secrets already set.
#   present   one file per secret: the value from this process's environment
#             (the store's decrypt) or .env, exactly as compose's old
#             `environment:` delivery took it. An unset secret is an EMPTY
#             file (the pointer env `${NAME:+/run/secrets/...}` stays unset, so
#             the reader never opens it, but the bind source must exist or
#             compose refuses to create the container).
#   written   each file 0400 BEFORE it is handed to its uid, via a temp name
#             and an atomic rename, so a container that restarts mid-launch
#             never sees a half-written file. Files the compose files no
#             longer name are removed.
#   fails     return 1 with the reason: rundir not tmpfs, not creatable, not
#             owned by us, owner conflict between consumers, chown failed.
#             The temp files are removed; load_secrets passes the failure up
#             and every launcher aborts before `compose up`.
write_secret_files() {
    local compose="${1:-docker-compose.cluster.yml}" plan d name var owner tmp manifest bad f
    [ -f "$compose" ] || return 0
    # shellcheck disable=SC2046  # a file list, split on purpose
    plan="$(_secret_file_plan $(_secret_compose_files "$compose"))" || return 1
    [ -n "$plan" ] || return 0
    bad="$(_secret_form_conflicts $(_secret_compose_files "$compose"))"
    if [ -n "$bad" ]; then
        echo "ERROR: an add-on overlay still sources a secret from 'environment:' but extends a read-only service:" >&2
        printf '         %s\n' "$bad" >&2
        echo "       The stack's trellion service is read_only, which compose refuses to give an environment-sourced" >&2
        echo "       secret (and an overlay that extends it inherits that). Nothing was started or changed." >&2
        echo "       Fix: update the add-on (noo addons upgrade), whose overlay uses 'file: \${NOO_SECRET_RUNDIR}/<name>'" >&2
        echo "       with 'x-noo-source:'; or disable it (addons.<name>: false in noomesh.yaml) until it ships." >&2
        return 1
    fi
    bad="$(printf '%s\n' "$plan" | awk '$3 == "CONFLICT" || $3 == "NOSOURCE" { print $1 " (" $3 ")" }')"
    if [ -n "$bad" ]; then
        echo "ERROR: compose secret(s) the launcher cannot place: $bad" >&2
        echo "       CONFLICT: services with different non-root uids take the same secret (one file has one owner)." >&2
        echo "       NOSOURCE: no 'x-noo-source: <VARIABLE>' beside its file: entry." >&2
        return 1
    fi
    d="$(secret_rundir)"
    _secret_rundir_prepare "$d" || return 1
    manifest=".chown.$$"
    { : > "$d/$manifest" && chmod 0644 "$d/$manifest"; } || return 1
    while read -r name var owner; do
        tmp=".$$.$name"
        if [ -n "${!var+x}" ]; then
            (umask 077; printf '%s' "${!var}" > "$d/$tmp") || { _secret_tmp_cleanup "$d"; echo "ERROR: could not write secret file $name under $d" >&2; return 1; }
        else
            (umask 077; _secret_value "$var" > "$d/$tmp") || { _secret_tmp_cleanup "$d"; echo "ERROR: could not write secret file $name under $d" >&2; return 1; }
        fi
        chmod 0400 "$d/$tmp" || { _secret_tmp_cleanup "$d"; return 1; }
        printf '%s %s\n' "$owner" "$tmp" >> "$d/$manifest"
    done <<EOF
$plan
EOF
    if ! _secret_chown_files "$d" "$manifest"; then
        _secret_tmp_cleanup "$d"
        echo "ERROR: could not hand the secret files under $d to their containers' uids." >&2
        echo "       Fix: make sure docker can run '${NOO_SECRET_CHOWN_IMAGE:-alpine}' (docker pull ${NOO_SECRET_CHOWN_IMAGE:-alpine}), or run the launcher as root." >&2
        return 1
    fi
    while read -r name var owner; do
        mv -f "$d/.$$.$name" "$d/$name" || { _secret_tmp_cleanup "$d"; return 1; }
    done <<EOF
$plan
EOF
    _secret_tmp_cleanup "$d"
    # Drop files no declared secret names any more (a renamed secret must not
    # leave its old plaintext behind).
    for f in "$d"/*; do
        [ -e "$f" ] || continue
        printf '%s\n' "$plan" | awk -v n="$(basename "$f")" '$1 == n { found = 1 } END { exit !found }' || rm -f "$f"
    done
    export NOO_SECRET_RUNDIR="$d"
}

# remove_secret_files - `noo stack stop`: delete the secret files and the
# directory. Safe to call with nothing there. A running container keeps its
# own bind of the (now unlinked) inode; nothing else can read it.
remove_secret_files() {
    local d f
    d="$(secret_rundir)"
    [ -d "$d" ] && [ ! -L "$d" ] || return 0
    for f in "${d:?}"/* "${d:?}"/.[!.]*; do
        [ -e "$f" ] && rm -f "$f"
    done
    rmdir "$d" 2>/dev/null || true
}

# Store keys load_secrets never exports (see _load_secrets_sops). The CLI-only
# names include every noo-cli/src/commands/secrets.rs CLI_ONLY_SECRETS row
# (tests/test_secrets_not_exported.py holds the two equal).
_SECRETS_NOT_EXPORTED="NOO_IMAGE_TAG NOO_ADDON_REGISTRY_TOKEN NOO_ADDON_REGISTRY_USER"

_load_secrets_sops() {
    local enc="${NOO_SOPS_FILE:-secrets/env.sops}"
    # noo-secrets-sops-init.sh installs sops/age to ~/.local/bin (deliberately,
    # so onboarding needs no sudo). That dir is on an interactive shell's PATH
    # but NOT on the minimal PATH a systemd unit, cron job, or the host watcher
    # runs with — where PATH is typically /usr/local/bin:/usr/bin:/bin.
    #
    # Without this, those contexts decide "sops is not installed" and fail to
    # load secrets, which is far worse than it sounds: the host watcher then
    # runs backups with no passphrase and silently writes them UNENCRYPTED,
    # while an operator checking by hand (interactive PATH) sees everything
    # correctly encrypted. Look in the known install dir before giving up.
    secrets_sops_path_repair
    if ! command -v sops >/dev/null 2>&1; then
        echo "ERROR: NOO_SECRETS_BACKEND=sops but 'sops' is not installed." >&2
        echo "       Run scripts/noo-secrets-sops-init.sh (or install sops + age)." >&2
        echo "       (searched PATH and \$HOME/.local/bin)" >&2
        return 1
    fi
    if [ ! -f "$enc" ]; then
        echo "ERROR: encrypted secrets file not found: $enc" >&2
        echo "       Run scripts/noo-secrets-sops-init.sh to create it from .env." >&2
        return 1
    fi
    local decrypted
    # --input-type dotenv is REQUIRED: the file is named *.sops (not *.env), so
    # sops can't infer the format and would emit nothing (silent 0-value load →
    # the gateway starts with no secrets). Explicit type makes decrypt reliable.
    if ! decrypted="$(sops -d --input-type dotenv --output-type dotenv "$enc" 2>/dev/null)"; then
        echo "ERROR: failed to decrypt $enc — is the age key available?" >&2
        echo "       (SOPS_AGE_KEY_FILE / ~/.config/sops/age/keys.txt). Failing closed." >&2
        return 1
    fi
    # Export each KEY=VALUE so the compose child process inherits them.
    local count=0 line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        [ "${line#*=}" = "$line" ] && continue  # skip lines without '='
        # Never exported from the store (_SECRETS_NOT_EXPORTED):
        #  - NOO_IMAGE_TAG: the stack pin is CONFIG, not a secret; a stale one
        #    frozen in env.sops must never override the launcher's resolved
        #    tag or the .env pin.
        #  - CLI-only secrets (noo-cli secrets.rs CLI_ONLY_SECRETS): read by
        #    the noo CLI from the store itself, held by no container, so they
        #    must not sit in the launcher's, compose's or any child's env.
        case " $_SECRETS_NOT_EXPORTED " in *" ${line%%=*} "*) continue ;; esac
        export "$line"
        count=$((count + 1))
    done <<EOF
$decrypted
EOF
    # File-shaped credentials absorbed into the store: materialize
    # each at launch under secrets/.runtime (0700), cleaned by
    # noomesh-stop.sh, and export the consuming var. Plaintext exists only
    # while the stack runs.
    # NO FILE. The Google service-account key is a value in this store like
    # every other secret, and the gateway parses it from
    # GOOGLE_CHAT_CREDENTIALS_JSON in memory (google_auth.rs).
    #
    # What used to be here: the base64 decoded back onto the disk at every
    # start and bind-mounted into three containers, because the gateway
    # could only read a PATH. It aimed for 0640 owned by the gateway's gid,
    # could not chgrp without membership of that group, and widened to 0644
    # rather than fail. Measured 0644 on the live controller — guarded on
    # the HOST by a 0700 parent, and not guarded at all inside the
    # container it was mounted into, where anything could read a key that
    # acts as the Chat bot.
    #
    # The one remaining use of a plaintext key FILE is the input side:
    # `noo security secrets absorb-files` reads the JSON Google gave you and
    # puts it in here. That is once, by hand, and it is the copy to keep for
    # onboarding tests.

    if declare -F ui_kv >/dev/null 2>&1; then ui_kv "Secrets" "$count values from $enc $(ui_muted "(SOPS+age)")"; else echo "secrets: loaded $count values from $enc (SOPS+age)"; fi
}

# require_core_secrets — refuse to deploy a stack whose core credentials
# resolve to NOTHING (finding #99: `noo upgrade --stack` on an offboard-
# residue ~/.noo launched compose with a BLANK POSTGRES_PASSWORD — a
# half-install must never deploy with empty credentials). A secret counts
# as present when it is in the process env (sops load) OR non-empty in
# .env (plaintext backend — compose reads .env natively). Call AFTER
# load_secrets.
require_core_secrets() {
    local missing="" key val
    for key in POSTGRES_PASSWORD NOO_JWT_SECRET NOO_CLUSTER_SECRET; do
        val="$(printenv "$key" 2>/dev/null || true)"
        if [ -z "$val" ] && [ -f .env ]; then
            val="$(grep -E "^[[:space:]]*${key}=" .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
        fi
        [ -z "$val" ] && missing="$missing $key"
    done
    if [ -n "$missing" ]; then
        echo "FATAL: core secrets missing:$missing" >&2
        echo "       This install is INCOMPLETE — offboard residue, or a box that was never" >&2
        echo "       onboarded. Deploying would run postgres/auth with BLANK credentials." >&2
        echo "       Fresh setup:  noo onboard      Restore a controller:  noo migrate import <archive>" >&2
        return 1
    fi
    return 0
}

# require_bus_keys — refuse a start whose store lacks any bus-principal key
#. The gateway
# signs every worker.* message per audience and each verifier checks ONLY its
# own key, so a missing key is a container that boots "healthy" and then
# refuses every bus message — a silent outage of that surface. All three are
# minted on every install (`noo onboard`, `noo upgrade --stack`), so enabling
# an add-on later never needs the gateway recreated to learn its key; a
# missing one is never "this add-on is off". Call AFTER load_secrets.
require_bus_keys() {
    local missing="" key val
    for key in NOO_BUS_KEY_WORKER NOO_BUS_KEY_TRELLION NOO_BUS_KEY_TRELLION_INTEL NOO_BROWSER_KEY; do
        val="$(printenv "$key" 2>/dev/null || true)"
        if [ -z "$val" ] && [ -f .env ]; then
            val="$(grep -E "^[[:space:]]*${key}=" .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
        fi
        [ -z "$val" ] && missing="$missing $key"
    done
    if [ -n "$missing" ]; then
        echo "FATAL: per-service key(s) missing from the secret store:$missing" >&2
        echo "       The gateway signs every worker.* message per audience and each worker verifies" >&2
        echo "       only its own key; without one, that worker refuses every message." >&2
        echo "       NOO_BROWSER_KEY is the browser door's own key; without it the door answers 503." >&2
        echo "       Fix:  noo upgrade --stack   (mints any bus key the store lacks, then starts)" >&2
        echo "        or:  noo security secrets rotate <KEY>   (a source checkout; once per missing key)" >&2
        return 1
    fi
    return 0
}

# require_audit_key — refuse a start whose store lacks NOO_AUDIT_HMAC_KEY.
# The gateway refuses to boot without it (every security audit row would be
# refused), so catching it here replaces a crash-looping container with one
# explained line. `noo stack start|restart|rebuild` mints it into the
# encrypted store BEFORE this runs; what reaches here is an install with no
# encrypted store (plaintext .env, or a half-install). Call AFTER load_secrets.
require_audit_key() {
    local val
    val="$(printenv NOO_AUDIT_HMAC_KEY 2>/dev/null || true)"
    if [ -z "$val" ] && [ -f .env ]; then
        val="$(grep -E "^[[:space:]]*NOO_AUDIT_HMAC_KEY=" .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"')"
    fi
    if [ -z "$val" ]; then
        echo "FATAL: NOO_AUDIT_HMAC_KEY is not set." >&2
        echo "       The gateway signs every security audit row with it and refuses to start without it" >&2
        echo "       (logins, exec denials, posture changes and erases would go unrecorded)." >&2
        echo "       Fix:  noo upgrade --stack   (mints it into the encrypted store, then starts)" >&2
        echo "        or:  noo onboard --reconfigure --only secrets --secrets-backend sops" >&2
        return 1
    fi
    return 0
}
