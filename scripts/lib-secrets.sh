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

# ── File-backed delivery (2026-09-29) ───────────────────────────────────────
# docker-compose.cluster.yml hands every tier-1 secret to noomesh's own
# containers as a FILE: a top-level `secrets:` entry whose source is
# `environment: VAR` — a variable of THIS process — which compose copies into
# the container at create time as /run/secrets/<target>. Nothing here writes
# a file: the values live in this launcher's environment (where
# _load_secrets_sops already put them) and in the consuming container, and
# nowhere else. tests/test_compose_secret_files.py (G4) fails the build if
# this library, or a launcher that sources it, grows a redirection into
# secrets/ or a mkdir of a runtime secrets directory.

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
# secret is sourced from, one per line. Read from the file itself so the list
# has one home: the compose declaration. The add-on overlays beside it
# (docker-compose.<addon>.yml) declare their own top-level secrets (compose
# merges them across `-f` files), so every `docker-compose.*.yml` next to the
# base is read too — a source exported for an overlay that is not composed is
# inert, and one missed for an overlay that IS composed stops compose
# creating that service ("required by secret … is not set").
file_secret_sources() {
    local compose="${1:-docker-compose.cluster.yml}" f
    [ -f "$compose" ] || return 0
    for f in "$compose" "$(dirname "$compose")"/docker-compose.*.yml; do
        [ -f "$f" ] || continue
        _file_secret_sources_one "$f"
    done | awk '!seen[$0]++'
}

_file_secret_sources_one() {
    awk '
        /^secrets:[[:space:]]*$/ { inblk = 1; next }
        inblk && /^[^[:space:]#]/ { inblk = 0 }
        inblk && /^[[:space:]]+environment:[[:space:]]*[A-Z_][A-Z0-9_]*[[:space:]]*$/ { print $2 }
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
    for v in $(file_secret_sources "$compose"); do
        if [ -n "${!v+x}" ]; then
            export "${v?}"
        elif ! _dotenv_has "$v"; then
            export "$v="
        fi
    done
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
