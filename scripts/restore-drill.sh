#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Mesh - Backup Restore Drill
#
# An untested backup is a hypothesis. This restores the LATEST pg dump into
# a throwaway Postgres container (never touching noo-postgres), sanity-checks
# the restored schema, and tears everything down. Run it periodically
# (quarterly is fine) or after changing anything about backups.
#
# Usage: ./scripts/restore-drill.sh [backup-file.sql.gz]
#
# Both NOO_BACKUP_PASSPHRASE and NOO_AGE_BACKUP_PASSPHRASE are required to read
# what backup-controller.sh now writes — every artefact it produces is
# encrypted. Source them the same way the backup does:
#   . scripts/lib-secrets.sh && load_secrets && ./scripts/restore-drill.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

BACKUP_DIR="${NOO_BACKUP_DIR:-$HOME/noo-backups}"
# Unique per run: a fixed name makes two drills (or a leftover container from an
# interrupted run) collide and clobber each other's Postgres.
DRILL_NAME="noo-restore-drill-$$"
# Resolve the image the way the stack does, dev or dist. Hardcoded
# `pai-assistant/postgres-pgvector:latest` here until 2026-09-12: that name
# stopped being built on 2026-09-06 (the local namespace became `noomesh/`),
# so on a dev box this only worked off a stale cached layer, and on a --dist
# controller it failed at `docker run` with "pull access denied" — meaning the
# one command that proves a backup is restorable could not run at all on the
# install type most likely to need it.
DRILL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/lib-dist.sh
source "$DRILL_ROOT/scripts/lib-dist.sh"
apply_dist_mode "$DRILL_ROOT" >/dev/null 2>&1 || true
IMAGE="${NOO_DRILL_PG_IMAGE:-$(resolve_release_image postgres-pgvector)}"

# Newest backup of either kind (plaintext .sql.gz or encrypted .sql.gz.enc).
# A missing pg backup is NOT fatal here: DB and age-key are independent recovery
# paths, so we still run the age-key check below and fail the overall drill at the
# end. (Postgres and secrets are useless without each other — verify both.)
BACKUP="${1:-$(ls -t "$BACKUP_DIR"/pg_*.sql.gz "$BACKUP_DIR"/pg_*.sql.gz.enc 2>/dev/null | head -1 || true)}"

FAIL=0

# Passphrase for encrypted (.enc) backups — same source as backup-controller.sh.
PASS="${NOO_BACKUP_PASSPHRASE:-}"
if [ -z "$PASS" ] && [ -n "${NOO_BACKUP_PASSPHRASE_FILE:-}" ] && [ -f "$NOO_BACKUP_PASSPHRASE_FILE" ]; then
    PASS="$(cat "$NOO_BACKUP_PASSPHRASE_FILE")"
fi

# Emit the (gzipped) dump to stdout, decrypting first if the backup is .enc.
dump_stream() {
    case "$BACKUP" in
        *.enc)
            if [ -z "$PASS" ]; then
                echo -e "${RED}ERROR: $BACKUP is encrypted but no NOO_BACKUP_PASSPHRASE set${NC}" >&2
                exit 1
            fi
            BACKUP_PASS="$PASS" openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_PASS -in "$BACKUP"
            ;;
        *)
            cat "$BACKUP"
            ;;
    esac
}

cleanup() { docker rm -f "$DRILL_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

if [ -z "$BACKUP" ] || [ ! -f "$BACKUP" ]; then
    echo -e "${RED}✗ No Postgres backup found in $BACKUP_DIR${NC} — run backup-controller.sh (or the database_backup heartbeat)"
    FAIL=1
else
    echo -e "${CYAN}Restore drill: $BACKUP${NC}"
    echo "  drill image: $IMAGE"
    # Don't swallow the failure reason: if the image is missing or the daemon
    # refuses, you want to see it now, not a bare "never became ready" later.
    if ! run_err="$(docker run -d --name "$DRILL_NAME" \
            -e POSTGRES_USER=noo -e POSTGRES_DB=noomesh -e POSTGRES_PASSWORD=drill \
            "$IMAGE" 2>&1)"; then
        echo -e "${RED}ERROR: could not start drill container${NC}"
        echo "$run_err" | tail -5
        exit 1
    fi

    echo "Waiting for throwaway Postgres..."
    for i in $(seq 1 30); do
        docker exec "$DRILL_NAME" pg_isready -U noo -d noomesh >/dev/null 2>&1 && break
        sleep 2
        if [ "$i" = 30 ]; then
            # A silent timeout is useless mid-disaster — show what the container
            # actually did (crash loop, bad image, out of disk...).
            echo -e "${RED}ERROR: drill Postgres never became ready after 60s${NC}"
            echo "  container state: $(docker inspect -f '{{.State.Status}} (exit {{.State.ExitCode}})' "$DRILL_NAME" 2>/dev/null || echo unknown)"
            echo "  --- last 15 log lines ---"
            docker logs "$DRILL_NAME" 2>&1 | tail -15 | sed 's/^/  /'
            exit 1
        fi
    done

    # --- Roles first (cluster-global; pg_dump does not carry them) ---
    # The dump says `ALTER SCHEMA evolve OWNER TO noo_evolve_ddl`, `GRANT ... TO
    # noo_app`, `ALTER DEFAULT PRIVILEGES FOR ROLE noo_trellion_ddl ...`. On a
    # clean server none of those roles exist, so every one of those statements
    # fails. backup-controller.sh now writes pgroles_<ts>.sql.enc next to the
    # dump; a backup from before that has no such file and gets the known
    # noo_* roles pre-created NOLOGIN with no password.
    BASE="$(basename "$BACKUP")"
    BK_TS="${BASE#pg_}"; BK_TS="${BK_TS%%.sql.gz*}"
    ROLES_BK="$(dirname "$BACKUP")/pgroles_${BK_TS}.sql.enc"
    ERRLOG="$(mktemp)"
    first_errors() { grep -m3 -i 'error' "$ERRLOG" | sed 's/^/    /' || true; }
    psql_apply() {  # reads SQL on stdin; stops at the FIRST error
        docker exec -i "$DRILL_NAME" psql -q -v ON_ERROR_STOP=1 -U noo -d noomesh >/dev/null 2>"$ERRLOG"
    }
    RESTORE_OK=1
    if [ -f "$ROLES_BK" ]; then
        echo "Applying roles: $ROLES_BK"
        if [ -z "$PASS" ]; then
            echo -e "${RED}ERROR: $ROLES_BK is encrypted but no NOO_BACKUP_PASSPHRASE set${NC}" >&2
            RESTORE_OK=0
        elif ! BACKUP_PASS="$PASS" openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_PASS -in "$ROLES_BK" \
                2>"$ERRLOG" | psql_apply; then
            echo -e "${RED}✗ ROLES APPLY FAILED — first error:${NC}"; first_errors
            RESTORE_OK=0
        fi
    else
        echo -e "${CYAN}note: no pgroles_${BK_TS}.sql.enc beside this backup (taken before roles were backed up) —${NC}"
        echo "      pre-creating the known noo_* roles NOLOGIN with no password, as a by-hand restore would."
        if ! printf '%s\n' \
                "$(for r in noo_app noo_trellion noo_trellion_ddl noo_evolve noo_evolve_ddl; do
                    printf "DO \$r\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN CREATE ROLE %s NOLOGIN; END IF; END \$r\$;\n" "$r" "$r"
                  done)" | psql_apply; then
            echo -e "${RED}✗ FALLBACK ROLE CREATION FAILED — first error:${NC}"; first_errors
            RESTORE_OK=0
        fi
    fi

    if [ "$RESTORE_OK" = 1 ]; then
        echo "Restoring dump..."
        # ON_ERROR_STOP: the first failing statement ends the restore and is
        # NAMED, instead of ~150 lines of cascading errors that bury the cause
        # (and a psql that exits 0 after printing them).
        if ! dump_stream | gunzip -c | psql_apply; then
            echo -e "${RED}✗ RESTORE FAILED — this backup may not be usable. First error:${NC}"
            first_errors
            RESTORE_OK=0
        fi
    fi
    rm -f "$ERRLOG"

    if [ "$RESTORE_OK" = 0 ]; then
        FAIL=1
    else
        echo "Sanity checks..."
        # Where the tables live is a property of the install (fresh installs
        # keep mesh tables in schema `mesh`; older ones in `public`) and the
        # search_path that finds them is set by the service's connection, not
        # stored in the dump. So look in every schema the stack uses.
        SP="SET search_path = mesh, public, trellion, evolve;"
        q() { docker exec "$DRILL_NAME" psql -tA -U noo -d noomesh -c "$1" 2>/dev/null | tail -1; }
        check_tables() {
            local n
            n="$(q "SELECT count(*) FROM information_schema.tables WHERE table_type='BASE TABLE' AND table_schema IN ('mesh','public','trellion','evolve')")"
            if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
                echo -e "  ${GREEN}✓${NC} tables restored (mesh/public/trellion/evolve): $n"
            else
                echo -e "  ${RED}✗${NC} tables restored: ${n:-0} — the restore ran clean but produced NO tables"
                FAIL=1
            fi
        }
        check_rows() {  # check_rows <label> <table>: missing vs empty are different failures
            local reg n
            reg="$(q "$SP SELECT to_regclass('$2') IS NOT NULL")"
            if [ "$reg" != "t" ]; then
                echo -e "  ${RED}✗${NC} $1: table $2 is MISSING from the restore"
                FAIL=1
                return
            fi
            n="$(q "$SP SELECT count(*) FROM $2")"
            if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
                echo -e "  ${GREEN}✓${NC} $1: $n"
            else
                echo -e "  ${RED}✗${NC} $1: restored but EMPTY (table exists, 0 rows)"
                FAIL=1
            fi
        }
        check_tables
        check_rows "conversation rows"    noo_conversations
        check_rows "cluster node records" cluster_nodes
        check_rows "knowledge base pages" pages
        if [ "$FAIL" = 0 ]; then
            echo -e "${GREEN}✓ Postgres restore PASSED — this DB backup is restorable${NC}"
        else
            echo -e "${RED}✗ Postgres restore FAILED — investigate before you need this backup for real${NC}"
        fi
    fi
fi

# --- Age-key restore: prove the backed-up age key can decrypt secrets/env.sops ---
# A pg backup is useless if the secrets to run the stack are unrecoverable. This
# takes the newest age-key backup, decrypts it (if .enc) with the INDEPENDENT
# age passphrase, and uses ONLY that restored key to decrypt env.sops — the exact
# fresh-machine recovery path.
#
# Skip ONLY when SOPS isn't in use (no env.sops). When SOPS *is* in use, a
# missing age-key backup is a FAILURE, not a skip: it means every encrypted
# secret dies with this machine. A drill that prints PASSED while the secrets
# are unrecoverable is worse than no drill at all.
echo -e "${CYAN}Age-key restore check...${NC}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_SOPS="${NOO_SOPS_FILE:-$REPO_ROOT/secrets/env.sops}"
AGE_BK="$(ls -t "$BACKUP_DIR"/age-key_*.txt "$BACKUP_DIR"/age-key_*.txt.enc 2>/dev/null | head -1 || true)"
AGE_PASS="${NOO_AGE_BACKUP_PASSPHRASE:-}"
if [ -z "$AGE_PASS" ] && [ -n "${NOO_AGE_BACKUP_PASSPHRASE_FILE:-}" ] && [ -f "$NOO_AGE_BACKUP_PASSPHRASE_FILE" ]; then
    AGE_PASS="$(cat "$NOO_AGE_BACKUP_PASSPHRASE_FILE")"
fi
if [ ! -f "$ENV_SOPS" ] || ! command -v sops >/dev/null 2>&1; then
    echo -e "  ${CYAN}—${NC} sops or $ENV_SOPS not present — SOPS not in use here (skipped)"
elif [ -z "$AGE_BK" ]; then
    echo -e "  ${RED}✗${NC} SOPS IS in use ($ENV_SOPS) but there is NO age-key backup in $BACKUP_DIR"
    echo -e "    ${RED}Every encrypted secret is unrecoverable if this machine is lost.${NC}"
    echo -e "    Fix: NOO_AGE_BACKUP_PASSPHRASE=<offline-passphrase> ./scripts/backup-controller.sh"
    echo -e "    then move the age-key_*.txt.enc + passphrase OFF-MACHINE."
    FAIL=1
else
    DRILL_TMP="$(mktemp -d)"
    trap 'cleanup; rm -rf "$DRILL_TMP" 2>/dev/null || true' EXIT
    RESTORED_KEY="$DRILL_TMP/age-key.txt"
    ok=1
    case "$AGE_BK" in
        *.enc)
            if [ -z "$AGE_PASS" ]; then
                echo -e "  ${RED}✗${NC} $AGE_BK is encrypted but no NOO_AGE_BACKUP_PASSPHRASE set"; ok=0
            elif ! BACKUP_PASS="$AGE_PASS" openssl enc -d -aes-256-cbc -pbkdf2 \
                    -pass env:BACKUP_PASS -in "$AGE_BK" -out "$RESTORED_KEY" 2>/dev/null; then
                echo -e "  ${RED}✗${NC} could not decrypt age-key backup (wrong passphrase?)"; ok=0
            fi
            ;;
        *)
            # A plaintext age-key backup is a FINDING, not a convenience.
            # backup-controller.sh stopped producing these on 2026-09-11
            # (tracker R23/D10), so any that remain are historical copies of
            # the private key that opens EVERY sops secret, sitting unencrypted
            # in a directory that also gets rsync'd, tarred and copied around.
            # The drill still reads it — mid-disaster you use what you have —
            # but it fails, loudly, with the cleanup command.
            echo -e "  ${RED}✗${NC} $AGE_BK is PLAINTEXT — the age private key is unencrypted on disk"
            echo -e "    Clean up now: run ./scripts/backup-controller.sh (writes a .enc copy),"
            echo -e "    verify it here, then: shred -u $BACKUP_DIR/age-key_*.txt"
            FAIL=1
            cp "$AGE_BK" "$RESTORED_KEY"
            ;;
    esac
    if [ "$ok" = 1 ]; then
        chmod 600 "$RESTORED_KEY" 2>/dev/null || true
        n="$(SOPS_AGE_KEY_FILE="$RESTORED_KEY" sops --input-type dotenv --output-type dotenv -d "$ENV_SOPS" 2>/dev/null | grep -c '=' || echo 0)"
        if [ "${n:-0}" -gt 0 ]; then
            echo -e "  ${GREEN}✓${NC} restored age key decrypts env.sops ($n secrets recovered): $AGE_BK"
        else
            echo -e "  ${RED}✗${NC} restored age key did NOT decrypt env.sops"; FAIL=1
        fi
    else
        FAIL=1
    fi
    rm -f "$RESTORED_KEY" 2>/dev/null || true
fi

if [ "$FAIL" = 0 ]; then
    echo -e "${GREEN}✓ Restore drill PASSED — backups are restorable${NC}"
else
    echo -e "${RED}✗ Restore drill FAILED — investigate before you need this backup for real${NC}"
    exit 1
fi
