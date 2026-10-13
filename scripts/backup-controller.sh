#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Backup PostgreSQL data for the PAI controller.
#
# Single source of truth for controller backups: run directly via cron, or
# triggered by the `database_backup` heartbeat action through the host spool
# (noo-hostd's `backup` op -> here). Both paths get the same output.
#   0 */6 * * * /home/user/pai-assistant/scripts/backup-controller.sh
#
# Encryption at rest is REQUIRED, not optional. This script never
# writes an unencrypted artefact: no passphrase means no backup. It refuses
# BEFORE it dumps anything, and it exits non-zero, so noo-hostd records
# ok:false and the `database_backup` heartbeat action turns that into an
# operator alert. A backup you did not get is recoverable; a plaintext copy of
# the age key in ~/noo-backups is not.
#
# There used to be a NOO_BACKUP_ENCRYPT_REQUIRED=1 opt-in for that behaviour.
# It was set nowhere, on any box, ever — so the default (write plaintext, print
# a warning to a stream nobody reads) was the only behaviour that ran. A safety
# switch whose off position is the dangerous one is not a safety switch. The
# variable is GONE; do not reintroduce it.
#
# Two INDEPENDENT passphrases, both resolved up front:
#   NOO_BACKUP_PASSPHRASE      -> the Postgres dump   (pg_<ts>.sql.gz.enc)
#   NOO_AGE_BACKUP_PASSPHRASE  -> the age private key (age-key_<ts>.txt.enc)
#
# Age key (SOPS root of trust): when NOO_SECRETS_BACKEND=sops, the age private
# key decrypts secrets/env.sops. Losing it makes EVERY encrypted secret
# unrecoverable, so this script also backs the key up. It MUST NOT share a
# passphrase with the pg dump: NOO_BACKUP_PASSPHRASE lives in env.sops, and if
# that same value protected the age-key backup recovery would be circular —
# you would need the age key to read the passphrase that decrypts the age key.
# This script refuses when the two are equal.
#
# Both passphrases are minted by `noo onboard` into the secret store, which
# means the age one lives in env.sops too. That is fine for RUNNING (the age
# key is on the box) and useless for RECOVERY (the box is gone). It is the key
# to the key: store it OFF-BOX in a password manager, with the encrypted
# age-key backup in a different place again. See
# docs/operating/runbooks/backup-restore-secrets.md.
#
# Decrypt/verify with scripts/restore-drill.sh (reads the same passphrases).
#
# Env:
#   NOO_BACKUP_DIR             backup output dir (default ~/noo-backups)
#   NOO_BACKUP_PASSPHRASE      AES-256 passphrase for the pg dump (REQUIRED)
#   NOO_BACKUP_PASSPHRASE_FILE file holding it (alternative to above)
#   NOO_AGE_BACKUP_PASSPHRASE  AES-256 passphrase for the age-key backup
#                              (REQUIRED when an age key is present; independent)
#   NOO_AGE_BACKUP_PASSPHRASE_FILE  file holding it
#   NOO_BACKUP_RETAIN_DAYS     retention window (default 7)
#
# Note: Redis is intentionally NOT backed up — it holds reconstructible/ephemeral
# state (rate limits, queues, cache, heartbeat flags), and the system of record
# is Postgres.

set -euo pipefail

BACKUP_DIR="${NOO_BACKUP_DIR:-$HOME/noo-backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETAIN_DAYS="${NOO_BACKUP_RETAIN_DAYS:-7}"

# ── Preflight: resolve BOTH passphrases before anything is written ────────
# Fail-closed, and fail EARLY. Refusing after the dump is already on disk
# would mean the very artefact we are refusing to write in plaintext has
# already been written in plaintext.
AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-$HOME/.config/sops/age/keys.txt}"

# Inline env wins over file.
PASSPHRASE="${NOO_BACKUP_PASSPHRASE:-}"
if [ -z "$PASSPHRASE" ] && [ -n "${NOO_BACKUP_PASSPHRASE_FILE:-}" ] && [ -f "$NOO_BACKUP_PASSPHRASE_FILE" ]; then
    PASSPHRASE="$(cat "$NOO_BACKUP_PASSPHRASE_FILE")"
fi
AGE_PASS="${NOO_AGE_BACKUP_PASSPHRASE:-}"
if [ -z "$AGE_PASS" ] && [ -n "${NOO_AGE_BACKUP_PASSPHRASE_FILE:-}" ] && [ -f "$NOO_AGE_BACKUP_PASSPHRASE_FILE" ]; then
    AGE_PASS="$(cat "$NOO_AGE_BACKUP_PASSPHRASE_FILE")"
fi

if [ -z "$PASSPHRASE" ]; then
    echo "  ERROR: no NOO_BACKUP_PASSPHRASE — REFUSING to run. This backup is encrypted or it does not happen." >&2
    echo "         Fix: noo security secrets audit NOO_BACKUP_PASSPHRASE — if it is missing, mint it with" >&2
    echo "              scripts/noo-backup-rotate-passphrase.sh --pg, then re-run. Keep a copy OFF-BOX." >&2
    exit 1
fi

if [ -f "$AGE_KEY_FILE" ] && [ -z "$AGE_PASS" ]; then
    echo "  ERROR: an age private key is present ($AGE_KEY_FILE) but no NOO_AGE_BACKUP_PASSPHRASE — REFUSING to run." >&2
    echo "         The age key opens EVERY sops secret; it is never written to disk unencrypted." >&2
    echo "         Fix: scripts/noo-backup-rotate-passphrase.sh --age (or set the value), then re-run." >&2
    echo "         Store that passphrase OFF-BOX: it is the key to the key, and it lives in env.sops," >&2
    echo "         which the age key itself decrypts — on-box it is no help once the box is gone." >&2
    exit 1
fi

# The two must differ, or recovery is circular: NOO_BACKUP_PASSPHRASE lives in
# env.sops, and reading env.sops needs the age key, which is what the age-key
# backup holds. Equal passphrases make the off-site age-key backup openable
# only by someone who already has the age key.
if [ -n "$AGE_PASS" ] && [ "$AGE_PASS" = "$PASSPHRASE" ]; then
    echo "  ERROR: NOO_AGE_BACKUP_PASSPHRASE equals NOO_BACKUP_PASSPHRASE — REFUSING to run." >&2
    echo "         They must be INDEPENDENT or disaster recovery is circular. Rotate one:" >&2
    echo "         scripts/noo-backup-rotate-passphrase.sh --age" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"
# Backups contain the full system of record — keep the dir owner-only.
chmod 700 "$BACKUP_DIR" 2>/dev/null || true

echo "[$(date)] Starting PAI controller backup..."

# --- PostgreSQL dump (+ optional AES-256 encryption at rest) ---
# PG_OK gates retention below: we must never delete old backups on a run that
# produced no new one, or a prolonged Postgres outage silently deletes every
# backup you have.
PG_OK=0
ROLES_FAILED=0
ROLES_FILE=""
if docker inspect noo-postgres >/dev/null 2>&1; then
    PG_FILE="$BACKUP_DIR/pg_${TIMESTAMP}.sql.gz.enc"
    # pg_dump -> gzip -> openssl AES-256-CBC (pbkdf2, random salt). Pass the
    # passphrase via an env var (not argv) so it never appears in `ps`.
    # There is no unencrypted branch: preflight already refused without a
    # passphrase, so reaching here means we have one.
    if ! docker exec noo-postgres pg_dump -U noo noomesh \
            | gzip \
            | BACKUP_PASS="$PASSPHRASE" openssl enc -aes-256-cbc -pbkdf2 -salt \
                -pass env:BACKUP_PASS -out "$PG_FILE"; then
        rm -f "$PG_FILE"
        echo "  ERROR: encrypted PostgreSQL backup failed" >&2
        exit 1
    fi
    chmod 600 "$PG_FILE" 2>/dev/null || true
    PG_OK=1
    echo "  PostgreSQL backup (encrypted): $PG_FILE ($(du -h "$PG_FILE" | cut -f1))"
    # Machine-readable, on stderr: noo-hostd captures only stderr and turns this
    # line into the result's artifact/bytes (annotateBackup), so the gateway can
    # check the dump itself. Keep the prefix in step with backupArtifactMarker.
    echo "NOO_BACKUP_ARTIFACT=$PG_FILE" >&2

    # --- Cluster roles the dump depends on (pgroles_<ts>.sql.enc) ---
    # pg_dump is per-database; roles are cluster-global, so the dump above
    # carries `ALTER ... OWNER TO noo_trellion_ddl`, `GRANT ... TO noo_app`
    # and friends but NOT the roles. Restored into a clean server, every one of
    # those fails ("role ... does not exist"), which is how a backup that looked
    # healthy was not restorable (restore drill, 2026-10-12). This emits an
    # idempotent CREATE ROLE script for every live noo_* role: attributes only
    # (never SUPERUSER/CREATEROLE/BYPASSRLS), NEVER a password -- passwords live
    # in the secret store and are re-applied by `noo security secrets resync`.
    ROLES_FILE="$BACKUP_DIR/pgroles_${TIMESTAMP}.sql.enc"
    ROLES_SQL="SELECT format('DO \$r\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %L) THEN CREATE ROLE %I %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; END IF; END \$r\$;', rolname, rolname, CASE WHEN rolcanlogin THEN 'LOGIN' ELSE 'NOLOGIN' END) FROM pg_roles WHERE rolname LIKE 'noo\\_%' ORDER BY rolname"
    roles_sql="$(docker exec noo-postgres psql -tA -U noo -d noomesh -c "$ROLES_SQL")" || roles_sql=""
    if [ -z "$roles_sql" ]; then
        echo "  ERROR: could not read the noo_* roles from Postgres — NO roles file written (the dump alone is not restorable on a clean server without pre-creating them; see docs/operating/runbooks/backup-restore-secrets.md)" >&2
        ROLES_FAILED=1
    elif ! printf -- '-- noomesh cluster roles for pg_%s (no passwords)\n%s\n' "$TIMESTAMP" "$roles_sql" \
            | BACKUP_PASS="$PASSPHRASE" openssl enc -aes-256-cbc -pbkdf2 -salt \
                -pass env:BACKUP_PASS -out "$ROLES_FILE"; then
        rm -f "$ROLES_FILE"
        echo "  ERROR: encrypted roles backup failed" >&2
        ROLES_FAILED=1
    else
        chmod 600 "$ROLES_FILE" 2>/dev/null || true
        echo "  Roles backup (encrypted): $ROLES_FILE ($(printf '%s\n' "$roles_sql" | wc -l) roles)"
    fi
else
    echo "  ERROR: noo-postgres container not running — NO database dump was made (this run fails at the end)" >&2
fi

# --- Age key backup (SOPS root of trust; encrypted with an INDEPENDENT passphrase) ---
# AGE_KEY_FILE and AGE_PASS were resolved and validated in preflight. There is
# no `cp` of the private key here and there must never be one again: until
# 2026-09-11 this block copied the age PRIVATE KEY in plaintext to
# ~/noo-backups/age-key_<ts>.txt every six hours on every box, because the
# passphrase was optional and nothing set it.
if [ -f "$AGE_KEY_FILE" ]; then
    AGE_FILE="$BACKUP_DIR/age-key_${TIMESTAMP}.txt.enc"
    # openssl AES-256-CBC (pbkdf2, random salt); passphrase via env, not argv.
    if ! BACKUP_PASS="$AGE_PASS" openssl enc -aes-256-cbc -pbkdf2 -salt \
            -pass env:BACKUP_PASS -in "$AGE_KEY_FILE" -out "$AGE_FILE"; then
        rm -f "$AGE_FILE"
        echo "  ERROR: encrypted age-key backup failed" >&2
        exit 1
    fi
    chmod 600 "$AGE_FILE" 2>/dev/null || true
    echo "  Age key backup (encrypted): $AGE_FILE — store this + its passphrase OFF-MACHINE"
else
    echo "  note: no age key at $AGE_KEY_FILE — skipping age-key backup (SOPS not in use?)"
fi

# --- Retain last N days, remove older backups (both plaintext and encrypted) ---
# ONLY when this run actually produced a new dump. Otherwise a Postgres outage
# longer than the retention window silently deletes every backup you have —
# retention would be quietly converting "DB is down" into "DB is unrecoverable".
# Additionally, never delete the last PG_KEEP_MIN dumps regardless of age: a
# stale backup beats no backup.
PG_KEEP_MIN="${NOO_BACKUP_KEEP_MIN:-3}"
if [ "$PG_OK" = 1 ]; then
    # Candidates for age-based deletion, excluding the newest PG_KEEP_MIN.
    # shellcheck disable=SC2012
    # `ls -t a b` exits NON-ZERO when either glob matches nothing, and under
    # `set -euo pipefail` that aborts the whole script — AFTER the dump is
    # safely written but BEFORE "Backup complete". The scheduled task then
    # reported FAILED on every run while backups were in fact fine.
    # Observed 2026-08-01: every backup is .enc, so the plaintext glob never
    # matched and `ls` exited 2. `|| true` keeps retention best-effort; a
    # cleanup that cannot list files must never fail a successful backup.
    ls -t "$BACKUP_DIR"/pg_*.sql.gz "$BACKUP_DIR"/pg_*.sql.gz.enc 2>/dev/null \
        | tail -n +$((PG_KEEP_MIN + 1)) \
        | while IFS= read -r f; do
            if [ -n "$(find "$f" -mtime +"${RETAIN_DAYS}" 2>/dev/null)" ]; then
                rm -f "$f"
                # The roles file shares the dump's timestamp and ages out with it.
                ts="$(basename "$f")"; ts="${ts#pg_}"; ts="${ts%%.sql.gz*}"
                rm -f "$BACKUP_DIR/pgroles_${ts}.sql.enc"
            fi
          done || true
else
    echo "  note: no new dump this run — skipping retention so existing backups are preserved"
fi
# Age-key backups are tiny and the key rarely rotates — keep the newest 3
# regardless of age so the only copy of the current key can never age out while
# backups are silently stalled.
# shellcheck disable=SC2012
# Same `ls` trap the retention block above guards against, and the last
# unguarded instance: with no age-key backups yet, the glob matches nothing,
# `ls` exits 2, `2>/dev/null` hides the message but NOT the status, and
# `set -euo pipefail` aborts the script here — on a first-ever run, after the
# dump is already safely written.
{ ls -t "$BACKUP_DIR"/age-key_* 2>/dev/null || true; } | tail -n +4 | xargs -r rm -f

echo "[$(date)] Backup complete. Backups in $BACKUP_DIR:"
found="$(find "$BACKUP_DIR" -maxdepth 1 \( -name 'pg_*.sql.gz' -o -name 'pg_*.sql.gz.enc' -o -name 'pgroles_*.sql.enc' -o -name 'age-key_*' \) 2>/dev/null | sort)"
if [ -n "$found" ]; then
    # shellcheck disable=SC2086
    ls -lh $found
else
    echo "  (no backups found)"
fi

# ── Off the machine ───────────────────────────────────────────────────────
#
# A backup on the machine it protects survives nothing. That is not a
# hypothetical: this box holds the Postgres volume, every dump, and the
# encrypted copy of the age key, so one disk takes the data and the means to
# read it back together.
#
# NOO_BACKUP_OFFSITE says where a copy goes. Unset is not "no" — it is
# "nobody has decided", which is why `noo backups status` reports it and
# onboarding asks:
#
#   ssh:user@host:/path   scp each new artifact to another machine
#   dir:/mnt/whatever     copy to a mounted disk (an external drive, a NAS)
#   s3:s3://bucket/pfx    hand to `aws s3 cp` or `rclone copyto`
#   portable              no automatic copy — the operator runs
#                         `scripts/noo-backup-export.sh` and carries the
#                         bundle off by hand. The honest answer for a box
#                         with no second host and no network target.
#   none                  the risk is understood and accepted, on purpose
#
# A FAILED copy does not delete or fail the local backup — you keep what you
# got — but it DOES exit non-zero, so noo-hostd records ok:false and
# the `database_backup` heartbeat action raises it. A copy that silently
# stopped working is the same as no copy, discovered at the worst moment.
offsite_copy() {
    local dest="${NOO_BACKUP_OFFSITE:-}"
    [ -n "$dest" ] || { echo "  offsite: not configured (noo backups setup)"; return 0; }
    case "$dest" in
        none)     echo "  offsite: declined — the risk is recorded as accepted"; return 0 ;;
        portable) echo "  offsite: portable — run scripts/noo-backup-export.sh and carry it off"; return 0 ;;
    esac

    # Only what this run produced. Re-copying the whole directory every six
    # hours is how an offsite target fills up and starts failing for a reason
    # that has nothing to do with backups.
    # `${VAR:-}` and if-statements, not `[ -f "$X" ] && …`: PG_FILE is only
    # set inside the dump branch, so a bare reference aborts under `set -u`,
    # and a false `&&` chain as a standalone statement aborts under `set -e`
    # — on a run where the dump was skipped, i.e. exactly when this must
    # still report cleanly.
    local made=()
    if [ -n "${PG_FILE:-}" ] && [ -f "${PG_FILE}" ]; then made+=("$PG_FILE"); fi
    if [ -n "${ROLES_FILE:-}" ] && [ -f "${ROLES_FILE}" ]; then made+=("$ROLES_FILE"); fi
    if [ -n "${AGE_FILE:-}" ] && [ -f "${AGE_FILE}" ]; then made+=("$AGE_FILE"); fi
    if [ ${#made[@]} -eq 0 ]; then
        echo "  offsite: nothing new this run"
        return 0
    fi

    local rc=0
    case "$dest" in
        ssh:*)
            local target="${dest#ssh:}"
            # BatchMode: a copy that stops to ask for a password inside a
            # scheduled backup hangs forever instead of failing.
            scp -B -o StrictHostKeyChecking=accept-new -- "${made[@]}" "$target/" || rc=$?
            ;;
        dir:*)
            local target="${dest#dir:}"
            if [ ! -d "$target" ]; then
                echo "  offsite: FAILED — $target is not a directory (unmounted?)" >&2
                return 1
            fi
            cp -- "${made[@]}" "$target/" || rc=$?
            ;;
        s3:*)
            local target="${dest#s3:}"
            for f in "${made[@]}"; do
                if command -v aws >/dev/null 2>&1; then
                    aws s3 cp -- "$f" "$target/$(basename "$f")" || rc=$?
                elif command -v rclone >/dev/null 2>&1; then
                    rclone copyto "$f" "$target/$(basename "$f")" || rc=$?
                else
                    echo "  offsite: FAILED — neither aws nor rclone is installed" >&2
                    return 1
                fi
            done
            ;;
        *)
            echo "  offsite: FAILED — unknown destination '$dest'" >&2
            echo "           expected ssh:… dir:… s3:… portable none" >&2
            return 1
            ;;
    esac

    if [ "$rc" -ne 0 ]; then
        echo "  offsite: FAILED to copy to $dest (exit $rc) — the LOCAL backup is intact" >&2
        return 1
    fi
    echo "  offsite: copied ${#made[@]} artifact(s) to $dest"
    return 0
}

offsite_copy || OFFSITE_RC=$?
if [ -n "${OFFSITE_RC:-}" ]; then
    echo "[$(date)] Backup written, but the offsite copy FAILED — see above." >&2
    exit "$OFFSITE_RC"
fi

# A run that made no database dump did not back up the system of record. The
# age key and offsite steps above still ran (they are independent and worth
# having), but the run must FAIL: exiting 0 here reported "backup OK" for a
# backup that never happened, the silent-success shape of #247. Retention was
# already skipped (PG_OK gate) so existing dumps are preserved.
if [ "$PG_OK" != 1 ]; then
    echo "[$(date)] Backup FAILED: no database dump was produced (noo-postgres is not running)." >&2
    exit 1
fi

# The dump is only restorable on a clean server with its roles. A run that
# wrote the dump but not the roles file is a failed backup, said out loud.
if [ "$ROLES_FAILED" = 1 ]; then
    echo "[$(date)] Backup FAILED: the database dump was written but the roles file was not." >&2
    exit 1
fi
