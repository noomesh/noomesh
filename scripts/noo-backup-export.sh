#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# noo-backup-export.sh — one file you can carry off this machine.
#
# For the box with no second host and no network target. A backup that never
# leaves the machine it protects survives nothing, and "set up object storage
# first" is not an answer for a controller in a cupboard. This makes a single
# archive you can put on a USB stick, hand to another machine, or attach to
# something — and it tells you plainly what is in it and what is not.
#
#   scripts/noo-backup-export.sh                 # newest dump + age key
#   scripts/noo-backup-export.sh --all           # every dump in the dir
#   scripts/noo-backup-export.sh --out /mnt/usb  # write it there
#
# WHAT IS INSIDE: the artifacts exactly as they sit on disk — already
# encrypted, each with AES-256 under a passphrase this script never sees and
# never asks for. The archive adds no second layer, because a second
# passphrase to lose helps nobody, and re-encrypting would mean decrypting
# first, which would put plaintext on a disk that is about to be carried
# around.
#
# WHAT IS NOT INSIDE, and must not be: the two passphrases. They live in your
# password manager. An archive holding both the ciphertext and the key to it
# is a plaintext backup with extra steps. The manifest names them so a future
# reader knows what they need rather than discovering it during a restore.
set -euo pipefail

say() { printf '%s\n' "$*"; }
BACKUP_DIR="${NOO_BACKUP_DIR:-$HOME/noo-backups}"
OUT_DIR="$PWD"
ALL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --all) ALL=1; shift ;;
        --out) OUT_DIR="${2:?--out needs a directory}"; shift 2 ;;
        -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) say "ERROR: unknown argument $1"; exit 2 ;;
    esac
done

[ -d "$BACKUP_DIR" ] || { say "ERROR: no backup dir at $BACKUP_DIR"; exit 1; }
[ -d "$OUT_DIR" ] || { say "ERROR: --out $OUT_DIR is not a directory"; exit 1; }

# Newest dump, plus the newest age-key backup. The age key is the small one
# that matters most: without it every encrypted secret is unrecoverable, so it
# goes in every export regardless of --all.
mapfile -t DUMPS < <(ls -t "$BACKUP_DIR"/pg_*.sql.gz.enc 2>/dev/null || true)
mapfile -t AGEKEYS < <(ls -t "$BACKUP_DIR"/age-key_*.enc 2>/dev/null || true)
[ "${#DUMPS[@]}" -gt 0 ] || { say "ERROR: no encrypted dumps in $BACKUP_DIR — nothing to export"; exit 1; }

FILES=()
if [ "$ALL" -eq 1 ]; then FILES+=("${DUMPS[@]}"); else FILES+=("${DUMPS[0]}"); fi
[ "${#AGEKEYS[@]}" -gt 0 ] && FILES+=("${AGEKEYS[0]}")
# The roles file beside each exported dump: without it the dump does not
# restore on a clean server. Older dumps have none; that is fine.
for d in "${FILES[@]}"; do
    case "$(basename "$d")" in
        pg_*.sql.gz.enc)
            _ts="$(basename "$d")"; _ts="${_ts#pg_}"; _ts="${_ts%%.sql.gz*}"
            [ -f "$BACKUP_DIR/pgroles_${_ts}.sql.enc" ] && FILES+=("$BACKUP_DIR/pgroles_${_ts}.sql.enc")
            ;;
    esac
done

# Refuse to export anything that is not encrypted. The globs above only
# match `.enc`, so this cannot normally fire — it is kept because the globs
# are one edit away from being widened, and a plaintext dump inside an
# archive meant to be carried around would make it the most dangerous file
# you own.
for f in "${FILES[@]}"; do
    case "$f" in
        *.enc) ;;
        *) say "ERROR: $f is not encrypted — refusing to put it in a portable archive"; exit 1 ;;
    esac
done

# A PLAINTEXT artifact in the backup dir is a finding in its own right, not
# just something to leave out. backup-controller.sh refuses to write one, so
# any that exist predate that rule (or came from somewhere else) — and the
# runbook's cleanup step is `shred -u`. Saying nothing here would quietly
# leave an unencrypted copy of the database next to the archive you are
# about to carry away, which is the opposite of the point.
mapfile -t PLAIN < <(ls "$BACKUP_DIR"/pg_*.sql.gz "$BACKUP_DIR"/age-key_*.txt 2>/dev/null | grep -v '\.enc$' || true)
if [ "${#PLAIN[@]}" -gt 0 ]; then
    say "WARNING: ${#PLAIN[@]} UNENCRYPTED artifact(s) in $BACKUP_DIR — not exported, and they should not exist:"
    for f in "${PLAIN[@]}"; do say "  $f"; done
    say "  remove with: shred -u <file>   (see docs/operating/runbooks/backup-restore-secrets.md)"
    say
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/noo-export-XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT INT TERM
chmod 700 "$STAGE"
BUNDLE="$OUT_DIR/noo-backup-export_${STAMP}.tar.gz"

for f in "${FILES[@]}"; do cp -- "$f" "$STAGE/"; done

{
    echo "noomesh portable backup export"
    echo "created:  $(date -Is)"
    echo "host:     $(hostname)"
    echo
    echo "CONTENTS (already encrypted, AES-256-CBC + pbkdf2):"
    for f in "${FILES[@]}"; do
        printf '  %s  %s\n' "$(basename "$f")" "$(du -h "$f" | cut -f1)"
    done
    echo
    echo "TO RESTORE you also need, and they are deliberately NOT in here:"
    echo "  NOO_BACKUP_PASSPHRASE      opens pg_*.sql.gz.enc and pgroles_*.sql.enc"
    echo "  NOO_AGE_BACKUP_PASSPHRASE  opens age-key_*.enc  (a DIFFERENT value)"
    echo "Both live in your password manager. An archive carrying the"
    echo "ciphertext and its key together is a plaintext backup with extra steps."
    echo
    echo "Decrypt one file with:"
    echo "  openssl enc -d -aes-256-cbc -pbkdf2 -in <file> -out <out>"
    echo "Full procedure: docs/operating/runbooks/backup-restore-secrets.md"
} > "$STAGE/MANIFEST.txt"

tar -czf "$BUNDLE" -C "$STAGE" .
chmod 600 "$BUNDLE"

# Prove it before saying it is done. A bundle that does not list is not a
# bundle, and finding that out later defeats the purpose of having one.
tar -tzf "$BUNDLE" >/dev/null || { say "ERROR: the archive did not verify"; rm -f "$BUNDLE"; exit 1; }

say "✓ $BUNDLE"
say "  $(du -h "$BUNDLE" | cut -f1), $(( ${#FILES[@]} )) artifact(s) + MANIFEST.txt"
say
say "  Carry it off this machine. It is encrypted; the passphrases are not in it."
say "  Keep the archive and the password manager in different places."
