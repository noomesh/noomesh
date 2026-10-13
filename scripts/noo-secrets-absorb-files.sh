#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# noo-secrets-absorb-files.sh — fold file-shaped credentials into the SOPS
# store. Today's inventory: the Google Chat service-account JSON.
# After absorbing, the credential lives base64'd inside env.sops and is
# handed to the gateway as a VALUE (GOOGLE_CHAT_CREDENTIALS_JSON, parsed in
# memory). Nothing writes it back to disk: the runtime copy, its three
# bind-mounts and the 0644 fallback are gone.
#
# Usage (from the install/repo root):
#   scripts/noo-secrets-absorb-files.sh                # absorb, shred the original
#   scripts/noo-secrets-absorb-files.sh --keep-source  # absorb, LEAVE the original
#
# --keep-source exists because Google issues that JSON once and re-issuing
# it is a console round-trip. Shredding is still the default — on a real
# install the point is that no bare key is left at rest — but an operator
# keeping ONE copy outside the deployment, to re-run onboarding against, is
# doing something reasonable and should not have it destroyed underneath
# them. Keep that copy somewhere the stack does not read.
#
# Idempotent: nothing to absorb → exits 0 saying so.
set -euo pipefail

say() { printf '%s\n' "$*"; }
KEEP_SOURCE=0
for arg in "$@"; do
    case "$arg" in
        --keep-source) KEEP_SOURCE=1 ;;
        *) say "ERROR: unknown argument $arg (only --keep-source)"; exit 2 ;;
    esac
done
ENC="${NOO_SOPS_FILE:-secrets/env.sops}"
[ -f "$ENC" ] || { say "ERROR: $ENC not found — sops backend not initialised (scripts/noo-secrets-sops-init.sh)"; exit 1; }
command -v sops >/dev/null 2>&1 || { [ -x "$HOME/.local/bin/sops" ] && PATH="$HOME/.local/bin:$PATH"; }
command -v sops >/dev/null 2>&1 || { say "ERROR: sops not installed"; exit 1; }

# Locate the plaintext GChat key: .env's GOOGLE_CHAT_KEY_FILE, else default.
KEY_FILE="$(grep -E '^GOOGLE_CHAT_KEY_FILE=' .env 2>/dev/null | tail -1 | cut -d= -f2- || true)"
KEY_FILE="${KEY_FILE:-./secrets/service_account_key.json}"
if [ ! -f "$KEY_FILE" ]; then
    say "nothing to absorb: no plaintext Google Chat key at $KEY_FILE"
    exit 0
fi
if [ -f "$KEY_FILE" ] && grep -qE '\.runtime/' <<<"$KEY_FILE"; then
    say "nothing to absorb: $KEY_FILE is already a runtime materialization"
    exit 0
fi

B64="$(base64 -w0 "$KEY_FILE" 2>/dev/null || base64 "$KEY_FILE" | tr -d '\n')"
[ -n "$B64" ] || { say "ERROR: could not base64 $KEY_FILE"; exit 1; }

# Decrypt → upsert the key → re-encrypt (the established safe recipe: the
# .sops.yaml creation rule pins the recipients, so re-encryption keeps them).
# Stage under secrets/ (0700), not the system temp dir: $TMP/plain.env is the
# WHOLE decrypted store, and /tmp is shared, often a tmpfs that survives in
# swap, and on some boxes world-traversable. Keep it beside the store it came
# from, and shred it — this script's own closing line says "plaintext
# shredded", while the trap was a plain `rm -rf` that only unlinks (tracker
# R27).
TMP="$(mktemp -d "$(dirname "$ENC")/.absorb.XXXXXX")"
chmod 700 "$TMP"
trap 'shred -u "$TMP"/* 2>/dev/null || true; rm -rf "$TMP"' EXIT INT TERM
( umask 077; sops -d --input-type dotenv --output-type dotenv "$ENC" > "$TMP/plain.env" )
grep -v '^NOO_FILECRED_GOOGLE_CHAT_B64=' "$TMP/plain.env" > "$TMP/next.env" || true
printf 'NOO_FILECRED_GOOGLE_CHAT_B64=%s\n' "$B64" >> "$TMP/next.env"
cp "$ENC" "$ENC.bak_absorb_$(date +%s)"
# sops matches creation rules against the INPUT path — encrypting a
# /tmp/... file never matches `secrets/.*\.sops$` ("no matching creation
# rules", host8 live-fire 2026-09-01; this path had never been exercised).
# Use the documented ritual: stage plaintext under a rule-matching name in
# secrets/ (0700 dir, file 0600) and encrypt IN PLACE.
NEXT="${ENC%.sops}.new.sops"
install -m 600 "$TMP/next.env" "$NEXT"
if ! sops -e -i --input-type dotenv --output-type dotenv "$NEXT"; then
    rm -f "$NEXT"
    say "ERROR: sops encryption failed — env.sops untouched (backup kept)"
    exit 1
fi
mv "$NEXT" "$ENC"

# Verify round-trip BEFORE destroying the plaintext.
if ! sops -d --input-type dotenv --output-type dotenv "$ENC" | grep -q '^NOO_FILECRED_GOOGLE_CHAT_B64='; then
    # Say what is actually true. The old message claimed "env.sops restored
    # from backup" — nothing restores it; $ENC was already overwritten by the
    # mv above and the .bak_absorb_* copy just sits there. An operator who
    # believed that message would walk away from a broken store.
    say "ERROR: verification failed — $ENC has ALREADY been replaced and does not round-trip."
    say "       Restore it yourself, now:  cp $ENC.bak_absorb_* $ENC"
    say "       The plaintext key at $KEY_FILE is untouched."
    exit 1
fi
if [ "$KEEP_SOURCE" -eq 1 ]; then
    say "✓ Google Chat key absorbed into $ENC"
    say "  KEPT the original at $KEY_FILE (--keep-source) — it is a bare private key;"
    say "  store it outside anything the stack reads or serves."
else
    shred -u "$KEY_FILE" 2>/dev/null || rm -f "$KEY_FILE"
    say "✓ Google Chat key absorbed into $ENC (plaintext shredded)"
fi
# A stale .env path would shadow the stored value on the next onboarding
# pass, and the file it names may no longer exist.
if [ "$KEEP_SOURCE" -eq 0 ] && grep -qE '^GOOGLE_CHAT_KEY_FILE=' .env 2>/dev/null; then
    sed -i '/^GOOGLE_CHAT_KEY_FILE=/d' .env
fi
say "  the gateway reads it from the store as a value — no file, no mount"
say "  restart to apply:  noo stack restart"
