#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# The sensitive literals in a take's RAW output, one per line, sorted and
# unique: what the recorder's leak check then looks for in the MASKED output
# (record-onboarding.sh `leak_check`). Reads the raw log on stdin.
#
#   leak-literals.sh [HOSTNAME] [EXTRA_NAMES]
#
# HOSTNAME is the filmed machine's name (masked to node-N), EXTRA_NAMES the
# NOO_DEMO_MASK_NAMES list (space or comma separated). Kept as its own script
# so tests/test_demo_studio.py can feed it lines and read what it would flag.
#
# The "label: value" rule mirrors the masker's (mask.pl): the separator is
# `:` or `=` (optionally after "is"), never a bare space. Take 10 (2026-10-25)
# was deleted over "sudo needs no password here" — a sentence, not a secret:
# the old rule took "here" as the value, found "here" in the masked output,
# and called it a leak. A real secret printed as "password hunter2" with no
# separator is not a shape anything in noo prints; the masker does not mask
# it either, and a check looser than the masker only manufactures leaks.
# No -e/pipefail: a rule that matches nothing is the normal case, and a
# grep with no match exits 1.
set -u
host="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
extra="${2:-}"
raw="$(mktemp)"
trap 'rm -f "$raw"' EXIT
cat > "$raw"
# Output: <rule><TAB><literal>. The rule names what matched (ip, name, token,
# tsnet, email, label), so a LEAK report can say what kind of value survived
# without printing it. A `label` value shorter than 6 characters is dropped:
# "Secrets: 9 present" is a count, and a one-digit "secret" is found in any
# version string (take 11, 2026-10-25: "9" in "29.9.2"). The stand-ins the
# masker writes (node-N, you, server) are never leaks, in any case.
{
  grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$raw" | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255&&$1!=127&&$1!=0&&$0!="255.255.255.255"&&!($1==192&&$2==0&&$3==2)&&!($1==198&&$2==51&&$3==100)' | sed 's/^/ip\t/'
  grep -oiwE "host3|host8-ma|host8|host9|host6|host2|host5${host:+|$host}${extra:+|${extra//[ ,]/|}}|peerbox" "$raw" | sed 's/^/name\t/'
  grep -oE 'gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|noo-ent1\.[A-Za-z0-9._-]+' "$raw" | sed 's/^/token\t/'  # leak-ok: the masking regex for token shapes, not a token
  grep -oE '[A-Za-z0-9.-]+\.ts\.net' "$raw" | sed 's/^/tsnet\t/'
  grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]+' "$raw" | grep -viE '@(noomesh\.ai|example\.com)$' | sed 's/^/email\t/' || true
  # A value that is an ENVIRONMENT VARIABLE NAME (upper case with underscores:
  # "secrets … moved to files: NOO_NODE_AGENT_TOKEN") names a secret, it is not
  # one; take 13 (2026-10-26) was deleted because that name, matched case-
  # insensitively, is also in Compose's own warning text.
  grep -oiE '(pass(word|phrase)?|token|secret|api[_ -]?key|credential)s?( is)?[ ]*[:=][ ]*[^ ]+' "$raw" | sed -E 's/^[^:=]*[:=][ ]*//' | grep -v '^\*\{8\}' | grep -E '^.{6,}$' | grep -vE '^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$' | sed 's/^/label\t/' || true
} | grep -viE $'\t(node-[0-9]+|you|server)?$' | sort -u || true
