#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# public-leak-scan.sh — a self-contained leak scanner for a PUBLIC repository.
#
# GENERIC patterns only: it knows no private name, needs no secret and reaches
# no private repository. It is what CI runs on a public repo (the reusable
# workflow .github/workflows/public-leak-scan.yml calls it); the copy in the
# public trellion repo is this file, unchanged.
#
#   scripts/public-leak-scan.sh [DIR]      # default: the current directory
#
# Exit 0 = clean, 1 = hits (file:line: kind), 2 = could not run.
#
# Waive ONE occurrence with a same-line comment `leak-ok: <reason>`; a bare
# `leak-ok` waives nothing. Waive a file that must exist (a test key, a
# template) with a `.public-leak-scan-allow` file at DIR root: one path per
# line, each followed by ` # <reason>` (no reason, no waiver).
set -uo pipefail

DIR="${1:-.}"
[[ -d "$DIR" ]] || { echo "public-leak-scan: $DIR is not a directory" >&2; exit 2; }
cd "$DIR" || exit 2
echo x | grep -qP x 2>/dev/null || { echo "public-leak-scan: grep -P is required" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/pls.XXXXXX")"; trap 'rm -rf "$TMP"' EXIT
if git rev-parse --git-dir >/dev/null 2>&1; then
    git ls-files -z --cached --others --exclude-standard >"$TMP/files"
else
    find . -type f -not -path './.git/*' -not -path '*/node_modules/*' -print0 | sed -z 's#^\./##' >"$TMP/files"
fi

# kind@@PCRE. `@@` separates the fields so no pattern needs escaping around a delimiter.
RULES=(
  'private key block@@-----BEGIN [A-Z ]*PRIVATE KEY'
  'AWS access key id@@AKIA[0-9A-Z]{16}'
  'GitHub token@@(ghp_|gho_|ghs_)[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}'  # leak-ok: the scanner's own token pattern, not a token
  'API key (sk-)@@sk-[A-Za-z0-9_-]{20,}'
  'Slack token@@xox[abposr]-[A-Za-z0-9-]{10,}'
  'age secret key@@AGE-SECRET-KEY-1' # leak-ok: the scanner's own pattern, not a value
  'JWT@@eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'
  'HF / tailscale / google / gitlab token@@hf_[A-Za-z0-9]{30,}|tskey-(api|auth)-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{15,}'
  'CGNAT address (tailnet)@@(?<![0-9.])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d{1,3}\.\d{1,3}(?![0-9])'
  'LAN address@@(?<![0-9.])(192\.168|10\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01]))\.\d{1,3}\.\d{1,3}(?![0-9])'
  'tailnet hostname@@[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.ts\.net'
  'real home path@@/(home|Users)/(?!(user|runner|ubuntu|node|app|nonroot|root|you|me|example|someone|name|username|USER|builder|vagrant|noo)/)[A-Za-z][A-Za-z0-9._-]*/'
)
# ts.net placeholders, the doc range 100.64.0.0/24 and the MagicDNS resolver are NOT leaks.
OK_LINE='leak-ok:[[:space:]]*[^[:space:]]'
PLACEHOLDER='(example|your-tailnet|tailnet-name|<[^>]*>|XXXX|placeholder)\.ts\.net|[A-Za-z0-9-]*\.(example|your-tailnet|tailnet-name|placeholder)\.ts\.net|100\.64\.0\.[0-9]+|100\.100\.100\.100'

hits=0
for r in "${RULES[@]}"; do
    kind="${r%%@@*}"; re="${r#*@@}"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$kind" == "CGNAT address (tailnet)" || "$kind" == "tailnet hostname" ]]; then
            text="${line#*:*:}"
            stripped="$(sed -E "s#$PLACEHOLDER##g" <<<"$text")"
            grep -qP -- "$re" <<<"$stripped" || continue
        fi
        printf '%s: %s\n' "$(cut -d: -f1,2 <<<"$line")" "$kind"
        hits=$((hits+1))
    done < <(xargs -0 -r grep -HnIP -e "$re" <"$TMP/files" 2>/dev/null | grep -vE "$OK_LINE")
done

# files that must not be in a public tree
ALLOW="$TMP/allow"
{ [[ -f .public-leak-scan-allow ]] && grep -E '#[[:space:]]*[^[:space:]]' .public-leak-scan-allow | sed -E 's/[[:space:]]*#.*$//'; } >"$ALLOW" 2>/dev/null || : >"$ALLOW"
while IFS= read -r -d '' f; do
    b="${f##*/}"
    case "$b" in
        .env.example|.env.sample|.env.template) continue ;;
        *.pem|*.key|*.p12|*.pfx|*.sops|env.sops*|.env|.env.*|id_rsa*|id_ed25519*|*.age) ;;
        *) continue ;;
    esac
    grep -qxF -- "$f" "$ALLOW" && continue
    printf '%s: key / secret / env file is present in the tree\n' "$f"
    hits=$((hits+1))
done <"$TMP/files"

if (( hits > 0 )); then
    echo "public-leak-scan: FAIL - $hits hit(s). Remove the value, or waive one occurrence with 'leak-ok: <reason>'." >&2
    exit 1
fi
echo "public-leak-scan: clean"
