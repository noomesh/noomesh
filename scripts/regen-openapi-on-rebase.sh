#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Resolve a rebase/merge that stopped ONLY on the generated OpenAPI files.
#
#   scripts/regen-openapi-on-rebase.sh      # in the stopped rebase/merge
#
# Adding a route touches four generated files (the gateway spec, its public
# split, the console's contract and its typed client), so two PRs that add
# different routes conflict on lines that never collide. This:
#   1. merges the gateway spec and the contract key by key
#      (scripts/openapi-merge3.py: one side's change wins, the same entry
#      changed on both sides stops it, nothing hand-written is lost);
#   2. regenerates what is a pure function of them: the contract
#      (export-openapi.py), the public split (gen-public-openapi.py) and
#      ui/packages/api/src/schema.d.ts (openapi-typescript);
#   3. runs every --check and stages the files.
# It refuses when anything ELSE is conflicted, and stages nothing unless all
# the checks pass. Then: `git rebase --continue` (or commit the merge).
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

SPEC=src/noomesh/gateway/static/openapi.json
PUBLIC=src/noomesh/gateway/static/openapi.public.json
CONTRACT=ui/contracts/openapi.json
CLIENT=ui/packages/api/src/schema.d.ts
generated=("$SPEC" "$PUBLIC" "$CONTRACT" "$CLIENT")

mapfile -t unmerged < <(git diff --name-only --diff-filter=U)
if [ "${#unmerged[@]}" -eq 0 ]; then
  echo "regen-openapi: nothing is conflicted" >&2
  exit 1
fi
others=()
for f in "${unmerged[@]}"; do
  case " ${generated[*]} " in *" $f "*) ;; *) others+=("$f") ;; esac
done
if [ "${#others[@]}" -gt 0 ]; then
  echo "regen-openapi: other files are conflicted too; resolve these by hand first:" >&2
  printf '  %s\n' "${others[@]}" >&2
  exit 1
fi
if [ ! -x ui/node_modules/.bin/openapi-typescript ]; then
  echo "regen-openapi: ui/node_modules is not installed (needed for $CLIENT): run \`npm ci --prefix ui\`" >&2
  exit 1
fi

# 1. The two hand-edited specs: key-by-key merge. Unconflicted ones are as git left them.
for f in "$SPEC" "$CONTRACT"; do
  case " ${unmerged[*]} " in *" $f "*) python3 scripts/openapi-merge3.py "$f" ;; esac
done

# 2. Everything derived from them is rebuilt, conflicted or not.
python3 scripts/gen-openapi.py >/dev/null
python3 scripts/export-openapi.py >/dev/null
python3 scripts/gen-public-openapi.py >/dev/null
(cd ui && npm run --silent gen:api >/dev/null)

# 3. Every check, then stage.
python3 scripts/gen-openapi.py --check >/dev/null
python3 scripts/export-openapi.py --check >/dev/null
python3 scripts/gen-public-openapi.py --check >/dev/null
python3 scripts/check-openapi-drift.py >/dev/null
git add -- "${generated[@]}"
echo "regen-openapi: merged and regenerated ${#unmerged[@]} file(s); all OpenAPI checks pass. Review \`git diff --cached --stat\`, then continue the rebase."
