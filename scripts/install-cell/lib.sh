# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
# shellcheck shell=bash

# Sourced by scripts/install-cell/run.sh and the per-mode hooks
# (prep-no-docker.sh, onboard-interactive.sh). Needs OUT (the cell's output
# dir) and python3.
#
#   step NAME TIMEOUT_S -- CMD...
#
# runs CMD with a hard timeout, passes every output line through the
# redactor (the logs and artifacts of this workflow are PUBLIC), shows it
# live, keeps it in $OUT/logs/NAME.log, and appends the step's record (rc,
# wall seconds, first error, prompt-shaped and warning lines, last 50
# lines) to $OUT/steps.jsonl. Returns CMD's exit code (124 on timeout).

CELL_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CELL_PY="$CELL_LIB_DIR/cell.py"
mkdir -p "$OUT/logs"

step() {
    local name="$1" timeout="$2"; shift 2
    [ "${1:-}" = "--" ] && shift
    local log="$OUT/logs/$name.log" start rc
    start=$(date +%s)
    echo "::group::$name"
    python3 "$CELL_PY" run "$timeout" -- "$@" < /dev/null 2>&1 \
        | python3 "$CELL_PY" redact | tee "$log"
    rc=${PIPESTATUS[0]}
    echo "::endgroup::"
    python3 "$CELL_PY" record "$name" "$rc" "$(( $(date +%s) - start ))" "$log" >> "$OUT/steps.jsonl"
    [ "$rc" = 0 ] || echo "::warning::$CELL: step $name exited $rc"
    return "$rc"
}

# The same, for a step that needs a terminal or stdin of its own (the pty
# driver feeds onboard itself): stdin is NOT redirected.
step_tty() {
    local name="$1" timeout="$2"; shift 2
    [ "${1:-}" = "--" ] && shift
    local log="$OUT/logs/$name.log" start rc
    start=$(date +%s)
    echo "::group::$name"
    python3 "$CELL_PY" run "$timeout" -- "$@" 2>&1 \
        | python3 "$CELL_PY" redact | tee "$log"
    rc=${PIPESTATUS[0]}
    echo "::endgroup::"
    python3 "$CELL_PY" record "$name" "$rc" "$(( $(date +%s) - start ))" "$log" >> "$OUT/steps.jsonl"
    return "$rc"
}

# meta KEY VALUE: one fact about the cell for the summary (version, limits).
meta() {
    python3 - "$OUT/meta.json" "$1" "$2" <<'PY'
import json, sys, os
p, k, v = sys.argv[1:]
d = json.load(open(p)) if os.path.exists(p) else {}
if k == "limits":
    d.setdefault("limits", []).append(v)
else:
    d[k] = v
json.dump(d, open(p, "w"), indent=1)
PY
}
