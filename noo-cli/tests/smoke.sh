#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

#
# Gateway-free integration smoke test for the `noo` Rust front door.
#
# Exercises the STANDALONE contract of the BUILT binary — the guarantees that
# must hold on a shipped host with no Python toolchain and no gateway. Every
# case runs the binary under `env -i` (empty environment: no PATH, no Python,
# no repo `.env`, no NOO_* config) so we test exactly the "nothing installed"
# path, including the unknown-verb usage errors and the native
# version/help banners.
#
# Contract asserted (exit code + output substring):
#   1. --version                        -> exit 0, prints a version line
#   2. bare `noo` / --help              -> exit 0, prints the native group banner
#   3. `db revision` (RETIRED 2026-09-03) -> exit 2, unknown subcommand of a
#      native group, never a Python hint
#   4. bare `plugins`                   -> exit 2, needs a subcommand
#   4c. `tui` (RETIRED 2026-08-16)      -> exit 1, native pointer message
#   5. unknown verb                     -> exit 2, unknown command; native
#      `chat` refuses non-TTY REPL with the --message hint
#   6. native gateway cmd, unreachable  -> exit 3 (gateway unreachable)
#
# Dependency-free: bash + the binary. No gateway required. Exits nonzero on the
# first failed assertion.
#
# Usage: tests/smoke.sh [path-to-noo-binary]
#   Binary resolution: $1, else $NOO_CLI_BIN, else <repo>/target/release/noo.

set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${1:-${NOO_CLI_BIN:-$here/../target/release/noo}}"

if [[ ! -x "$BIN" ]]; then
  echo "FATAL: noo binary not found or not executable: $BIN" >&2
  echo "       build it first: cargo build --release" >&2
  exit 1
fi

pass=0
fail=0

# run <expected_rc> <substr> -- <argv...>
# Runs the binary under an empty environment, captures combined output + rc,
# and asserts both the exit code and that <substr> appears in the output.
run() {
  local want_rc="$1" want_sub="$2"; shift 2
  [[ "${1:-}" == "--" ]] && shift
  local out rc
  out="$(env -i "$BIN" "$@" 2>&1 </dev/null)"
  rc=$?
  local ok=1
  if [[ "$rc" -ne "$want_rc" ]]; then ok=0; fi
  # Case-insensitive: CLI_STYLE_GUIDE rev 2 applies sentence/Title case
  # centrally in ui.rs, so the contract is the words, not their case.
  if [[ -n "$want_sub" && "${out,,}" != *"${want_sub,,}"* ]]; then ok=0; fi
  if [[ "$ok" -eq 1 ]]; then
    pass=$((pass + 1))
    printf 'ok   [rc=%s] noo %s\n' "$rc" "$*"
  else
    fail=$((fail + 1))
    printf 'FAIL noo %s\n' "$*"
    printf '     want rc=%s substr=%q\n' "$want_rc" "$want_sub"
    printf '     got  rc=%s\n' "$rc"
    printf '     output: %s\n' "$out"
  fi
}

echo "== noo-cli standalone smoke test =="
echo "binary: $BIN"
echo

# 1. --version reports our own version with no Python present.
run 0 "noo (noomesh CLI, alias: pai)" -- --version

# 2. Bare invocation and --help print the native group banner (no Python).
run 0 "local-first AI agent mesh" -- --help
run 0 "local-first AI agent mesh"    # bare `noo` (no args)

# 3. A retired subcommand of a native group is an unknown subcommand: exit 2,
#    the offending word named, the real subcommands listed. Nothing is
#    exec'd and no Python is ever suggested.
run 2 "unknown command" -- db revision
if env -i "$BIN" db revision 2>&1 </dev/null | grep -qi "python\|NOO_PY_CLI"; then
    echo "FAIL noo db revision must not mention Python"; fail=$((fail+1))
fi

# 4. A bare group is a usage error too (exit 2), never a Python hand-off.
run 2 "needs a subcommand" -- plugins

# 4b. The native onboarding TUI needs a real terminal: non-TTY stdin/stdout
#     -> clear guard message pointing at plain `noo onboard` / --ci, exit 2.
run 2 "interactive terminal" -- onboard --tui

# 4c. `tui` is RETIRED (2026-08-16): answered natively with a pointer to
#     the dashboard / `noo chat` — no Python involved, generic exit 1.
run 1 "retired" -- tui

# 5. An unknown verb: exit 2, unknown command, nothing exec'd.
run 2 "unknown command" -- definitelynotacommand

# 5b. `chat` is native now: non-TTY without --message refuses cleanly (no hang,
#     no hand-off) and names the one-shot escape hatch.
run 2 "--message" -- chat

# 6. A native gateway command against an unreachable gateway -> exit 3.
#    (On a bare host this path used to stack-overflow instead of returning
#    a clean rc.)
run 3 "" -- --gateway https://127.0.0.1:59999 health

# 7. WP-PL: git-style `noo-<name>` plugin shims (dispatch + native list).
#    runp = run with PATH/HOME pointed at a temp dir holding a fake shim.
plugdir="$(mktemp -d)"
cat > "$plugdir/noo-frobnicate" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--noo-plugin-info" ]; then echo "Frobnicates the widget"; exit 0; fi
echo "frobnicated:$*"
exit 7
EOF
chmod +x "$plugdir/noo-frobnicate"
# A shim that tries to shadow a native builtin — must never be dispatched.
printf '#!/bin/sh\nexit 7\n' > "$plugdir/noo-health"
chmod +x "$plugdir/noo-health"

runp() {
  local want_rc="$1" want_sub="$2"; shift 2
  [[ "${1:-}" == "--" ]] && shift
  local out rc
  out="$(env -i PATH="$plugdir" HOME="$plugdir" "$BIN" "$@" 2>&1 </dev/null)"
  rc=$?
  if [[ "$rc" -eq "$want_rc" && ( -z "$want_sub" || "$out" == *"$want_sub"* ) ]]; then
    pass=$((pass + 1)); printf 'ok   [rc=%s] noo %s (plugin env)\n' "$rc" "$*"
  else
    fail=$((fail + 1))
    printf 'FAIL noo %s (plugin env)\n     want rc=%s substr=%q\n     got rc=%s output: %s\n' \
      "$*" "$want_rc" "$want_sub" "$rc" "$out"
  fi
}

# 7a. Unknown word + matching shim -> exec'd with the remaining argv,
#     child exit code (7) propagated, output streamed through.
runp 7 "frobnicated:a b" -- frobnicate a b
# 7b. `plugins list` is native: shows the shim, its path, and the
#     --noo-plugin-info one-liner; exit 0 with no Python and no gateway.
runp 0 "Frobnicates the widget" -- plugins list
runp 0 "frobnicate" -- --json plugins list
# 7c. Builtins always win: noo-health exists but `health` stays native
#     (unreachable gateway -> exit 3, NOT the shim's 7).
runp 3 "" -- --gateway https://127.0.0.1:59999 health
# 7d. `plugins list` created the user plugins dir on demand (under $HOME).
if [[ -d "$plugdir/.config/mesh/plugins/bin" ]]; then
  pass=$((pass + 1)); echo "ok   plugins dir created on demand"
else
  fail=$((fail + 1)); echo "FAIL plugins dir not created: $plugdir/.config/mesh/plugins/bin"
fi
# 7e. Without the shim on PATH (empty env), the same word is an unknown
#     command answered natively (exit 2, suggestions) — never a plugin
#     error (never a plugin error, never a Python hand-off).
run 2 "nknown command" -- frobnicate a
rm -rf "$plugdir"

echo
echo "== $pass passed, $fail failed =="
[[ "$fail" -eq 0 ]]
