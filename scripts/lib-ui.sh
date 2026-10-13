#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# lib-ui.sh — the launchers' half of noo-cli/CLI_STYLE_GUIDE.md (§4 tokens,
# §5 layout + Rhythm). Sourced by noomesh-start/stop/restart/rebuild/clean so
# the bash side of `noo stack …` looks like the Rust side. Presentation only:
# nothing here changes what a launcher executes.
#
# Mode (mirrors ui.rs):  NOO_COLOR=never|always wins; then NO_COLOR (off);
# then CLICOLOR_FORCE≠0 (on); then TERM=dumb (off); else stdout-is-a-TTY.
# Depth: COLORTERM=truecolor|24bit → brand Slate hex; otherwise 16 colours.
# Glyph fallbacks are single characters so alignment matches in both modes.

# Idempotent: a launcher may be sourced by another launcher.
if [ -n "${_NOO_UI_LOADED:-}" ]; then return 0 2>/dev/null || true; fi
_NOO_UI_LOADED=1

_ui_styled() {
    case "${NOO_COLOR:-}" in
        never) return 1 ;;
        always) return 0 ;;
    esac
    [ -n "${NO_COLOR:-}" ] && return 1
    if [ -n "${CLICOLOR_FORCE:-}" ] && [ "${CLICOLOR_FORCE}" != "0" ]; then return 0; fi
    [ "${TERM:-}" = "dumb" ] && return 1
    [ -t 1 ]
}

if _ui_styled; then
    UI_STYLED=1
    if [ "${COLORTERM:-}" = "truecolor" ] || [ "${COLORTERM:-}" = "24bit" ]; then
        # Slate palette, dark-theme values (pai-mesh-ui packages/tokens).
        UI_BRAND=$'\033[38;2;95;143;208m'
        UI_GOOD=$'\033[38;2;70;192;138m'
        UI_WARN=$'\033[38;2;224;162;74m'
        UI_BAD=$'\033[38;2;229;103;90m'
        UI_MUTED=$'\033[38;2;137;147;166m'
    else
        UI_BRAND=$'\033[34m'
        UI_GOOD=$'\033[32m'
        UI_WARN=$'\033[33m'
        UI_BAD=$'\033[31m'
        UI_MUTED=$'\033[2m'
    fi
    UI_EMPH=$'\033[1m'
    UI_RESET=$'\033[0m'
    UI_G_OK="✓"; UI_G_ERR="✗"; UI_G_WARN="!"; UI_G_STEP="→"
    UI_G_BULLET="•"; UI_G_SECTION="◆"; UI_G_HINT="▸"; UI_RULE_CHAR="─"
else
    UI_STYLED=""
    UI_BRAND=""; UI_GOOD=""; UI_WARN=""; UI_BAD=""; UI_MUTED=""; UI_EMPH=""; UI_RESET=""
    UI_G_OK="+"; UI_G_ERR="x"; UI_G_WARN="!"; UI_G_STEP=">"
    UI_G_BULLET="-"; UI_G_SECTION="#"; UI_G_HINT=">"; UI_RULE_CHAR="-"
fi
export NOO_COLOR="${NOO_COLOR:-}"   # pass the operator's choice to child launchers

# Layout width: COLUMNS, else the tty, else 80; capped at 100 like ui.rs.
_ui_width() {
    local w="${COLUMNS:-}"
    if [ -z "$w" ]; then w="$(tput cols 2>/dev/null || true)"; fi
    case "$w" in ''|*[!0-9]*) w=80 ;; esac
    [ "$w" -lt 40 ] && w=40
    [ "$w" -gt 100 ] && w=100
    printf '%s' "$w"
}

# ── tokens ──────────────────────────────────────────────────────────────
ui_brand() { printf '%s%s%s' "$UI_BRAND" "$*" "$UI_RESET"; }
ui_good()  { printf '%s%s%s' "$UI_GOOD"  "$*" "$UI_RESET"; }
ui_warn_c() { printf '%s%s%s' "$UI_WARN" "$*" "$UI_RESET"; }
ui_bad()   { printf '%s%s%s' "$UI_BAD"   "$*" "$UI_RESET"; }
ui_emph()  { printf '%s%s%s' "$UI_EMPH"  "$*" "$UI_RESET"; }
ui_muted() { printf '%s%s%s' "$UI_MUTED" "$*" "$UI_RESET"; }
ui_cmd()   { ui_brand "$@"; }

# ── layout ──────────────────────────────────────────────────────────────
# A muted rule the layout width.
ui_rule() {
    local w; w="$(_ui_width)"
    local line=""; local i
    for ((i = 0; i < w; i++)); do line+="$UI_RULE_CHAR"; done
    printf '%s\n' "$(ui_muted "$line")"
}

# ◆ Label — blank line before, rule after. For phases of a multi-phase run.
ui_phase() {
    printf '\n%s %s\n' "$(ui_brand "$UI_G_SECTION")" "$(ui_emph "$*")"
    ui_rule
}

# Status lines. Callers write the case they mean (sentence case, no period).
ui_step()   { printf '%s %s\n' "$(ui_brand "$UI_G_STEP")" "$*"; }
ui_done()   { printf '%s %s\n' "$(ui_good "$UI_G_OK")" "$*"; }
ui_warned() { printf '%s %s\n' "$(ui_warn_c "$UI_G_WARN")" "$*"; }
ui_bullet() { printf '%s %s\n' "$UI_G_BULLET" "$*"; }
# Errors are stderr in every mode.
ui_failed() { printf '%s %s\n' "$(ui_bad "$UI_G_ERR")" "$*" >&2; }

# Closing lines: one blank line first (Rhythm).
ui_close_done()   { printf '\n'; ui_done "$@"; }
ui_close_warned() { printf '\n'; ui_warned "$@"; }
ui_close_failed() { printf '\n'; ui_failed "$@"; }

# Muted explanation under a line (four-space indent).
ui_note() { printf '    %s\n' "$(ui_muted "$*")"; }

# Key-value row: bold label padded to WIDTH (default 18), two-space gutter,
# two-space indent. Pass the width the block needs; ui_kv_w sets a default
# for the following rows.
UI_KV_WIDTH=18
ui_kv_w() { UI_KV_WIDTH="$1"; }
ui_kv() {
    local label="$1"; shift
    printf '  %s  %s\n' "$(ui_emph "$(printf "%-${UI_KV_WIDTH}s" "$label")")" "$*"
}

# ▸ command  + muted why line (Guidance). Print ui_rule before a block.
ui_guide_cmd() {
    local cmd="$1"; shift
    printf '%s %s\n' "$(ui_brand "$UI_G_HINT")" "$(ui_cmd "$cmd")"
    [ -n "${1:-}" ] && ui_note "$*"
    return 0
}
