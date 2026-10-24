#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# Film the onboarding: a stranger on a clean Ubuntu box goes from nothing to a
# first chat, rendered by vhs to a GIF and an MP4 in demo-out/.
#
#   scripts/demo/record-onboarding.sh --smoke        # toolchain + masking check, harmless
#   NOO_DEMO_SANDBOX=1 scripts/demo/record-onboarding.sh [--speed 2]
#
# The real run INSTALLS noo and ONBOARDS a full stack on the machine it runs
# on, and the film shows that machine's output. So it refuses to run unless
# you say you are on a throwaway sandbox (NOO_DEMO_SANDBOX=1) and the machine
# looks clean (no noo binary, no ~/.noo). Never run it on a fleet node.
#
# Everything noo and the installer print goes through scripts/demo/mask.pl
# (node names, IPs, tailnet names, e-mails, home paths and tokens become generic
# stand-ins). The recorder logs the output raw and masked and, after rendering,
# checks that no sensitive value from the raw log is still in the masked one; if
# one is, the film is deleted. The raw log is always deleted.
#
# The install URL comes from the repo's one declared release repo
# (noo-cli/install.sh), so the film follows the org move by itself. Override
# with NOO_DEMO_INSTALL_URL.
#
# Box mode (NOO_DEMO_BOX=<container>, set by scripts/demo/studio.sh): vhs runs
# here but the film is shot INSIDE a throwaway container that studio.sh made
# (it must carry the label noo-demo-box=1). The guard rails then check that
# container, not this machine, and the logs are copied out afterwards.
#
# Failed steps: the shell records the exit status of every command typed into
# the film. If any step failed, the takes are renamed *.FAILED.* and the run
# fails, so a broken take is never mistaken for a publishable one.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT=demo-out
SMOKE=0
SPEED=2
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) SMOKE=1 ;;
    --speed) SPEED="${2:?--speed needs a number}"; shift ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '4,25p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

die() { echo "ERROR: $*" >&2; exit 1; }

missing=()
for t in vhs ttyd ffmpeg perl; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
# The film itself runs `curl | sh`; on a bare machine curl must exist here, in box mode it must exist in the box.
[ -n "${NOO_DEMO_BOX:-}" ] || command -v curl >/dev/null 2>&1 || missing+=(curl)
if [ ${#missing[@]} -gt 0 ]; then
  cat >&2 <<HINT
Missing: ${missing[*]}
On Ubuntu 24.04:
  sudo apt update && sudo apt install -y ffmpeg ttyd perl
  echo 'deb [trusted=yes] https://repo.charm.sh/apt/ /' | sudo tee /etc/apt/sources.list.d/charm.list
  sudo apt update && sudo apt install -y vhs
vhs downloads a headless Chromium on its first run.
HINT
  exit 1
fi

cd "$ROOT"
mkdir -p "$OUT"
OUT_ABS="$(cd "$OUT" && pwd)"
RAW="$OUT_ABS/raw.log"
MASKED="$OUT_ABS/masked.log"
EXIT_LOG="$OUT_ABS/exit.log"
# NOO_DEMO_MASK is a test seam: point it at /bin/cat to prove the leak check fails a film whose masker masks nothing.
MASK="${NOO_DEMO_MASK:-$ROOT/scripts/demo/mask.pl}"

# Where the TAPE finds the masker and the logs: here, or inside the box.
BOX="${NOO_DEMO_BOX:-}"
T_RAW="$RAW"; T_MASKED="$MASKED"; T_EXIT="$EXIT_LOG"; T_MASK="$MASK"
ENTER="true"
BOXDIR=/tmp/demo
bx() { docker exec -u you "$BOX" "$@"; }
if [ -n "$BOX" ]; then
  command -v docker >/dev/null 2>&1 || die "box mode needs the docker CLI"
  [ "$(docker inspect -f '{{index .Config.Labels "noo-demo-box"}}' "$BOX" 2>/dev/null)" = "1" ] \
    || die "container '$BOX' is not a film box (no label noo-demo-box=1); make one with scripts/demo/studio.sh up"
  T_RAW="$BOXDIR/raw.log"; T_MASKED="$BOXDIR/masked.log"; T_EXIT="$BOXDIR/exit.log"; T_MASK="$BOXDIR/mask.pl"
  ENTER="exec docker exec -it -u you -w /home/you -e TERM=xterm-256color $BOX bash --norc -i"
fi
box_cleanup() { [ -z "$BOX" ] || docker exec -u root "$BOX" rm -rf "$BOXDIR" >/dev/null 2>&1 || true; }
# Whatever happens, the raw log (it holds the real values) does not outlive the run.
trap 'rm -f "$RAW"; box_cleanup' EXIT
box_prepare() {
  [ -n "$BOX" ] || return 0
  docker exec -u root "$BOX" sh -c "rm -rf $BOXDIR && mkdir -m 755 $BOXDIR" || die "cannot prepare $BOXDIR in $BOX"
  docker cp "$MASK" "$BOX:$BOXDIR/mask.pl"
  docker exec -u root "$BOX" sh -c ": > $BOXDIR/raw.log && : > $BOXDIR/masked.log && : > $BOXDIR/exit.log && chown -R you $BOXDIR && chmod 755 $BOXDIR/mask.pl && chmod 600 $BOXDIR/raw.log" || die "cannot set up the logs in $BOX"
}
box_collect() {
  [ -n "$BOX" ] || return 0
  local f
  for f in raw masked exit; do docker cp "$BOX:$BOXDIR/$f.log" "$OUT_ABS/$f.log" || die "cannot copy $f.log out of $BOX"; done
  chmod 600 "$RAW"
  box_cleanup
}

# Fill a template: $1 template, $2 output tape.
fill() {
  sed -e "s|@INSTALL_URL@|${INSTALL_URL:-https://example.invalid/install.sh}|g" \
      -e "s|@PLAYBACK_SPEED@|${SPEED}|g" \
      -e "s|@RAW_LOG@|${T_RAW}|g" -e "s|@MASKED_LOG@|${T_MASKED}|g" -e "s|@MASK@|${T_MASK}|g" \
      -e "s|@EXIT_LOG@|${T_EXIT}|g" -e "s|@ENTER@|${ENTER}|g" "$1" > "$2"
}

# Every sensitive value found in the raw log must be absent from the masked log.
# Prints only a COUNT, never the values. Returns 1 if any survived.
leak_check() {
  local raw="$1" masked="$2" n=0 lit host
  [ -s "$raw" ] || { echo "leak check: no output was logged (nothing went through the masker; did the typed commands reach the shell?)" >&2; return 2; }
  if [ -n "$BOX" ]; then host="$(bx hostname | tr '[:upper:]' '[:lower:]')"; else host="$(hostname | tr '[:upper:]' '[:lower:]')"; fi
  while IFS= read -r lit; do
    [ -n "$lit" ] || continue
    if grep -qiF -- "$lit" "$masked"; then n=$((n + 1)); fi
  done < <(
    {
      grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$raw" | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255&&$1!=127&&$1!=0&&$0!="255.255.255.255"&&!($1==192&&$2==0&&$3==2)&&!($1==198&&$2==51&&$3==100)'
      grep -oiwE "host3|host8-ma|host8|host8|host9|host6|host2|host5|${host}${NOO_DEMO_MASK_NAMES:+|${NOO_DEMO_MASK_NAMES//[ ,]/|}}|peerbox" "$raw"
      grep -oE 'gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|noo-ent1\.[A-Za-z0-9._-]+' "$raw"  # leak-ok: the masking regex for token shapes, not a token
      grep -oE '[A-Za-z0-9.-]+\.ts\.net' "$raw"
      grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]+' "$raw" | grep -viE '@(noomesh\.ai|example\.com)$' || true
      grep -oiE '(pass(word|phrase)?|token|secret|api[_ -]?key)s?[: =]+[^ ]+' "$raw" | sed -E 's/^[^: =]*[: =]+//' | grep -v '^\*\{8\}' || true
    } | grep -vE '^(node-[0-9]+|you|server)$' | sort -u
  )
  if [ "$n" -gt 0 ]; then
    echo "LEAK: $n sensitive value(s) from the raw output are still present in the masked output." >&2
    return 1
  fi
  echo "leak check: no raw sensitive value survives in the masked output"
}

# Every command typed into the film left its exit status(es) in the exit log.
# A missing/empty log is a failure too: it would mean nothing was recorded.
exit_check() {
  [ -s "$EXIT_LOG" ] || { echo "exit check: no command exit statuses were recorded" >&2; return 1; }
  local bad
  bad="$(tr ' ' '\n' < "$EXIT_LOG" | grep -vxcE '0' || true)"
  if [ "${bad:-0}" -gt 0 ]; then
    echo "exit check: $bad step(s) in the film returned a non-zero status" >&2
    return 1
  fi
  echo "exit check: every step in the film succeeded"
}

# gif_from_mp4 MP4 GIF: the GIF is made from the MP4, not by vhs. vhs's GIF
# render computes ONE palette over every frame of the film, which holds all of
# them in memory: a 20-minute take was killed at 7 GB and, uncapped, took a
# 19 GiB WSL2 host down twice (2026-10-23/24). This streams instead: a palette
# per frame (`stats_mode=single` + `paletteuse=new=1`), at a GIF-sized frame
# rate and width. The MP4 keeps the full frames; the GIF is the preview.
gif_from_mp4() {
  local mp4="$1" gif="$2" range=()
  [ -s "$mp4" ] || { echo "no MP4 to make the GIF from: $mp4" >&2; return 1; }
  # NOO_DEMO_GIF_RANGE=START:SECONDS makes a teaser of one stretch (a GIF of a
  # whole five-minute take is hundreds of MB whatever the rate: take 7's was
  # 577 MB at 12 fps/1000 px). The default is the whole take at 8 fps, 800 px.
  if [ -n "${NOO_DEMO_GIF_RANGE:-}" ]; then
    range=(-ss "${NOO_DEMO_GIF_RANGE%%:*}" -t "${NOO_DEMO_GIF_RANGE#*:}")
  fi
  ffmpeg -loglevel error -y "${range[@]}" -i "$mp4" \
    -vf "fps=${NOO_DEMO_GIF_FPS:-8},scale=${NOO_DEMO_GIF_WIDTH:-800}:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=single[p];[b][p]paletteuse=new=1:dither=bayer:bayer_scale=5" \
    "$gif" || { echo "GIF render failed; the MP4 stands" >&2; return 1; }
}

finish() { # $1 base name (smoke|onboarding)
  local base="$1"
  local lc=0
  leak_check "$RAW" "$MASKED" || lc=$?
  if [ "$lc" -eq 2 ]; then
    rm -f "$RAW" "$MASKED" "$OUT_ABS/$base.gif" "$OUT_ABS/$base.mp4" "$OUT_ABS/contact-sheet.png"
    die "film deleted: nothing was logged, so nothing could be checked. The commands did not run in the film shell."
  fi
  if [ "$lc" -ne 0 ]; then
    # the "masked" log of a failed run may hold the very values that leaked: delete it too
    rm -f "$RAW" "$MASKED" "$OUT_ABS/$base.gif" "$OUT_ABS/$base.mp4" "$OUT_ABS/contact-sheet.png"
    die "film deleted: the masker missed something. Add the pattern to scripts/demo/mask.pl and a case to tests/test_demo_mask.py, then record again."
  fi
  rm -f "$RAW"
  if ! exit_check; then
    mv -f "$OUT_ABS/$base.gif" "$OUT_ABS/$base.FAILED.gif" 2>/dev/null || true
    mv -f "$OUT_ABS/$base.mp4" "$OUT_ABS/$base.FAILED.mp4" 2>/dev/null || true
    die "a step failed: the takes were renamed $base.FAILED.*. Read $MASKED (the masked transcript), fix the cause, record again."
  fi
  ls -la "$OUT_ABS/$base.gif" "$OUT_ABS/$base.mp4"
}

: > "$RAW"; : > "$MASKED"; chmod 600 "$RAW"

if [ "$SMOKE" -eq 1 ]; then
  fill scripts/demo/smoke.tape.in "$OUT/smoke.generated.tape"
  box_prepare
  vhs "$OUT/smoke.generated.tape"
  rm -f "$OUT/smoke.generated.tape"
  box_collect
  finish smoke
  echo "smoke ok: vhs, ttyd, ffmpeg and the masker render a masked GIF and MP4"
  exit 0
fi

# ---- the real film: guard rails first ----------------------------------------
if [ -n "$BOX" ]; then
  : # the label check above is the sandbox confirmation; the box is what gets inspected below
else
  [ "${NOO_DEMO_SANDBOX:-}" = "1" ] || die "set NOO_DEMO_SANDBOX=1 to confirm this is a throwaway sandbox (the film installs noo and onboards a stack here)"
fi
if [ "$FORCE" -ne 1 ]; then
  if [ -n "$BOX" ]; then
    if bx sh -c 'command -v noo >/dev/null 2>&1 || [ -e "$HOME/.noo" ] || [ -e "$HOME/.local/bin/noo" ]'; then
      die "the box already has noo or ~/.noo; make a fresh one (studio.sh down && studio.sh up)"
    fi
  elif command -v noo >/dev/null 2>&1 || [ -e "$HOME/.noo" ] || [ -e "$HOME/.local/bin/noo" ]; then
    die "this machine already has noo or ~/.noo; film on a clean sandbox (or --force if you really mean it)"
  fi
fi
if [ -n "$BOX" ]; then host="$(bx hostname | tr "[:upper:]" "[:lower:]")"; else host="$(hostname | tr "[:upper:]" "[:lower:]")"; fi
case "$host" in
  host3*|host8*|host8*|host9*|host6*|host2*|host5*) die "refusing to film on a fleet node ($host)" ;;
esac
if [ -n "$BOX" ]; then who="$(bx id -un)"; else who="$(id -un)"; fi
[ "$who" = "you" ] || echo "note: run as a user named 'you' so any home path in the installer output is generic (it is masked anyway)" >&2

if [ -n "${NOO_DEMO_INSTALL_URL:-}" ]; then
  INSTALL_URL="$NOO_DEMO_INSTALL_URL"
else
  repo="$(sed -n 's/^REPO="\${NOO_CLI_REPO:-\([^}]*\)}".*/\1/p' noo-cli/install.sh | head -1)"
  [ -n "$repo" ] || die "could not read the declared release repo from noo-cli/install.sh"
  INSTALL_URL="https://github.com/${repo}/releases/latest/download/install.sh"
fi
echo "film will install from: $INSTALL_URL"
# In box mode ask from inside the box: it is the stranger's view, and the recorder image has no curl.
if [ -n "$BOX" ]; then probe=(bx curl -fsSI "$INSTALL_URL"); else probe=(curl -fsSI "$INSTALL_URL"); fi
"${probe[@]}" >/dev/null 2>&1 || die "the install URL does not answer anonymously (is the repo public yet?): $INSTALL_URL"

fill scripts/demo/onboarding.tape.in "$OUT/onboarding.generated.tape"
box_prepare
vhs "$OUT/onboarding.generated.tape"
rm -f "$OUT/onboarding.generated.tape"
box_collect
gif_from_mp4 "$OUT/onboarding.mp4" "$OUT/onboarding.gif"
finish onboarding

# A contact sheet (one frame every 5 s) for the last look before publishing.
ffmpeg -loglevel error -y -i "$OUT/onboarding.mp4" -vf "fps=1/5,scale=640:-1,tile=4x6" -frames:v 1 "$OUT/contact-sheet.png" || true
echo
echo "Look at $OUT/contact-sheet.png and the MP4 BEFORE publishing. $OUT/masked.log is the masked transcript."
