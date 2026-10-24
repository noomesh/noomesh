#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# The tighter cut: speed up the stretches of a take that are only the network
# (image and model pulls) and say so on screen, without refilming.
#
#   scripts/demo/cut.sh IN.mp4 OUT.mp4 EDITS
#
# EDITS is a text file, one edit per line:
#
#   START END SPEED [CAPTION…]
#
# START/END in seconds of IN.mp4 (END may be `end`), SPEED a factor (8 = eight
# times faster; 1 = as filmed, caption only). Everything between the edits
# plays as filmed, uncaptioned. Lines starting with # are comments. A caption
# is drawn bottom-left for the whole edit, so a viewer knows what the blur is:
#
#   # take 7 (2026-10-24): the two pulls are the network, not the product
#   30  180 8  Pulling the stack images: ~13 GB, as fast as your network (8x)
#   255 300 8  Pulling the chat model (3.5 GB) — same (8x)
#
# Runs ffmpeg on this machine if it has one with drawtext, else inside the
# recorder image (the same ffmpeg the studio renders with). The take itself
# is never modified; the cut is a new file next to it.
set -euo pipefail

usage() { sed -n '4,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
[ $# -eq 3 ] || usage
IN="$1"; OUT="$2"; EDITS="$3"
[ -s "$IN" ] || { echo "no such take: $IN" >&2; exit 2; }
[ -s "$EDITS" ] || { echo "no such edit list: $EDITS" >&2; exit 2; }
VHS_IMAGE="${NOO_STUDIO_VHS_IMAGE:-ghcr.io/charmbracelet/vhs:latest}"
FONT="${NOO_DEMO_CAPTION_FONT:-DejaVu Sans}"
SIZE="${NOO_DEMO_CAPTION_SIZE:-26}"

# ffmpeg/ffprobe: local when they can draw text, else the recorder image with
# the take's directory mounted (paths are rewritten to the mount).
WORK="$(cd "$(dirname "$IN")" && pwd)"
if command -v ffmpeg >/dev/null 2>&1 && ffmpeg -hide_banner -filters 2>/dev/null | grep -q ' drawtext '; then
  FF=(ffmpeg); FP=(ffprobe); P() { printf '%s' "$1"; }
else
  command -v docker >/dev/null 2>&1 || { echo "need ffmpeg with drawtext, or docker for $VHS_IMAGE" >&2; exit 2; }
  FF=(docker run --rm -v "$WORK":/work -w /work --entrypoint ffmpeg "$VHS_IMAGE")
  FP=(docker run --rm -v "$WORK":/work -w /work --entrypoint ffprobe "$VHS_IMAGE")
  P() { case "$1" in "$WORK"/*) printf '/work/%s' "${1#"$WORK"/}" ;; /*) echo "the cut and its captions must live next to the take ($WORK): $1" >&2; exit 2 ;; *) printf '/work/%s' "$1" ;; esac; }
fi
IN_ABS="$(cd "$(dirname "$IN")" && pwd)/$(basename "$IN")"
OUT_ABS="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
DUR="$("${FP[@]}" -v error -show_entries format=duration -of csv=p=0 "$(P "$IN_ABS")")"
DUR="${DUR%.*}"

# Captions go through text files (no drawtext escaping of : ' % \), kept next
# to the take for the container case and removed at the end.
CAPDIR="$WORK/.cut-captions.$$"
mkdir -p "$CAPDIR"
trap 'rm -rf "$CAPDIR"' EXIT

segments=()   # "start end speed capfile"
cursor=0
n=0
while read -r start end speed caption; do
  case "$start" in ''|'#'*) continue ;; esac
  [ "$end" = end ] && end="$DUR"
  if ! [[ "$start" =~ ^[0-9]+(\.[0-9]+)?$ && "$end" =~ ^[0-9]+(\.[0-9]+)?$ && "$speed" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "bad edit line: '$start $end $speed $caption' (START END SPEED [CAPTION])" >&2; exit 2
  fi
  if awk "BEGIN{exit !($start < $cursor)}"; then echo "edits overlap or are out of order at $start s" >&2; exit 2; fi
  if awk "BEGIN{exit !($start > $cursor)}"; then segments+=("$cursor $start 1 -"); fi
  cap=-
  if [ -n "$caption" ]; then cap="$CAPDIR/$n.txt"; printf '%s' "$caption" > "$cap"; fi
  segments+=("$start $end $speed $cap")
  cursor="$end"; n=$((n + 1))
done < "$EDITS"
if awk "BEGIN{exit !($cursor < $DUR)}"; then segments+=("$cursor $DUR 1 -"); fi

filter=""; labels=""; i=0
for seg in "${segments[@]}"; do
  read -r s e sp cap <<<"$seg"
  f="[0:v]trim=start=$s:end=$e,setpts=(PTS-STARTPTS)/$sp"
  if [ "$cap" != - ]; then
    f="$f,drawtext=textfile='$(P "$cap")':font='$FONT':fontsize=$SIZE:fontcolor=white:box=1:boxcolor=black@0.6:boxborderw=14:x=28:y=h-th-28"
  fi
  filter="${filter}${f}[s${i}];"
  labels="${labels}[s${i}]"
  i=$((i + 1))
done
filter="$filter${labels}concat=n=$i:v=1:a=0,fps=30[v]"

"${FF[@]}" -loglevel error -y -i "$(P "$IN_ABS")" -filter_complex "$filter" -map "[v]" \
  -c:v libx264 -preset slow -crf 23 -pix_fmt yuv420p "$(P "$OUT_ABS")"
echo "cut: $OUT_ABS ($("${FP[@]}" -v error -show_entries format=duration -of csv=p=0 "$(P "$OUT_ABS")") s from $DUR s, $i segment(s))"
