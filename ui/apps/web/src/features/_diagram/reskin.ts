// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Reskin the legacy architecture-diagram palette to the Slate design system.
//
// The base diagrams (ported verbatim from the legacy SVG so layout/arrows/
// animations stay exact) encode meaning in six per-layer hues. We keep the
// per-layer encoding but remap every hue — in both #hex and `r,g,b` triplet
// form — to a desaturated palette that sits well on the Slate light/dark grounds.

type Pair = [from: RegExp, to: string];

// old hue → new hue, as [hex, "r,g,b"]. Order-independent (no new value is also
// an old pattern), applied globally to the raw SVG string.
const MAP: Array<{ hex: [string, string]; rgb: [string, string] }> = [
  { hex: ['#38bdf8', '#5f8fd0'], rgb: ['56,189,248', '95,143,208'] }, // Interface  → slate-blue
  { hex: ['#10b981', '#5aa66e'], rgb: ['16,185,129', '90,166,110'] }, // System 1   → green
  { hex: ['#06b6d4', '#3f9fb0'], rgb: ['6,182,212', '63,159,176'] }, //  Long-term  → teal
  { hex: ['#ec4899', '#9a7bc8'], rgb: ['236,72,153', '154,123,200'] }, // System 2  → violet
  { hex: ['#ef4444', '#e0a24a'], rgb: ['239,68,68', '224,162,74'] }, //  Identity   → amber
  { hex: ['#f97316', '#9a8f80'], rgb: ['249,115,22', '154,143,128'] }, // Infra     → warm grey
  { hex: ['#f59e0b', '#d9a441'], rgb: ['245,158,11', '217,164,65'] }, //  Self-tuning → gold
  { hex: ['#84cc16', '#8a9a4e'], rgb: ['132,204,22', '138,154,78'] }, //  Prompt evolution → olive
];

const RULES: Pair[] = MAP.flatMap(({ hex, rgb }) => [
  [new RegExp(hex[0], 'gi'), hex[1]] as Pair,
  [new RegExp(rgb[0].replace(/,/g, ',\\s*'), 'g'), rgb[1]] as Pair,
]);

/** Recolor a raw SVG string from the legacy palette to Slate. */
export function reskin(svg: string): string {
  return RULES.reduce((s, [re, to]) => s.replace(re, to), svg);
}

/** Recolor a single color value (e.g. a node's modal dot color). */
export function reskinColor(c: string): string {
  return reskin(c);
}
