# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Dependency-free inline-SVG chart primitives.

Everything renders as a self-contained ``<svg>`` string — no JS, no external
assets — so the report drops straight into a strict-CSP Artifact page and into
any browser or email client. Colours use CSS custom properties defined by the
report shell so charts theme with light/dark automatically.
"""
from __future__ import annotations

import html
from typing import Optional

# Palette references CSS vars set in report.py; fallbacks keep raw SVG viewable.
INK = "var(--ink, #1a1a2e)"
MUTED = "var(--muted, #6b7280)"
GRID = "var(--grid, #e5e7eb)"
ACCENT = "var(--accent, #4f46e5)"
OK = "var(--ok, #10b981)"
WARN = "var(--warn, #f59e0b)"
BAD = "var(--bad, #ef4444)"
SERIES = ["var(--s1,#4f46e5)", "var(--s2,#0ea5e9)", "var(--s3,#10b981)",
          "var(--s4,#f59e0b)", "var(--s5,#ec4899)", "var(--s6,#8b5cf6)"]


def _esc(s: str) -> str:
    return html.escape(str(s))


def _txt(x: float, y: float, s: str, *, size=12, fill=INK, anchor="start", weight="400") -> str:
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}" '
            f'font-family="ui-sans-serif,system-ui,sans-serif">{_esc(s)}</text>')


def bar_group(
    labels: list[str],
    series: dict[str, list[float]],
    *,
    width=640, height=280, unit="", title: Optional[str] = None,
) -> str:
    """Grouped vertical bar chart. ``series`` maps series-name -> per-label value."""
    pad_l, pad_r, pad_t, pad_b = 48, 16, (36 if title else 16), 56
    pw, ph = width - pad_l - pad_r, height - pad_t - pad_b
    allv = [v for vals in series.values() for v in vals] or [0]
    vmax = max(allv) * 1.15 or 1.0
    n = len(labels)
    slot = pw / max(1, n)
    snames = list(series.keys())
    bw = min(38, (slot * 0.7) / max(1, len(snames)))
    out = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img">']
    if title:
        out.append(_txt(pad_l, 22, title, size=14, weight="600"))
    # y gridlines
    for i in range(5):
        gy = pad_t + ph * i / 4
        val = vmax * (1 - i / 4)
        out.append(f'<line x1="{pad_l}" y1="{gy:.1f}" x2="{width-pad_r}" y2="{gy:.1f}" stroke="{GRID}" stroke-width="1"/>')
        out.append(_txt(pad_l - 6, gy + 4, f"{val:.0f}", size=10, fill=MUTED, anchor="end"))
    # bars
    for li, lab in enumerate(labels):
        x0 = pad_l + slot * li + (slot - bw * len(snames)) / 2
        for si, sn in enumerate(snames):
            v = series[sn][li] if li < len(series[sn]) else 0
            bh = ph * (v / vmax)
            x = x0 + si * bw
            y = pad_t + ph - bh
            out.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw-3:.1f}" height="{bh:.1f}" rx="2" fill="{SERIES[si % len(SERIES)]}"><title>{_esc(sn)} · {_esc(lab)}: {v:.1f}{_esc(unit)}</title></rect>')
        out.append(_txt(pad_l + slot * li + slot / 2, height - pad_b + 16, lab, size=10, fill=MUTED, anchor="middle"))
    # legend
    if len(snames) > 1:
        lx = pad_l
        for si, sn in enumerate(snames):
            out.append(f'<rect x="{lx}" y="{height-18}" width="10" height="10" rx="2" fill="{SERIES[si % len(SERIES)]}"/>')
            out.append(_txt(lx + 14, height - 9, sn, size=10, fill=MUTED))
            lx += 20 + len(sn) * 7
    out.append("</svg>")
    return "".join(out)


def line_series(
    series: dict[str, list[tuple[float, float]]],
    *,
    width=640, height=260, unit="", x_label="", title: Optional[str] = None,
    markers: Optional[list[tuple[float, str, str]]] = None,
) -> str:
    """Multi-line time series. ``markers`` = list of (x, label, colour) vertical rules."""
    pad_l, pad_r, pad_t, pad_b = 48, 16, (36 if title else 16), 40
    pw, ph = width - pad_l - pad_r, height - pad_t - pad_b
    xs = [x for pts in series.values() for x, _ in pts] or [0, 1]
    ys = [y for pts in series.values() for _, y in pts] or [0, 1]
    xmin, xmax = min(xs), max(xs) or 1
    ymax = max(ys) * 1.15 or 1.0
    xr = (xmax - xmin) or 1.0

    def px(x): return pad_l + pw * (x - xmin) / xr
    def py(y): return pad_t + ph * (1 - y / ymax)

    out = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img">']
    if title:
        out.append(_txt(pad_l, 22, title, size=14, weight="600"))
    for i in range(5):
        gy = pad_t + ph * i / 4
        out.append(f'<line x1="{pad_l}" y1="{gy:.1f}" x2="{width-pad_r}" y2="{gy:.1f}" stroke="{GRID}" stroke-width="1"/>')
        out.append(_txt(pad_l - 6, gy + 4, f"{ymax*(1-i/4):.0f}", size=10, fill=MUTED, anchor="end"))
    if markers:
        for mx, mlab, mcol in markers:
            X = px(mx)
            out.append(f'<line x1="{X:.1f}" y1="{pad_t}" x2="{X:.1f}" y2="{pad_t+ph}" stroke="{mcol}" stroke-width="1.5" stroke-dasharray="4 3"/>')
            out.append(_txt(X + 3, pad_t + 12, mlab, size=9, fill=mcol))
    for si, (sn, pts) in enumerate(series.items()):
        col = SERIES[si % len(SERIES)]
        d = " ".join(f'{"M" if i==0 else "L"}{px(x):.1f} {py(y):.1f}' for i, (x, y) in enumerate(pts))
        out.append(f'<path d="{d}" fill="none" stroke="{col}" stroke-width="2"/>')
        for x, y in pts:
            out.append(f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="2.5" fill="{col}"><title>{_esc(sn)} @ {x:.0f}{_esc(x_label)}: {y:.1f}{_esc(unit)}</title></circle>')
    if len(series) > 1:
        lx = pad_l
        for si, sn in enumerate(series):
            out.append(f'<rect x="{lx}" y="{height-16}" width="10" height="10" rx="2" fill="{SERIES[si % len(SERIES)]}"/>')
            out.append(_txt(lx + 14, height - 7, sn, size=10, fill=MUTED))
            lx += 24 + len(sn) * 7
    out.append("</svg>")
    return "".join(out)


def donut(segments: list[tuple[str, float]], *, size=180, unit="") -> str:
    """Donut chart. ``segments`` = list of (label, value)."""
    total = sum(v for _, v in segments) or 1.0
    cx = cy = size / 2
    r, rin = size * 0.42, size * 0.26
    out = [f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img">']
    import math
    a0 = -math.pi / 2
    for i, (lab, v) in enumerate(segments):
        frac = v / total
        a1 = a0 + frac * 2 * math.pi
        large = 1 if frac > 0.5 else 0
        x0o, y0o = cx + r * math.cos(a0), cy + r * math.sin(a0)
        x1o, y1o = cx + r * math.cos(a1), cy + r * math.sin(a1)
        x1i, y1i = cx + rin * math.cos(a1), cy + rin * math.sin(a1)
        x0i, y0i = cx + rin * math.cos(a0), cy + rin * math.sin(a0)
        col = SERIES[i % len(SERIES)]
        out.append(f'<path d="M{x0o:.1f} {y0o:.1f} A{r:.1f} {r:.1f} 0 {large} 1 {x1o:.1f} {y1o:.1f} '
                   f'L{x1i:.1f} {y1i:.1f} A{rin:.1f} {rin:.1f} 0 {large} 0 {x0i:.1f} {y0i:.1f} Z" '
                   f'fill="{col}"><title>{_esc(lab)}: {v:.0f}{_esc(unit)} ({frac*100:.0f}%)</title></path>')
        a0 = a1
    out.append(_txt(cx, cy + 5, f"{total:.0f}", size=20, weight="700", anchor="middle"))
    out.append("</svg>")
    return "".join(out)


def gauge(value: float, vmax: float, *, label="", unit="", width=180, thresholds=(0.7, 0.9)) -> str:
    """Half-circle gauge; colours green/amber/red by threshold fraction."""
    import math
    frac = 0.0 if vmax == 0 else min(1.0, value / vmax)
    col = OK if frac < thresholds[0] else (WARN if frac < thresholds[1] else BAD)
    h = width * 0.62
    cx, cy, r = width / 2, h - 10, width * 0.4
    def pt(f):
        a = math.pi * (1 - f)
        return cx + r * math.cos(a), cy - r * math.sin(a)
    x0, y0 = pt(0)
    x1, y1 = pt(1)
    xv, yv = pt(frac)
    large = 1 if frac > 0.5 else 0
    out = [f'<svg viewBox="0 0 {width} {h+24}" width="{width}" role="img">']
    out.append(f'<path d="M{x0:.1f} {y0:.1f} A{r:.1f} {r:.1f} 0 1 1 {x1:.1f} {y1:.1f}" fill="none" stroke="{GRID}" stroke-width="12" stroke-linecap="round"/>')
    out.append(f'<path d="M{x0:.1f} {y0:.1f} A{r:.1f} {r:.1f} 0 {large} 1 {xv:.1f} {yv:.1f}" fill="none" stroke="{col}" stroke-width="12" stroke-linecap="round"/>')
    out.append(_txt(cx, cy - 6, f"{value:g}{unit}", size=18, weight="700", anchor="middle"))
    out.append(_txt(cx, h + 16, label, size=11, fill=MUTED, anchor="middle"))
    out.append("</svg>")
    return "".join(out)
