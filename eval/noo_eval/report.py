# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Render a ``RunResult`` into a self-contained HTML evaluation report.

The output is a single HTML file (inline SVG, inline CSS, no JS, no external
assets) so it renders in a strict-CSP Artifact page, a browser, or an email.
It is theme-aware (light/dark) via CSS custom properties.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from . import svg
from .harness_compare import first_line, report_json, summarize
from .metrics import Aggregates, aggregate
from .schema import RunResult

_AXIS_LABEL = {"node": "Multi-node", "user": "Multi-user",
               "location": "Multi-location", "controller": "Multi-controller"}


def _esc(s) -> str:
    return html.escape(str(s))


def _kpi(value: str, label: str, tone: str = "") -> str:
    cls = f"kpi {tone}".strip()
    return f'<div class="{cls}"><div class="kpi-v">{_esc(value)}</div><div class="kpi-l">{_esc(label)}</div></div>'


def _topology_table(run: RunResult) -> str:
    rows = []
    for n in run.topology:
        dot = "online" if n.online else "offline"
        gpu = f"{_esc(n.gpu_model)} · {n.vram_gb:g}GB" if n.gpu_model else "CPU"
        rows.append(
            f"<tr><td><span class='dot {dot}'></span>{_esc(n.node_id)}</td>"
            f"<td>{_esc(n.role)}</td><td>{_esc(n.location)}</td>"
            f"<td>{gpu}</td><td>{_esc(', '.join(n.backends) or '—')}</td>"
            f"<td>T{n.tier}</td></tr>"
        )
    return ("<table class='grid'><thead><tr><th>Node</th><th>Role</th><th>Location</th>"
            "<th>Compute</th><th>Backends</th><th>Tier</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def _latency_table(agg: Aggregates) -> str:
    rows = []
    for node, s in agg.by_node.items():
        tone = "bad" if s.error_rate > 0.05 else ("warn" if s.error_rate > 0 else "")
        rows.append(
            f"<tr><td>{_esc(node)}</td><td>{s.count}</td>"
            f"<td>{s.p50:.0f}</td><td>{s.p95:.0f}</td><td>{s.p99:.0f}</td>"
            f"<td class='{tone}'>{s.error_rate*100:.1f}%</td></tr>"
        )
    return ("<table class='grid'><thead><tr><th>Node</th><th>Reqs</th>"
            "<th>p50 ms</th><th>p95 ms</th><th>p99 ms</th><th>Errors</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def _isolation_matrix(run: RunResult) -> str:
    if not run.isolation_tests:
        return "<p class='muted'>No cross-user isolation probes in this scenario.</p>"
    rows = []
    for t in run.isolation_tests:
        verdict = ("<span class='pill bad'>LEAK</span>" if t.leaked
                   else "<span class='pill ok'>isolated</span>")
        rows.append(
            f"<tr><td>{_esc(t.user_b)}</td><td>{_esc(t.user_a)}</td>"
            f"<td>{_esc(t.probe)}</td><td>{verdict}</td><td class='muted'>{_esc(t.detail)}</td></tr>"
        )
    leaks = sum(1 for t in run.isolation_tests if t.leaked)
    banner = (f"<p class='pill bad'>{leaks} cross-user LEAK(s) — H-D1 control FAILING</p>" if leaks
              else "<p class='pill ok'>All probes isolated — H-D1 control passing</p>")
    return (banner + "<table class='grid'><thead><tr><th>Probing user</th><th>Target</th>"
            "<th>Probe</th><th>Result</th><th>Detail</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def _fault_panel(run: RunResult, agg: Aggregates) -> str:
    if not run.faults:
        return "<p class='muted'>No faults injected in this scenario.</p>"
    cards = []
    for f in run.faults:
        mttr = f"{f.recovered_s:.1f}s" if f.recovered_s is not None else "—"
        det = f"{f.detected_s:.1f}s" if f.detected_s is not None else "—"
        cards.append(
            f"<div class='fault'><div class='fault-h'>{_esc(f.kind)} → {_esc(f.target)}</div>"
            f"<div class='fault-m'>detect <b>{det}</b> · recover <b>{mttr}</b> @ t+{f.t_offset_s:.0f}s</div>"
            f"<div class='muted'>{_esc(f.note)}</div></div>"
        )
    return "<div class='faults'>" + "".join(cards) + "</div>"


def _num(v, fmt="{:,}") -> str:
    return "—" if v is None else fmt.format(v)


def _compare_tables(run: RunResult) -> str:
    """One table per task set, one row per harness kind — the point of i83 F."""
    hc = run.harness_compare
    rows = summarize(hc)
    out = []
    for s in dict.fromkeys(r["task_set"] for r in rows):
        trs = []
        for r in (x for x in rows if x["task_set"] == s):
            tone = "ok" if r["total"] and r["passed"] == r["total"] else ("bad" if r["passed"] == 0 else "warn")
            got, of = r["tokens_reported"].split("/")
            tok_note = (f" <span class='muted'>({_esc(r['tokens_reported'])} reported)</span>"
                        if r["prompt_tokens"] is not None and got != of else "")
            fails = "<br>".join(_esc(f) for f in r["failures"]) or "<span class='muted'>none</span>"
            skipped = f" <span class='muted'>(+{r['skipped']} skipped)</span>" if r["skipped"] else ""
            trs.append(
                f"<tr><td><b>{_esc(r['harness_kind'])}</b></td>"
                f"<td class='{tone}'>{r['passed']}/{r['total']}{skipped}</td>"
                f"<td>{_num(r['mean_loops'], '{:g}')}</td><td>{_num(r['mean_wall_s'], '{:.1f}')}</td>"
                f"<td>{_num(r['prompt_tokens'])}{tok_note}</td><td>{_num(r['completion_tokens'])}</td>"
                f"<td class='wrap-cell'>{fails}</td></tr>")
        out.append(
            f"<h3>Task set: {_esc(s)}</h3>"
            "<table class='grid'><thead><tr><th>harness_kind</th><th>Passed</th><th>Mean loops</th>"
            "<th>Mean wall s</th><th>Prompt tokens</th><th>Completion tokens</th><th>Failures</th>"
            "</tr></thead><tbody>" + "".join(trs) + "</tbody></table>")
    return "".join(out)


def _compare_detail(run: RunResult) -> str:
    trs = []
    for r in run.harness_compare.runs:
        verdict = ("<span class='pill ok'>pass</span>" if r.passed else
                   "<span class='muted'>skipped</span>" if r.skipped else "<span class='pill bad'>fail</span>")
        where = f"{_esc(r.node or '—')}" + ("" if r.dispatched or not r.task_id else " <span class='warn'>(in process)</span>")
        trs.append(
            f"<tr><td>{_esc(r.task)}</td><td>{_esc(r.kind)}</td><td>{verdict}</td><td>{_esc(r.state)}</td>"
            f"<td>{_esc(r.check)}</td><td>{r.loops}</td><td>{_num(r.wall_s, '{:.1f}')}</td>"
            f"<td>{_num(r.prompt_tokens)} / {_num(r.completion_tokens)}</td><td>{where}</td>"
            f"<td class='muted wrap-cell'>{_esc(first_line(r.note) or first_line(r.result))}</td></tr>")
    return ("<table class='grid'><thead><tr><th>Task</th><th>Kind</th><th>Verdict</th><th>State</th><th>Check</th>"
            "<th>Loops</th><th>Wall s</th><th>Tokens p / c</th><th>Node</th><th>Note / result</th>"
            "</tr></thead><tbody>" + "".join(trs) + "</tbody></table>")


def _render_compare(run: RunResult) -> str:
    hc = run.harness_compare
    rows = summarize(hc)
    totals: dict[str, list[int]] = {}
    for r in rows:
        t = totals.setdefault(r["harness_kind"], [0, 0])
        t[0] += r["passed"]
        t[1] += r["total"]
    rate = {k: (p / n) for k, (p, n) in totals.items() if n}
    top = max(rate.values(), default=None)
    best = [k for k, v in rate.items() if v == top]     # a tie names every kind in it
    kpis = [_kpi(str(len(hc.kinds)), "harness kinds"),
            _kpi(str(len({(r.task_set, r.task) for r in hc.runs})), "tasks per kind")]
    if best:
        p, n = totals[best[0]]
        kpis.append(_kpi(", ".join(best), f"best pass rate ({p}/{n})", "ok" if top else "bad"))
    kpis.append(_kpi("yes" if hc.restored else "NO", "placement restored", "ok" if hc.restored else "bad"))
    kind_lines = "".join(
        f"<li><b>{_esc(k.kind)}</b>: " + (f"harness running {k.ready_s}s after placing" if k.ready else _esc(k.error))
        + "</li>" for k in hc.kind_runs)
    synthetic = "SYNTHETIC" in run.scenario.upper()
    banner = ('<div class="synthetic-banner">SYNTHETIC FIXTURE — every value below came from the '
              'fake gateway in noo_eval/harness_fake.py, to test the pipeline and the report. '
              'It says nothing about any harness.</div>' if synthetic else "")
    notes = [f"Node {hc.node}: original harness kind {hc.original_kind or '(no harness placement)'}; "
             f"{hc.restore_note}.", hc.token_method, *run.notes]
    return f"""
<style>{_CSS}</style>
<div class="wrap">
{banner}
<header>
  <div class="eyebrow">harness compare</div>
  <h1>{_esc(run.scenario)}</h1>
  <div class="meta">node {_esc(hc.node)} &nbsp;·&nbsp; kinds {_esc(', '.join(hc.kinds))} &nbsp;·&nbsp; {_esc(run.gateway or 'cluster')} &nbsp;·&nbsp; {_esc(run.started_at)}</div>
</header>
<div class="kpis">{''.join(kpis)}</div>
<section><h2>Which harness is better here</h2><p class='sub'>The same task set, run under each harness kind on one node in turn. Tokens are the harness:&lt;kind&gt; usage the run could attribute (— = not reported).</p>{_compare_tables(run)}</section>
<section><h2>Placing each kind</h2><ul>{kind_lines}</ul></section>
<section><h2>Every task run</h2>{_compare_detail(run)}</section>
<section><h2>Notes</h2><ul>{''.join(f"<li>{_esc(n)}</li>" for n in notes if n)}</ul></section>
<footer>Generated by <code>noo-eval</code> · schema v{_esc(__import__('noo_eval').__version__)} · self-contained (no external assets)</footer>
</div>
"""


def _render(run: RunResult) -> str:
    if run.harness_compare is not None:
        return _render_compare(run)
    agg = aggregate(run)
    axes = " · ".join(_AXIS_LABEL.get(a, a) for a in run.axes)

    # KPIs
    o = agg.overall
    mttr_vals = [v for v in agg.mttr.values()]
    kpis = [
        _kpi(str(o.count), "requests"),
        _kpi(f"{o.p95:.0f} ms", "p95 latency"),
        _kpi(f"{o.p99:.0f} ms", "p99 latency"),
        _kpi(f"{o.error_rate*100:.1f}%", "error rate",
             "bad" if o.error_rate > 0.05 else ("warn" if o.error_rate > 0 else "ok")),
        _kpi(str(len([n for n in run.topology if n.online])) + f"/{len(run.topology)}", "nodes online"),
    ]
    if mttr_vals:
        kpis.append(_kpi(f"{max(mttr_vals):.0f}s", "worst MTTR",
                         "warn" if max(mttr_vals) > 30 else "ok"))
    leaks = sum(1 for t in run.isolation_tests if t.leaked)
    if run.isolation_tests:
        kpis.append(_kpi(str(leaks), "isolation leaks", "bad" if leaks else "ok"))

    # Charts
    lat_labels = list(agg.by_node.keys())
    lat_chart = svg.bar_group(
        lat_labels,
        {"p50": [agg.by_node[n].p50 for n in lat_labels],
         "p95": [agg.by_node[n].p95 for n in lat_labels],
         "p99": [agg.by_node[n].p99 for n in lat_labels]},
        unit="ms", title="Latency by node (p50/p95/p99)",
    )
    routing_chart = svg.donut([(k, v) for k, v in agg.routing.items()], unit=" req")
    tput_markers = [(f.t_offset_s, f.kind.split("_")[0], svg.BAD) for f in run.faults]
    tput_chart = svg.line_series(
        {"requests/bucket": [(t, c) for t, c in agg.throughput]},
        unit="", x_label="s", title="Throughput over time (fault markers in red)",
        markers=tput_markers,
    )

    loc_labels = list(agg.by_location.keys())
    loc_chart = ""
    if "location" in run.axes and loc_labels:
        loc_chart = svg.bar_group(
            loc_labels,
            {"p95 ms": [agg.by_location[loc].p95 for loc in loc_labels]},
            unit="ms", title="p95 latency by location",
        )

    repl_chart = ""
    if run.replication:
        by_ctrl: dict[str, list[tuple[float, float]]] = {}
        for e in run.replication:
            by_ctrl.setdefault(e.controller, []).append((e.t_offset_s, e.lag_s))
        repl_chart = svg.line_series(by_ctrl, unit="s", x_label="s",
                                     title="Replication lag by controller")

    sec = run.security
    sec_gauges = "".join([
        svg.gauge(sec.auth_failures, max(10, sec.auth_failures), label="auth failures", width=150),
        svg.gauge(sec.exec_denials, max(5, sec.exec_denials), label="exec denials", width=150),
        svg.gauge(sec.rate_limited, max(10, sec.rate_limited), label="rate-limited", width=150),
    ])

    def section(title, body, sub=""):
        s = f"<p class='sub'>{_esc(sub)}</p>" if sub else ""
        return f"<section><h2>{_esc(title)}</h2>{s}{body}</section>"

    synthetic = "SYNTHETIC" in run.scenario.upper()
    banner = ('<div class="synthetic-banner">⚠️ SYNTHETIC DEMO — every value below is '
              'fabricated to show the report layout. This is NOT your cluster. '
              'Run <code>python -m noo_eval topology</code> for real data.</div>'
              if synthetic else "")

    body = f"""
<style>{_CSS}</style>
<div class="wrap">
{banner}
<header>
  <div class="eyebrow">mesh cluster evaluation</div>
  <h1>{_esc(run.scenario)}</h1>
  <div class="meta">{_esc(axes)} &nbsp;·&nbsp; {run.duration_s:.0f}s &nbsp;·&nbsp; {_esc(run.gateway or 'cluster')} &nbsp;·&nbsp; {_esc(run.started_at)}</div>
</header>
<div class="kpis">{''.join(kpis)}</div>
{section("Topology", _topology_table(run), "Nodes, roles, locations, and backends seen during the run.")}
{section("Latency & routing", f"<div class='row'><div class='col-2'>{lat_chart}</div><div class='col-1'><div class='chart-title'>Routing distribution</div>{routing_chart}</div></div>{_latency_table(agg)}")}
{section("Throughput & availability", tput_chart + _fault_panel(run, agg), "Injected faults and time-to-recover.")}
{(section("Multi-location", loc_chart) if loc_chart else "")}
{(section("Multi-controller / federated", repl_chart) if repl_chart else "")}
{section("Cross-user isolation (H-D1 control test)", _isolation_matrix(run), "Each probe has user B attempt to read user A's planted secret. Any LEAK fails the tenant-isolation control.")}
{section("Security posture", f"<div class='gauges'>{sec_gauges}</div><p class='muted'>Counters over the run window from Prometheus (noo_auth_failures_5m / noo_exec_denials_5m) and the audit sink ({sec.audit_rows_written} rows written).</p>")}
{("<section><h2>Notes</h2><ul>" + "".join(f"<li>{_esc(n)}</li>" for n in run.notes) + "</ul></section>") if run.notes else ""}
<footer>Generated by <code>noo-eval</code> · schema v{_esc(__import__('noo_eval').__version__)} · self-contained (no external assets)</footer>
</div>
"""
    return body


def build_body(run: RunResult) -> str:
    """Body-only HTML (``<style>`` + content) — publishable directly as an Artifact.

    The Artifact host wraps this in its own ``<!doctype><head><body>`` skeleton,
    so we must NOT emit those tags here.
    """
    return _render(run)


def build_html(run: RunResult) -> str:
    """Standalone HTML document — openable in any browser or email client."""
    inner = _render(run)
    doc = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>{_esc(run.scenario)} — noo-eval</title></head><body>'
           f'{inner}</body></html>')
    return doc


def write_report(run: RunResult, path: str | Path, *, standalone: bool = True) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(build_html(run) if standalone else build_body(run), encoding="utf-8")
    return p


def write_compare_json(run: RunResult, path: str | Path) -> Path:
    """The JSON twin of a harness-compare report: the summary table plus
    every task run, for a script (or the next run) to read."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = report_json(run.harness_compare, run.scenario)
    doc.update({"gateway": run.gateway, "started_at": run.started_at, "notes": run.notes})
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return p


_CSS = """
:root{--bg:#f7f7fb;--card:#fff;--ink:#1a1a2e;--muted:#6b7280;--grid:#e5e7eb;
--accent:#4f46e5;--ok:#10b981;--warn:#f59e0b;--bad:#ef4444;
--s1:#4f46e5;--s2:#0ea5e9;--s3:#10b981;--s4:#f59e0b;--s5:#ec4899;--s6:#8b5cf6;
--border:#e5e7eb;--shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);}
@media(prefers-color-scheme:dark){:root{--bg:#0f1117;--card:#171a21;--ink:#e8e9ef;
--muted:#9aa2b1;--grid:#2a2f3a;--border:#262b36;--shadow:0 1px 3px rgba(0,0,0,.4);}}
:root[data-theme=dark]{--bg:#0f1117;--card:#171a21;--ink:#e8e9ef;--muted:#9aa2b1;--grid:#2a2f3a;--border:#262b36;}
:root[data-theme=light]{--bg:#f7f7fb;--card:#fff;--ink:#1a1a2e;--muted:#6b7280;--grid:#e5e7eb;--border:#e5e7eb;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;line-height:1.5;
-webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto;padding:32px 20px 64px}
header{margin-bottom:24px}.eyebrow{text-transform:uppercase;letter-spacing:.08em;
font-size:12px;color:var(--accent);font-weight:600}
h1{font-size:30px;margin:6px 0 4px;font-weight:700;letter-spacing:-.02em}
.meta{color:var(--muted);font-size:14px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:8px 0 28px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:12px;
padding:14px 16px;box-shadow:var(--shadow)}
.kpi-v{font-size:24px;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.kpi-l{font-size:12px;color:var(--muted);margin-top:2px}
.kpi.ok .kpi-v{color:var(--ok)}.kpi.warn .kpi-v{color:var(--warn)}.kpi.bad .kpi-v{color:var(--bad)}
section{background:var(--card);border:1px solid var(--border);border-radius:14px;
padding:20px 22px;margin-bottom:20px;box-shadow:var(--shadow)}
h2{font-size:17px;margin:0 0 4px;font-weight:650}
.sub{color:var(--muted);font-size:13px;margin:0 0 16px}
.chart-title{font-size:13px;font-weight:600;margin-bottom:8px;color:var(--muted)}
.row{display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start;margin-bottom:12px}
.col-2{flex:2 1 380px;min-width:0}.col-1{flex:1 1 200px;text-align:center}
table.grid{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px;
display:block;overflow-x:auto}
table.grid th{text-align:left;color:var(--muted);font-weight:600;padding:8px 10px;
border-bottom:1px solid var(--border);white-space:nowrap}
table.grid td{padding:8px 10px;border-bottom:1px solid var(--border);white-space:nowrap;font-variant-numeric:tabular-nums}
td.bad,.bad{color:var(--bad)}td.warn,.warn{color:var(--warn)}.muted{color:var(--muted)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px}
.dot.online{background:var(--ok)}.dot.offline{background:var(--muted)}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}
.pill.ok{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
.pill.bad{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}
.faults{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:14px}
.fault{border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.fault-h{font-weight:600;font-size:14px}.fault-m{font-size:13px;margin:4px 0}
.gauges{display:flex;gap:16px;flex-wrap:wrap;justify-content:space-around}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:32px}
code{background:color-mix(in srgb,var(--ink) 8%,transparent);padding:1px 5px;border-radius:5px;font-size:.9em}
ul{margin:8px 0;padding-left:20px}li{margin:4px 0}
h3{font-size:14px;margin:14px 0 2px;font-weight:600}
table.grid td.wrap-cell{white-space:normal;min-width:220px}
.synthetic-banner{background:color-mix(in srgb,var(--bad) 15%,var(--card));
border:1px solid var(--bad);color:var(--bad);border-radius:10px;padding:12px 16px;
margin-bottom:18px;font-size:13px;font-weight:600}
.synthetic-banner code{background:color-mix(in srgb,var(--bad) 20%,transparent);color:inherit}
"""
