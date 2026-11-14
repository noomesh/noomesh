#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Postgres connections on a one-machine install, MEASURED (connections
forensics: max_connections is left at Postgres's default, 100, while every
Python process opens a sync AND an async SQLAlchemy pool sized by its CPU
count). How many does the stack hold, idle and under a chat or an ingest?

    pg_conns.py sample --out FILE --point NAME --cell CELL [--cpus]
    pg_conns.py watch  --samples JSONL --stop FILE [--interval 1]
                       [--max-seconds N] [--parent PID]
    pg_conns.py fold   --samples JSONL --point NAME --out FILE --cell CELL

`sample` reads pg_stat_activity once and records it as a point in FILE
(pg-conns.json; points accumulate across calls). `watch` samples every
INTERVAL seconds into JSONL until the STOP file appears (or N seconds, or
PID exits); `fold` then records the step's MAXIMUM as one point. --cpus also
records what os.cpu_count() and the affinity mask say INSIDE the worker and
trellion containers (the pools are sized from it) and their docker CPU limits.

Read-only: one SELECT over pg_stat_activity (grouped; never the query text)
and two settings, through `docker exec <prefix>-postgres psql -U <the
container's POSTGRES_USER> -d postgres` (the onboard's own way in; no
password involved), retried through `sudo -n`. Our own psql session is not
counted. A figure that cannot be read is "unknown: why", never 0. The
install-cell runs this on PG_CONNS_CELLS only, as probes: never the cell's
failed step. Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import memory_baseline as MB  # noqa: E402 - the sibling's Host (docker via sudo -n)

# The cells that take these samples: run.sh gates on the same name
# (PG_CONNS_CELL) and the size report expects pg-conns.json from them only.
PG_CONNS_CELLS = ["ubuntu-24.04-amd64-default"]

SEP = "\x1f"  # psql field separator: no application_name holds it
# Grouped by who and what; client backends are what max_connections limits.
ACTIVITY_SQL = (
    "SELECT coalesce(application_name, ''), coalesce(usename, ''), coalesce(datname, ''), "
    "coalesce(state, ''), coalesce(host(client_addr), 'local'), coalesce(backend_type, ''), count(*) "
    "FROM pg_stat_activity WHERE pid <> pg_backend_pid() GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY 7 DESC"
)
SETTINGS_SQL = "SELECT current_setting('max_connections'), current_setting('superuser_reserved_connections')"
CLIENT = "client backend"
NO_APP = "(none)"
# The containers whose pools are sized by os.cpu_count() (engine.py).
CPU_CONTAINERS = ["worker", "trellion"]


# ---------------------------------------------------------------- pure parts

def parse_activity(text: str) -> list[dict] | None:
    """psql -At -F SEP output of ACTIVITY_SQL -> rows, or None when a line
    is not that shape (an error message is not an empty table)."""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        f = line.split(SEP)
        if len(f) != 7 or not f[6].strip().isdigit():
            return None
        rows.append({"application_name": f[0], "usename": f[1], "datname": f[2], "state": f[3],
                     "client": f[4], "backend_type": f[5], "count": int(f[6])})
    return rows


def parse_settings(text: str) -> dict | None:
    f = text.strip().split(SEP)
    if len(f) != 2 or not all(x.strip().isdigit() for x in f):
        return None
    return {"max_connections": int(f[0]), "superuser_reserved_connections": int(f[1])}


def source_of(client: str, ip_map: dict[str, str]) -> str:
    if client == "local":
        return "(local socket)"
    return ip_map.get(client) or f"{client} (no container has this address)"


def _add(d: dict, k: str, n: int) -> None:
    d[k] = d.get(k, 0) + n


def summarize(rows: list[dict], ip_map: dict[str, str]) -> dict:
    """Client backends (what max_connections limits) in total and grouped by
    application_name, by source container (client_addr mapped to its
    container), by user/db, by state; other backend types apart."""
    s: dict = {"total": 0, "by_app": {}, "by_source": {}, "by_user_db": {}, "by_state": {}, "other_backends": {}}
    for r in rows:
        n = r["count"]
        if r["backend_type"] != CLIENT:
            _add(s["other_backends"], r["backend_type"] or "(unnamed)", n)
            continue
        s["total"] += n
        _add(s["by_app"], r["application_name"] or NO_APP, n)
        _add(s["by_source"], source_of(r["client"], ip_map), n)
        _add(s["by_user_db"], f"{r['usename'] or '?'}@{r['datname'] or '?'}", n)
        _add(s["by_state"], r["state"] or "(no state)", n)
    return s


def fold(samples: list[dict]) -> dict:
    """A step's samples -> one point: the PEAK sample's breakdown, each
    group's own maximum over the step, and how many samples were read. No
    readable sample -> unknown with the reasons, never a 0."""
    ok = [s for s in samples if "total" in s]
    bad = [s for s in samples if "total" not in s]
    out: dict = {"kind": "max over step", "samples": len(samples), "samples_read": len(ok)}
    if not ok:
        whys = sorted({s.get("unknown", "no reason recorded") for s in bad})
        out["unknown"] = ("no sample taken" if not samples else "no sample could be read: " + "; ".join(whys)[:400])
        return out
    peak = max(ok, key=lambda s: s["total"])
    out.update({k: peak[k] for k in ("total", "by_app", "by_source", "by_user_db", "by_state", "other_backends")
                if k in peak})
    out["peak_at"] = peak.get("at")
    out["min_total"] = min(s["total"] for s in ok)
    for group in ("by_app", "by_source"):
        m: dict = {}
        for s in ok:
            for k, v in s.get(group, {}).items():
                m[k] = max(m.get(k, 0), v)
        out[f"{group}_max"] = m
    if bad:
        out["unreadable_samples"] = sorted({s.get("unknown", "?") for s in bad})[:5]
    return out


def whole_run_max(points: list[dict]) -> dict:
    known = [p for p in points if "total" in p]
    if not known:
        return {"unknown": "no point could be read" if points else "no point taken"}
    p = max(known, key=lambda x: x["total"])
    return {"total": p["total"], "point": p["point"], "points_read": len(known), "points": len(points),
            "note": "the maximum over the sampled points (1 s sampling during first-answer and the RAG probe), "
                    "not a continuous watch"}


def fmt_groups(g: dict | None) -> str:
    if not g:
        return "-"
    return ", ".join(f"{k}={v}" for k, v in sorted(g.items(), key=lambda kv: (-kv[1], kv[0])))


def limit_text(doc: dict) -> str:
    st = doc.get("settings") or {}
    if "max_connections" not in st:
        return f"max_connections unknown: {st.get('unknown', 'not read')}"
    return (f"max_connections {st['max_connections']} "
            f"({st['superuser_reserved_connections']} reserved for superusers: "
            f"{st['max_connections'] - st['superuser_reserved_connections']} for the stack's roles)")


def total_text(p: dict, doc: dict) -> str:
    if "total" not in p:
        return f"unknown: {p.get('unknown', 'not read')}"
    mx = (doc.get("settings") or {}).get("max_connections")
    return f"{p['total']} of {mx}" if mx else f"{p['total']} (of unknown)"


def cpus_text(doc: dict) -> str:
    c = doc.get("cpus")
    if not c:
        return "cpu_count in the pool-sizing containers: not recorded"
    parts = [f"runner os.cpu_count()={c.get('runner_cpu_count', '?')}"]
    for x in c.get("containers", []):
        if "unknown" in x:
            parts.append(f"{x['name']}: unknown: {x['unknown']}")
            continue
        lim = x.get("docker_limit", "?")
        parts.append(f"{x['name']}: os.cpu_count()={x['cpu_count']} sched_getaffinity={x['affinity']} docker limit {lim}")
    return "; ".join(parts)


def render(doc: dict) -> str:
    """The step log's table."""
    L = [f"POSTGRES CONNECTIONS: cell {doc['meta'].get('cell')}, {limit_text(doc)}",
         cpus_text(doc), "",
         "client backends (what max_connections limits); 'unknown' = could not be read, never 0", ""]
    for p in doc["points"]:
        L.append(f"{p['point']:28} {p.get('kind', 'sample'):14} total {total_text(p, doc)}"
                 + (f" (peak of {p['samples_read']}/{p['samples']} samples, min {p.get('min_total', '?')})"
                    if p.get("kind") == "max over step" and "total" in p else ""))
        if "total" in p:
            L.append(f"    by application_name: {fmt_groups(p.get('by_app'))}")
            L.append(f"    by source container: {fmt_groups(p.get('by_source'))}")
            L.append(f"    by user@db: {fmt_groups(p.get('by_user_db'))}; by state: {fmt_groups(p.get('by_state'))}")
            if p.get("other_backends"):
                L.append(f"    not counted (other backend types): {fmt_groups(p['other_backends'])}")
    w = doc.get("whole_run_max") or {}
    L += ["", "whole run max: " + (f"{w['total']} at {w['point']}" if "total" in w else f"unknown: {w.get('unknown')}")]
    return "\n".join(L) + "\n"


def render_report(doc: dict | None, missing: str | None = None) -> list[str]:
    """The size report's section (release-size-report.py)."""
    if doc is None:
        return ["", f"#### Postgres connections: not measured: {missing}"]
    L = ["", "#### Postgres connections (measured: client backends in pg_stat_activity)", "",
         f"{limit_text(doc)}. {cpus_text(doc)}.", "",
         "| point | kind | total vs max_connections | by application_name | by source container | by user@db |",
         "|---|---|---|---|---|---|"]
    for p in doc.get("points", []):
        kind = p.get("kind", "sample")
        if kind == "max over step" and "total" in p:
            kind += f" ({p['samples_read']}/{p['samples']} samples)"
        L.append(f"| {p['point']} | {kind} | {total_text(p, doc)} | {fmt_groups(p.get('by_app'))} "
                 f"| {fmt_groups(p.get('by_source'))} | {fmt_groups(p.get('by_user_db'))} |")
    w = doc.get("whole_run_max") or {}
    L.append("\nwhole run max: " + (f"**{w['total']}** at {w['point']} ({w.get('note', '')})" if "total" in w
                                   else f"unknown: {w.get('unknown')}"))
    return L


# ---------------------------------------------------------------- IO

def prefix() -> str:
    return os.environ.get("NOO_CONTAINER_PREFIX", "noo")


class PG:
    def __init__(self, host: MB.Host):
        self.host = host
        self.container = f"{prefix()}-postgres"
        out, _ = host.cmd("docker", "exec", self.container, "printenv", "POSTGRES_USER", timeout=30)
        self.user = (out or "").strip() or "noo"

    def query(self, sql: str) -> tuple[str | None, str | None]:
        return self.host.cmd("docker", "exec", self.container, "psql", "-X", "-At", "-F", SEP,
                             "-U", self.user, "-d", "postgres", "-c", sql, timeout=30)


def ip_map(host: MB.Host) -> dict[str, str]:
    ids, _ = host.cmd("docker", "ps", "-q")
    if not ids or not ids.split():
        return {}
    raw, _ = host.cmd("docker", "inspect", *ids.split())
    out = {}
    try:
        for c in json.loads(raw or "[]"):
            for net in ((c.get("NetworkSettings") or {}).get("Networks") or {}).values():
                if (net or {}).get("IPAddress"):
                    out[net["IPAddress"]] = c.get("Name", "?").lstrip("/")
    except ValueError:
        return {}
    return out


def sample_once(pg: PG, ips: dict[str, str]) -> dict:
    s: dict = {"at": int(time.time())}
    out, why = pg.query(ACTIVITY_SQL)
    if out is None:
        return {**s, "unknown": f"psql in {pg.container} failed ({why})"}
    rows = parse_activity(out)
    if rows is None:
        return {**s, "unknown": f"psql answered something that is not the grouped table: {out.strip()[:160]!r}"}
    return {**s, **summarize(rows, ips), "rows": rows}


def read_settings(pg: PG) -> dict:
    out, why = pg.query(SETTINGS_SQL)
    if out is None:
        return {"unknown": f"psql in {pg.container} failed ({why})"}
    st = parse_settings(out)
    return st if st else {"unknown": f"settings answer not understood: {out.strip()[:120]!r}"}


def read_cpus(host: MB.Host) -> dict:
    names = [f"{prefix()}-{n}" for n in CPU_CONTAINERS]
    ps, _ = host.cmd("docker", "ps", "--format", "{{.Names}}")
    names += sorted(n for n in (ps or "").split() if n.startswith(f"{prefix()}-worker-extra") or "worker-extra" in n)
    out = {"runner_cpu_count": os.cpu_count(), "containers": []}
    for n in names:
        e: dict = {"name": n}
        txt, why = host.cmd("docker", "exec", n, "python3", "-c",
                            "import os; print(os.cpu_count(), len(os.sched_getaffinity(0)))", timeout=60)
        f = (txt or "").split()
        if txt is None or len(f) != 2 or not all(x.isdigit() for x in f):
            e["unknown"] = why or f"answer not understood: {(txt or '').strip()[:80]!r}"
        else:
            e["cpu_count"], e["affinity"] = int(f[0]), int(f[1])
            raw, _ = host.cmd("docker", "inspect", "-f", "{{.HostConfig.NanoCpus}} {{.HostConfig.CpusetCpus}}", n)
            g = (raw or "").split()
            if raw is None or not g:
                e["docker_limit"] = "unknown"
            else:
                nano = int(g[0]) if g[0].isdigit() else 0
                e["docker_limit"] = (f"cpus={nano / 1e9:g}" if nano else "none") + (f" cpuset={g[1]}" if len(g) > 1 else "")
        out["containers"].append(e)
    return out


def load_doc(path: str, cell: str) -> dict:
    try:
        with open(path) as f:
            d = json.load(f)
        if isinstance(d.get("points"), list):
            return d
    except (OSError, ValueError):
        pass
    return {"schema": 1, "meta": {"cell": cell}, "points": []}


def write_point(path: str, cell: str, point: dict, pg: PG | None, cpus: dict | None) -> dict:
    doc = load_doc(path, cell)
    doc["points"] = [p for p in doc["points"] if p.get("point") != point["point"]] + [point]
    if pg is not None and "max_connections" not in (doc.get("settings") or {}):
        doc["settings"] = read_settings(pg)
    if cpus is not None:
        doc["cpus"] = cpus
    doc["meta"]["updated"] = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc["whole_run_max"] = whole_run_max(doc["points"])
    with open(path, "w") as f:
        json.dump(doc, f, indent=1)
    return doc


def _alive(pid: int | None) -> bool:
    if not pid:
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def cmd_sample(a) -> int:
    host = MB.Host()
    pg = PG(host)
    s = sample_once(pg, ip_map(host))
    point = {"point": a.point, "kind": "sample", **{k: v for k, v in s.items() if k != "rows"}}
    if "rows" in s:
        point["rows"] = s["rows"]
    doc = write_point(a.out, a.cell, point, pg, read_cpus(host) if a.cpus else None)
    sys.stdout.write(render(doc))
    return 0  # a probe: what could not be read is in the file as unknown


def cmd_watch(a) -> int:
    host = MB.Host()
    pg = PG(host)
    ips = ip_map(host)
    start = time.time()
    with open(a.samples, "a") as f:
        while not os.path.exists(a.stop) and time.time() - start < a.max_seconds and _alive(a.parent):
            t = time.time()
            s = sample_once(pg, ips)
            s.pop("rows", None)
            f.write(json.dumps(s) + "\n")
            f.flush()
            time.sleep(max(0.0, a.interval - (time.time() - t)))
    return 0


def cmd_fold(a) -> int:
    samples = []
    try:
        with open(a.samples) as f:
            samples = [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError) as e:
        samples = [{"unknown": f"samples file unreadable ({e})"}]
    host = MB.Host()
    point = {"point": a.point, **fold(samples)}
    doc = write_point(a.out, a.cell, point, PG(host), None)
    sys.stdout.write(render(doc))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--out", required=True)
    s.add_argument("--point", required=True)
    s.add_argument("--cell", required=True)
    s.add_argument("--cpus", action="store_true")
    w = sub.add_parser("watch")
    w.add_argument("--samples", required=True)
    w.add_argument("--stop", required=True)
    w.add_argument("--interval", type=float, default=1.0)
    w.add_argument("--max-seconds", type=float, default=3600)
    w.add_argument("--parent", type=int)
    f = sub.add_parser("fold")
    f.add_argument("--samples", required=True)
    f.add_argument("--point", required=True)
    f.add_argument("--out", required=True)
    f.add_argument("--cell", required=True)
    a = ap.parse_args(argv)
    return {"sample": cmd_sample, "watch": cmd_watch, "fold": cmd_fold}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
