#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The whole stack's memory at idle after onboard, MEASURED (operator
2026-11-14: the first job is the number, tracked per release).

    memory_baseline.py measure --out FILE --cell NAME --model MODE [--settle S]

run.sh's probe-memory-baseline calls this after health and the verify
probes and BEFORE first-answer, so no chat has loaded a chat model yet.
It waits SETTLE seconds, then reads:

  containers  every running one: name, image, `docker stats --no-stream`
              memory usage, and from its cgroup v2 dir memory.stat
              `anon` and `file` plus memory.current
  host units  noo-node-agent, noo-hostd, noo-harness: `systemctl show`
              MemoryCurrent and MemoryPeak (the cgroup source the node
              agent's noo_unit_memory_bytes metric exports, #1026), the
              unit cgroup's memory.stat anon/file, and the main process's
              VmRSS from /proc/<pid>/status

A figure that cannot be read is OMITTED with its reason, never written as
0, and every total is the sum of what was measured, with how many of how
many it covers. Writes FILE (JSON) and prints a table. Standard library
only; docker and unreadable files are retried through `sudo -n` (the
docker=none cells' old shell lacks the docker group).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import time

NODE_SHARE_LABEL = "node share of a one-machine install"
CONTROLLER_SHARE_LABEL = "controller share"

# THE classification rule. A container is the NODE's when its name, with the
# container prefix (NOO_CONTAINER_PREFIX, "noo") taken off, matches one of
# these: the inference/backend containers, the stunnel doors that front
# them, and the node agent when it runs in a container. Everything else is
# the CONTROLLER's. Names from docker-compose*.yml.
NODE_CONTAINER_PATTERNS = [
    "ollama*", "llamacpp*", "vllm*", "tei*", "reranker*", "whisper*", "piper*",
    "stunnel-ollama*", "stunnel-llamacpp*", "stunnel-vllm*", "stunnel-tei*",
    "stunnel-reranker*", "stunnel-whisper*", "stunnel-piper*",
    "node-agent*",
]
HOST_UNITS = ["noo-node-agent", "noo-hostd", "noo-harness"]

# Figures, in the order the table prints them.
CONTAINER_FIGURES = ["anon_bytes", "file_bytes", "memory_current_bytes", "docker_stats_bytes"]
UNIT_FIGURES = ["anon_bytes", "file_bytes", "memory_current_bytes", "memory_peak_bytes", "vmrss_bytes"]
# What the totals add up (docker stats and VmRSS are cross-checks, not summed
# into the grand total: they overlap the cgroup figures).
TOTAL_FIGURES = ["anon_bytes", "file_bytes", "memory_current_bytes"]

# systemd's "no value" spellings (UINT64_MAX is how it prints an unknown).
_UNSET = {"", "[not set]", "infinity", "18446744073709551615"}


# ---------------------------------------------------------------- pure parts

def strip_prefix(name: str) -> str:
    name = name.lstrip("/")
    prefix = os.environ.get("NOO_CONTAINER_PREFIX", "noo")
    return name[len(prefix) + 1:] if name.startswith(prefix + "-") else name


def classify(name: str) -> str:
    """'node' or 'controller' for a container name (see NODE_CONTAINER_PATTERNS)."""
    base = strip_prefix(name)
    return "node" if any(fnmatch.fnmatchcase(base, p) for p in NODE_CONTAINER_PATTERNS) else "controller"


def parse_memory_stat(text: str) -> dict[str, int]:
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[parts[0]] = int(parts[1])
    return out


_UNITS = {"b": 1, "kb": 10**3, "mb": 10**6, "gb": 10**9, "tb": 10**12,
          "kib": 2**10, "mib": 2**20, "gib": 2**30, "tib": 2**40}


def parse_size(s: str) -> int | None:
    """Docker's human size ("123.4MiB", "1.2GB", "512B") as bytes, or None."""
    m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?i?B)\s*", s, re.I)
    if not m:
        return None
    return int(round(float(m.group(1)) * _UNITS[m.group(2).lower()]))


def parse_docker_stats(text: str) -> dict[str, tuple[int | None, str | None]]:
    """`docker stats --no-stream --format '{{.Name}}\\t{{.MemUsage}}'` ->
    {name: (bytes, None) | (None, reason)}."""
    out: dict[str, tuple[int | None, str | None]] = {}
    for line in text.splitlines():
        if "\t" not in line:
            continue
        name, usage = line.split("\t", 1)
        used = usage.split("/", 1)[0].strip()
        b = parse_size(used)
        if b is None:
            out[name.strip()] = (None, f"docker stats gave no usage ({usage.strip() or 'empty'})")
        elif b == 0:
            # A running container never uses 0 B: docker prints 0B when it
            # could not read the cgroup. Not a measurement.
            out[name.strip()] = (None, f"docker stats read 0 B ({usage.strip()}): not a measurement")
        else:
            out[name.strip()] = (b, None)
    return out


def parse_systemctl_show(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def systemd_bytes(props: dict[str, str], key: str) -> tuple[int | None, str | None]:
    if key not in props:
        return None, f"{key} not reported by this systemd"
    v = props[key]
    if v in _UNSET or not v.isdigit():
        return None, f"{key}={v or 'empty'} (systemd has no figure: accounting off or unit not running)"
    return int(v), None


def parse_vmrss(text: str) -> int | None:
    m = re.search(r"^VmRSS:\s+(\d+)\s+kB", text, re.M)
    return int(m.group(1)) * 1024 if m else None


def cgroup_candidates(container_id: str) -> list[str]:
    """Where a container's cgroup v2 dir lives, relative to the cgroup root:
    systemd cgroup driver, then cgroupfs."""
    return [f"system.slice/docker-{container_id}.scope", f"docker/{container_id}"]


def put(entry: dict, key: str, value: int | None, reason: str | None) -> None:
    """A figure goes into entry['figures'] when measured, into
    entry['omitted'] with its reason when not. Never a 0 stand-in."""
    if value is None:
        entry.setdefault("omitted", {})[key] = reason or "not read"
    else:
        entry.setdefault("figures", {})[key] = value


def _sum(entries: list[dict], key: str) -> dict:
    vals = [e["figures"][key] for e in entries if key in e.get("figures", {})]
    return {"bytes": sum(vals), "measured": len(vals), "of": len(entries)}


def totals(containers: list[dict], units: list[dict]) -> dict:
    """Sums of what was MEASURED only, each with `measured` of `of`."""
    node_c = [c for c in containers if c["class"] == "node"]
    ctrl_c = [c for c in containers if c["class"] == "controller"]
    present_units = [u for u in units if u.get("present")]
    out = {"containers": {}, "host_units": {}, "grand": {}, "controller_share": {}, "node_share": {}}
    for k in TOTAL_FIGURES:
        out["containers"][k] = _sum(containers, k)
        out["host_units"][k] = _sum(present_units, k)
        out["grand"][k] = _sum(containers + present_units, k)
        out["controller_share"][k] = _sum(ctrl_c, k)
        out["node_share"][k] = _sum(node_c + present_units, k)
    out["containers"]["docker_stats_bytes"] = _sum(containers, "docker_stats_bytes")
    out["host_units"]["vmrss_bytes"] = _sum(present_units, "vmrss_bytes")
    out["node_share_label"] = NODE_SHARE_LABEL
    return out


def mb(b: int | None) -> str:
    return "-" if b is None else f"{b / 2**20:.1f}"


def _cell(entry: dict, key: str) -> str:
    if key in entry.get("figures", {}):
        return mb(entry["figures"][key])
    return "omitted" if key in entry.get("omitted", {}) else "-"


def _tot(t: dict) -> str:
    s = mb(t["bytes"])
    return s if t["measured"] == t["of"] else f"{s} ({t['measured']} of {t['of']} measured)"


def render(doc: dict) -> str:
    """The readable table for the step's log."""
    m = doc["meta"]
    L = [f"MEMORY BASELINE (idle after onboard, before the first chat): cell {m.get('cell')}, "
         f"noo {m.get('noo_version')}, model {m.get('model')}, settled {m.get('settle_seconds')} s, "
         f"host RAM {mb(m.get('host_mem_total_bytes'))} MiB, at {m.get('timestamp')}", "",
         "figures in MiB; 'omitted' = could not be read (reason below), never 0", "",
         f"{'container':34} {'class':10} {'anon':>9} {'file':>9} {'current':>9} {'stats':>9}  image"]
    for c in doc["containers"]:
        L.append(f"{c['name'][:34]:34} {c['class']:10} " + " ".join(f"{_cell(c, k):>9}" for k in CONTAINER_FIGURES)
                 + f"  {c.get('image', '?')}")
    if doc.get("containers_omitted"):
        L.append(f"containers: {doc['containers_omitted']}")
    L += ["", f"{'host unit':34} {'anon':>9} {'file':>9} {'current':>9} {'peak':>9} {'VmRSS':>9}"]
    for u in doc["host_units"]:
        if not u.get("present"):
            L.append(f"{u['unit']:34} absent ({u.get('why', 'not on this host')})")
            continue
        L.append(f"{u['unit']:34} " + " ".join(f"{_cell(u, k):>9}" for k in UNIT_FIGURES))
    reasons = [(e.get("name") or e.get("unit"), k, why) for e in doc["containers"] + doc["host_units"]
               for k, why in e.get("omitted", {}).items()]
    if reasons:
        L += ["", "omitted figures:"] + [f"  {n} {k}: {why}" for n, k, why in reasons]
    t = doc["totals"]
    L += ["", f"{'total':40} {'anon':>22} {'file':>22} {'current':>22}"]
    for key, label in (("containers", "all containers"), ("host_units", "all host units"),
                       ("grand", "grand total"), ("controller_share", CONTROLLER_SHARE_LABEL),
                       ("node_share", NODE_SHARE_LABEL)):
        L.append(f"{label:40} " + " ".join(f"{_tot(t[key][k]):>22}" for k in TOTAL_FIGURES))
    L += ["", f"docker stats sum (cross-check): {_tot(t['containers']['docker_stats_bytes'])} MiB; "
              f"host units VmRSS sum: {_tot(t['host_units']['vmrss_bytes'])} MiB"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- IO

class Host:
    """Everything this script reads from the box, in one place (tests fake
    the binaries on PATH and point the roots at a fixture tree)."""

    def __init__(self, cgroup_root: str = "/sys/fs/cgroup", proc_root: str = "/proc"):
        self.cgroup_root = cgroup_root
        self.proc_root = proc_root
        self.sudo = shutil.which("sudo") if os.geteuid() != 0 else None

    def cmd(self, *argv: str, timeout: int = 120) -> tuple[str | None, str | None]:
        """stdout, or (None, reason). Retried through `sudo -n` on failure."""
        tries = [list(argv)] + ([[self.sudo, "-n", *argv]] if self.sudo else [])
        err = "not run"
        for t in tries:
            try:
                r = subprocess.run(t, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
            except (OSError, subprocess.TimeoutExpired) as e:
                err = f"{argv[0]}: {e}"
                continue
            if r.returncode == 0:
                return r.stdout, None
            err = f"{' '.join(argv[:3])} exited {r.returncode}: {(r.stderr.strip().splitlines() or [''])[-1][:200]}"
        return None, err

    def read(self, path: str) -> tuple[str | None, str | None]:
        try:
            with open(path) as f:
                return f.read(), None
        except FileNotFoundError:
            return None, f"{path} does not exist"
        except OSError as e:
            if not self.sudo:
                return None, f"{path}: {e.strerror}"
        out, err = self.cmd("cat", path, timeout=30)
        return (out, None) if out is not None else (None, f"{path}: unreadable even with sudo ({err})")


def cgroup_figures(host: Host, rel: str, entry: dict) -> None:
    base = os.path.join(host.cgroup_root, rel.lstrip("/"))
    stat, why = host.read(os.path.join(base, "memory.stat"))
    st = parse_memory_stat(stat) if stat is not None else {}
    for key, field in (("anon_bytes", "anon"), ("file_bytes", "file")):
        if field in st:
            put(entry, key, st[field], None)
        else:
            put(entry, key, None, why or f"memory.stat has no '{field}' line")
    cur, why = host.read(os.path.join(base, "memory.current"))
    if cur is not None and cur.strip().isdigit():
        put(entry, "memory_current_bytes", int(cur.strip()), None)
    else:
        put(entry, "memory_current_bytes", None, why or f"memory.current reads {cur.strip()[:40]!r}")


def find_container_cgroup(host: Host, cid: str, pid: int | None) -> tuple[str | None, str]:
    tried = []
    for rel in cgroup_candidates(cid):
        tried.append(rel)
        if os.path.isdir(os.path.join(host.cgroup_root, rel)):
            return rel, ""
    # Any other layout: the container's init process names its own cgroup.
    if pid:
        text, _ = host.read(os.path.join(host.proc_root, str(pid), "cgroup"))
        m = re.search(r"^0::(/\S+)$", text or "", re.M)
        if m and os.path.isdir(os.path.join(host.cgroup_root, m.group(1).lstrip("/"))):
            return m.group(1).lstrip("/"), ""
        tried.append(f"/proc/{pid}/cgroup")
    return None, "no cgroup v2 dir for the container (tried " + ", ".join(
        t.replace(cid, cid[:12] + "…") for t in tried) + ")"


def measure_containers(host: Host) -> tuple[list[dict], str | None]:
    ids, why = host.cmd("docker", "ps", "-q", "--no-trunc")
    if ids is None:
        return [], f"not measured: docker ps failed ({why})"
    ids = ids.split()
    if not ids:
        return [], "no running containers"
    raw, why = host.cmd("docker", "inspect", *ids)
    if raw is None:
        return [], f"not measured: docker inspect failed ({why})"
    stats_text, stats_why = host.cmd("docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}")
    stats = parse_docker_stats(stats_text) if stats_text is not None else {}
    out = []
    for c in json.loads(raw):
        name = c.get("Name", "").lstrip("/")
        cid = c.get("Id", "")
        e = {"name": name, "id": cid[:12], "image": (c.get("Config") or {}).get("Image", "?"), "class": classify(name)}
        rel, why = find_container_cgroup(host, cid, (c.get("State") or {}).get("Pid"))
        if rel:
            e["cgroup"] = rel.replace(cid, cid[:12] + "…")
            cgroup_figures(host, rel, e)
        else:
            for k in ("anon_bytes", "file_bytes", "memory_current_bytes"):
                put(e, k, None, why)
        if stats_text is None:
            put(e, "docker_stats_bytes", None, f"docker stats failed ({stats_why})")
        else:
            b, r = stats.get(name, (None, "not in docker stats output"))
            put(e, "docker_stats_bytes", b, r)
        out.append(e)
    out.sort(key=lambda e: (e["class"], e["name"]))
    return out, None


def measure_unit(host: Host, unit: str) -> dict:
    e: dict = {"unit": unit}
    text, why = host.cmd("systemctl", "show", unit, "-p", "LoadState", "-p", "ActiveState", "-p", "MainPID",
                         "-p", "ControlGroup", "-p", "MemoryCurrent", "-p", "MemoryPeak")
    if text is None:
        return {**e, "present": False, "why": f"systemctl show failed ({why})"}
    p = parse_systemctl_show(text)
    if p.get("LoadState") != "loaded" or p.get("ActiveState") != "active":
        return {**e, "present": False,
                "why": f"LoadState={p.get('LoadState', '?')} ActiveState={p.get('ActiveState', '?')}"}
    e["present"] = True
    for key, prop in (("memory_current_bytes", "MemoryCurrent"), ("memory_peak_bytes", "MemoryPeak")):
        put(e, key, *systemd_bytes(p, prop))
    if p.get("ControlGroup"):
        sub: dict = {}
        cgroup_figures(host, p["ControlGroup"], sub)
        for k in ("anon_bytes", "file_bytes"):
            put(e, k, sub.get("figures", {}).get(k), sub.get("omitted", {}).get(k))
    else:
        for k in ("anon_bytes", "file_bytes"):
            put(e, k, None, "systemd names no ControlGroup for the unit")
    pid = p.get("MainPID", "0")
    if pid.isdigit() and int(pid) > 0:
        st, why = host.read(os.path.join(host.proc_root, pid, "status"))
        rss = parse_vmrss(st) if st is not None else None
        put(e, "vmrss_bytes", rss, why or "no VmRSS line in /proc/<pid>/status")
    else:
        put(e, "vmrss_bytes", None, f"MainPID={pid}: no main process")
    return e


def host_meta(host: Host) -> dict:
    out = {}
    mi, _ = host.read(os.path.join(host.proc_root, "meminfo"))
    for key, field in (("host_mem_total_bytes", "MemTotal"), ("host_mem_available_bytes", "MemAvailable")):
        m = re.search(rf"^{field}:\s+(\d+)\s+kB", mi or "", re.M)
        if m:
            out[key] = int(m.group(1)) * 1024
    v, _ = host.cmd("noo", "--version", timeout=30) if shutil.which("noo") else (None, None)
    out["noo_version"] = (v or "").strip().splitlines()[0] if v and v.strip() else "unknown"
    return out


def measure(args) -> int:
    host = Host(args.cgroup_root, args.proc_root)
    if args.settle > 0:
        print(f"settling {args.settle} s before reading (idle after onboard)", flush=True)
        time.sleep(args.settle)
    containers, c_why = measure_containers(host)
    units = [measure_unit(host, u) for u in HOST_UNITS]
    doc = {
        "schema": 1,
        "meta": {"cell": args.cell, "model": args.model, "settle_seconds": args.settle,
                 "timestamp": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "point": "idle after onboard: after health and the verify probes, before the first chat",
                 **host_meta(host)},
        "classification": {"node_container_patterns": NODE_CONTAINER_PATTERNS, "host_units": HOST_UNITS,
                           "rule": "node = host units + containers matching a pattern (prefix stripped); "
                                   "controller = every other container"},
        "containers": containers,
        "host_units": units,
        "totals": totals(containers, units),
    }
    if c_why:
        doc["containers_omitted"] = c_why
    with open(args.out, "w") as f:
        json.dump(doc, f, indent=1)
    sys.stdout.write(render(doc))
    measured = doc["totals"]["grand"]["memory_current_bytes"]["measured"]
    if measured == 0:
        print("MEMORY BASELINE: nothing could be measured")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure")
    m.add_argument("--out", required=True)
    m.add_argument("--cell", required=True)
    m.add_argument("--model", default="?")
    m.add_argument("--settle", type=int, default=60)
    m.add_argument("--cgroup-root", default="/sys/fs/cgroup")
    m.add_argument("--proc-root", default="/proc")
    a = ap.parse_args(argv)
    return measure(a)


if __name__ == "__main__":
    sys.exit(main())
