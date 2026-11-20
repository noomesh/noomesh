#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Scan the third-party images we PIN, one issue per image (noomesh-internal i1100).

Our scans cover the images we BUILD (infra-staged.yml daily, the release
lanes). An image we only pin by digest (stack-lock-third-party.py THIRD_PARTY:
nats, nginx, the DHI set, tei, tei-cpu, vllm) was scanned nowhere after the day
it was pinned: nginx sat at 3 CRITICAL / 67 HIGH on an EOL line unnoticed. The
weekly .github/workflows/third-party-scan.yml scans every pinned digest (dev's
compose and the latest final's lock) with Trivy and runs this script:

  targets   every THIRD_PARTY row's pinned digest from the compose file and,
            with --lock, the final's lock rows; unique by digest. Writes
            targets.json and prints `<digest> <repo>@<digest>` per scan.
  decide    pure: the Trivy JSONs + targets + scripts/third-party-lines.json +
            the open issues -> one action per row (create / update / close /
            none / skip).
  apply     carries the actions out with `gh` (the issue job only).

Rules (decided by the release lead):
  * a default-on service: an issue when any pinned digest has a FIXABLE
    (Trivy FixedVersion non-empty) CRITICAL or HIGH, an EOSL base (Trivy
    Metadata.OS.EOSL), or its line's re-check date has passed;
  * an opt-in backend (`opt_in` in the lines file): an issue only on a fixable
    CRITICAL or an EOSL base; its HIGH findings are a COUNT in the body, never a
    list;
  * one open issue per row, labelled `third-party-image`, found by the hidden
    marker `<!-- third-party-image:<row> digests=... set=<hash> -->`;
  * a comment only when the triggering set (its hash is in the marker) changes;
  * closed when none of its digests is pinned any more (the pin moved) or
    nothing triggers, with a comment saying which.

THE REPOSITORY IS PUBLIC. An issue carries only the row name, the image
repository, digests, versions, counts, CVE/GHSA ids (strict pattern), upstream
tags (strict pattern), the line data from the lines file and the run URL.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINES = ROOT / "scripts" / "third-party-lines.json"
LABEL = "third-party-image"
ID_CAP = 30
PUBLIC_ID = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})$")
TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ROW = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
OS_NAME = re.compile(r"^[a-z][a-z0-9-]* [0-9][0-9A-Za-z._-]*$")
RUN_URL = re.compile(r"^https://[A-Za-z0-9.-]+/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/actions/runs/\d+$")
MARKER = re.compile(r"<!-- third-party-image:([a-z0-9][a-z0-9._-]*) digests=([a-z0-9:,]*) set=([0-9a-f]*) -->")
HIGH_OMITTED = ("The HIGH list is omitted on purpose for an opt-in backend: a 1,300-line issue helps no one. "
                "The full Trivy report is the run's `third-party-scan` artifact")


def _lock_module():
    spec = importlib.util.spec_from_file_location("stack_lock_third_party", ROOT / "scripts/stack-lock-third-party.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


LOCK = _lock_module()
THIRD_PARTY = LOCK.THIRD_PARTY


def log(msg: str) -> None:
    print(f"third-party-scan: {msg}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ targets

def compose_pin(name: str, text: str) -> tuple[str, str]:
    """(version, digest) every compose service running THIRD_PARTY row `name` names."""
    version = LOCK.compose_version(name, text)
    hook = re.compile(r"\$\{" + re.escape(LOCK.digest_var(name)) + r":-@(sha256:[0-9a-f]{64})\}")
    digests = {m.group(1) for line in LOCK._image_re(name, True).finditer(text)
               for m in [hook.search(line.group(0))] if m}
    if len(digests) != 1:
        raise LOCK.LockError(f"compose pins {name} at {len(digests)} digests {sorted(digests)}: want exactly one")
    return version, digests.pop()


def lock_rows(text: str) -> dict[str, str]:
    """THIRD_PARTY rows of a stack lock: name -> digest."""
    out = {}
    for line in text.splitlines():
        m = re.fullmatch(r"([a-z0-9][a-z0-9._-]*)@(sha256:[0-9a-f]{64})", line.strip())
        if m and m.group(1) in THIRD_PARTY:
            out[m.group(1)] = m.group(2)
    return out


def targets(compose_text: str, lock_text: str | None = None, lock_name: str = "") -> list[dict]:
    """One entry per (row, pinned digest), every THIRD_PARTY row."""
    final = lock_rows(lock_text) if lock_text else {}
    out = []
    for row, entry in sorted(THIRD_PARTY.items()):
        version, digest = compose_pin(row, compose_text)
        out.append({"row": row, "repo": entry["repo"], "digest": digest, "version": version,
                    "pinned_by": ["dev compose"]})
        fd = final.get(row)
        if fd and fd == digest:
            out[-1]["pinned_by"].append(f"final lock {lock_name}".strip())
        elif fd:
            out.append({"row": row, "repo": entry["repo"], "digest": fd, "version": None,
                        "pinned_by": [f"final lock {lock_name}".strip()]})
    return out


def scan_list(tgts: list[dict]) -> list[tuple[str, str]]:
    """(digest, ref) to scan, once per digest."""
    seen, out = set(), []
    for t in tgts:
        if t["digest"] not in seen:
            seen.add(t["digest"])
            out.append((t["digest"], f"{t['repo']}@{t['digest']}"))
    return out


# ------------------------------------------------------------------ findings

def findings(report: dict) -> dict:
    """Counts and fixable ids of one Trivy JSON report (vulnerability ids deduplicated)."""
    sev: dict[str, dict[str, bool]] = {"CRITICAL": {}, "HIGH": {}}
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            s = v.get("Severity")
            vid = str(v.get("VulnerabilityID", ""))
            if s in sev and vid:
                sev[s][vid] = sev[s].get(vid, False) or bool(v.get("FixedVersion"))
    meta = report.get("Metadata") or {}
    os_ = meta.get("OS") or {}
    os_name = f"{os_.get('Family', '')} {os_.get('Name', '')}".strip()
    labels = (((meta.get("ImageConfig") or {}).get("config") or {}).get("Labels") or {})
    version = str(labels.get("org.opencontainers.image.version", ""))
    return {
        "critical": len(sev["CRITICAL"]), "high": len(sev["HIGH"]),
        "fixable_critical": sorted(i for i, f in sev["CRITICAL"].items() if f),
        "fixable_high": sorted(i for i, f in sev["HIGH"].items() if f),
        "eosl": bool(os_.get("EOSL")),
        "os": os_name if OS_NAME.match(os_name) else "",
        "label_version": version if TAG.match(version) else "",
    }


def newer_in_line(version: str | None, line: str | None, tags: list[str]) -> str | None:
    """The newest tag in `line` shaped like `version` and newer than it."""
    if not version or not line:
        return None

    def shape(t: str) -> str:
        return re.sub(r"\d+", "N", t)

    def nums(t: str) -> tuple[int, ...]:
        return tuple(int(x) for x in re.findall(r"\d+", t))

    def in_line(t: str) -> bool:
        return t == line or (t.startswith(line) and not t[len(line)].isdigit())

    cands = [t for t in tags if TAG.match(t) and shape(t) == shape(version) and in_line(t) and nums(t) > nums(version)]
    return max(cands, key=nums) if cands else None


def in_declared_line(version: str | None, line: str | None) -> bool:
    if not version or not line:
        return True
    return version == line or (version.startswith(line) and not version[len(line)].isdigit())


# ------------------------------------------------------------------ the rule

def triggers(row: str, per_digest: dict[str, dict], meta: dict, today: date) -> list[str]:
    """The triggering set of one row: what keeps its issue open."""
    opt_in = bool(meta.get("opt_in"))
    out = []
    for digest, f in per_digest.items():
        out += [f"{digest}|CRITICAL|{i}" for i in f["fixable_critical"]]
        if not opt_in:
            out += [f"{digest}|HIGH|{i}" for i in f["fixable_high"]]
        if f["eosl"]:
            out.append(f"{digest}|EOSL")
    rb = meta.get("recheck_by")
    if not opt_in and rb and today > date.fromisoformat(rb):
        out.append(f"recheck|{rb}")
    return sorted(set(out))


def set_hash(items: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(items)).encode()).hexdigest()[:16] if items else ""


def marker(row: str, digests: list[str], h: str) -> str:
    return f"<!-- third-party-image:{row} digests={','.join(sorted(digests))} set={h} -->"


def parse_marker(body: str) -> dict | None:
    m = MARKER.search(body or "")
    if not m:
        return None
    return {"row": m.group(1), "digests": [d for d in m.group(2).split(",") if d], "set": m.group(3)}


def summary(items: list[str]) -> str:
    c = sum(1 for i in items if "|CRITICAL|" in i)
    h = sum(1 for i in items if "|HIGH|" in i)
    parts = []
    if c:
        parts.append(f"{c} fixable CRITICAL")
    if h:
        parts.append(f"{h} fixable HIGH")
    if any(i.endswith("|EOSL") for i in items):
        parts.append("EOSL base")
    if any(i.startswith("recheck|") for i in items):
        parts.append("line re-check date passed")
    return ", ".join(parts)


def title(row: str, items: list[str]) -> str:
    return f"third-party image {row}: {summary(items)}"


def _ids(ids: list[str]) -> tuple[list[str], int]:
    """(public ids up to the cap, number omitted: past the cap or not a CVE/GHSA id)."""
    pub = [i for i in ids if PUBLIC_ID.match(i)]
    return pub[:ID_CAP], len(ids) - min(len(pub), ID_CAP)


def body(row: str, entries: list[dict], scans: dict[str, dict], meta: dict, items: list[str],
         run_url: str, newer: str | None, today: date) -> str:
    opt_in = bool(meta.get("opt_in"))
    repo = THIRD_PARTY[row]["repo"]
    digests = [e["digest"] for e in entries]
    kind = "an opt-in backend" if opt_in else "a default-on service"
    lines = [marker(row, digests, set_hash(items)),
             f"**{row}** (`{repo}`), {kind}, pinned by digest and built upstream (scripts/stack-lock-third-party.py).",
             "", f"Why this issue is open: {summary(items)}.", "",
             "| pinned by | version | digest | CRITICAL fixable/all | HIGH fixable/all | EOSL base |",
             "|---|---|---|---|---|---|"]
    for e in entries:
        f = scans[e["digest"]]
        version = e.get("version") or f["label_version"] or "unknown"
        eosl = ("yes" + (f" ({f['os']})" if f["os"] else "")) if f["eosl"] else "no"
        lines.append(f"| {', '.join(e['pinned_by'])} | `{version}` | `{e['digest']}` | "
                     f"{len(f['fixable_critical'])}/{f['critical']} | {len(f['fixable_high'])}/{f['high']} | {eosl} |")
    lines.append("")
    for e in entries:
        f = scans[e["digest"]]
        short = e["digest"][len("sha256:"):][:12]
        crit, crit_more = _ids(f["fixable_critical"])
        if crit:
            lines.append(f"Fixable CRITICAL in `{short}`: " + ", ".join(crit)
                         + (f" ({crit_more} more omitted)" if crit_more else ""))
        if opt_in:
            if f["high"]:
                lines.append(f"HIGH in `{short}`: {len(f['fixable_high'])} fixable of {f['high']}. {HIGH_OMITTED}: {run_url}")
        else:
            high, high_more = _ids(f["fixable_high"])
            if high:
                lines.append(f"Fixable HIGH in `{short}`: " + ", ".join(high)
                             + (f" ({high_more} more omitted: see the run's `third-party-scan` artifact)"
                                if high_more else ""))
    lines.append("")
    line = meta.get("line")
    if line:
        pol = meta.get("policy")
        rb = meta.get("recheck_by")
        txt = f"Line `{line}`; support policy: {pol or 'none published upstream'}"
        if rb and not opt_in:
            txt += f"; re-check by {rb}" + (" (PASSED: re-read the policy, then move the pin or the date in "
                                             "scripts/third-party-lines.json)" if today > date.fromisoformat(rb) else "")
        lines.append(txt + ".")
        for e in entries:
            if e.get("version") and not in_declared_line(e["version"], line):
                lines.append(f"The pinned `{e['version']}` is outside the declared line `{line}`.")
    if newer:
        lines.append(f"Newer upstream tag in the line: `{newer}`.")
    lines += ["", f"Run: {run_url}", "",
              "_Kept by .github/workflows/third-party-scan.yml (scripts/third-party-scan.py): it comments only "
              "when the triggering set changes and closes this issue when the pin moves or nothing triggers._"]
    return "\n".join(lines) + "\n"


def change_comment(old_hash: str, new: list[str], run_url: str) -> str:
    return (f"The triggering set changed (set {old_hash or 'none'} -> {set_hash(new)}): now {summary(new)}. "
            f"The issue body is updated.\n\nRun: {run_url}\n")


def decide(tgts: list[dict], scans: dict[str, dict], lines: dict, issues: list[dict],
           tags: dict[str, list[str]], today: date, run_url: str) -> list[dict]:
    """One action per THIRD_PARTY row (and one per stray issue of an unknown row)."""
    if not RUN_URL.match(run_url):
        raise ValueError(f"unexpected run URL shape: {run_url!r}")
    rows_meta = lines.get("rows") or {}
    open_by_row: dict[str, list[dict]] = {}
    for i in sorted(issues, key=lambda x: x["number"]):
        mk = parse_marker(i.get("body", ""))
        if mk:
            open_by_row.setdefault(mk["row"], []).append({**i, "marker": mk})
    actions = []
    by_row: dict[str, list[dict]] = {}
    for t in tgts:
        by_row.setdefault(t["row"], []).append(t)
    for row in sorted(set(by_row) | set(open_by_row)):
        entries = by_row.get(row, [])
        open_ = open_by_row.get(row, [])
        issue = open_[0] if open_ else None
        pinned = {e["digest"] for e in entries}
        missing = [e["digest"] for e in entries if e["digest"] not in scans]
        if missing:
            actions.append({"action": "skip", "row": row, "why": f"no scan for {', '.join(missing)}"})
            continue
        meta = rows_meta.get(row, {})
        per = {e["digest"]: scans[e["digest"]] for e in entries}
        items = triggers(row, per, meta, today) if entries else []
        h = set_hash(items)
        dev = next((e for e in entries if "dev compose" in e["pinned_by"]), None)
        newer = newer_in_line(dev["version"] if dev else None, meta.get("line"), tags.get(row, []))
        if issue and not (set(issue["marker"]["digests"]) & pinned):
            now = ", ".join(sorted(pinned)) or "nothing"
            actions.append({"action": "close", "row": row, "number": issue["number"],
                            "comment": f"The pin moved: {', '.join(issue['marker']['digests'])} is no longer pinned by "
                                       f"dev's compose or the latest final's lock (now: {now}). Closing; a new issue "
                                       f"opens if the new pin triggers.\n\nRun: {run_url}\n"})
            issue = None
        elif issue and not items:
            actions.append({"action": "close", "row": row, "number": issue["number"],
                            "comment": "Nothing triggers any more: no fixable CRITICAL"
                                       + ("" if meta.get("opt_in") else " or HIGH")
                                       + ", no EOSL base" + ("" if meta.get("opt_in") else ", no passed re-check date")
                                       + f" for {', '.join(sorted(pinned))}. Closing.\n\nRun: {run_url}\n"})
            continue
        elif issue and h != issue["marker"]["set"]:
            actions.append({"action": "update", "row": row, "number": issue["number"], "title": title(row, items),
                            "body": body(row, entries, per, meta, items, run_url, newer, today),
                            "comment": change_comment(issue["marker"]["set"], items, run_url)})
            continue
        elif issue:
            actions.append({"action": "none", "row": row, "number": issue["number"], "why": "triggering set unchanged"})
            continue
        if items:
            actions.append({"action": "create", "row": row, "title": title(row, items),
                            "body": body(row, entries, per, meta, items, run_url, newer, today)})
        elif not any(a["row"] == row for a in actions):
            actions.append({"action": "none", "row": row, "why": "nothing triggers"})
    return actions


# ------------------------------------------------------------------ gh

def gh(*args: str) -> str:
    p = subprocess.run(["gh", *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:2])} failed ({p.returncode}): {p.stderr.strip()[:300]}")
    return p.stdout


def _body_file(text: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(text)
        return f.name


def apply(repo: str, actions: list[dict]) -> None:
    labelled = False
    for a in actions:
        if a["action"] == "create":
            if not labelled:
                names = {x.get("name") for x in json.loads(gh("label", "list", "-R", repo, "--json", "name",
                                                              "--limit", "500") or "[]")}
                if LABEL not in names:
                    gh("label", "create", LABEL, "-R", repo, "--color", "D93F0B",
                       "--description", "a pinned third-party image needs attention (third-party-scan.yml)")
                labelled = True
            gh("issue", "create", "-R", repo, "--title", a["title"], "--label", LABEL,
               "--body-file", _body_file(a["body"]))
            log(f"{a['row']}: opened an issue")
        elif a["action"] == "update":
            gh("issue", "edit", str(a["number"]), "-R", repo, "--title", a["title"], "--body-file", _body_file(a["body"]))
            gh("issue", "comment", str(a["number"]), "-R", repo, "--body-file", _body_file(a["comment"]))
            log(f"{a['row']}: updated #{a['number']}")
        elif a["action"] == "close":
            gh("issue", "close", str(a["number"]), "-R", repo, "--comment", a["comment"])
            log(f"{a['row']}: closed #{a['number']}")
        else:
            log(f"{a['row']}: {a['action']} ({a.get('why', '')})")


# ------------------------------------------------------------------ main

def _load_scans(d: Path) -> dict[str, dict]:
    out = {}
    for p in sorted(d.glob("*.json")):
        if re.fullmatch(r"[0-9a-f]{64}", p.stem):
            out["sha256:" + p.stem] = findings(json.loads(p.read_text()))
    return out


def _load_tags(d: Path | None) -> dict[str, list[str]]:
    if not d or not d.is_dir():
        return {}
    return {p.stem: [t.strip() for t in p.read_text().splitlines() if t.strip()] for p in d.glob("*.txt")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("targets")
    t.add_argument("--compose", type=Path, default=LOCK.COMPOSE)
    t.add_argument("--lock", type=Path)
    t.add_argument("--out", type=Path, required=True)
    d = sub.add_parser("decide")
    d.add_argument("--targets", type=Path, required=True)
    d.add_argument("--scans", type=Path, required=True)
    d.add_argument("--lines", type=Path, default=LINES)
    d.add_argument("--issues", type=Path, required=True)
    d.add_argument("--tags", type=Path)
    d.add_argument("--today", default=date.today().isoformat())
    d.add_argument("--run-url", required=True)
    d.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("apply")
    p.add_argument("--repo", required=True)
    p.add_argument("--actions", type=Path, required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "targets":
            lock_text = a.lock.read_text() if a.lock else None
            lock_name = a.lock.name[: -len(".lock")] if a.lock else ""
            tg = targets(a.compose.read_text(), lock_text, lock_name)
            a.out.write_text(json.dumps(tg, indent=1) + "\n")
            for digest, ref in scan_list(tg):
                print(f"{digest} {ref}")
        elif a.cmd == "decide":
            acts = decide(json.loads(a.targets.read_text()), _load_scans(a.scans), json.loads(a.lines.read_text()),
                          json.loads(a.issues.read_text() or "[]"), _load_tags(a.tags),
                          date.fromisoformat(a.today), a.run_url)
            a.out.write_text(json.dumps(acts, indent=1) + "\n")
            for x in acts:
                log(f"{x['row']}: {x['action']}" + (f" #{x['number']}" if "number" in x else ""))
        else:
            apply(a.repo, json.loads(a.actions.read_text()))
    except LOCK.LockError as e:
        print(f"::error::third-party-scan: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
