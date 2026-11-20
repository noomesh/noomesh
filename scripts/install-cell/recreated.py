#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Which stack containers a `noo stack start` recreated, judged from their IDs.

  recreated.py snap FILE
      one line per compose container named noo-*: "name id service depends_on"
  recreated.py judge NAME BEFORE AFTER (--none | --all | --only SERVICE)
      prints ONE verdict line and exits 0 (PASS) or 1 (FAIL):
        --none          nothing recreated, created or removed
        --all           every container recreated
        --only SERVICE  SERVICE recreated; every other recreated container is
                        one compose itself recreates because it depends on SERVICE
  recreated.py reload-record STATE
      what the start-inputs state says about nats's last reload: none (no
      record: a build that does not record reloads), unconfirmed (a HUP was
      delivered but not confirmed) or confirmed
  recreated.py after-provision NAME BEFORE AFTER START_LOG START_RC
                               CONF_CHANGED RECORD PROVISION_LOG PROVISION_RC
      the plain start after users.conf was re-rendered and nats HUPed: PASS
      (exit 0) when nats was not recreated; NOTE (exit 0) when users.conf did
      not change (nothing to reload) or the build records no reload; FAIL
      (exit 1) naming each recreated container with the launcher's reason line
  recreated.py after-forced-restart NAME BEFORE_RESTART RESTARTED AFTER_START
                                    START_LOG START_RC RESTART_RC RESTART_LOG
      the plain start after `noo cluster nats-creds rotate worker --restart`
      (noomesh-restart.sh --force, which force-recreates every container and
      labels them): PASS (exit 0) when nothing the restart recreated is
      recreated again; FAIL (exit 1) naming each with its reason line, or
      when the restart failed or did not recreate the worker. No NOTE.

The verdict always comes from the container IDs; the launcher's own lines
(`noo stack start`: "13 running, 0 recreated", "recreated gateway: its inputs
changed (...)") only say WHY (reasons(), shared by the upgrade cell's B4 and
the fresh cell's start checks).

A container that changed ID was recreated; one only in BEFORE was removed, one
only in AFTER created. Only compose containers (with a service label) count:
an agent-placed backend is not the launcher's.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

FMT = ('{{.Name}} {{.Id}} {{index .Config.Labels "com.docker.compose.service"}} '
       '{{index .Config.Labels "com.docker.compose.depends_on"}}')


def _docker(args: list[str]) -> str:
    for pre in (["docker"], ["sudo", "-n", "docker"]):
        try:
            r = subprocess.run(pre + args, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            return r.stdout
    raise SystemExit(f"cannot run docker {' '.join(args[:2])} (nor with sudo -n)")


def snap(path: str) -> int:
    ids = _docker(["ps", "-aq", "--filter", "name=noo-"]).split()
    rows = []
    if ids:
        for line in _docker(["inspect", "-f", FMT, *ids]).splitlines():
            parts = line.replace("<no value>", "-").split(" ", 3)
            if len(parts) >= 3 and parts[2] not in ("", "-"):
                rows.append(" ".join(p.strip() or "-" for p in (parts + ["-"])[:4]))
    with open(path, "w") as f:
        f.write("".join(r + "\n" for r in sorted(rows)))
    print(f"{len(rows)} compose containers recorded")
    return 0


def read(path: str) -> dict[str, tuple[str, str, str]]:
    """name -> (id, service, depends_on)"""
    out = {}
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) >= 3:
                out[p[0].lstrip("/")] = (p[1], p[2], p[3] if len(p) > 3 else "-")
    return out


def _read_or_empty(path: str) -> dict:
    try:
        return read(path)
    except OSError:
        return {}


def judge(name: str, before: dict, after: dict, mode: str, only: str = "") -> tuple[bool, str]:
    recreated = sorted(n for n in before if n in after and before[n][0] != after[n][0])
    removed = sorted(n for n in before if n not in after)
    created = sorted(n for n in after if n not in before)
    if not before:
        return False, f"{name} FAIL: no stack container was recorded before the start"
    extra = "".join([f"; removed: {', '.join(removed)}" if removed else "",
                     f"; created: {', '.join(created)}" if created else ""])
    if mode == "none":
        if not recreated and not removed and not created:
            return True, f"{name} PASS: 0 containers recreated ({len(after)} unchanged)"
        return False, f"{name} FAIL: {len(recreated)} recreated: {', '.join(recreated) or '-'}{extra}"
    if mode == "all":
        kept = sorted(n for n in before if n in after and before[n][0] == after[n][0])
        if not kept and not removed:
            return True, f"{name} PASS: all {len(recreated)} containers recreated"
        return False, f"{name} FAIL: {len(kept)} not recreated: {', '.join(kept) or '-'}{extra}"
    target = [n for n in recreated if after[n][1] == only]
    others = [n for n in recreated if after[n][1] != only]
    # compose recreates a dependent of a recreated service itself:
    # its depends_on label reads "svc:condition:restart,…".
    stray = [n for n in others if not any(d.split(":")[0] == only for d in after[n][2].split(","))]
    if target and not stray and not removed and not created:
        dep = f" (+ {len(others)} that depend on it: {', '.join(others)})" if others else ""
        return True, f"{name} PASS: only {only} recreated{dep}; {len(after) - len(recreated)} unchanged"
    if not target:
        return False, f"{name} FAIL: {only} was not recreated (its input changed); recreated: {', '.join(recreated) or '-'}{extra}"
    return False, f"{name} FAIL: {len(stray)} recreated that do not depend on {only}: {', '.join(stray)}{extra}"


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# The launcher's report (scripts/noo-start-inputs.py report_lines, printed by
# lib-start-inputs.sh start_inputs_report): the count line, then one line per
# recreated SERVICE (or one "recreated: a, b (why)" line for all of them).
COUNT_LINE = re.compile(r"\b([0-9]+) running, ([0-9]+) recreated\b.*$")
REASON_LINE = re.compile(r"^recreated ([A-Za-z0-9_.-]+)(?:: .*)?$")
ALL_LINE = re.compile(r"^recreated: .*$")


def reasons(log: str) -> tuple[str, dict[str, str]]:
    """(the launcher's count line or "", {service: its "recreated X: ..." line})
    from a `noo stack start` output."""
    count, per = "", {}
    for raw in (log or "").splitlines():
        line = ANSI.sub("", raw).strip()
        m = COUNT_LINE.search(line)
        if m:
            count = m.group(0)
        m = REASON_LINE.match(line)
        if m:
            per[m.group(1)] = line
        elif ALL_LINE.match(line):
            per.setdefault("*", line)
    return count, per


def recreated_with_reasons(before: dict, after: dict, log: str) -> list[str]:
    """Each recreated container, with the launcher's line for its service."""
    _, per = reasons(log)
    out = []
    for n in sorted(n for n in before if n in after and before[n][0] != after[n][0]):
        svc = after[n][1]
        out.append(f"{n} ({per.get(svc) or per.get('*') or 'no reason line from the launcher'})")
    return out


def plain_start(name: str, before: dict, after: dict, log: str, rc) -> tuple[str, str]:
    """A plain `noo stack start` that must recreate nothing: (verdict, line)."""
    count, _ = reasons(log)
    if str(rc) != "0":
        tail = [ANSI.sub("", l).strip() for l in (log or "").splitlines() if l.strip()]
        return "FAIL", f"{name} FAIL: noo stack start exited {rc}: {tail[-1] if tail else 'no output'}"
    ok, line = judge(name, before, after, "none")
    if ok:
        return "PASS", line + (f"; the launcher: {count}" if count else "")
    moved = recreated_with_reasons(before, after, log)
    return "FAIL", line + (f"; why: {'; '.join(moved)}" if moved else "")


def reload_record(state_path: str) -> str:
    """none | unconfirmed | confirmed: nats's reload record in the start-inputs
    state (`"reloaded": {"nats": {"container": ID, "paths": {PATH: VALUE|null}}}`,
    written by `noo` once a HUP is confirmed). Names only a kind: the values
    are keyed and never leave the file."""
    try:
        state = json.load(open(state_path))
    except (OSError, ValueError):
        return "none"
    rec = (state.get("reloaded") or {}).get("nats") if isinstance(state, dict) else None
    if not isinstance(rec, dict):
        return "none"
    paths = rec.get("paths") if isinstance(rec.get("paths"), dict) else {}
    if not rec.get("container") or not paths or any(not isinstance(v, str) for v in paths.values()):
        return "unconfirmed"
    return "confirmed"


def after_provision(name: str, before: dict, after: dict, log: str, rc, conf_changed: str, record: str,
                    prov_log: str, prov_rc) -> tuple[str, str]:
    """The plain start after `noo cluster provision <self>`: (verdict, line).
    The provision re-renders users.conf and HUPs nats, which re-reads it live;
    a build that records the reload (stack start: "a users.conf nats has
    reloaded no longer recreates nats") must then leave nats running."""
    if str(rc) != "0":
        return plain_start(name, before, after, log, rc)
    if not before:
        return "FAIL", f"{name} FAIL: no stack container was recorded before the start"
    moved = [n for n in before if n in after and before[n][0] != after[n][0]]
    nats = [n for n in moved if after[n][1] == "nats"]
    why = recreated_with_reasons({n: before[n] for n in moved}, after, log)
    prov = "" if str(prov_rc) == "0" else "; the provision exited %s: %s" % (
        prov_rc, ([ANSI.sub("", l).strip() for l in (prov_log or "").splitlines() if l.strip()] or ["no output"])[-1])
    if conf_changed not in ("yes", "no"):
        return "FAIL", f"{name} FAIL: users.conf could not be read before and after the provision{prov}"
    if conf_changed == "no":
        if nats:
            return "FAIL", f"{name} FAIL: users.conf unchanged by the provision, yet nats was recreated: {'; '.join(why)}{prov}"
        return "NOTE", f"{name} NOTE: users.conf unchanged by the provision; nothing to reload{prov}"
    if record == "none":
        return "NOTE", (f"{name} NOTE: this build does not record nats reloads (no reload record after the provision); "
                        f"nats {'recreated' if nats else 'not recreated'}{prov}")
    if nats:
        return "FAIL", (f"{name} FAIL: {len(moved)} recreated after the provision's users.conf reload "
                        f"(record: {record}): {'; '.join(why)}{prov}")
    others = f"; also recreated: {'; '.join(why)}" if moved else ""
    return "PASS", f"{name} PASS: nats not recreated after the provision's users.conf reload (record: {record}){others}{prov}"


def after_forced_restart(name: str, before_restart: dict, restarted: dict, after: dict, log: str, rc,
                         restart_rc, restart_log: str) -> tuple[str, str]:
    """The plain start after a forced restart: (verdict, line). The set is
    every container the restart recreated or created (IDs before vs after
    it); none of them may be recreated by the plain start."""
    if str(restart_rc) != "0":
        tail = [ANSI.sub("", l).strip() for l in (restart_log or "").splitlines() if l.strip()]
        return "FAIL", f"{name} FAIL: the rotation's --restart exited {restart_rc}: {tail[-1] if tail else 'no output'}"
    if str(rc) != "0":
        return plain_start(name, restarted, after, log, rc)
    made = sorted(n for n in restarted if n not in before_restart or before_restart[n][0] != restarted[n][0])
    if not any(restarted[n][1] == "worker" for n in made):
        return "FAIL", (f"{name} FAIL: the --restart did not recreate the worker; it recreated: "
                        f"{', '.join(made) or '-'}")
    moved = [n for n in made if n in after and restarted[n][0] != after[n][0]]
    gone = [n for n in made if n not in after]
    if moved or gone:
        why = recreated_with_reasons({n: restarted[n] for n in moved}, after, log)
        return "FAIL", (f"{name} FAIL: {len(moved)} of the {len(made)} containers the --restart recreated were "
                        f"recreated again by the plain start: {'; '.join(why) or '-'}"
                        + (f"; removed: {', '.join(gone)}" if gone else ""))
    count, _ = reasons(log)
    others = [n for n in restarted if n in after and n not in made and restarted[n][0] != after[n][0]]
    also = recreated_with_reasons({n: restarted[n] for n in others}, after, log)
    return "PASS", (f"{name} PASS: none of the {len(made)} containers the --restart recreated "
                    f"({', '.join(made)}) was recreated by the plain start"
                    + (f"; the launcher: {count}" if count else "")
                    + (f"; also recreated: {'; '.join(also)}" if also else ""))


def _text(path: str) -> str:
    try:
        return open(path, errors="replace").read()
    except OSError:
        return ""


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "snap":
        return snap(argv[1])
    if len(argv) >= 5 and argv[0] == "judge" and argv[4] in ("--none", "--all", "--only"):
        mode = argv[4][2:]
        only = argv[5] if mode == "only" and len(argv) > 5 else ""
        if mode == "only" and not only:
            print(__doc__, file=sys.stderr)
            return 2
        ok, line = judge(argv[1], read(argv[2]), read(argv[3]), mode, only)
        print(line)
        return 0 if ok else 1
    if len(argv) == 2 and argv[0] == "reload-record":
        print(reload_record(argv[1]))
        return 0
    if len(argv) == 10 and argv[0] == "after-provision":
        _, name, b, a, slog, src, changed, record, plog, prc = argv
        verdict, line = after_provision(name, _read_or_empty(b), _read_or_empty(a), _text(slog), src, changed,
                                        record, _text(plog), prc)
        print(line)
        return 1 if verdict == "FAIL" else 0
    if len(argv) == 9 and argv[0] == "after-forced-restart":
        _, name, b, r, a, slog, src, rrc, rlog = argv
        verdict, line = after_forced_restart(name, _read_or_empty(b), _read_or_empty(r), _read_or_empty(a), _text(slog),
                                             src, rrc, _text(rlog))
        print(line)
        return 1 if verdict == "FAIL" else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
