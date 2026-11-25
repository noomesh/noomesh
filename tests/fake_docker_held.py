#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""A stateful fake `docker` for the held-container launcher tests.

State lives in the JSON file named by $FAKE_STATE: containers (id, name,
service, project, status), the one id Docker does not answer for ("hung"), the
services whose compose call would touch it ("touch_hang": the held service and
the services linked to it), the rendered compose config and service list.
Every call is appended to $FAKE_LOG as one line. A call that names the hung
container, or a compose call that would touch it, sleeps 25 s (the real one
never returns); a `docker ps` hangs when $FAKE_PS_HANGS is set. Nothing real
is touched.
"""
import json
import os
import sys
import time

# Some launcher steps scrub the environment: fall back to the files beside
# the install (bin/docker, ../state.json, ../docker.log).
_BASE = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.environ.setdefault("FAKE_LOG", os.path.join(_BASE, "docker.log"))
os.environ.setdefault("FAKE_STATE", os.path.join(_BASE, "state.json"))
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(" ".join(args) + "\n")
S = json.load(open(os.environ["FAKE_STATE"]))
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME") or "noomesh"


def save():
    json.dump(S, open(os.environ["FAKE_STATE"], "w"))


def hang():
    time.sleep(25)
    sys.exit(0)


def find(ref):
    for c in S["containers"]:
        if c["id"].startswith(ref) or ref.startswith(c["id"]) or c["name"] == ref.lstrip("/"):
            return c
    return None


def is_hung(c):
    return bool(c) and c["id"] == S.get("hung")


def fmt(c, f):
    health = "healthy" if c["status"] == "running" else c["status"]
    pairs = [
        ('{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}', health),
        ('{{.State.Status}}', c["status"]), ('{{.State.ExitCode}}', "0"),
        ('{{.State.Running}}', "true" if c["status"] == "running" else "false"),
        ('{{.Name}}', "/" + c["name"]), ('{{.Names}}', c["name"]), ('{{.ID}}', c["id"]), ('{{.Id}}', c["id"]),
        ('{{index .Config.Labels "com.docker.compose.service"}}', c["service"]),
        ('{{index .Config.Labels "com.docker.compose.project"}}', c["project"]),
        ('{{.Label "com.docker.compose.service"}}', c["service"]),
        ('{{.Label "com.docker.compose.project"}}', c["project"]),
        ('{{.Created}}', "2026-11-25T00:00:00Z"),
    ]
    for k, v in pairs:
        f = f.replace(k, v)
    return f


def parse_flags(a, valued=()):
    flags, rest, i = {}, [], 0
    while i < len(a):
        x = a[i]
        if x in valued:
            flags.setdefault(x, []).append(a[i + 1]); i += 2; continue
        if x.startswith("-"):
            flags.setdefault(x, []).append(True)
        else:
            rest.append(x)
        i += 1
    return flags, rest


def ps(a, compose_services=None):
    flags, rest = parse_flags(a, ("--filter", "--format"))
    # the probe's listing of the project's containers is what hangs here
    if os.environ.get("FAKE_PS_HANGS") and any(x.startswith("label=com.docker.compose.project=") for x in flags.get("--filter", [])):
        hang()
    out = list(S["containers"])
    for flt in flags.get("--filter", []):
        k, _, v = flt.partition("=")
        if k == "label":
            lk, _, lv = v.partition("=")
            if lk == "com.docker.compose.project":
                out = [c for c in out if c["project"] == lv]
            elif lk == "com.docker.compose.service":
                out = [c for c in out if c["service"] == lv]
        elif k == "status":
            out = [c for c in out if c["status"] == v]
    allflag = any(x in flags for x in ("-a", "-aq", "--all"))
    if not allflag:
        out = [c for c in out if c["status"] == "running"]
    quiet = any(x in flags for x in ("-q", "-aq"))
    f = (flags.get("--format") or [None])[0]
    for c in out:
        print(c["id"] if quiet or not f else fmt(c, f))


def closure(svc):
    cfg = json.loads(S["cfg"]).get("services", {})
    seen, todo = set(), [svc]
    while todo:
        s = todo.pop()
        if s in seen:
            continue
        seen.add(s)
        d = (cfg.get(s) or {}).get("depends_on") or {}
        todo.extend(d)
    return seen


def compose(a):
    i = 0
    while i < len(a):
        if a[i] in ("-f", "--profile", "-p", "--project-name"):
            i += 2; continue
        break
    verb, rest = a[i], a[i + 1:]
    if verb == "version":
        print("Docker Compose version v2.30.0"); return
    if verb == "config":
        if "--services" in rest:
            print("\n".join(S["services"]))
        else:
            print(S["cfg"])
        return
    flags, svcs = parse_flags(rest, ("--scale", "-t", "--timeout", "--status", "--wait-timeout"))
    scale0 = {x.split("=")[0] for x in flags.get("--scale", []) if x.endswith("=0")}
    mine = [c for c in S["containers"] if c["project"] == PROJECT]
    if verb == "ps":
        if not svcs and S.get("hung"):
            hang()
        if any(s in S["touch_hang"] for s in svcs):
            hang()
        status = (flags.get("--status") or [None])[0]
        for c in mine:
            if (not svcs or c["service"] in svcs) and (status is None or c["status"] == status):
                print(c["id"])
        return
    if verb in ("up", "restart", "stop", "start", "rm"):
        targets = svcs or [s for s in S["services"]]
        if verb == "up" and "--no-deps" not in flags:
            deps = set()
            for s in targets:
                deps |= closure(s)
            targets = sorted(set(targets) | deps)
        if any(s in S["touch_hang"] for s in targets):
            hang()
        for s in targets:
            if s in scale0 and verb == "up":
                continue
            cs = [c for c in mine if c["service"] == s]
            if verb == "up":
                if not cs:
                    cs = [{"id": "n%03d" % len(S["containers"]), "name": "noo-" + s, "service": s, "project": PROJECT, "status": "running"}]
                    S["containers"].append(cs[0])
                for c in cs:
                    c["status"] = "created" if s in S.get("up_leaves_created", []) else "running"
            elif verb in ("restart", "start"):
                for c in cs:
                    c["status"] = "running"
            elif verb == "stop":
                for c in cs:
                    c["status"] = "exited"
        save()
        sys.exit(int(os.environ.get("FAKE_UP_RC", "0")) if verb == "up" else 0)


def main():
    if not args:
        return
    cmd = args[0]
    if cmd == "compose":
        return compose(args[1:])
    if cmd == "ps":
        return ps(args[1:])
    if cmd == "inspect":
        flags, ids = parse_flags(args[1:], ("-f", "--format"))
        f = (flags.get("-f") or flags.get("--format") or [None])[0]
        for r in ids:
            c = find(r)
            if is_hung(c):
                hang()
            if c is not None and c["id"] == os.environ.get("FAKE_SLOW_ID"):
                time.sleep(float(os.environ.get("FAKE_SLOW_SECS", "0")))
            if c is None:
                sys.stderr.write("Error: No such object: %s\n" % r); sys.exit(1)
            print(fmt(c, f) if f else json.dumps(c))
        return
    if cmd in ("start", "stop", "rm", "logs", "restart", "kill"):
        names = [x for x in args[1:] if not x.startswith("-") and not x.isdigit()]
        for n in names:
            c = find(n)
            if is_hung(c):
                hang()
            if c and cmd == "start" and os.environ.get("FAKE_START_FAILS"):
                sys.stderr.write("Error: cannot start %s\n" % n); sys.exit(1)
            if c:
                if cmd in ("start", "restart"):
                    c["status"] = "running"
                elif cmd == "stop":
                    c["status"] = "exited"
                elif cmd == "rm":
                    S["containers"].remove(c)
        save()
        return
    if cmd == "volume" and args[1:2] == ["ls"]:
        print("\n".join(S.get("volumes", []))); return
    if cmd == "info":
        print("{}"); return
    if cmd == "image" and args[1:2] == ["inspect"]:
        sys.exit(1)
    return


main()
