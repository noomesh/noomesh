# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""scripts/noo-netns-restore.sh starts exactly the namespace joiners dockerd
failed to start, after their door is up, and nothing else.

rc.2 install matrix probe (2026-11-12): on a real dockerd, one start in five
left noo-ollama-embed exited 128, "cannot join network namespace of a non
running container: container noo-stunnel-ollama-embed is exited", and nothing
restarted it. The script runs the real logic against a fake docker.
"""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "noo-netns-restore.sh"
NS_ERR = "cannot join network namespace of a non running container: container noo-stunnel-ollama-embed is exited"

FAKE = r'''#!/usr/bin/env python3
import json, os, sys
st = os.environ["FAKE_STATE"]
db = json.load(open(st))
a = sys.argv[1:]
open(st + ".log", "a").write(" ".join(a) + "\n")
def save(): json.dump(db, open(st, "w"))
if a[0] == "info":
    sys.exit(0 if db.get("up", True) else 1)
if a[0] == "ps":
    print("\n".join(i for i, c in db["c"].items() if c["status"] in ("exited", "created"))); sys.exit(0)
if a[0] == "inspect":
    fmt, ident = a[2], a[3]
    c = db["c"].get(ident) or next((v for v in db["c"].values() if v["name"] == ident), None)
    if c is None: sys.exit(1)
    if fmt == "{{.State.Running}}": print("true" if c["status"] == "running" else "false"); sys.exit(0)
    if fmt == "{{.Name}}": print("/" + c["name"]); sys.exit(0)
    print("|".join(["/" + c["name"], c.get("mode", "default"), c.get("proj", ""), c.get("mby", ""), c.get("policy", "unless-stopped"), c.get("err", "")])); sys.exit(0)
if a[0] == "start":
    c = db["c"][a[1]]
    if c.get("start_fails"): sys.exit(1)
    c["status"] = "running"; c["err"] = ""; save(); sys.exit(0)
sys.exit(2)
'''


def run(tmp_path, containers, up=True, door_wait="0"):
    bindir = tmp_path / "bin"; bindir.mkdir()
    (bindir / "docker").write_text(FAKE); (bindir / "docker").chmod(0o755)
    st = tmp_path / "state.json"
    st.write_text(json.dumps({"up": up, "c": containers}))
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "FAKE_STATE": str(st), "NOO_NETNS_DOOR_WAIT": door_wait, "NOO_NETNS_DOCKER_WAIT": "0"}
    r = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=env, timeout=60)
    db = json.loads(st.read_text())
    log = (tmp_path / "state.json.log").read_text().splitlines() if (tmp_path / "state.json.log").exists() else []
    return r, db, log


def door(status="running"):
    return {"name": "noo-stunnel-ollama-embed", "status": status, "proj": "noomesh"}


def joiner(**kw):
    c = {"name": "noo-ollama-embed", "status": "exited", "proj": "noomesh", "mode": "container:D", "err": NS_ERR}
    c.update(kw)
    return c


def test_a_joiner_that_failed_its_namespace_join_is_started_after_its_door(tmp_path):
    r, db, log = run(tmp_path, {"D": door(), "J": joiner()})
    assert r.returncode == 0, r.stderr
    assert db["c"]["J"]["status"] == "running"
    assert "start J" in log
    assert r.stdout.strip() == "noo-netns-restore: started noo-ollama-embed (it joins noo-stunnel-ollama-embed's network, which dockerd had not started first)"


def test_nothing_else_is_started_and_nothing_to_do_is_silent(tmp_path):
    cs = {
        "D": door(),
        "HAND": joiner(name="noo-stopped-by-hand", err=""),              # stopped by hand: no join error
        "MBY": joiner(name="noo-agent-owned", mby="noo-node-agent"),    # the agent's convergence owns it
        "NOPOL": joiner(name="noo-oneshot", policy="no"),               # a one-shot
        "OTHER": joiner(name="someone-elses", proj=""),                 # not a compose stack container
        "BRIDGE": {"name": "noo-plain", "status": "exited", "proj": "noomesh", "mode": "noomesh_default", "err": NS_ERR},
    }
    r, db, log = run(tmp_path, cs)
    assert r.returncode == 0 and r.stdout == "" and r.stderr == "", (r.stdout, r.stderr)
    assert not [l for l in log if l.startswith("start ")], log
    assert all(db["c"][k]["status"] == "exited" for k in cs if k != "D")


def test_a_door_that_does_not_come_up_is_reported_not_started(tmp_path):
    r, db, log = run(tmp_path, {"D": door("exited"), "J": joiner()}, door_wait="0")
    assert r.returncode == 1
    assert db["c"]["J"]["status"] == "exited" and not [l for l in log if l.startswith("start ")]
    assert "noo-ollama-embed not started: its network door noo-stunnel-ollama-embed is not running" in r.stderr


def test_docker_not_answering_starts_nothing(tmp_path):
    r, _, log = run(tmp_path, {"D": door(), "J": joiner()}, up=False)
    assert r.returncode == 1 and "docker did not answer" in r.stderr
    assert not [l for l in log if l.startswith(("start ", "ps "))]


def test_the_script_ships_in_the_standalone_slice():
    assert '"scripts/noo-netns-restore.sh"' in (ROOT / "noo-cli" / "build.rs").read_text()
    assert os.access(SCRIPT, os.X_OK)
