# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The UPGRADE cell's resolver and judge (scripts/install-cell/upgrade.sh).

    upgrade_judge.py resolve OWNER/REPO CLI_TAG PREV_OUT TARGET_OUT
        The newest noo-cli-vX.Y.Z FINAL strictly below the release under test.
    upgrade_judge.py before VERIFY_JSON SELF
        The self node's rows that say what the box was before the roll.
    upgrade_judge.py judge
        One line per assert, `UPGRADE <id> PASS|FAIL|NOTE|NOT REACHED: <why>`,
        quoting the product's own line on a FAIL. Exit 1 on any FAIL. Reads
        $OUT/logs/<step>.log and $J/* written by upgrade.sh.

Standard library only (hosted runner's python3).
"""
import json
import os
import re
import stat
import subprocess
import sys
import urllib.request


def resolve(repo, tag, prev_out, target_out):
    req = urllib.request.Request("https://api.github.com/repos/%s/releases?per_page=100" % repo,
                                 headers={"Accept": "application/vnd.github+json"})
    if os.environ.get("GH_TOKEN"):
        req.add_header("Authorization", "Bearer " + os.environ["GH_TOKEN"])
    rel = json.load(urllib.request.urlopen(req, timeout=30))
    fin = re.compile(r"^noo-cli-v(\d+)\.(\d+)\.(\d+)$")
    finals = sorted({tuple(map(int, m.groups())) for r in rel
                     if not r.get("prerelease") and not r.get("draft")
                     for m in [fin.match(r.get("tag_name", ""))] if m})
    if tag == "latest":
        if len(finals) < 2:
            sys.exit("fewer than two finals are published")
        target, below = "noo-cli-v%d.%d.%d" % finals[-1], finals[:-1]
    else:
        m = re.match(r"^noo-cli-v(\d+)\.(\d+)\.(\d+)", tag)
        if not m:
            sys.exit("CLI_TAG %r is not noo-cli-vX.Y.Z[-rc.N]" % tag)
        base = tuple(map(int, m.groups()))
        target, below = tag, [f for f in finals if f < base]
    if not below:
        sys.exit("no final below %s" % target)
    prev = "noo-cli-v%d.%d.%d" % below[-1]
    print("previous final: %s; release under test: %s" % (prev, target))
    open(prev_out, "w").write(prev)
    open(target_out, "w").write(target)


def load(path):
    try:
        txt = open(path, errors="replace").read()
        return json.JSONDecoder().raw_decode(txt[txt.index("{"):])[0]
    except Exception:
        return None


def rows(verify, name, self_node):
    """Every check called `name`: on this node, then on the controller."""
    out = []
    if not verify:
        return out
    for n in verify.get("nodes") or []:
        if n.get("node") == self_node:
            out += [c for c in n.get("checks") or [] if c.get("name") == name]
    out += [c for c in (verify.get("controller") or {}).get("checks") or [] if c.get("name") == name]
    return out


def one(s, n=300):
    return (s or "").replace("\n", " ").strip()[:n]


def before(path, self_node):
    v = load(path)
    for name in ("self-agent lane", "release check", "agent protect"):
        for c in rows(v, name, self_node):
            print("before: %s %s: %s" % (name, c.get("verdict"), one(c.get("detail"), 200)))


def text(path):
    try:
        return open(path, errors="replace").read()
    except OSError:
        return None


def judge():
    out, j, me = os.environ["OUT"], os.environ["J"], os.environ["SELF"]
    lines, failed = [], False

    def say(aid, verdict, why):
        nonlocal failed
        failed |= verdict == "FAIL"
        lines.append("UPGRADE %s %s: %s" % (aid, verdict, one(why, 400)))

    roll = text(os.path.join(out, "logs", "upgrade-all.log"))
    stack = text(os.path.join(out, "logs", "upgrade-stack-same-tag.log"))
    # the whole roll (--all and the same-tag --stack): A3, where a refusal anywhere counts
    journal = (text(os.path.join(j, "apply.journal")) or "") + (text(os.path.join(j, "node.journal")) or "")
    # the --all window only (captured before the --stack ran): A2
    roll_journal = text(os.path.join(j, "roll-window.journal")) or ""
    after = load(os.path.join(j, "verify-after.json"))
    final = load(os.path.join(j, "verify-final.json"))
    roll_rc = (text(os.path.join(j, "roll.rc")) or "").strip()

    # ── after --all ──
    if roll is None:
        for a in ("A1", "A2", "A3", "A4", "A5", "A6", "A7"):
            say(a, "NOT REACHED", "the --all roll did not run")
    else:
        stopped = [l for l in roll.splitlines() if "Upgrade stopped at the" in l or "staging failed" in l
                   or "has not adopted the fleet signing key" in l]
        if roll_rc == "0" and not stopped:
            say("A1", "PASS", "noo upgrade --all exited 0 and nothing says 'Upgrade stopped at the'")
        else:
            say("A1", "FAIL", "exit %s; %s" % (roll_rc or "?", " | ".join(stopped[:3]) or "no stop line"))

        tags = re.findall(r"release-check: generation=\d+[^\n]*", roll_journal + "\n" + roll)
        if any("generation=2" in t for t in tags):
            say("A2", "PASS", [t for t in tags if "generation=2" in t][-1])
        elif tags:
            say("A2", "FAIL", "the applier reports %s (the old applier is still in place)" % tags[-1])
        else:
            say("A2", "FAIL", "no 'release-check:' line from the applier during the --all roll")

        refused = [("%s: %s" % (src, l.strip())) for src, body in (("--all", roll), ("--stack", stack or ""), ("journal", journal))
                   for l in body.splitlines() if "noo-apply: REFUSED" in l or "REFUSED release check:" in l]
        # Strict: the first roll's applier-only bootstrap refusal is NOT
        # exempt (general, 2026-11-18): rc.3 makes an applier-only bundle
        # equal to the installed applier a no-op, so any REFUSED line FAILs.
        say("A3", "FAIL" if refused else "PASS",
            " | ".join(refused[:2]) if refused else "no 'noo-apply: REFUSED' in the --all roll, the --stack or the node's journal")

        rc = rows(after, "release check", me)
        ok = [c for c in rc if c.get("verdict") == "ok" and "root code installs only from a release-signed list on" in (c.get("detail") or "")]
        if ok:
            say("A4", "PASS", ok[0].get("detail"))
        elif rc:
            say("A4", "FAIL", "%s: %s" % (rc[0].get("verdict"), rc[0].get("detail")))
        else:
            say("A4", "FAIL", "no 'release check' row in verify after the roll")

        net = [l.strip() for l in roll.splitlines() if "noo-netns-restore" in l]
        # a sudo or tee ON the unit; the product's own "no sudo" wording is not one
        bad = [l for l in net if re.search(r"\bsudo\b|\btee\b", l.replace("no sudo", ""))]
        gen1 = [l for l in net if "not installed: the self-node's applier (generation 1) predates the netns-unit kind, so no sudo is run for it" in l]
        staged = [i for i, l in enumerate(net) if "staged to the self-node" in l and "whose applier installs it (no sudo)" in l]
        enabled = any("noo-netns-restore.service installed and enabled by the self-node's applier" in l for l in net)
        late = staged and any("not installed (" in l for l in net[staged[0]:])
        if bad:
            say("A5", "FAIL", bad[0])
        elif late:
            say("A5", "FAIL", [l for l in net[staged[0]:] if "not installed (" in l][0])
        elif not net and os.path.exists(os.environ.get("NETNS_UNIT", "/etc/systemd/system/noo-netns-restore.service")) \
                and "unit before: " in (text(os.path.join(out, "logs", "remove-netns-unit.log")) or "unit before: present"):
            # 0.6.26's onboard installed it; the roll found it current and said nothing (97)
            say("A5", "PASS", "no netns line: the unit was already installed and current before the roll")
        elif gen1 and not staged:
            say("A5", "PASS", gen1[0])
        elif staged and enabled:
            say("A5", "PASS", net[staged[0]] + " + installed and enabled by the self-node's applier")
        else:
            say("A5", "FAIL", " | ".join(net[:3]) or "no noo-netns-restore line in the roll")

        ap = rows(after, "agent protect", me)
        okp = [c for c in ap if c.get("verdict") == "ok" and "the node agent writes only where it must on" in (c.get("detail") or "")
               and me in (c.get("detail") or "")]
        if okp:
            say("A6", "PASS", okp[0].get("detail"))
        elif ap:
            say("A6", "FAIL", "%s: %s" % (ap[0].get("verdict"), ap[0].get("detail")))
        else:
            say("A6", "FAIL", "no 'agent protect' row after the roll (the self node's hold was never reported)")

        # A7: the self node's agent is back on the new build (provision.rs
        # rendered its env with the literal noo-controller on rc.2: cut off)
        cut = [l.strip() for l in journal.splitlines() if "lookup noo-controller" in l]
        silent = [l.strip() for l in roll.splitlines() if "no heartbeat from the new build within" in l]
        ver = rows(final or after, "version", me)
        tgt = (text(os.path.join(j, "target")) or "").strip().replace("noo-cli-v", "")
        on_new = ver and ver[0].get("verdict") == "ok" and tgt and tgt in (ver[0].get("detail") or "")
        if on_new and not cut and not silent:
            say("A7", "PASS", "the self node heartbeats on the new build: %s" % ver[0].get("detail"))
        else:
            say("A7", "FAIL", " | ".join((cut[:1] + silent[:1] + ["version: %s: %s" % (ver[0].get("verdict"), ver[0].get("detail")) if ver else "no version row"])))

    # ── after the same-tag --stack ──
    if stack is None:
        for b in ("B1", "B2", "B3"):
            say(b, "NOT REACHED", "the same-tag --stack did not run")
    else:
        s1 = "installing noo-netns-restore.service: staged to the self-node"
        s2 = "noo-netns-restore.service installed and enabled by the self-node's applier"
        a, b = [l.strip() for l in stack.splitlines() if s1 in l and "whose applier installs it (no sudo)" in l], s2 in stack
        if a and b:
            say("B1", "PASS", a[0] + " + " + s2)
        else:
            net = [l.strip() for l in stack.splitlines() if "noo-netns-restore" in l]
            say("B1", "FAIL", " | ".join(net[:3]) or "no noo-netns-restore line in the same-tag --stack")

        unit = os.environ.get("NETNS_UNIT", "/etc/systemd/system/noo-netns-restore.service")
        try:
            st = os.stat(unit)
            body = open(unit).read()
            user = (re.findall(r"^User=(.*)$", body, re.M) or [""])[-1].strip()
            execs = (re.findall(r"^ExecStart=(.*)$", body, re.M) or [""])[-1].strip()
            en = os.environ.get("NETNS_UNIT_ENABLED") or subprocess.run(["systemctl", "is-enabled", "noo-netns-restore.service"], capture_output=True, text=True).stdout.strip()
            owner = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
            probs = []
            want_owner = tuple(int(x) for x in os.environ.get("NETNS_UNIT_OWNER", "0:0").split(":"))
            if (st.st_uid, st.st_gid) != want_owner:
                probs.append("owner %d:%d, not root:root" % (st.st_uid, st.st_gid))
            if stat.S_IMODE(st.st_mode) != 0o644:
                probs.append("mode %04o, not 0644" % stat.S_IMODE(st.st_mode))
            if not user or user == "root" or user != owner:
                probs.append("User=%s, not the install owner %s" % (user or "(none)", owner))
            # `ExecStart=/path/noo-netns-restore.sh` or `ExecStart=/bin/bash "/path/noo-netns-restore.sh"`
            if not any(w.strip('"\'').endswith("noo-netns-restore.sh") for w in execs.split()):
                probs.append("ExecStart=%s" % execs)
            if en != "enabled":
                probs.append("is-enabled=%s" % (en or "?"))
            say("B2", "FAIL" if probs else "PASS",
                "; ".join(probs) if probs else "%s root:root 0644, User=%s, ExecStart=%s, enabled" % (unit, user, execs))
        except OSError as e:
            say("B2", "FAIL", "%s: %s" % (unit, e.strerror))

        sj = text(os.path.join(j, "sudo-stack.journal")) or ""
        cmds = [l.strip() for l in sj.splitlines() if "COMMAND=" in l]
        say("B3", "FAIL" if cmds else "PASS",
            ("%d sudo command(s) during the --stack: %s" % (len(cmds), cmds[0])) if cmds
            else "0 sudo commands in the journal during the same-tag --stack (operator: %s)"
            % subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip())

    # ── general's rows, after both ──
    v = final or after
    hf = rows(v, "hf-cache hub owner", me)
    if hf and hf[0].get("verdict") == "ok" and "not judged" in (hf[0].get("detail") or ""):
        say("G1", "NOTE", "the row is OK but judged nothing: %s" % hf[0].get("detail"))
    else:
        say("G1", "PASS" if hf and hf[0].get("verdict") == "ok" else "FAIL",
            ("%s: %s" % (hf[0].get("verdict"), hf[0].get("detail"))) if hf else "no 'hf-cache hub owner' row")
    om = rows(v, "ollama models", me)
    if om and om[0].get("verdict") == "ok" and "not yet checked" in (om[0].get("detail") or ""):
        # i1067: a held model the restarted agent has not checked yet is
        # OK on the row, but proves nothing about its bytes.
        say("G2", "NOTE", "the row is OK but a model is not yet checked (the agent's first pass after the roll): %s"
            % om[0].get("detail"))
    elif om and om[0].get("verdict") == "ok":
        say("G2", "PASS", om[0].get("detail"))
    elif om and "no controller record" in (om[0].get("detail") or ""):
        say("G2", "NOTE", "the model the previous final's onboard pulled has no controller record (the 0.6.27 roll note's "
            "existing-install case): %s; remedy %s" % (om[0].get("detail"), om[0].get("remedy")))
    else:
        say("G2", "FAIL", ("%s: %s" % (om[0].get("verdict"), om[0].get("detail"))) if om else "no 'ollama models' row")
    bs = rows(v, "backend starts", me)
    say("G3", "FAIL" if bs else "PASS",
        ("%s: %s" % (bs[0].get("verdict"), bs[0].get("detail"))) if bs else "no 'backend starts' row (no start refused)")
    ll = rows(v, "legacy lanes", me)
    say("G4", "PASS" if ll and ll[0].get("verdict") == "ok" else "FAIL",
        ("%s: %s" % (ll[0].get("verdict"), ll[0].get("detail"))) if ll else "no 'legacy lanes' row")
    chat = text(os.path.join(out, "logs", "chat-after.log"))
    rec = {}
    try:
        for l in open(os.path.join(out, "steps.jsonl")):
            d = json.loads(l)
            if d.get("step") == "chat-after":
                rec = d
    except OSError:
        pass
    if chat is None:
        say("G5", "NOT REACHED", "no chat after the upgrade")
    else:
        body = [l for l in chat.splitlines() if l.strip()]
        say("G5", "PASS" if rec.get("rc") == 0 and body else "FAIL",
            "noo chat answered after the upgrade: %s" % one(" ".join(body[-2:]), 160) if rec.get("rc") == 0 and body
            else "noo chat exit %s: %s" % (rec.get("rc"), one(" ".join(body[-2:]), 200)))

    print("\n".join(lines))
    return 1 if failed else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["resolve"] and len(a) == 5:
        resolve(*a[1:])
    elif a[:1] == ["before"] and len(a) == 3:
        before(*a[1:])
    elif a[:1] == ["judge"]:
        sys.exit(judge())
    else:
        sys.exit("usage: upgrade_judge.py resolve OWNER/REPO TAG PREV TARGET | before VERIFY SELF | judge")
