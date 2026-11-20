# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The UPGRADE cell's resolver and judge (scripts/install-cell/upgrade.sh).

    upgrade_judge.py resolve OWNER/REPO CLI_TAG PREV_OUT TARGET_OUT [PREV_TAG]
        The newest noo-cli-vX.Y.Z FINAL strictly below the release under test.
        PREV_TAG (the dispatch input `prev_tag`; empty = that default) chooses
        the start instead, strictly: exactly noo-cli-vX.Y.Z, strictly below the
        release under test's X.Y.Z, and a published, non-prerelease, non-draft
        release of OWNER/REPO. Anything else exits 1 naming the rule, before
        anything installs.
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
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recreated  # noqa: E402  the plain-start parser run.sh's start checks use


# fullmatch (`$` lets a trailing newline through); [0-9], not \d (Unicode digits)
FINAL = re.compile(r"noo-cli-v([0-9]+)\.([0-9]+)\.([0-9]+)")
# The release under test (CLI_TAG, the dispatch input `cli_tag`): the same
# rule as validate_tag.sh's CLI_TAG_RE, held equal by running both on one
# corpus (tests/test_dispatch_inputs_never_reach_a_shell_raw.py).
CLI_TAG = re.compile(r"latest|noo-cli-v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-rc\.[0-9]+)?")


def _api(repo, path, missing_ok=False):
    """GET https://api.github.com/repos/<repo>/<path> (read-only GH_TOKEN when
    set): the parsed JSON; None on a 404 when missing_ok, else it raises."""
    req = urllib.request.Request("https://api.github.com/repos/%s/%s" % (repo, path),
                                 headers={"Accept": "application/vnd.github+json"})
    if os.environ.get("GH_TOKEN"):
        req.add_header("Authorization", "Bearer " + os.environ["GH_TOKEN"])
    try:
        return json.load(urllib.request.urlopen(req, timeout=30))
    except urllib.error.HTTPError as e:
        if missing_ok and e.code == 404:
            return None
        raise


def refuse_prev(chosen, rule, why):
    sys.exit("PREV_TAG %r refused (%s): %s; nothing installed" % (chosen, rule, why))


def prev_version(chosen):
    """Rule 1 of a chosen start: exactly noo-cli-vX.Y.Z. Its (X, Y, Z)."""
    m = FINAL.fullmatch(chosen)
    if not m:
        refuse_prev(chosen, "pattern", "not exactly noo-cli-vX.Y.Z (a final's tag: no rc or other suffix, "
                    "no branch, ref or sha, no `latest`, three-part versions only)")
    return tuple(map(int, m.groups()))


def chosen_previous(repo, chosen, base, target, rel):
    """The operator's chosen start (`prev_tag`), held to the strict rules:
    pattern, strictly below the release under test, a published final."""
    ver = prev_version(chosen)
    if not ver < base:
        refuse_prev(chosen, "not below the target", "%d.%d.%d is not strictly below %s's %d.%d.%d"
                    % (ver + (target,) + base))
    hit = [r for r in rel if r.get("tag_name") == chosen]
    # not in the first page of the list: the tag's own release (the same API)
    r = hit[0] if hit else _api(repo, "releases/tags/" + chosen, missing_ok=True)
    if not r:
        refuse_prev(chosen, "no release", "%s has no published release named %s" % (repo, chosen))
    if r.get("draft"):
        refuse_prev(chosen, "draft", "the %s release of %s is a draft, not a published final" % (chosen, repo))
    if r.get("prerelease"):
        refuse_prev(chosen, "prerelease", "the %s release of %s is marked prerelease, not a final" % (chosen, repo))
    return chosen


def resolve(repo, tag, prev_out, target_out, chosen=""):
    m = CLI_TAG.fullmatch(tag)
    if not m:
        sys.exit("CLI_TAG %r refused: must be exactly latest or noo-cli-vX.Y.Z with an optional -rc.N" % tag)
    if chosen:
        prev_version(chosen)  # the pattern refuses before any network read
    rel = _api(repo, "releases?per_page=100")
    finals = sorted({tuple(map(int, m.groups())) for r in rel
                     if not r.get("prerelease") and not r.get("draft")
                     for m in [FINAL.fullmatch(r.get("tag_name", ""))] if m})
    if tag == "latest":
        if not chosen and len(finals) < 2:
            sys.exit("fewer than two finals are published")
        if not finals:
            sys.exit("no final is published")
        target, base = "noo-cli-v%d.%d.%d" % finals[-1], finals[-1]
    else:
        target, base = tag, tuple(map(int, m.groups()))
    if chosen:
        prev = chosen_previous(repo, chosen, base, target, rel)
        print("chosen start (prev_tag): %s; release under test: %s" % (prev, target))
    else:
        below = [f for f in finals if f < base]
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


def step_rc(out, name):
    """The step's exit code from steps.jsonl (the last record of that name)."""
    rc = None
    try:
        for l in open(os.path.join(out, "steps.jsonl")):
            d = json.loads(l)
            if d.get("step") == name:
                rc = d.get("rc")
    except (OSError, ValueError):
        pass
    return rc


def text(path):
    try:
        return open(path, errors="replace").read()
    except OSError:
        return None


# The applier's LAST line on a refusal (noomesh #1464): exactly
# `noo-apply: refusal=<name> (exit <N>)`. It never says REFUSED, and it lands
# in noo-fetch's journal (the applier is noo-fetch.service's child).
REFUSAL = re.compile(r"^noo-apply: refusal=([a-z][a-z0-9_]*) \(exit ([0-9]+)\)$")
# journald's short prefix: `Nov 20 09:08:38 host noo-fetch[123]: `
JOURNAL_PREFIX = re.compile(r"^(?:.*? )?[A-Za-z0-9_.@-]+\[[0-9]+\]: ")


def refusal(line):
    """(name, exit) when the line, or its journal message, is the applier's
    refusal-name line; else None."""
    bare = line.strip()
    m = JOURNAL_PREFIX.match(bare)
    for msg in (bare, bare[m.end():] if m else None):
        r = REFUSAL.match(msg) if msg is not None else None
        if r:
            return r.group(1), r.group(2)
    return None


# Where sudo puts a binary it resolved (secure_path): the cell's own commands
# are recognised there only, never anywhere a product binary might live.
SUDO_BIN_DIRS = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/")
EPOCH = re.compile(r"[0-9]+")


def own_sudo_commands(roll_t0, stack_t0, stack_t1):
    """The EXACT sudo commands upgrade.sh itself runs in or next to the
    same-tag --stack's window, arguments included (the release lead's rule:
    never by command name, so a product `sudo journalctl -u …` or `sudo
    systemctl restart …` still counts):
      the --all window's journal and later the node's (`--since @ROLL_T0`),
      the applier's journal (`-t noo-apply --since @ROLL_T0`),
      the unit removal and its daemon-reload (remove-netns-unit),
      and the sudo journal B3 reads itself."""
    own = ["rm -f /etc/systemd/system/noo-netns-restore.service", "systemctl daemon-reload"]
    if roll_t0 and EPOCH.fullmatch(roll_t0):
        own += ["journalctl --no-pager --since @%s" % roll_t0,
                "journalctl -t noo-apply --no-pager --since @%s" % roll_t0]
    if stack_t0 and stack_t1 and EPOCH.fullmatch(stack_t0) and EPOCH.fullmatch(stack_t1):
        own.append("journalctl _COMM=sudo --no-pager --since @%s --until @%s" % (stack_t0, stack_t1))
    return own


def is_own_sudo(line, own):
    """True when the journal line's COMMAND= is exactly one of `own`, its
    binary at a path sudo resolves to."""
    m = re.search(r"COMMAND=(.*)$", line)
    if not m:
        return False
    cmd = m.group(1).strip()
    binary, sep, args = cmd.partition(" ")
    d, _, base = binary.rpartition("/")
    if d + "/" not in SUDO_BIN_DIRS:
        return False
    return base + sep + args in own


# ── NO-DOCKERHUB: the Docker daemon touches no Docker Hub image ─────────────
# upgrade.sh records `docker events` (image + container) across `noo upgrade
# --all`, the same-tag `--stack`, the plain `noo stack start` after them
# (and the cell's own remove-netns-unit step between): the NEW version's
# roll and start, never the previous final's onboard/start.
HUB_HOSTS = ("docker.io", "index.docker.io", "registry-1.docker.io")
# Images a container can name without a registry that are Docker Hub's, and
# that no noomesh build is called: the leak the 0.6.28 `docker run alpine
# chgrp` was. Compared on the normalised repo (no host, `library/`, tag, digest).
HUB_KNOWN = ("alpine", "busybox", "hello-world", "debian", "ubuntu")


def image_parts(ref):
    """(registry, repo) of an image reference. registry is the host Docker
    would contact: Docker's own rule, the first path part is a host only when
    it holds a `.` or `:` or is `localhost`; otherwise (bare `name`, bare
    `org/name`) the image is Docker Hub's, registry "docker.io". Tag and
    digest are dropped; Hub aliases and a leading `library/` are folded so
    `alpine`, `library/alpine` and `docker.io/library/alpine` share the repo
    `alpine`. An image id (`sha256:...`) names no registry: (None, id)."""
    ref = (ref or "").strip()
    ref = ref.split("@", 1)[0]
    if not ref or re.fullmatch(r"(sha256:)?[0-9a-f]{12,64}", ref):
        return None, ref
    first, sep, rest = ref.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = "docker.io", ref
    if host in HUB_HOSTS:
        host = "docker.io"
        if path.startswith("library/"):
            path = path[len("library/"):]
    # a tag is a `:` after the last `/`
    last = path.rsplit("/", 1)
    last[-1] = last[-1].split(":", 1)[0]
    return host, "/".join(last)


def is_hub_pull(ref):
    """A `pull` event names a Docker Hub image: the registry is Docker Hub's,
    whether spelled out or implied by a bare name or org/name."""
    return image_parts(ref)[0] == "docker.io"


def is_hub_container(ref, pulled_repos):
    """A container `create` runs a Docker Hub image. A bare `noo-browser:latest`
    reads as Hub but is a LOCAL build that is never pulled, so a bare name
    alone is not a verdict. Hub only when (1) the reference spells a Hub host,
    or (2) that repo was pulled from Hub in this window, or (3) it is one of
    the well-known Hub-only names (HUB_KNOWN). A create event carries no repo
    digest, so a locally-held Hub image created without a pull in the window
    and not in HUB_KNOWN is not caught here (it has no registry to read)."""
    ref = (ref or "").strip()
    head = ref.split("@", 1)[0].partition("/")[0]
    if head in HUB_HOSTS:
        return True
    host, repo = image_parts(ref)
    if host != "docker.io":
        return False
    return repo in pulled_repos or repo in HUB_KNOWN


def judge_dockerhub(lines):
    """(verdict, why) from `docker events --format '{{json .}}'` lines."""
    pulls, creates, bad, n = [], [], 0, 0
    for l in lines:
        if not l.strip():
            continue
        try:
            e = json.loads(l)
            a = e.get("Actor") or {}
            attrs = a.get("Attributes") or {}
            typ, act = e.get("Type"), e.get("Action") or e.get("status")
            when = time.strftime("%H:%M:%S", time.gmtime(e.get("time") or 0))
            if typ == "image" and act == "pull":
                pulls.append((when, attrs.get("name") or a.get("ID") or e.get("id") or ""))
            elif typ == "container" and act == "create":
                creates.append((when, attrs.get("image") or "", attrs.get("name") or ""))
            n += 1
        except (ValueError, AttributeError):
            bad += 1
    if False:
        return "NOT JUDGED", "docker events recorded no event (%d unparseable line(s))" % bad
    pulled = {image_parts(r)[1] for _, r in pulls if is_hub_pull(r)}
    off = ["%s pull %s" % (t, r) for t, r in pulls if is_hub_pull(r)]
    off += ["%s create %s (container %s)" % (t, r, c) for t, r, c in creates if is_hub_container(r, pulled)]
    if off:
        return "FAIL", "%d Docker Hub image event(s): %s" % (len(off), "; ".join(off))
    by_reg, by_img = {}, {}
    for _, r in pulls:
        h = image_parts(r)[0] or "?"
        by_reg[h] = by_reg.get(h, 0) + 1
    for _, r, _c in creates:
        k = image_parts(r)[1] or "?"
        by_img[k] = by_img.get(k, 0) + 1
    fmt = lambda d: ", ".join("%s x%d" % kv for kv in sorted(d.items())) or "none"
    return "PASS", "no Docker Hub pull or container: %d pull(s) by registry [%s]; %d container create(s) by image [%s]" % (
        len(pulls), fmt(by_reg), len(creates), fmt(by_img))


def judge():
    out, j, me = os.environ["OUT"], os.environ["J"], os.environ["SELF"]
    lines, failed = [], False

    def say(aid, verdict, why, n=400):
        nonlocal failed
        failed |= verdict == "FAIL"
        lines.append("UPGRADE %s %s: %s" % (aid, verdict, one(why, n)))

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

        refused = []
        for src, body in (("--all", roll), ("--stack", stack or ""), ("journal", journal)):
            for l in body.splitlines():
                named = refusal(l)
                if named:
                    # the applier's refusal-name line (#1464): name and exit first
                    refused.append("noo-apply refusal=%s (exit %s) (%s: %s)" % (named + (src, l.strip())))
                elif "noo-apply: REFUSED" in l or "REFUSED release check:" in l:
                    refused.append("%s: %s" % (src, l.strip()))
        # Strict: the first roll's applier-only bootstrap refusal is NOT
        # exempt (general, 2026-11-18): rc.3 makes an applier-only bundle
        # equal to the installed applier a no-op, so any REFUSED line FAILs.
        say("A3", "FAIL" if refused else "PASS",
            " | ".join(refused[:2]) if refused else
            "no 'noo-apply: REFUSED' and no 'noo-apply: refusal=' in the --all roll, the --stack or the node's journal")

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
        for b in ("B1", "B2", "B3", "B4"):
            say(b, "NOT REACHED", "the same-tag --stack did not run")
    else:
        s1 = "installing noo-netns-restore.service: staged to the self-node"
        s2 = "noo-netns-restore.service installed and enabled by the self-node's applier"
        # Case-insensitive: the CLI's ui::step capitalises a step's first
        # letter ("> Installing …"), so rc.1's cell FAILed B1 on a pass.
        a, b = [l.strip() for l in stack.splitlines() if s1 in l.lower() and "whose applier installs it (no sudo)" in l], s2 in stack.lower()
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
        own = own_sudo_commands(os.environ.get("ROLL_T0", ""), os.environ.get("STACK_T0", ""),
                                os.environ.get("STACK_T1", ""))
        every = [l.strip() for l in sj.splitlines() if "COMMAND=" in l]
        cmds = [l for l in every if not is_own_sudo(l, own)]
        mine = len(every) - len(cmds)
        say("B3", "FAIL" if cmds else "PASS",
            ("%d sudo command(s) during the --stack: %s" % (len(cmds), cmds[0])) if cmds
            else "0 sudo commands in the journal during the same-tag --stack (operator: %s%s)"
            % (subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip(),
               "; %d of the cell's own, matched exactly, not counted" % mine if mine else ""))

        # B4: a plain `noo stack start` after the upgrade recreates nothing:
        # every container the upgrade made carries the start-inputs labels
        # (the release lead). Judged from the container IDs (recreated.py,
        # the parser of run.sh's start-idempotent), the launcher's lines say why.
        slog = text(os.path.join(out, "logs", "start-after-upgrade.log"))
        if slog is None:
            say("B4", "NOT REACHED", "no plain noo stack start after the upgrade")
        else:
            verdict, line = recreated.plain_start(
                "B4", recreated._read_or_empty(os.path.join(j, "start-after.before")),
                recreated._read_or_empty(os.path.join(j, "start-after.after")), slog,
                step_rc(out, "start-after-upgrade"))
            # every recreated container is named, each with its reason line
            say("B4", verdict, line.split(": ", 1)[1] if ": " in line else line, 4000)

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

    # ── the Docker daemon, across the new version's roll and plain start ──
    ev = text(os.path.join(out, "logs", "docker-events-upgrade.jsonl"))
    if ev is None or not ev.strip():
        err = one(text(os.path.join(out, "logs", "docker-events-upgrade.err")), 200)
        say("NO-DOCKERHUB", "NOT JUDGED", "no docker events were recorded (%s)%s"
            % ("file missing" if ev is None else "file empty", "; watcher said: " + err if err else ""), 600)
    else:
        v_, why = judge_dockerhub(ev.splitlines())
        say("NO-DOCKERHUB", v_, why, 4000)

    print("\n".join(lines))
    return 1 if failed else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["resolve"] and len(a) in (5, 6):
        resolve(*a[1:])
    elif a[:1] == ["before"] and len(a) == 3:
        before(*a[1:])
    elif a[:1] == ["judge"]:
        sys.exit(judge())
    else:
        sys.exit("usage: upgrade_judge.py resolve OWNER/REPO TAG PREV TARGET [PREV_TAG] | before VERIFY SELF | judge")
