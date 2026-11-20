# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The install matrix's UPGRADE cell judge (scripts/install-cell/upgrade_judge.py).

Each assert prints one `UPGRADE <id> PASS|FAIL|NOTE|NOT REACHED` line. These
tests feed the judge the outputs a real roll writes and check the verdict AND
that the evidence is the product's own line: a judge that passes without
reading what it judges is the bug these exist for.
"""
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
JUDGE = ROOT / "scripts" / "install-cell" / "upgrade_judge.py"
SELF = "runner-a"

ROLL_OK = """\
+ stack v0.6.27-rc.9: images staged
  noo-netns-restore.service not installed: the self-node's applier (generation 1) predates the netns-unit kind, so no sudo is run for it
+ runner-a: bundle staged, applied
"""
STACK_OK = """\
  installing noo-netns-restore.service: staged to the self-node runner-a, whose applier installs it (no sudo)
+ noo-netns-restore.service installed and enabled by the self-node's applier
"""
JOURNAL_OK = "Nov 18 noo-apply[1]: release-check: generation=2 release=none release-prev=none\nNov 18 noo-apply[1]: applied: agent-env agent-protect=6\n"


# The plain start after the upgrade (B4): recreated.py snapshots and the
# launcher's report (scripts/noo-start-inputs.py report_lines).
SNAP = "noo-gateway g1 gateway postgres:service_healthy:false\nnoo-nats n1 nats -\nnoo-postgres p1 postgres -\n"
START_OK = "> Starting the stack\n  Containers          3 running, 0 recreated\n+ stack up\n"
ROLL_T0, STACK_T0, STACK_T1 = "1763629700", "1763629900", "1763630100"


def verify(self_rows, ctl_rows):
    return json.dumps({"nodes": [{"node": SELF, "checks": self_rows}], "controller": {"checks": ctl_rows}})


GOOD_SELF = [
    {"name": "version", "verdict": "ok", "detail": "agent v0.6.27-rc.9 = controller"},
    {"name": "release check", "verdict": "ok", "detail": "root code installs only from a release-signed list on runner-a (floor none)"},
    {"name": "ollama models", "verdict": "ok", "detail": "verified against the controller: gemma4:e2b (matches the controller's record of its pull)"},
]
GOOD_CTL = [
    {"name": "agent protect", "verdict": "ok", "detail": "the node agent writes only where it must on runner-a (6 writable paths)"},
    {"name": "hf-cache hub owner", "verdict": "ok", "detail": "both owned by 999:987"},
    {"name": "legacy lanes", "verdict": "ok", "detail": "0 uses"},
]


def cell(tmp, roll=ROLL_OK, stack=STACK_OK, journal=JOURNAL_OK, roll_rc="0", self_rows=None, ctl_rows=None,
         chat="ok\n", chat_rc=0, unit=True, sudo_journal="", unit_user=None, stack_journal=None, exec_start=None,
         start_log=START_OK, start_rc=0, start_after=SNAP, events=None):
    out, j = tmp / "out", tmp / "out" / "judge"
    (out / "logs").mkdir(parents=True)
    j.mkdir()
    if roll is not None:
        (out / "logs" / "upgrade-all.log").write_text(roll)
        (j / "roll.rc").write_text(roll_rc)
    if stack is not None:
        (out / "logs" / "upgrade-stack-same-tag.log").write_text(stack)
    (j / "target").write_text("noo-cli-v0.6.27-rc.9")
    (j / "apply.journal").write_text(journal if stack_journal is None else journal + stack_journal)
    (j / "roll-window.journal").write_text(journal)
    (j / "node.journal").write_text("")
    (j / "sudo-stack.journal").write_text(sudo_journal)
    v = verify(GOOD_SELF if self_rows is None else self_rows, GOOD_CTL if ctl_rows is None else ctl_rows)
    (j / "verify-after.json").write_text(v)
    (j / "verify-final.json").write_text(v)
    (out / "logs" / "chat-after.log").write_text(chat)
    if events is not None:
        (out / "logs" / "docker-events-upgrade.jsonl").write_text(events)
    steps = [{"step": "chat-after", "rc": chat_rc}]
    if start_log is not None:
        (out / "logs" / "start-after-upgrade.log").write_text(start_log)
        (j / "start-after.before").write_text(SNAP)
        (j / "start-after.after").write_text(start_after)
        steps.insert(0, {"step": "start-after-upgrade", "rc": start_rc})
    (out / "steps.jsonl").write_text("".join(json.dumps(d) + "\n" for d in steps))
    me = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
    env = dict(os.environ, OUT=str(out), J=str(j), SELF=SELF, NETNS_UNIT_ENABLED="enabled",
               ROLL_T0=ROLL_T0, STACK_T0=STACK_T0, STACK_T1=STACK_T1,
               NETNS_UNIT_OWNER="%d:%d" % (os.getuid(), os.getgid()))
    u = tmp / "noo-netns-restore.service"
    if unit:
        u.write_text("[Service]\nUser=%s\nExecStart=%s\n" % (unit_user or me, exec_start or "/home/%s/.local/share/noo/noo-netns-restore.sh" % me))
        u.chmod(0o644)
    env["NETNS_UNIT"] = str(u)
    r = subprocess.run([sys.executable, str(JUDGE), "judge"], env=env, capture_output=True, text=True)
    return r.returncode, {l.split()[1]: l for l in r.stdout.splitlines() if l.startswith("UPGRADE ")}


def test_a_clean_first_roll_passes_every_assert(tmp_path):
    rc, got = cell(tmp_path)
    assert rc == 0, got
    for a in ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "B1", "B2", "B3", "B4", "G1", "G2", "G3", "G4", "G5"):
        assert " PASS" in got[a] and got[a].startswith("UPGRADE %s PASS" % a), got[a]
    assert "release-check: generation=2" in got["A2"]
    assert "generation 1) predates the netns-unit kind" in got["A5"]
    assert "staged to the self-node runner-a, whose applier installs it (no sudo)" in got["B1"]


def test_the_rc1_dind_stop_is_a_fail_quoting_it(tmp_path):
    roll = "x runner-a not staged — staging failed\n  Upgrade stopped at the nodes stage\n"
    rc, got = cell(tmp_path, roll=roll, roll_rc="1")
    assert rc == 1
    assert " FAIL: " in got["A1"] and "Upgrade stopped at the nodes stage" in got["A1"], got["A1"]


def test_an_old_applier_or_no_release_check_line_fails_a2(tmp_path):
    rc, got = cell(tmp_path, journal="noo-apply[1]: release-check: generation=1 release=none\n")
    assert " FAIL: " in got["A2"] and "generation=1" in got["A2"], got["A2"]
    rc, got = cell(tmp_path / "b", journal="noo-apply[1]: applied: agent-env\n")
    assert " FAIL: " in got["A2"] and "no 'release-check:' line" in got["A2"], got["A2"]


def test_a_refused_line_anywhere_fails_a3(tmp_path):
    j = JOURNAL_OK + "noo-apply[1]: noo-apply: REFUSED applier — not in the release list; run noo upgrade --all (75)\n"
    rc, got = cell(tmp_path, journal=j)
    assert rc == 1 and " FAIL: " in got["A3"] and "noo-apply: REFUSED applier" in got["A3"], got["A3"]


def test_a_release_check_warn_naming_an_old_applier_fails_a4(tmp_path):
    rows = [GOOD_SELF[0], dict(GOOD_SELF[1], verdict="warn", detail="NOT yet on runner-a: their applier predates the check"), GOOD_SELF[2]]
    rc, got = cell(tmp_path, self_rows=rows)
    assert " FAIL: " in got["A4"] and "NOT yet on runner-a" in got["A4"], got["A4"]


def test_a_sudo_on_the_netns_unit_fails_a5_and_b3(tmp_path):
    roll = ROLL_OK.replace("so no sudo is run for it", "so no sudo is run for it") + "  sudo tee /etc/systemd/system/noo-netns-restore.service\n"
    rc, got = cell(tmp_path, roll=roll, sudo_journal="Nov 18 sudo[9]: runner : COMMAND=/usr/bin/tee /etc/systemd/system/noo-netns-restore.service\n")
    assert " FAIL: " in got["A5"] and "sudo tee" in got["A5"], got["A5"]
    assert " FAIL: " in got["B3"] and "COMMAND=/usr/bin/tee" in got["B3"], got["B3"]


def test_an_unheld_agent_fails_a6(tmp_path):
    ctl = [dict(GOOD_CTL[0], verdict="warn", detail="no hold reported on runner-a (installed by onboard, or never applied)")] + GOOD_CTL[1:]
    rc, got = cell(tmp_path, ctl_rows=ctl)
    assert " FAIL: " in got["A6"] and "no hold reported on runner-a" in got["A6"], got["A6"]


def test_the_netns_unit_must_be_the_install_owners(tmp_path):
    rc, got = cell(tmp_path, unit_user="root")
    assert " FAIL: " in got["B2"] and "User=root" in got["B2"], got["B2"]
    rc, got = cell(tmp_path / "b", unit=False)
    assert " FAIL: " in got["B2"], got["B2"]


def test_a_model_pulled_before_the_record_existed_is_a_note_not_a_fail(tmp_path):
    rows = GOOD_SELF[:2] + [{"name": "ollama models", "verdict": "warn", "remedy": "on runner-a: noo models pull gemma4:e2b",
                           "detail": "gemma4:e2b: unverified (no controller record); re-pull it through noo to verify it"}]
    rc, got = cell(tmp_path, self_rows=rows)
    assert rc == 0 and " NOTE" in got["G2"] and "noo models pull gemma4:e2b" in got["G2"], got["G2"]


def test_a_model_not_yet_checked_is_a_note_not_a_pass(tmp_path):
    # i1067: right after the roll the agent lists a held model as pending;
    # the row is OK, but nothing about the bytes is proven yet.
    rows = GOOD_SELF[:2] + [{"name": "ollama models", "verdict": "ok", "detail": "gemma4:e2b: not yet checked"}]
    rc, got = cell(tmp_path, self_rows=rows)
    assert rc == 0 and " NOTE" in got["G2"] and "gemma4:e2b: not yet checked" in got["G2"], got["G2"]


def test_a_backend_start_refusal_or_a_used_lane_fails(tmp_path):
    rows = GOOD_SELF + [{"name": "backend starts", "verdict": "fail", "detail": "runner-a: llamacpp: model_missing: m.gguf"}]
    ctl = GOOD_CTL[:2] + [{"name": "legacy lanes", "verdict": "warn", "detail": "requests from a node with no node certificate were REFUSED 3 time(s)"}]
    rc, got = cell(tmp_path, self_rows=rows, ctl_rows=ctl)
    assert " FAIL: " in got["G3"] and "model_missing" in got["G3"], got["G3"]
    assert " FAIL: " in got["G4"] and "no node certificate" in got["G4"], got["G4"]


def test_a_roll_that_never_ran_is_not_reached(tmp_path):
    rc, got = cell(tmp_path, roll=None, stack=None)
    for a in ("A1", "A6", "B1", "B3", "B4"):
        assert " NOT REACHED: " in got[a], got[a]


def test_no_chat_answer_after_the_upgrade_fails_g5(tmp_path):
    rc, got = cell(tmp_path, chat="Error: no chat backend is ready\n", chat_rc=1)
    assert " FAIL: " in got["G5"] and "no chat backend" in got["G5"], got["G5"]


def test_a2_judges_the_all_window_only_never_the_later_stack(tmp_path):
    """--all left the old applier; only the same-tag --stack's apply logged
    generation=2. A2 must FAIL: that is the first-roll failure (97)."""
    rc, got = cell(tmp_path, journal="noo-fetch[1]: release-check: generation=1 release=none\n",
                   stack_journal="noo-fetch[2]: release-check: generation=2 release=none release-prev=none\n")
    assert " FAIL: " in got["A2"] and "generation=1" in got["A2"], got["A2"]


def test_a3_names_the_step_a_refusal_came_from(tmp_path):
    stack = STACK_OK + "noo-apply: REFUSED netns-unit — not in the release list; run noo upgrade --all (75)\n"
    rc, got = cell(tmp_path, stack=stack)
    assert " FAIL: " in got["A3"] and "--stack: noo-apply: REFUSED netns-unit" in got["A3"], got["A3"]


def test_b2_accepts_the_script_run_through_bash_with_a_quoted_path(tmp_path):
    """rc.2's real unit: ExecStart=/bin/bash "/home/runner/.noo/scripts/noo-netns-restore.sh"."""
    rc, got = cell(tmp_path, exec_start='/bin/bash "/home/runner/.noo/scripts/noo-netns-restore.sh"')
    assert " PASS: " in got["B2"], got["B2"]
    rc, got = cell(tmp_path / "b", exec_start="/bin/bash /home/runner/other.sh")
    assert " FAIL: " in got["B2"] and "ExecStart=" in got["B2"], got["B2"]


def test_an_ok_row_that_judged_nothing_is_a_note_not_a_pass(tmp_path):
    """rc.2's run: hf-cache hub owner `ok` with "... not judged" (the self agent was offline)."""
    ctl = GOOD_CTL[:1] + [{"name": "hf-cache hub owner", "verdict": "ok",
                           "detail": "cannot tell which HF cache the self-node agent uses (no self node in the gateway's node list): not judged"}] + GOOD_CTL[2:]
    rc, got = cell(tmp_path, ctl_rows=ctl)
    assert " NOTE: " in got["G1"] and "not judged" in got["G1"], got["G1"]


def test_the_self_agent_cut_off_after_the_roll_fails_a7(tmp_path):
    """rc.2's real outcome: the rail rendered the self node's env with the literal
    noo-controller; the new agent never heartbeated."""
    j = JOURNAL_OK + 'noo-node-agent[2]: {"level":"ERROR","msg":"registration error","error":"dial tcp: lookup noo-controller on 127.0.0.53:53: server misbehaving"}\n'
    rows = [{"name": "version", "verdict": "starting", "detail": "restarting after the upgrade 51s ago (no parsable agent version (-))"}] + GOOD_SELF[1:]
    rc, got = cell(tmp_path, journal=j, self_rows=rows,
                   roll=ROLL_OK + "! runner-a: no heartbeat from the new build within 75s — judging the last record it sent\n")
    assert rc == 1 and " FAIL: " in got["A7"] and "lookup noo-controller" in got["A7"], got["A7"]


def test_the_first_roll_bootstrap_refusal_still_fails_a3(tmp_path):
    """Strict by decision: rc.2's applier-only 75 is a known FAIL until rc.3 makes it a no-op."""
    j = JOURNAL_OK + "noo-apply[1]: REFUSED release check: applier — the bundle carries root code but no release-signed list (release-sums)\n"
    rc, got = cell(tmp_path, journal=j, roll=ROLL_OK + "! runner-a: the applier-only bundle reported exit 75 — staging the full bundle anyway\n")
    assert " FAIL: " in got["A3"] and "no release-signed list" in got["A3"], got["A3"]


def test_b1_matches_the_cli_s_capitalised_step_line(tmp_path):
    """0.6.29-rc.1's cell: ui::step capitalises a step's first letter, so the
    same-tag --stack printed "> Installing …" and B1 FAILed on a pass."""
    stack = ("> Installing noo-netns-restore.service: staged to the self-node runner-a, whose applier installs it (no sudo)\n"
             "+ noo-netns-restore.service installed and enabled by the self-node's applier\n")
    rc, got = cell(tmp_path, stack=stack)  # ONLY the capitalised line, as rc.1 printed it
    assert " PASS: " in got["B1"], got["B1"]
    assert "staged to the self-node runner-a" in got["B1"]


# ── B3: the cell's own sudos, by exact command (0.6.26 -> rc.1, run 44706791256) ──
def _sudo(cmd):
    return "Nov 20 09:08:38 host sudo[9]:   runner : PWD=/home/runner ; USER=root ; COMMAND=%s\n" % cmd


CELL_OWN = [
    "/usr/bin/journalctl --no-pager --since @" + ROLL_T0,
    "/usr/bin/rm -f /etc/systemd/system/noo-netns-restore.service",
    "/usr/bin/systemctl daemon-reload",
]


def test_b3_ignores_the_cells_own_three_sudos_by_exact_command(tmp_path):
    """run 44706791256: the roll-window journalctl, the unit removal and its
    daemon-reload landed in STACK_T0's second and failed B3."""
    rc, got = cell(tmp_path, sudo_journal="".join(_sudo(c) for c in CELL_OWN))
    assert rc == 0 and " PASS: " in got["B3"] and "3 of the cell's own" in got["B3"], got["B3"]
    # the other exact journalctl invocations upgrade.sh makes next to the window
    more = ["/usr/bin/journalctl -t noo-apply --no-pager --since @" + ROLL_T0,
            "/usr/bin/journalctl _COMM=sudo --no-pager --since @%s --until @%s" % (STACK_T0, STACK_T1)]
    rc, got = cell(tmp_path / "b", sudo_journal="".join(_sudo(c) for c in more))
    assert " PASS: " in got["B3"], got["B3"]


def test_b3_still_fails_a_product_sudo_of_the_same_command_names(tmp_path):
    for i, cmd in enumerate(["/usr/bin/journalctl -u noo-node-agent",
                             "/usr/bin/systemctl restart docker",
                             "/usr/bin/journalctl --no-pager --since @1763629701",
                             "/usr/bin/rm -f /etc/systemd/system/noo-netns-restore.service.d",
                             "/tmp/x/systemctl daemon-reload"]):
        rc, got = cell(tmp_path / str(i), sudo_journal="".join(_sudo(c) for c in CELL_OWN) + _sudo(cmd))
        assert rc == 1 and " FAIL: " in got["B3"] and "1 sudo command(s)" in got["B3"] and cmd in got["B3"], got["B3"]


def test_upgrade_sh_sleeps_before_stack_t0_and_passes_the_window_to_the_judge():
    text = (JUDGE.parent / "upgrade.sh").read_text()
    rm = text.index("sudo -n rm -f /etc/systemd/system/noo-netns-restore.service && sudo -n systemctl daemon-reload")
    t0 = text.index('STACK_T0="$(date +%s)"')
    assert rm < text.index("sleep 1", rm) < t0
    assert 'sudo -n journalctl --no-pager --since "@$ROLL_T0"' in text[:rm], "the roll-window capture B3 ignores"
    assert "export J SELF ROLL_T0 STACK_T0 STACK_T1 OUT" in text


# ── A3: the applier's refusal-name line (#1464) ─────────────────────────────
def test_a3_fails_on_the_applier_refusal_name_line_naming_it(tmp_path):
    j = JOURNAL_OK + "Nov 20 09:08:38 host noo-fetch[123]: noo-apply: refusal=bundle_decrypt_failed (exit 65)\n"
    rc, got = cell(tmp_path, journal=j)
    assert rc == 1 and "A3 FAIL: noo-apply refusal=bundle_decrypt_failed (exit 65)" in got["A3"], got["A3"]
    rc, got = cell(tmp_path / "b", stack=STACK_OK + "noo-apply: refusal=bundle_decrypt_io (exit 73)\n")
    assert rc == 1 and "A3 FAIL: noo-apply refusal=bundle_decrypt_io (exit 73)" in got["A3"], got["A3"]


def test_a3_counts_only_the_exact_refusal_line(tmp_path):
    for i, line in enumerate(["Nov 20 09:08:38 host noo-fetch[123]: noo-apply: refusal=Bad Name (exit 65)",
                              "Nov 20 09:08:38 host noo-fetch[123]: noo-apply: refusal=bundle_decrypt_failed (exit 65) later",
                              "Nov 20 09:08:38 host noo-fetch[123]: noo-apply: refusal=bundle_decrypt_failed"]):
        rc, got = cell(tmp_path / str(i), journal=JOURNAL_OK + line + "\n")
        assert rc == 0 and " PASS: " in got["A3"], (line, got["A3"])
    rc, got = cell(tmp_path / "none")
    assert " PASS: " in got["A3"], got["A3"]


# ── B4: a plain start after the upgrade recreates nothing ───────────────────
def test_b4_passes_on_0_recreated(tmp_path):
    rc, got = cell(tmp_path)
    assert rc == 0 and got["B4"].startswith("UPGRADE B4 PASS: 0 containers recreated"), got["B4"]
    assert "3 running, 0 recreated" in got["B4"], got["B4"]


def test_b4_fails_naming_each_recreated_container_with_its_reason(tmp_path):
    after = SNAP.replace(" g1 ", " g2 ").replace(" n1 ", " n2 ")
    log = ("  Containers          3 running, 2 recreated\n"
           "    recreated gateway: its compose config or image changed\n"
           "    recreated nats: its inputs changed (config monitoring/nats/users.conf)\n")
    rc, got = cell(tmp_path, start_log=log, start_after=after)
    assert rc == 1 and " FAIL: 2 recreated: noo-gateway, noo-nats" in got["B4"], got["B4"]
    assert "noo-gateway (recreated gateway: its compose config or image changed)" in got["B4"], got["B4"]
    assert "noo-nats (recreated nats: its inputs changed (config monitoring/nats/users.conf))" in got["B4"], got["B4"]


def test_b4_fails_when_the_start_step_failed(tmp_path):
    rc, got = cell(tmp_path, start_log="x the stack did not start: noo-gateway unhealthy\n", start_rc=1)
    assert rc == 1 and " FAIL: noo stack start exited 1: x the stack did not start" in got["B4"], got["B4"]


def test_upgrade_sh_runs_the_plain_start_after_the_stack_and_before_chat():
    text = (JUDGE.parent / "upgrade.sh").read_text()
    t1, start, chat = (text.index('STACK_T1="$(date +%s)"'), text.index("step start-after-upgrade "),
                       text.index("step chat-after "))
    assert t1 < start < chat
    body = text[start:chat]
    assert '"$HERE/recreated.py" "$J"' in body and "noo stack start; rc=$?" in body
    assert 'snap "$2/start-after.before"' in body and 'snap "$2/start-after.after"' in body


# ── NO-DOCKERHUB: the daemon touches no Docker Hub image ────────────────────
sys.path.insert(0, str(JUDGE.parent))
import upgrade_judge as uj  # noqa: E402

DIGEST = "@sha256:" + "a" * 64


def ev(typ, act, t=1763629800, **attrs):
    """The minimal shape upgrade.sh captures (an image event's id is its ref)."""
    return json.dumps({"time": t, "type": typ, "action": act, "id": attrs.get("name", "") if typ == "image" else "abc123",
                       "image": attrs.get("image", ""), "name": attrs.get("name", "")}) + "\n"


def ev_full(typ, act, t=1763629800, **attrs):
    """The old full `{{json .}}` shape, still read."""
    a = {"Attributes": attrs}
    if typ == "image":
        a["ID"] = attrs.get("name", "")
    return json.dumps({"Type": typ, "Action": act, "time": t, "Actor": a}) + "\n"


def test_image_registry_classification():
    hub = ["alpine:latest", "alpine", "library/alpine", "docker.io/library/alpine", "index.docker.io/library/alpine:3",
           "registry-1.docker.io/x/y", "noomesh/stunnel:latest", "vllm/vllm-openai:v0.25.0" + DIGEST]
    for r in hub:
        assert uj.is_hub_pull(r), r
    for r in ["ghcr.io/x/y" + DIGEST, "localhost/x", "localhost:5000/x/y:1", "quay.io/a/b:1", "registry.example.com:443/a"]:
        assert not uj.is_hub_pull(r), r
    assert uj.image_parts("docker.io/library/alpine:3") == ("docker.io", "alpine")
    assert uj.image_parts("ghcr.io/x/y" + DIGEST) == ("ghcr.io", "x/y")
    assert uj.image_parts("localhost:5000/x/y:1") == ("localhost:5000", "x/y")
    assert uj.image_parts("sha256:" + "b" * 64) == (None, "sha256:" + "b" * 64)


def test_a_container_is_hub_only_if_pulled_known_or_spelled():
    # locally built, never pulled: bare names that must not fail
    for r in ("noo-sandbox-base:latest", "noo-browser:latest", "localhost/x", "sha256:" + "c" * 64):
        assert not uj.is_hub_container(r, set()), r
    # the well-known Hub names, however spelled
    for r in ("alpine", "alpine:latest", "library/alpine", "docker.io/library/alpine", "busybox", "ubuntu:24.04"):
        assert uj.is_hub_container(r, set()), r
    # a bare org/name is Hub only when it was pulled in the window
    assert not uj.is_hub_container("noomesh/stunnel:latest", set())
    assert uj.is_hub_container("noomesh/stunnel:latest", {"noomesh/stunnel"})
    assert not uj.is_hub_container("ghcr.io/x/y" + DIGEST, {"x/y"})


def test_no_dockerhub_passes_with_counts(tmp_path):
    e = (ev("image", "pull", name="ghcr.io/x/y") + ev("container", "create", image="ghcr.io/x/y" + DIGEST, name="g")
         + ev("container", "create", image="noo-browser:latest", name="b") + ev("container", "start", image="alpine"))
    rc, got = cell(tmp_path, events=e)
    assert " PASS: " in got["NO-DOCKERHUB"], got["NO-DOCKERHUB"]
    assert "1 pull(s) by registry [ghcr.io x1]" in got["NO-DOCKERHUB"] and "2 container create(s)" in got["NO-DOCKERHUB"]
    assert "noo-browser x1" in got["NO-DOCKERHUB"] and "x/y x1" in got["NO-DOCKERHUB"], got["NO-DOCKERHUB"]


def test_no_dockerhub_fails_naming_a_hub_pull_and_an_alpine_create(tmp_path):
    e = ev("image", "pull", t=1763629801, name="noomesh/stunnel:latest") + ev("container", "create", t=1763629802, image="alpine", name="chgrp")
    rc, got = cell(tmp_path, events=e)
    g = got["NO-DOCKERHUB"]
    assert rc == 1 and " FAIL: " in g and "2 Docker Hub image event(s)" in g, g
    assert "pull noomesh/stunnel:latest" in g and "create alpine (container chgrp)" in g and ":" in g.split("FAIL:")[1], g


def test_no_dockerhub_not_judged_without_events(tmp_path):
    rc, got = cell(tmp_path)
    assert " NOT JUDGED: " in got["NO-DOCKERHUB"] and "file missing" in got["NO-DOCKERHUB"], got["NO-DOCKERHUB"]
    rc, got = cell(tmp_path / "b", events="")
    assert " NOT JUDGED: " in got["NO-DOCKERHUB"] and "file empty" in got["NO-DOCKERHUB"], got["NO-DOCKERHUB"]
    rc, got = cell(tmp_path / "c", events="not json\n")
    assert " NOT JUDGED: " in got["NO-DOCKERHUB"] and "1 unparseable" in got["NO-DOCKERHUB"], got["NO-DOCKERHUB"]


def test_upgrade_sh_watches_docker_across_the_roll_and_plain_start_only():
    text = (JUDGE.parent / "upgrade.sh").read_text()
    start, roll = text.index("$DOCKER events --format '"), text.index('ROLL_T0="$(date +%s)"')
    stop, chat = text.index('kill "$EVENTS_PID"'), text.index("step chat-after ")
    assert text.index("step before-roll") < start < roll
    assert text.index("step start-after-upgrade ") < stop < chat
    assert "logs/docker-events-upgrade.jsonl" in text and "pkill" not in text


# ── the evidence a judged FAIL arrives with ─────────────────────────────────
def test_the_upload_covers_every_step_log_the_verify_jsons_and_the_agent_journal():
    sh = (JUDGE.parent / "upgrade.sh").read_text()
    wf = (ROOT / ".github" / "workflows" / "install-matrix.yml").read_text()
    job = wf[wf.index("\n  upgrade:\n"):wf.index("\n  size:\n")]
    # the workflow uploads the whole of OUT, and OUT is that same directory
    assert "OUT: ${{ runner.temp }}/cell\n" in job
    assert "path: ${{ runner.temp }}/cell/\n" in job and "if: always()" in job
    # step logs: lib.sh's step() keeps logs/<step>.log under OUT
    assert 'local log="$OUT/logs/$name.log"' in (JUDGE.parent / "lib.sh").read_text()
    # the judge's work dir is inside OUT, and holds every verify JSON the judge reads
    assert 'J="$OUT/judge"' in sh
    for name in ("verify-before.json", "verify-after.json", "verify-final.json"):
        assert '"$J/%s"' % name in sh or '"$2/%s"' % name in sh, name
    # the agent's journal around the roll, as a redacted step in logs/
    i = sh.index("step agent-state-after-roll ")
    assert 'journalctl -u noo-node-agent --no-pager --since "@$1"' in sh[i:i + 600]
    assert i > sh.index("step upgrade-all ") and i < sh.index("step remove-netns-unit "), "inside the roll, before B3's window"
    # the redacted journals the judge reads
    for name in ("roll-window.journal", "apply.journal", "node.journal"):
        assert '"$J/%s"' % name in sh, name


def test_the_scan_runs_over_the_whole_upload_and_withholds_it_on_a_hit():
    sh = (JUDGE.parent / "upgrade.sh").read_text()
    fin = sh[sh.index("finish() {"):sh.index("# ── 1.")]
    assert 'python3 "$CELL_PY" scan "$OUT"' in fin, "the scan covers logs/, judge/ and the agent step"
    assert 'rm -rf "$OUT/logs" "$OUT/judge"' in fin


# ── G2 waits for the row (the agent's first pass after a restart) ───────────
def _g2(tmp_path, first, later, bound="360"):
    """Judge with `first` as the final verify; `later` are the verifies a fake
    `noo` returns on each re-run (the last repeats)."""
    out, j = tmp_path / "out", tmp_path / "out" / "judge"
    (out / "logs").mkdir(parents=True)
    j.mkdir()
    (j / "verify-final.json").write_text(first)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for i, b in enumerate(later):
        (bindir / ("v%d" % i)).write_text(b)
    (bindir / "noo").write_text('#!/bin/sh\nd="%s"; n=$(cat "$d/n" 2>/dev/null || echo 0)\n'
                                '[ -f "$d/v$n" ] || n=%d\necho $((n+1)) > "$d/n"; cat "$d/v$n"\n' % (bindir, len(later) - 1))
    (bindir / "noo").chmod(0o755)
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]), G2_SLEEP="0")
    r = subprocess.run([sys.executable, str(JUDGE), "g2wait", str(out), str(j), SELF, "30", bound], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return out, j


def _g2_judged(out, j, tmp_path):
    # judge the wait file with the normal fixture around it
    rc, got = cell(tmp_path / "judged")
    return got


def _g2_line(tmp_path, first, later, bound="360"):
    out, j = _g2(tmp_path / "w", first, later, bound)
    jd = tmp_path / "j"
    rc, _ = cell(jd)
    jdir = jd / "out" / "judge"
    (jdir / "verify-final.json").write_text((j / "verify-final.json").read_text())
    (jdir / "verify-after.json").write_text((j / "verify-final.json").read_text())
    (jdir / "g2.wait").write_text((j / "g2.wait").read_text())
    env = dict(os.environ, OUT=str(jd / "out"), J=str(jdir), SELF=SELF, NETNS_UNIT_ENABLED="enabled", ROLL_T0=ROLL_T0,
               STACK_T0=STACK_T0, STACK_T1=STACK_T1, NETNS_UNIT=str(jd / "noo-netns-restore.service"),
               NETNS_UNIT_OWNER="%d:%d" % (os.getuid(), os.getgid()))
    r = subprocess.run([sys.executable, str(JUDGE), "judge"], env=env, capture_output=True, text=True)
    return next(l for l in r.stdout.splitlines() if l.startswith("UPGRADE G2 ")), out, j


NO_OM = verify([r for r in GOOD_SELF if r["name"] != "ollama models"], GOOD_CTL)
YES_OM = verify(GOOD_SELF, GOOD_CTL)


def test_g2_present_at_once_passes_after_0_s_1_try(tmp_path):
    line, out, j = _g2_line(tmp_path, YES_OM, [NO_OM])
    assert line.startswith("UPGRADE G2 PASS (after 0 s, 1 try): verified against the controller"), line
    assert (out / "logs" / "verify-g2-1.json").exists() and not (out / "logs" / "verify-g2-2.json").exists()


def test_g2_absent_then_present_passes_with_the_wait(tmp_path):
    line, out, j = _g2_line(tmp_path, NO_OM, [NO_OM, YES_OM])
    assert line.startswith("UPGRADE G2 PASS (after 0 s, 3 tries): verified against the controller"), line
    assert [(out / "logs" / ("verify-g2-%d.json" % n)).exists() for n in (1, 2, 3, 4)] == [True, True, True, False]


def test_g2_absent_past_the_bound_fails_with_the_wait(tmp_path):
    line, out, j = _g2_line(tmp_path, NO_OM, [NO_OM])
    assert line.startswith("UPGRADE G2 FAIL (still absent after 0 s, 13 tries): no 'ollama models' row"), line
    assert (out / "logs" / "verify-g2-13.json").exists() and not (out / "logs" / "verify-g2-14.json").exists()


def test_g2_not_yet_checked_is_pending_too(tmp_path):
    pend = [dict(r, detail="gemma4:e2b not yet checked") if r["name"] == "ollama models" else r for r in GOOD_SELF]
    line, out, j = _g2_line(tmp_path, verify(pend, GOOD_CTL), [YES_OM])
    assert line.startswith("UPGRADE G2 PASS (after 0 s, 2 tries)"), line


def test_upgrade_sh_waits_for_g2_after_the_final_verify():
    sh = (JUDGE.parent / "upgrade.sh").read_text()
    i = sh.index('noo --json cluster verify > "$J/verify-final.json"')
    assert 'upgrade_judge.py" g2wait "$OUT" "$J" "$SELF" 30 360' in sh[i:i + 700]
    assert i < sh.index("step judge ")


# ── the docker events capture: minimal fields, scan-clean ───────────────────
def test_the_events_capture_names_no_field_beyond_the_six():
    import re
    sh = (JUDGE.parent / "upgrade.sh").read_text()
    m = re.search(r"\$DOCKER events --format '([^']*)'", sh)
    assert m, "the capture format"
    fmt = m.group(1)
    assert fmt != "{{json .}}" and "{{json .}}" not in fmt
    assert re.findall(r'"(\w+)":', fmt) == ["time", "type", "action", "id", "image", "name"]
    # every template action reads one of those fields only
    acts = re.findall(r"\{\{(.*?)\}\}", fmt)
    assert [a.replace("json ", "").strip("()") for a in acts] == [
        ".Time", ".Type", ".Action", ".Actor.ID", 'index .Actor.Attributes "image"', 'index .Actor.Attributes "name"']


def test_a_minimal_events_file_passes_the_upload_scan(tmp_path):
    # a label-heavy container create as `{{json .}}` prints it: compose hashes,
    # our start inputs, and KEY=value strings inside label values
    attrs = {"com.docker.compose.config-hash": "9" * 64, "noo.inputs": "NOO_X_KEY=abc123def456 NOO_MODE=full",
             "org.opencontainers.image.description": "build ARG SIGNING_KEY=zz99yy88xx",
             "image": "ghcr.io/x/y" + DIGEST, "name": "noo-gateway"}
    full = json.dumps({"Type": "container", "Action": "create", "time": 1763629802, "Actor": {"ID": "abc", "Attributes": attrs}})
    sys.path.insert(0, str(JUDGE.parent))
    import cell as cellpy
    assert cellpy.secret_hits(full), "the full event is what the scan refused"
    f = tmp_path / "logs" / "docker-events-upgrade.jsonl"
    f.parent.mkdir()
    f.write_text(ev("image", "pull", name="ghcr.io/x/y:1") + ev("container", "create", image="ghcr.io/x/y" + DIGEST, name="noo-gateway")
                 + ev("container", "start", image="ghcr.io/x/y" + DIGEST, name="noo-gateway"))
    assert cellpy.cmd_scan([str(tmp_path)]) == 0
    assert uj.judge_dockerhub(f.read_text().splitlines())[0] == "PASS"


def test_no_dockerhub_still_reads_the_old_full_shape(tmp_path):
    e = ev_full("image", "pull", name="noomesh/stunnel:latest") + ev_full("container", "create", image="alpine", name="chgrp")
    assert uj.judge_dockerhub(e.splitlines())[0] == "FAIL"
