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
+ runner-a: installed the applier — staging the full bundle
+ stack v0.6.27-rc.9: images staged
  noo-netns-restore.service not installed: the self-node's applier (generation 1) predates the netns-unit kind, so no sudo is run for it
+ runner-a: bundle staged, applied
"""
STACK_OK = """\
> Installing noo-netns-restore.service: staged to the self-node runner-a, whose applier installs it (no sudo)
+ noo-netns-restore.service installed and enabled by the self-node's applier
"""
JOURNAL_OK = "Nov 18 noo-fetch[1]: noo-apply: applier-only bundle: this applier is already installed (sha256 ab12), nothing to install\nNov 18 noo-apply[1]: release-check: generation=2 release=none release-prev=none\nNov 18 noo-apply[1]: applied: agent-env agent-protect=6\n"


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


I1_STEPS_OK = [("i1-fetch", 0, ""), ("i1-reshape-self-node-by-hand-into-a-worker-env", 0, ""), ("i1-place", 0, ""), ("i1-wait", 0, "")]
I1_JOURNAL_OK = (
    'Nov 18 runner-a noo-node-agent[3]: {"level":"INFO","msg":"reconcile.ollama_import_start","model":"qwen2.5:0.5b","backend":"ollama"}\n'
    'Nov 18 runner-a noo-node-agent[3]: {"level":"INFO","msg":"ollama mirror import","model":"qwen2.5:0.5b","blobs":5,"via":"container","ollama":"https://noo-stunnel-ollama:11434"}\n'
    'Nov 18 runner-a noo-node-agent[3]: {"level":"INFO","msg":"ollama mirror imported","model":"qwen2.5:0.5b","via":"container"}\n')
I1_TAGS_OK = "NAME            ID              SIZE      MODIFIED\nqwen2.5:0.5b    a8b0c5157701    397 MB    5 seconds ago\n__rc=0\n"
I1_ROWS_OK = GOOD_SELF[:2] + [{"name": "ollama models", "verdict": "ok",
                               "detail": "verified against the controller: qwen2.5:0.5b (matches the controller's record of its pull, weights sha256:c5396e06af29…)"}]
# 0.6.27's own line: importMirror's fresh transport has no containerdial dial
I1_JOURNAL_0627 = I1_JOURNAL_OK.rsplit("Nov 18", 1)[0] + (
    'Nov 18 runner-a noo-node-agent[3]: {"time":"2026-11-18T10:02:11Z","level":"ERROR","msg":"reconcile.ollama_import_failed",'
    '"model":"qwen2.5:0.5b","backend":"ollama","error":"Head \\"https://noo-stunnel-ollama:11434/api/blobs/sha256:c5396e06af29\\": '
    'dial tcp: lookup noo-stunnel-ollama on 127.0.0.53:53: no such host","failures":1,"retry_after":"10m0s"}\n')


def cell(tmp, roll=ROLL_OK, stack=STACK_OK, journal=JOURNAL_OK, roll_rc="0", self_rows=None, ctl_rows=None,
         chat="ok\n", chat_rc=0, unit=True, sudo_journal="", unit_user=None, stack_journal=None, exec_start=None,
         i1=None):
    out, j, jr = tmp / "out", tmp / "out" / "judge", tmp / "raw"
    (out / "logs").mkdir(parents=True)
    j.mkdir()
    jr.mkdir()  # raw journals: outside the uploaded dir, as upgrade.sh keeps them
    if roll is not None:
        (out / "logs" / "upgrade-all.log").write_text(roll)
        (j / "roll.rc").write_text(roll_rc)
    if stack is not None:
        (out / "logs" / "upgrade-stack-same-tag.log").write_text(stack)
    (j / "target").write_text("noo-cli-v0.6.27-rc.9")
    (jr / "apply.journal").write_text(journal if stack_journal is None else journal + stack_journal)
    (jr / "roll-window.journal").write_text(journal)
    (jr / "node.journal").write_text("")
    (jr / "sudo-stack.journal").write_text(sudo_journal)
    v = verify(GOOD_SELF if self_rows is None else self_rows, GOOD_CTL if ctl_rows is None else ctl_rows)
    (j / "verify-after.json").write_text(v)
    (j / "verify-final.json").write_text(v)
    (out / "logs" / "chat-after.log").write_text(chat)
    (out / "steps.jsonl").write_text(json.dumps({"step": "chat-after", "rc": chat_rc}) + "\n")
    if i1 is not None:
        # I1's evidence, as upgrade.sh's step 6b writes it
        with open(out / "steps.jsonl", "a") as f:
            for name, rc, err in i1.get("steps", I1_STEPS_OK):
                f.write(json.dumps({"step": name, "rc": rc, "first_error": err, "tail": [err]}) + "\n")
        (j / "i1-model").write_text("qwen2.5:0.5b\n")
        (jr / "i1.journal").write_text(i1.get("journal", I1_JOURNAL_OK))
        (j / "i1-tags.txt").write_text(i1.get("tags", I1_TAGS_OK))
        (j / "verify-i1.json").write_text(verify(i1.get("rows", I1_ROWS_OK), GOOD_CTL))
    me = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
    env = dict(os.environ, OUT=str(out), J=str(j), JR=str(jr), SELF=SELF, NETNS_UNIT_ENABLED="enabled",
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
    for a in ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "B1", "B2", "B3", "G1", "G2", "G3", "G4", "G5"):
        assert " PASS: " in got[a], got[a]
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
    assert rc == 0 and " NOTE: " in got["G2"] and "noo models pull gemma4:e2b" in got["G2"], got["G2"]


def test_a_backend_start_refusal_or_a_used_lane_fails(tmp_path):
    rows = GOOD_SELF + [{"name": "backend starts", "verdict": "fail", "detail": "runner-a: llamacpp: model_missing: m.gguf"}]
    ctl = GOOD_CTL[:2] + [{"name": "legacy lanes", "verdict": "warn", "detail": "requests from a node with no node certificate were REFUSED 3 time(s)"}]
    rc, got = cell(tmp_path, self_rows=rows, ctl_rows=ctl)
    assert " FAIL: " in got["G3"] and "model_missing" in got["G3"], got["G3"]
    assert " FAIL: " in got["G4"] and "no node certificate" in got["G4"], got["G4"]


def test_a_roll_that_never_ran_is_not_reached(tmp_path):
    rc, got = cell(tmp_path, roll=None, stack=None)
    for a in ("A1", "A6", "B1", "B3"):
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


def test_rc2s_exit_75_bootstrap_fails_a8_and_rc3s_clean_handshake_passes(tmp_path):
    rc, got = cell(tmp_path, journal=JOURNAL_OK.split("\n", 1)[1],
                   roll=ROLL_OK + "! runner-a: the applier-only bundle reported exit 75 — staging the full bundle anyway\n")
    assert " FAIL: " in got["A8"] and "reported exit 75" in got["A8"], got["A8"]
    rc, got = cell(tmp_path / "b")
    assert " PASS: " in got["A8"] and "this applier is already installed" in got["A8"], got["A8"]


def test_a8_is_not_applicable_when_no_applier_only_bundle_was_staged(tmp_path):
    """A node that already reported an apply gets no applier-only bundle, so no handshake line (97)."""
    roll = ROLL_OK.replace("+ runner-a: installed the applier — staging the full bundle\n", "")
    rc, got = cell(tmp_path, roll=roll, journal=JOURNAL_OK.split("\n", 1)[1])
    assert " NOT APPLICABLE: " in got["A8"], got["A8"]


def test_a8_maps_the_three_cli_outcomes_one_to_one(tmp_path):
    """upgrade.rs: installed -> PASS (with the handshake), reported exit N -> FAIL, no report -> FAIL (97)."""
    base = ROLL_OK.replace("+ runner-a: installed the applier — staging the full bundle\n", "")
    rc, got = cell(tmp_path, roll=base + "! runner-a: no report for the applier — staging the full bundle without confirmation\n")
    assert " FAIL: " in got["A8"] and "staged but never reported" in got["A8"], got["A8"]
    rc, got = cell(tmp_path / "b", roll=base + "! runner-a: the applier-only bundle reported exit 76 — staging the full bundle anyway\n")
    assert " FAIL: " in got["A8"] and "reported exit 76" in got["A8"], got["A8"]
    rc, got = cell(tmp_path / "c", journal=JOURNAL_OK.split("\n", 1)[1])
    assert " FAIL: " in got["A8"] and "installed the applier" in got["A8"], "installed but no handshake line: " + got["A8"]


def test_b3_names_every_sudo_command_during_the_stack(tmp_path):
    sj = ("Nov 18 sudo[1]: runner : COMMAND=/usr/bin/tee /etc/systemd/system/noo-netns-restore.service\n"
          "Nov 18 sudo[2]: runner : COMMAND=/usr/bin/systemctl daemon-reload\n")
    rc, got = cell(tmp_path, sudo_journal=sj)
    assert " FAIL: 2 sudo command(s)" in got["B3"] and "/usr/bin/tee" in got["B3"] and "daemon-reload" in got["B3"], got["B3"]


def test_i1_passes_when_the_managed_ollama_serves_the_imported_tag_verified(tmp_path):
    rc, got = cell(tmp_path, i1={})
    assert rc == 0 and " PASS: " in got["I1"], got["I1"]
    assert "qwen2.5:0.5b a8b0c5157701 397" in got["I1"] and "verified against the controller: qwen2.5:0.5b (" in got["I1"], got["I1"]


def test_i1_fails_quoting_0627s_lookup_of_the_door_by_docker_name(tmp_path):
    """0.6.27 / 0.6.28-rc.1: importMirror's transport never got containerdial's dial."""
    rc, got = cell(tmp_path, i1={"journal": I1_JOURNAL_0627, "tags": "NAME ID SIZE MODIFIED\n__rc=0\n",
                                 "rows": GOOD_SELF[:2] + [{"name": "ollama models", "verdict": "warn", "detail": "qwen2.5:0.5b: could not be checked (not in this node's ollama)"}]})
    assert rc == 1 and " FAIL: the host-mode agent could not resolve the door by its docker name: " in got["I1"], got["I1"]
    assert "reconcile.ollama_import_failed" in got["I1"] and "lookup noo-stunnel-ollama on 127.0.0.53:53: no such host" in got["I1"], got["I1"]
    # systemd-resolved may answer a single-label name "server misbehaving": the lookup is the same defect
    j = I1_JOURNAL_0627.replace("no such host", "server misbehaving")
    rc, got = cell(tmp_path / "b", i1={"journal": j})
    assert " FAIL: " in got["I1"] and "lookup noo-stunnel-ollama on 127.0.0.53:53: server misbehaving" in got["I1"], got["I1"]


def test_i1_is_not_reached_when_a_prerequisite_command_failed_quoting_it(tmp_path):
    err = "x qwen2.5:0.5b: the registry answered 503 Service Unavailable"
    rc, got = cell(tmp_path, i1={"steps": [("i1-fetch", 0, ""), ("i1-reshape-self-node-by-hand-into-a-worker-env", 0, ""), ("i1-place", 1, err)],
                                 "journal": "", "tags": ""})
    assert " NOT REACHED: i1-place exited 1: " + err in got["I1"], got["I1"]
    rc, got = cell(tmp_path / "b")
    assert " NOT REACHED: the I1 step did not run" in got["I1"], got["I1"]


def test_i1_served_but_unverified_fails_and_the_probe_waits_until_the_evidence_decides(tmp_path):
    rows = GOOD_SELF[:2] + [{"name": "ollama models", "verdict": "warn", "detail": "qwen2.5:0.5b: unverified (no controller record); re-pull it through noo to verify it"}]
    rc, got = cell(tmp_path, i1={"rows": rows})
    assert " FAIL: qwen2.5:0.5b not imported within the wait: served by noo-ollama; ollama models: warn: " in got["I1"], got["I1"]
    d = tmp_path / "out" / "judge"
    env = dict(os.environ, J=str(d), JR=str(tmp_path / "raw"), SELF=SELF)
    r = subprocess.run([sys.executable, str(JUDGE), "i1-probe"], env=env, capture_output=True, text=True)
    assert r.stdout.startswith("PENDING: served=True verified=False"), r.stdout + r.stderr


def test_i1_says_it_reshaped_the_self_node_by_hand_on_every_verdict(tmp_path):
    """The release lead's condition (2026-11-19): I1 emulates a worker by
    emptying NOO_SELF_NODE and OLLAMA_URL in the self node's agent env, by
    hand, on a thrown-away runner; the step says so and every verdict names
    the limit, so a PASS is never read as a provisioned worker's."""
    limit = "[emulates a worker's env; not provisioned as one]"
    for case, i1 in (("pass", {}), ("fail", {"journal": I1_JOURNAL_0627}),
                     ("nr", {"steps": [("i1-fetch", 1, "x fetch failed")], "journal": "", "tags": ""})):
        _, got = cell(tmp_path / case, i1=i1)
        assert got["I1"].endswith(limit), (case, got["I1"])
    sh = (ROOT / "scripts/install-cell/upgrade.sh").read_text()
    assert "step i1-reshape-self-node-by-hand-into-a-worker-env " in sh
    assert "reshaped by hand into a worker" in sh and "NOO_SELF_NODE and OLLAMA_URL emptied" in sh
    # last: nothing after it but the judge, which reads captured files only
    tail = sh[sh.index("step i1-reshape-self-node-by-hand-into-a-worker-env"):]
    assert [l for l in tail.splitlines()[1:] if l.startswith("step ")] == ['step judge 120 -- python3 "$HERE/upgrade_judge.py" judge']
