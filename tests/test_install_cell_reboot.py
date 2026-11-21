# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The install matrix's REBOOT cell (scripts/install-cell/reboot.sh and reboot_judge.py).

The judge must read what the polls fetched (a judge that passes without
reading is the bug these exist for), and the script must never start the stack
before the judge file is written: the cell JUDGES that the stack comes back
with no command."""
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CELL = ROOT / "scripts" / "install-cell"
SCRIPT = CELL / "reboot.sh"


def _load():
    spec = importlib.util.spec_from_file_location("reboot_judge_t", CELL / "reboot_judge.py")
    m = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(CELL))
    spec.loader.exec_module(m)
    return m


J = _load()


def verify(*rows):
    return json.dumps({"controller": {"checks": [{"name": n, "id": i, "verdict": v} for n, i, v in rows]}})


CEIL = {"fail_rows_fail_the_cell": True, "fail_allowed": {}}


def test_verify_fails_on_a_fail_row_and_names_it():
    ok, msg = J.judge_verify(verify(("gateway", "gateway_up", "fail")), ceiling=CEIL, names={})
    assert not ok and "gateway_up" in msg


def test_verify_passes_with_warns_only_and_not_with_garbage():
    assert J.judge_verify(verify(("a", "a_row", "warn"), ("b", "b_row", "ok")), ceiling=CEIL, names={})[0]
    ok, msg = J.judge_verify("not json", ceiling=CEIL, names={})
    assert not ok and "NOT READ" in msg


def show(beat, status="online"):
    return json.dumps({"node": {"name": "n", "status": status, "last_heartbeat": beat}}, indent=1)


def test_agent_uses_last_heartbeat_after_the_reboot_command():
    ok, msg = J.judge_agent(show("2026-11-21T10:00:30Z"), 1_700_000_000 - 1)  # epoch 2023: far before
    assert ok and "source=cluster-show.last_heartbeat" in msg
    t0 = J.to_epoch("2026-11-21T10:00:00Z")
    ok, msg = J.judge_agent(show("2026-11-21T10:00:30.123456789Z"), t0)
    assert ok and "30s after" in msg
    ok, msg = J.judge_agent(show("2026-11-21T09:59:00+00:00"), t0)
    assert not ok and "not after the reboot" in msg


def test_a_stale_heartbeat_is_not_rescued_by_the_journal():
    t0 = J.to_epoch("2026-11-21T10:00:00Z")
    ok, _ = J.judge_agent(show("2026-11-21T09:59:00Z"), t0, "noo-node-agent: registered with controller")
    assert not ok


def test_agent_falls_back_to_the_journal_only_when_the_field_is_unreadable():
    ok, msg = J.judge_agent(show(None), 10, "Nov 21 agent[1]: registered with controller")
    assert ok and "source=journal" in msg
    ok, msg = J.judge_agent("garbage", 10, "")
    assert not ok and "no evidence" in msg


def test_epoch_forms():
    assert J.to_epoch(1_700_000_000) == 1_700_000_000
    assert J.to_epoch(1_700_000_000_000) == 1_700_000_000
    assert J.to_epoch("") is None and J.to_epoch("yesterday") is None and J.to_epoch(True) is None


def test_units():
    good = "noo-hostd system=inactive user=active\nnoo-node-agent system=active user=inactive\nnoo-netns-restore system=inactive user=inactive\n"
    assert J.judge_units(good)[0]
    ok, msg = J.judge_units(good.replace("user=active", "user=inactive"))
    assert not ok and "noo-hostd" in msg
    assert not J.judge_units("")[0]


def test_boot_restore():
    assert J.judge_bootrestore("")[0] == "SKIP"
    assert J.judge_bootrestore("noo-hostd[1]: boot-restore: done")[0] == "PASS"
    st, msg = J.judge_bootrestore("noo-hostd[1]: BOOT-RESTORE WARN: noo-nats still down (run `noo stack start`)\nx: boot-restore: done")
    assert st == "FAIL" and "noo-nats" in msg
    assert J.judge_bootrestore("BOOT-RESTORE gave up: run `noo stack start`")[0] == "FAIL"


def test_linger():
    assert J.judge_linger("system", "no", "u")[0] == "INFO"
    assert J.judge_linger("user", "yes", "u")[0] == "PASS"
    st, msg = J.judge_linger("user", "no", "alice")
    assert st == "FAIL" and "sudo loginctl enable-linger alice" in msg
    assert J.judge_linger("none", "yes", "u")[0] == "FAIL"


def rows(*r):
    return "".join("\t".join(x) + "\n" for x in r)


def test_judge_lines_and_exit(tmp_path):
    f = tmp_path / "rows.tsv"
    f.write_text(rows(("ssh-up", "PASS", "40", "up"), ("chat", "FAIL", "300", "no answer"), ("units", "SKIP", "", "x")))
    r = subprocess.run([sys.executable, str(CELL / "reboot_judge.py"), "judge", str(f), str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert r.returncode == 1
    txt = (tmp_path / "o" / "reboot.txt").read_text()
    assert "REBOOT ssh-up PASS 40 up\n" in txt and "REBOOT chat FAIL 300 no answer\n" in txt and "REBOOT units SKIP - x\n" in txt
    assert "FAIL: chat" in (tmp_path / "o" / "reboot.md").read_text()


def test_a_skip_is_neither_fail_nor_pass(tmp_path):
    f = tmp_path / "rows.tsv"
    f.write_text(rows(("kvm", "SKIP", "-", "no /dev/kvm on this runner")))
    r = subprocess.run([sys.executable, str(CELL / "reboot_judge.py"), "judge", str(f), str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert (tmp_path / "o" / "reboot.txt").read_text() == "REBOOT kvm SKIP - no /dev/kvm on this runner\n"
    assert "PASS" not in (tmp_path / "o" / "reboot.md").read_text().split("|---|")[0]


def test_diagnostic_pass_and_remedy_never_fail_the_cell(tmp_path):
    f = tmp_path / "rows.tsv"
    f.write_text(rows(("chat", "PASS", "9", "ok"), ("nolinger-gateway-healthy", "FAIL", "240", "x"),
                      ("remedy-stack-start", "FAIL", "5", "y")))
    r = subprocess.run([sys.executable, str(CELL / "reboot_judge.py"), "judge", str(f), str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert "DIAGNOSTIC" in (tmp_path / "o" / "reboot.md").read_text()


def test_a_bad_status_is_refused():
    try:
        J.read_rows("x\tMAYBE\t1\td\n")
    except ValueError:
        return
    raise AssertionError("an unknown status was accepted")


# ── the script ──────────────────────────────────────────────────────────────

def test_the_script_parses():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_no_stack_start_before_the_judge_is_written():
    text = SCRIPT.read_text()
    code = [l for l in text.splitlines() if not l.lstrip().startswith("#")]
    first_judge = next(i for i, l in enumerate(code) if l.startswith("step judge "))
    for i, l in enumerate(code[:first_judge]):
        assert not re.search(r"noo (stack|upgrade|onboard\b.*--only services)|\bstack start\b", l) or "gs onboard" in l or "gs onboard-model" in l, (i, l)
    assert any("noo stack start" in l for l in code[first_judge:]), "the remedy row is missing"


def test_polls_after_t0_are_read_only():
    text = SCRIPT.read_text()
    body = text[text.index("reboot_pass()"):text.index("# ── 5.")]
    for bad in ("stack start", "stack up", "noo upgrade", "noo onboard", "docker start", "docker compose up"):
        assert bad not in body, bad
