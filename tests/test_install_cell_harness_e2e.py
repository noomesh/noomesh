# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""HARNESS-E2E's decision (scripts/install-cell/harness_e2e.py `verdict`), from
fixture evidence: the judge reads honestly, whatever a cell did."""
from __future__ import annotations

import copy
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "install-cell"))
import harness_e2e as he  # noqa: E402

GOOD = {
    "systemd": True, "systemd_run": True, "machine": "x86_64",
    "node": "cell-a", "apply_msg": "noo-apply: applied: harness-env harness-binary harness-unit harness-egress=enforced",
    "harness_state": "running",
    "egress": {"state": "enforced", "resolver": "unit", "pid_match": True,
               "ip_deny": "0.0.0.0/0 ::/0", "ip_allow": "127.0.0.1/32 ::1/128"},
    "want_allow": ["127.0.0.1/32", "::1/128"],
    "unit_deny": "0.0.0.0/0 ::/0", "unit_allow": "::1/128 127.0.0.1/32",
    "cgroup": "/system.slice/noo-harness.service",
    "turn_status": 200, "in_flight": True, "probe_rc": 124, "probe_err": "", "control_rc": 0,
    "gateway_log_unreadable": "", "dispatched": 1, "fallback": [],
}


def with_(**kw):
    e = copy.deepcopy(GOOD)
    for k, v in kw.items():
        if k.startswith("egress_"):
            e["egress"][k[len("egress_"):]] = v
        else:
            e[k] = v
    return e


def state(e):
    return he.verdict(e)[0]


def test_the_good_cell_passes():
    assert he.verdict(GOOD)[0] == "PASS"


def test_an_allow_list_wider_than_loopback_and_the_controller_fails():
    assert state(with_(egress_ip_allow="127.0.0.1/32 ::1/128 10.0.0.0/8")) == "FAIL"
    assert state(with_(unit_allow="127.0.0.1/32 ::1/128 10.0.0.0/8")) == "FAIL"


def test_an_allow_list_missing_an_address_fails():
    assert state(with_(egress_ip_allow="127.0.0.1/32")) == "FAIL"


def test_a_deny_that_does_not_cover_any_fails():
    assert state(with_(egress_ip_deny="")) == "FAIL"
    assert state(with_(unit_deny="")) == "FAIL"
    assert state(with_(unit_deny="0.0.0.0/0")) == "FAIL"


def test_the_agents_object_and_the_unit_disagreeing_fails():
    assert state(with_(unit_allow="127.0.0.1/32 ::1/128 192.0.2.9/32")) == "FAIL"


def test_a_hold_not_enforced_or_not_its_own_fails():
    assert state(with_(egress_state="unenforced")) == "FAIL"
    assert state(with_(egress_resolver="none")) == "FAIL"
    assert state(with_(egress_pid_match=False)) == "FAIL"


def test_an_applier_that_declined_the_hold_fails():
    v = he.verdict(with_(apply_msg="applied: harness-unit harness-egress=UNENFORCED:selfcheck-unavailable"))
    assert v[0] == "FAIL" and "UNENFORCED" in v[1]


def test_an_in_process_fallback_fails():
    v = he.verdict(with_(fallback=["harness dispatch: no responder; running in process node=cell-a"]))
    assert v[0] == "FAIL" and "in process" in v[1]


def test_no_dispatch_line_for_the_conversation_fails():
    assert state(with_(dispatched=0)) == "FAIL"
    assert state(with_(dispatched=2)) == "FAIL"


def test_a_probe_that_connects_fails():
    v = he.verdict(with_(probe_rc=0))
    assert v[0] == "FAIL" and "CONNECTED" in v[1]


def test_a_host_that_cannot_reach_the_control_is_a_note_not_a_pass():
    assert state(with_(control_rc=124)) == "NOTE"
    assert state(with_(control_rc=124, probe_rc=124)) == "NOTE"


def test_a_probe_outside_the_cgroup_or_after_the_turn_fails():
    assert state(with_(probe_rc=999)) == "FAIL"
    assert state(with_(cgroup="")) == "FAIL"
    assert state(with_(in_flight=False)) == "FAIL"


def test_a_secret_in_the_output_fails():
    v = he.verdict({"leaked": True})
    assert v[0] == "FAIL" and "secret" in v[1]
    assert state(with_(leaked=True)) == "FAIL"


def test_no_systemd_wsl_or_arm_without_an_asset_is_a_note():
    assert state(with_(systemd=False)) == "NOTE"
    assert state(with_(systemd_run=False)) == "NOTE"
    assert state(with_(machine="riscv64")) == "NOTE"


def test_a_turn_that_never_ran_is_not_reached():
    e = with_()
    del e["turn_status"]
    assert state(e) == "NOT REACHED"


def test_a_failed_turn_or_an_unreadable_log_fails():
    assert state(with_(turn_status=503)) == "FAIL"
    assert state(with_(gateway_log_unreadable="permission denied")) == "FAIL"


def test_a_recorded_stop_is_the_verdict():
    assert he.verdict(with_(stop=["FAIL", "cannot read the agent env"])) == ("FAIL", "cannot read the agent env")
    assert he.verdict(with_(stop=["NOTE", "no asset"])) == ("NOTE", "no asset")


def test_a_harness_that_never_ran_fails():
    assert state(with_(harness_state="stopped")) == "FAIL"


def test_a_probe_that_never_really_tried_fails():
    for rc in (127, 126, 137, 2, 90):
        assert state(with_(probe_rc=rc)) == "FAIL", rc


def test_a_connect_that_failed_inside_the_hold_passes_and_one_refused_by_the_far_end_fails():
    assert state(with_(probe_rc=1, probe_err="/bin/bash: connect: Operation not permitted")) == "PASS"
    assert state(with_(probe_rc=1, probe_err="/bin/bash: connect: Connection timed out")) == "PASS"
    assert state(with_(probe_rc=1, probe_err="/bin/bash: connect: Connection refused")) == "FAIL"
    assert state(with_(probe_rc=1, probe_err="")) == "FAIL"


def test_the_evidence_lines_pass_the_cells_upload_gate():
    """Every evidence line the judge writes, shaped as on a PASS cell, passes
    cell.py's secret scan (a `key: value` shape withheld every log of the cell)."""
    import cell
    lines = [
        "node=cell-a controller_url=https://localhost:8080 nats_url=tls://localhost:4222 pki_dir=/etc/noo/pki",
        "release=0.6.30-rc.3 asset=noo-gateway-x86_64-unknown-linux-musl sha_ok=yes",
        "the fleet signing key is readable in the CLI's PKI directory (/home/runner/.noo/pki)",
        "staged: HTTP 200 (6 kinds, 64103104 bytes)",
        "place: rc=0 + cell-a: harness → auto (Running) — agent reconciles within 5 min",
        "apply: noo-apply: applied: harness-env harness-binary harness-unit harness-egress-file",
        "note: the applier printed no harness-egress tag (the agent's egress object below is what is judged)",
        'harness: state=running egress={"state": "enforced", "resolver": "unit", "pid_match": true, "ip_deny": "0.0.0.0/0 ::/0", "ip_allow": "127.0.0.1/32 ::1/128"}',
        "unit: IPAddressDeny=0.0.0.0/0 ::/0 IPAddressAllow=127.0.0.1/32 ::1/128 ControlGroup=/system.slice/noo-harness.service",
        "class: rc=0 he-held -> cell-a/ollama=qwen2.5:0.5b",
        "turn: conversation=7d899502-6657-4284-bc71-cb76e79689da HTTP 200 in 15.6s",
        "probe from the unit's cgroup (/system.slice/noo-harness.service) to 1.1.1.1:443: rc=124 (); turn in flight=True; host control rc=0",
        "cleanup: class unset rc=0, harness unplaced rc=0",
    ]
    assert cell.secret_hits("\n".join(lines) + "\n") == []
