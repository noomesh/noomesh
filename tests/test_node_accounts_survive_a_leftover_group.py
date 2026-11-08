# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""i545 finding 96: a box that held a node before kept the noo-agent GROUP
after its user went. prep-host's bare `useradd noo-agent` then refused
("group noo-agent exists") and prep died. noo-deenroll removed only the
noo-agent user, so it left that group and the noo-harness account behind.

Safety of THIS test: the batch and CI can run tests as root. The account
lines are cut out of each script and run with every account command
(id, getent, useradd, groupadd, userdel, groupdel) replaced by a bash
FUNCTION that only logs. A function shadows the binary, so nothing on the
machine running the test is created or deleted.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PREP = REPO / "scripts" / "prep-host.sh"
DEENROLL = REPO / "scripts" / "deenroll-node-local.sh"

# Fake account database: EXISTING_USERS / EXISTING_GROUPS name what exists.
SHIMS = r"""
log() { printf '%s\n' "$*" >> "$LOG"; }
has() { case " $1 " in *" $2 "*) return 0 ;; esac; return 1; }
id() { [ "$1" = -u ] && has "$EXISTING_USERS" "$2"; }
getent() { [ "$1" = group ] && has "$EXISTING_GROUPS" "$2"; }
useradd() { log "useradd $*"; }
groupadd() { log "groupadd $*"; }
userdel() { log "userdel $*"; }
groupdel() { log "groupdel $*"; }
say() { :; }
"""


def _run(block: str, tmp_path: Path, users: str, groups: str) -> list[str]:
    log = tmp_path / "accounts.log"
    log.write_text("")
    out = subprocess.run(
        ["bash", "-c", f"set -eu\n{SHIMS}\n{block}"],
        env={"PATH": "/usr/bin:/bin", "LOG": str(log), "EXISTING_USERS": users, "EXISTING_GROUPS": groups},
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    return log.read_text().splitlines()


def _prep_block() -> str:
    lines = PREP.read_text().splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("getent group noo-agent"))
    end = next(i for i, ln in enumerate(lines) if ln.startswith("id -u noo-agent") and "useradd" in ln)
    assert end == start + 1, "prep-host ensures the group on the line before it creates the user"
    return "\n".join(lines[start : end + 1])


def _deenroll_block() -> str:
    src = DEENROLL.read_text()
    head, rest = src.split("for _u in noo-harness noo-agent; do", 1)
    users, rest = rest.split("\ndone\n", 1)
    assert rest.startswith("for _g in noo-harness noo-agent; do"), "groups are removed right after users"
    groups = rest.split("\ndone\n", 1)[0]
    return f"for _u in noo-harness noo-agent; do{users}\ndone\n{groups}\ndone\n"


def test_prep_creates_the_user_into_a_leftover_group(tmp_path: Path) -> None:
    calls = _run(_prep_block(), tmp_path, users="", groups="noo-agent")
    assert not any(c.startswith("groupadd") for c in calls), calls
    assert calls == ["useradd --system --shell /usr/sbin/nologin --no-create-home --gid noo-agent noo-agent"], calls


def test_prep_on_a_clean_box_makes_the_group_then_the_user(tmp_path: Path) -> None:
    calls = _run(_prep_block(), tmp_path, users="", groups="")
    assert calls == [
        "groupadd --system noo-agent",
        "useradd --system --shell /usr/sbin/nologin --no-create-home --gid noo-agent noo-agent",
    ], calls


def test_prep_leaves_an_existing_agent_alone(tmp_path: Path) -> None:
    assert _run(_prep_block(), tmp_path, users="noo-agent", groups="noo-agent") == []


def test_deenroll_removes_both_accounts_then_their_groups(tmp_path: Path) -> None:
    calls = _run(
        _deenroll_block(),
        tmp_path,
        users="noo-harness noo-agent noo-ci",
        groups="noo-harness noo-agent noo-ci",
    )
    assert calls == [
        "userdel noo-harness",
        "userdel noo-agent",
        "groupdel noo-harness",
        "groupdel noo-agent",
    ], calls


def test_deenroll_removes_a_group_left_without_its_user(tmp_path: Path) -> None:
    calls = _run(_deenroll_block(), tmp_path, users="", groups="noo-agent")
    assert calls == ["groupdel noo-agent"], calls


def test_deenroll_never_names_the_ci_account() -> None:
    code = [ln for ln in DEENROLL.read_text().splitlines() if not ln.strip().startswith("#")]
    assert not any("noo-ci" in ln for ln in code), "noo-deenroll must never touch the CI account"
