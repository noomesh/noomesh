# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The upgrade's docker calls are bounded (i1149).

After a power cut the controller's hard NFS mount hung, and `noo upgrade
--all` printed `# Stack` and sat silent for hours on a bare
`Command::new("docker")... .output()` (`running_gateway_tag`): a child that
blocks on a dead mount lives until the server answers, and `.output()` waits
for it. Every docker call in `noo-cli/src/commands/upgrade.rs` now goes
through `crate::bounded::docker` (spawn, wait with a deadline, kill on
expiry), and `onboard::sh::docker` (used across onboard and the launchers)
does too.

This guard refuses a new `Command::new("docker")` in upgrade.rs, and a
return of one inside the shared helper. Sites that are allowed to stay
unbounded are listed in ALLOWED with the later item that migrates them;
today there are none in upgrade.rs (the batch that bounds the remaining
direct `Command::new("docker")` calls in cluster_verify, doctor, stack
status and the rest is the later `container_state()` item).

It also pins the order that makes the refusal safe: the storage check runs
at the top of `upgrade`, before the self-update, the channel step and the
stack work.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "noo-cli" / "src"

DOCKER_CMD = re.compile(r'Command::new\(\s*"docker"\s*\)')

# (file, fn name) -> reason. Empty: every docker call in upgrade.rs is bounded.
ALLOWED: dict[tuple[str, str], str] = {}


def code_of(rel: str) -> str:
    return rs.own_code((SRC / rel).read_text(encoding="utf-8"))


def unbounded_sites(code: str) -> list[int]:
    return [m.start() for m in DOCKER_CMD.finditer(code)]


def test_the_detector_sees_the_shapes_the_hang_had():
    old = 'std::process::Command::new("docker").args(["inspect", "x"]).output().ok()?;'
    assert unbounded_sites(old)
    assert unbounded_sites('Command::new( "docker" )\n    .args(a)\n    .status()')
    assert not unbounded_sites('crate::bounded::docker(&["inspect", "x"], limit)')
    assert not unbounded_sites('Command::new(format!("docker-credential-{helper}"))')


def test_upgrade_rs_spawns_no_docker_outside_the_bounded_helper():
    code = code_of("commands/upgrade.rs")
    hits = unbounded_sites(code)
    allowed = [k for k in ALLOWED if k[0] == "commands/upgrade.rs"]
    assert len(hits) == len(allowed), (
        "an unbounded `Command::new(\"docker\")` is back in upgrade.rs (i1149: a hung mount "
        "made one sit for hours): use crate::bounded::docker, or list the site in ALLOWED "
        f"with the item that will migrate it; found {len(hits)} at offsets {hits}")


def test_the_upgrade_asks_docker_through_the_bounded_helper():
    code = code_of("commands/upgrade.rs")
    tag = rs.fn_body(code, "fn running_gateway_tag(")
    assert "crate::bounded::docker(" in tag, tag
    mapped = rs.fn_body(code, "fn gateway_tag_from(")
    assert "Bounded::TimedOut" in mapped and "GatewayTag::TimedOut" in mapped, "a timeout is its own answer, never None"
    embed = rs.fn_body(code, "fn ensure_embedder_after_roll(")
    assert "crate::bounded::docker(" in embed, embed


def test_the_shared_onboard_docker_helper_is_bounded():
    code = code_of("onboard/sh.rs")
    body = rs.fn_body(code, "pub fn docker(")
    assert not unbounded_sites(body), body
    assert "crate::bounded::docker(" in body, body
    assert "docker_limit(" in body, body


def test_the_storage_check_runs_before_anything_is_touched():
    code = code_of("commands/upgrade.rs")
    up = rs.fn_body(code, "pub fn upgrade(")
    call = up.index("refuse_when_storage_hangs(g)")
    for later in ("if stage2 {", "super::channel::request(&chan)", "resolve_latest(g)", "run_fleet_stages("):
        assert call < up.index(later), f"the storage check must come before {later}"
    check = rs.fn_body(code, "fn refuse_when_storage_hangs(")
    assert "probe_data_roots()" in check and "running_gateway_tag" in check, check
    assert "fail(" in check, "a hung mount stops the upgrade"


# ── i1159b: the container-state batch ────────────────────────────────────
#
# In the files below the claims about a container ("not running", "Postgres
# is DOWN") and about docker itself ("give this account the docker API") ride
# on bounded probes: `container_state()`, `docker_refusal()`, the ghost-record
# sample. Every other `Command::new("docker")` here is listed by function:
# those calls run a command whose result is not read as a cause (an exec, a
# listing, a digest), and are the later batch's to bound. A NEW site, or a
# listed function that stops calling docker, fails this guard.

FN = re.compile(r"\bfn\s+(\w+)")

MIGRATED: dict[str, dict[str, str]] = {
    "commands/secrets_delivery.rs": {
        "env_entries": "reads a container's env for the digest rows; no cause claimed",
        "stack_project": "compose project label lookup; an empty answer is 'no stack'",
        "holders_in": "lists holders; docker_refusal() speaks for a refused listing",
        "audience_of": "reads one container's env for an audience",
        "digest_one": "exec of a digest; the row names the container",
    },
    "commands/secrets.rs": {
        "psql_stdin": "pipes SQL into psql; its failure is its own error text",
        "try_login": "a login probe whose failure is classified by its stderr",
        "container_routable_host": "inspect for an address; None is 'no address'",
    },
    "commands/cluster_push_secrets.rs": {
        "gateway_env_digest": "exec of a digest in the gateway",
    },
    "commands/cluster_verify.rs": {
        "vantage_here": "a version/vantage probe",
        "noo_data_bound_row": "inspect of mounts for the row",
        "sandbox_live_probe": "exec of the probe; the container gate is container_running",
        "voice_live_probe": "exec of the probe; the container gate is container_running",
        "postgres_probe": "exec of psql",
        "docker_lines": "a listing",
        "stack_rows_here": "a listing",
        "config_mounters": "inspect of mounts",
        "config_view": "exec of cat",
    },
    "commands/doctor.rs": {
        "docker_lines": "`ps` listings in the doctor; the daemon gate and the ghost loop are bounded",
        "container_env": "inspect of env",
        "docker_daemon_up": "a yes/no for callers that make no claim",
        "declared_services": "a listing",
        "doctor_strangers": "a listing",
    },
}


def docker_fns(code: str) -> dict[str, int]:
    found: dict[str, int] = {}
    for m in DOCKER_CMD.finditer(code):
        fns = FN.findall(code[: m.start()])
        name = fns[-1] if fns else "<top>"
        found[name] = found.get(name, 0) + 1
    return found


def test_the_fn_detector_names_the_enclosing_function():
    code = 'fn a() {}\nfn b() { Command::new("docker").output(); }\n'
    assert docker_fns(code) == {"b": 1}


def test_migrated_files_spawn_docker_only_from_the_listed_functions():
    for rel, allowed in MIGRATED.items():
        found = docker_fns(code_of(rel))
        extra = sorted(set(found) - set(allowed))
        stale = sorted(set(allowed) - set(found))
        assert not extra, (
            f"{rel}: an unbounded Command::new(\"docker\") in {extra}: use crate::bounded::docker "
            "(container_state() for a container's state, docker_refusal() for the daemon), or list it "
            "in MIGRATED with the reason its result claims no cause")
        assert not stale, f"{rel}: {stale} no longer call docker directly; drop them from MIGRATED"


def test_the_container_state_probe_and_the_daemon_probe_are_bounded():
    sec = code_of("commands/secrets.rs")
    state = rs.fn_body(sec, "pub(crate) fn container_state(")
    assert "crate::bounded::docker(" in state and "CONTAINER_STATE_SECS" in state, state
    delivery = code_of("commands/secrets_delivery.rs")
    probe = rs.fn_body(delivery, "pub(crate) fn docker_version_probe(")
    assert "crate::bounded::docker(" in probe and "DOCKER_VERSION_SECS" in probe, probe
    assert not unbounded_sites(probe) and not unbounded_sites(state)


def test_no_message_claims_a_cause_the_probe_did_not_see():
    sec = code_of("commands/secrets.rs")
    # The two "Postgres is not running" failures branch on the state.
    assert sec.count("container_state(&pg_container)") == 2
    assert "container_running(&pg_container)" not in sec
    push = code_of("commands/cluster_push_secrets.rs")
    assert "container_state(&gateway_container)" in push and "container_running(" not in push
    doc = code_of("commands/doctor.rs")
    for f in ("pub fn doctor_docker(", "pub fn doctor_exposure("):
        assert "daemon_gate(" in rs.fn_body(doc, f), f
