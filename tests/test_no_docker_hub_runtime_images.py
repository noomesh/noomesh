# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The GHCR mirror lanes for the stack's last two Docker Hub runtime images.

The stack runs two official Docker Hub images, `nats:2.14.9` (the bus) and
`nginx:<version>-alpine` (the model-cache weight server), straight from
registry-1.docker.io: a stranger's install needs Docker Hub reachable and
rides its anonymous rate limit. This change adds only the MIRROR, nothing
consumes it yet:
  - mirror-images.yml lanes copy them BY DIGEST to
    `ghcr.io/noomesh/<name>:<tag>` (nats at the digest compose pins today,
    nginx at 1.30.7, the version compose moves to separately);
  - every lane is add-or-fail: a guard before the copy refuses to move a tag
    that already holds another digest, and a step after it checks the mirror's
    digest is the source's;
  - the launcher's pull guard holds a third-party lock row to its digest pin
    and never to the stack tag, so the mirror refs (under the image prefix,
    upstream tag) start once compose names them.
Compose, the lock rows and the docs move to the mirror in a later change,
after the packages are public and an anonymous pull is confirmed.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MIRROR_WF = ROOT / ".github/workflows/mirror-images.yml"

spec = importlib.util.spec_from_file_location("stack_lock_third_party", ROOT / "scripts/stack-lock-third-party.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

NS = M.NS   # ghcr.io/noomesh, read from scripts/lib-dist.sh
ORG = NS.removeprefix("ghcr.io/")
MIRRORED = {"nats": "nats:2.14.9", "nginx": "nginx:1.30.7-alpine"}
# The upstream index digest each lane copies (checked against Docker Hub
# 2026-11-20: the tag resolved to it).
SOURCE_DIGEST = {
    "nats": "sha256:f0e72e96696382cc1e5bc637befd3177bb2d5b07c37fb507f8edd09827a342a3",
    "nginx": "sha256:caf4e1e032a20f9c3c5e28fc7f25ffd768ad8677b4975c54193075997b3a97e3",
}


def _wf() -> dict:
    return yaml.safe_load(MIRROR_WF.read_text())


def _lanes() -> list[dict]:
    return _wf()["jobs"]["mirror"]["strategy"]["matrix"]["include"]


def _steps() -> list[dict]:
    return _wf()["jobs"]["mirror"]["steps"]


@pytest.mark.parametrize("name", sorted(MIRRORED))
def test_the_mirror_lane_copies_the_compose_digest_by_digest(name):
    lanes = [ln for ln in _lanes() if ln.get("dest") == MIRRORED[name] and ln.get("dest_org") == ORG]
    assert len(lanes) == 1, lanes
    src = lanes[0]["source"]
    m = re.fullmatch(r"(?:docker\.io/)?(?:library/)?" + re.escape(MIRRORED[name]) + r"@(sha256:[0-9a-f]{64})", src)
    assert m, f"the lane must copy the official {MIRRORED[name]} BY DIGEST: {src}"
    assert lanes[0].get("auth") != "dhi"
    assert m.group(1) == SOURCE_DIGEST[name]
    # Wherever compose names this version, it pins the digest the lane copies:
    # the mirror carries the very bytes compose runs. (nats today; nginx once
    # compose moves to 1.30.7, so a compose bump with another digest fails.)
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    dig = re.findall(re.escape(MIRRORED[name]) + r"\$\{NOO_IMAGE_DIGEST_[A-Z]+:-@(sha256:[0-9a-f]{64})\}", compose)
    assert set(dig) <= {m.group(1)}, (dig, m.group(1))
    if name == "nats":
        assert dig, "compose pins nats 2.14.9 today: the agreement check must not be vacuous"


def test_the_job_does_not_fail_fast():
    # one refused lane must not cancel the others and hide their results
    assert _wf()["jobs"]["mirror"]["strategy"]["fail-fast"] is False


def test_the_copy_reads_the_pinned_source_and_runs_only_after_the_guard():
    steps = _steps()
    copy = next(s for s in steps if "imagetools create" in s.get("run", ""))
    guard = next(s for s in steps if s.get("id") == "guard")
    # the copy reads the matrix SOURCE (digest-pinned), never a re-resolved tag
    assert re.search(r'imagetools create \\\s*\n\s*--tag "ghcr\.io/\$\{dest_org\}/\$\{\{ matrix\.dest \}\}" \\\s*\n'
                     r'\s*"\$\{\{ matrix\.source \}\}"; then', copy["run"]), copy["run"]
    assert copy.get("if") == "steps.guard.outputs.action == 'copy'", copy.get("if")
    assert steps.index(guard) < steps.index(copy)
    # nothing but the copy step writes a tag
    assert [s for s in steps if "imagetools create" in s.get("run", "")] == [copy]


def test_the_provenance_step_follows_the_copy():
    steps = _steps()
    copy = next(s for s in steps if "imagetools create" in s.get("run", ""))
    prov = next(s for s in steps if s.get("name", "").startswith("Verify the mirror digest equals the source digest"))
    assert steps.index(prov) > steps.index(copy)
    assert "if" not in prov, "provenance is checked on a skipped lane too"


# ── the guard and provenance steps, run with a stubbed docker ───────────────

D = "sha256:" + "a" * 64
B = "sha256:" + "b" * 64


def _run_step(step_id_or_name: str, source: str, docker_out: str, docker_rc: int, tmp_path):
    step = next(s for s in _steps() if s.get("id") == step_id_or_name or s.get("name", "").startswith(step_id_or_name))
    body = (step["run"]
            .replace("${{ matrix.dest_org || github.repository_owner }}", ORG)
            .replace("${{ matrix.source }}", source)
            .replace("${{ matrix.dest }}", "nats:2.14.3"))
    assert "${{" not in body, body
    out = tmp_path / "gh_output"
    out.write_text("")
    calls = tmp_path / "calls"
    script = "\n".join([
        "set -e",
        'docker() { echo "$*" >> "$CALLS"; printf "%s\\n" "$STUB_OUT"; return "$STUB_RC"; }',
        "sleep() { :; }",
        body,
    ])
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "GITHUB_OUTPUT": str(out), "CALLS": str(calls),
                            "STUB_OUT": docker_out, "STUB_RC": str(docker_rc)})
    return r, out.read_text(), (calls.read_text() if calls.exists() else "")


def test_guard_copies_an_absent_tag(tmp_path):
    r, out, calls = _run_step("guard", f"nats:2.14.3@{D}",
                              f"ERROR: ghcr.io/{ORG}/nats:2.14.3: not found", 1, tmp_path)
    assert r.returncode == 0 and out.strip() == "action=copy", (r.stdout, r.stderr, out)
    assert f"imagetools inspect ghcr.io/{ORG}/nats:2.14.3" in calls


def test_guard_skips_a_tag_already_at_the_source_digest(tmp_path):
    r, out, _ = _run_step("guard", f"nats:2.14.3@{D}", f'"{D}"', 0, tmp_path)
    assert r.returncode == 0 and out.strip() == "action=skip", (r.stdout, r.stderr, out)


def test_guard_refuses_to_move_a_tag_at_another_digest(tmp_path):
    r, out, _ = _run_step("guard", f"nats:2.14.3@{D}", f'"{B}"', 0, tmp_path)
    assert r.returncode == 1 and "refusing to move an existing tag" in r.stdout, (r.stdout, r.stderr)
    assert B in r.stdout and D in r.stdout
    assert "action=" not in out, "no copy for a moved tag"


def test_guard_never_copies_over_a_read_it_could_not_make(tmp_path):
    # auth/network errors are not "absent": only a confirmed absence is copied
    r, out, calls = _run_step("guard", f"nats:2.14.3@{D}", "ERROR: denied: permission_denied", 1, tmp_path)
    assert r.returncode == 1 and "not proven absent" in r.stdout, (r.stdout, r.stderr)
    assert "action=" not in out
    assert calls.count("imagetools inspect") == 3, "retried before giving up"


def test_guard_refuses_a_lane_that_copies_a_moving_tag(tmp_path):
    r, out, calls = _run_step("guard", "nats:2.14.3", "", 1, tmp_path)
    assert r.returncode == 1 and "not pinned by digest" in r.stdout
    assert calls == "" and "action=" not in out


@pytest.mark.parametrize("got, ok", [(f'"{D}"', True), (f'"{B}"', False)], ids=["same", "different"])
def test_provenance_step_compares_the_mirror_to_the_source(tmp_path, got, ok):
    r, _, _ = _run_step("Verify the mirror digest equals the source digest", f"nats:2.14.3@{D}", got, 0, tmp_path)
    assert (r.returncode == 0) is ok, (r.stdout, r.stderr)


def test_provenance_step_refuses_a_tag_source(tmp_path):
    r, _, _ = _run_step("Verify the mirror digest equals the source digest", "nats:2.14.3", f'"{D}"', 0, tmp_path)
    assert r.returncode == 1 and "not pinned by digest" in r.stdout


# ── the launcher's pull guard (scripts/lib-dist.sh) ─────────────────────────

def _fn(name: str) -> str:
    src = (ROOT / "scripts/lib-dist.sh").read_text()
    start = src.index(f"{name}() {{")
    return src[start:src.index("\n}\n", start) + 3]


G = "sha256:" + "c" * 64


def _pull_guard(refs: list[str], pins: list[str]) -> subprocess.CompletedProcess:
    script = "\n".join([
        "set -euo pipefail",
        f"_DIST_PINS=({' '.join(repr(p) for p in pins)})",
        "DIST_TAG=v9.9.9",
        f"NOO_IMAGE_PREFIX={NS}",
        "compose_capture() { COMPOSE_OUT=\"$REFS\"; return 0; }",
        "compose_report_error() { :; }",
        "dist_assert_addon_refs() { return 0; }",
        _fn("dist_ref_is_stack_versioned"), _fn("dist_third_party_row"),
        _fn("dist_assert_third_party_ref"), _fn("dist_assert_pull_refs"),
        "dist_assert_pull_refs x",
    ])
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "REFS": "\n".join(refs)})


@pytest.mark.parametrize("name", sorted(MIRRORED))
def test_the_launcher_pulls_the_mirror_at_its_lock_pin(name):
    var = M.digest_var(name)
    ref = f"{NS}/{MIRRORED[name]}@{D}"
    gw = f"{NS}/gateway:v9.9.9@{G}"
    r = _pull_guard([gw, ref], [f"NOO_IMAGE_DIGEST_GATEWAY=@{G}", f"{var}=@{D}"])
    # Under the image prefix with its UPSTREAM tag: never held to the stack tag.
    assert r.returncode == 0, r.stderr
    assert "refusing" not in r.stderr, r.stderr


@pytest.mark.parametrize("name", sorted(MIRRORED))
def test_the_launcher_refuses_the_mirror_at_another_digest(name):
    var = M.digest_var(name)
    r = _pull_guard([f"{NS}/{MIRRORED[name]}@{B}"], [f"{var}=@{D}"])
    assert r.returncode == 1 and "not in stack.lock" in r.stderr, r.stderr
    r = _pull_guard([f"{NS}/{MIRRORED[name]}"], [f"{var}=@{D}"])
    assert r.returncode == 1 and "no digest" in r.stderr, r.stderr


def test_the_launcher_still_holds_a_stack_image_to_the_stack_tag():
    # The skip is for third-party rows only: a stack image of another tag is refused.
    r = _pull_guard([f"{NS}/gateway:v9.9.8@{G}"], [f"NOO_IMAGE_DIGEST_GATEWAY=@{G}"])
    assert r.returncode == 1 and "this start runs v9.9.9" in r.stderr, r.stderr


def test_the_launcher_still_accepts_todays_docker_hub_refs():
    r = _pull_guard([f"docker.io/library/nats:2.14.3@{D}", f"nginx:1.27-alpine@{G}"],
                    [f"NOO_IMAGE_DIGEST_NATS=@{D}", f"NOO_IMAGE_DIGEST_NGINX=@{G}"])
    assert r.returncode == 0, r.stderr
