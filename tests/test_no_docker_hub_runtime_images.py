# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A fresh install pulls nothing from Docker Hub for the stack itself.

Until 2026-11-20 the stack ran two official Docker Hub images, `nats:2.14.9`
(the bus) and `nginx:1.30.7-alpine` (the model-cache weight server), straight
from registry-1.docker.io: a stranger's install needed Docker Hub reachable
and rode its anonymous rate limit, while every other image came from ghcr.io.
They now run from OUR mirror, `ghcr.io/noomesh/<name>:<tag>`:
  - mirror-images.yml lanes copy them BY DIGEST (add-or-fail: a guard refuses
    to move a tag that holds another digest, a step after the copy checks the
    mirror's digest is the source's);
  - compose defaults to the mirror at that same digest;
  - their lock rows resolve from the mirror, so the lock job's provenance and
    anonymous-pull gates (scripts/stack-lock-third-party.py) apply to them;
  - the launcher's pull guard holds them to their digest pin and never to the
    stack tag (they sit under the image prefix with their UPSTREAM tag);
  - no compose service defaults to a Docker Hub image except the reasoned
    NOT_MIRRORED ones (vLLM, an opt-in GPU backend).
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
COMPOSE_FILES = sorted(ROOT.glob("docker-compose*.yml"))
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
    # compose's default names the MIRROR at the very digest the lane copied:
    # the mirror carries the very bytes compose runs, so a compose bump with
    # another digest (or a lane bump without compose) fails here.
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    dig = re.findall(re.escape(f"{NS}/{MIRRORED[name]}") + r"\$\{NOO_IMAGE_DIGEST_[A-Z]+:-@(sha256:[0-9a-f]{64})\}",
                     compose)
    assert dig and set(dig) == {m.group(1)}, (dig, m.group(1))
    # and the lock script reads the same lane (its provenance gate)
    assert M.mirror_source_digest(name, MIRRORED[name].split(":", 1)[1], MIRROR_WF.read_text()) == m.group(1)


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


def test_the_launcher_still_accepts_an_operators_docker_hub_override_at_its_pin():
    # NATS_IMAGE may still name the Docker Hub image (an operator's choice): the
    # third-party row holds it to the same digest pin wherever it comes from.
    r = _pull_guard([f"docker.io/library/nats:2.14.3@{D}", f"nginx:1.27-alpine@{G}"],
                    [f"NOO_IMAGE_DIGEST_NATS=@{D}", f"NOO_IMAGE_DIGEST_NGINX=@{G}"])
    assert r.returncode == 0, r.stderr


# ── compose: no service defaults to Docker Hub, unless listed with a reason ──

# Compose images that are neither ours (ghcr.io/noomesh/..., a local build, or
# a first-party name the dist overlay re-points) nor allowed to be silent.
# Repository -> why it is not mirrored. Adding one is a decision.
NOT_MIRRORED = {
    "vllm/vllm-openai":
        "the vLLM backend: opt-in (a GPU backend the wizard asks about), multi-GB per tag, pulled "
        "only when vLLM is placed; still Docker Hub by the release lead's decision, pinned by the "
        "lock (row vllm)",
}


def _default(img: str) -> str:
    """The effective default of an operator override `${X_IMAGE:-<default>}`
    (NATS_IMAGE, VLLM_IMAGE, ...); a `${NOO_BASE_REGISTRY:-...}/x` ref is no wrapper."""
    m = re.fullmatch(r"\$\{[A-Z][A-Z0-9_]*_IMAGE:-(.*)\}", img)
    return m.group(1) if m else img


def _repo(ref: str) -> str:
    ref = re.sub(r"\$\{NOO_IMAGE_DIGEST_[A-Z0-9_]+:-[^}]*\}", "", ref).split("@")[0]
    ref = re.sub(r"^\$\{NOO_BASE_REGISTRY:-([^}]+)\}", r"\1", ref)
    head, _, tail = ref.rpartition(":")
    return head if head and "/" not in tail else ref


def _is_docker_hub(repo: str) -> bool:
    """A reference with no registry host (`nats`, `vllm/vllm-openai`) or an
    explicit docker.io one resolves to Docker Hub."""
    if "/" not in repo:
        return True
    first = repo.split("/", 1)[0]
    return first in ("docker.io", "index.docker.io", "registry-1.docker.io") or not (
        "." in first or ":" in first or first == "localhost")


def _compose_images() -> list[tuple[str, str, str]]:
    """(file, service, effective default image) of every pulled compose image."""
    out = []
    for f in COMPOSE_FILES:
        for name, svc in (yaml.safe_load(f.read_text()).get("services") or {}).items():
            svc = svc or {}
            img = str(svc.get("image", ""))
            if not img or "build" in svc:
                continue
            # First-party: the release prefix, or a local-build name the dist
            # overlay (docker-compose.dist.yml) re-points at the prefix.
            if img.startswith(("${NOO_IMAGE_PREFIX", "noomesh/", "noo-")) or _default(img).startswith("${NOO_IMAGE_PREFIX"):
                continue
            out.append((f.name, name, _default(img)))
    return out


def test_the_scan_sees_the_runtime_images():
    # Not vacuous: a parser that finds nothing would pass every guard below.
    repos = {_repo(i) for _, _, i in _compose_images()}
    assert {NS + "/nats", NS + "/nginx", NS + "/dhi/redis", "vllm/vllm-openai"} <= repos, sorted(repos)
    assert _is_docker_hub("nats") and _is_docker_hub("vllm/vllm-openai") and _is_docker_hub("docker.io/library/nginx")
    assert not _is_docker_hub(NS + "/nats") and not _is_docker_hub("localhost:5000/x/y")
    assert not _is_docker_hub("ghcr.io/huggingface/text-embeddings-inference")


def test_no_compose_service_pulls_from_docker_hub_unlisted():
    hub = sorted({f"{f}:{svc}: {img}" for f, svc, img in _compose_images()
                  if _is_docker_hub(_repo(img)) and _repo(img) not in NOT_MIRRORED})
    assert not hub, ("compose services that pull from Docker Hub: mirror them into "
                     f"{NS}/<name> (mirror-images.yml) or list them in NOT_MIRRORED with the reason:\n  "
                     + "\n  ".join(hub))


def test_every_other_compose_image_is_ours_or_listed():
    other = sorted({f"{f}:{svc}: {img}" for f, svc, img in _compose_images()
                    if not _repo(img).startswith(NS + "/") and _repo(img) not in NOT_MIRRORED})
    assert not other, other


def test_the_not_mirrored_list_is_reasoned_and_not_stale():
    repos = {_repo(i) for _, _, i in _compose_images()}
    for repo, why in NOT_MIRRORED.items():
        assert len(why) > 40, repo
        assert repo in repos, f"{repo}: no compose service runs it any more, drop it"
    # The two this change moved never come back to the list.
    assert not ({"nats", "nginx", "library/nats", "library/nginx"} & set(NOT_MIRRORED))
    # Docker Hub's remaining entry is vLLM alone.
    assert {r for r in NOT_MIRRORED if _is_docker_hub(r)} == {"vllm/vllm-openai"}


@pytest.mark.parametrize("name", sorted(MIRRORED))
def test_compose_uses_the_ghcr_mirror(name):
    imgs = [(f, svc, i) for f, svc, i in _compose_images() if _repo(i).rsplit("/", 1)[-1] == name
            or _repo(i) in (name, f"library/{name}", f"docker.io/library/{name}")]
    assert imgs, f"no compose service runs {name}"
    for f, svc, img in imgs:
        assert _repo(img) == f"{NS}/{name}", f"{f}:{svc} runs {img}: not our mirror {NS}/{name}"
        assert img.startswith(f"{NS}/{MIRRORED[name]}$" + "{" + M.digest_var(name) + ":-@sha256:"), img


@pytest.mark.parametrize("name", sorted(MIRRORED))
def test_the_lock_rows_resolve_from_the_mirror(name):
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    entry = M.THIRD_PARTY[name]
    assert entry["repo"] == entry["compose"] == f"{NS}/{name}"
    assert M.mirror_org(name) == ORG, "a mirror row: the provenance and anonymous gates apply"
    assert M.compose_version(name, compose) == MIRRORED[name].split(":", 1)[1]
    # the CLI treats it as a third-party row (never staged for nodes)
    rs = (ROOT / "noo-cli/src/commands/image_stage.rs").read_text()
    rows = re.search(r"THIRD_PARTY_LOCK_ROWS: &\[&str\] = &\[([^\]]*)\]", rs).group(1)
    assert f'"{name}"' in rows


def test_the_lock_job_gates_both_mirror_rows_on_the_real_files(tmp_path, monkeypatch, capsys):
    """`rows` on today's compose and mirror-images.yml: nats and nginx resolve
    from the mirror, must equal the digest their lane copies, and are read
    anonymously; a mirror at another digest writes no row."""
    resolved, anon = [], []
    monkeypatch.setattr(M, "resolve", lambda ref: resolved.append(ref) or SOURCE_DIGEST[ref.split("/")[-1].split(":")[0]])
    monkeypatch.setattr(M, "anonymous_digest", lambda repo, d: anon.append((repo, d)) or ("present", d))
    out = tmp_path / "d"
    assert M.main(["rows", "--out", str(out), "--only", "nats", "--only", "nginx"]) == 0, capsys.readouterr().err
    assert resolved == [f"{NS}/{MIRRORED[n]}" for n in sorted(MIRRORED)]
    assert anon == [(f"{NS}/{n}", SOURCE_DIGEST[n]) for n in sorted(MIRRORED)]
    for n in MIRRORED:
        assert (out / n).read_text() == f"{n}@{SOURCE_DIGEST[n]}\n"
    # the log names both gates as passed, for each mirror row, before its row
    log = capsys.readouterr().out.splitlines()
    for n in sorted(MIRRORED):
        d = SOURCE_DIGEST[n]
        i = log.index(f"{n}@{d}   ({NS}/{MIRRORED[n]})")
        assert log[i - 2:i] == [f"  provenance ok: {n}@{d} = mirror-images.yml lane source",
                                f"  anonymous pull ok: {NS}/{n}@{d}"], log
    # the mirror at another digest than its lane copied: refused, no row
    monkeypatch.setattr(M, "resolve", lambda ref: B)
    assert M.main(["rows", "--out", str(tmp_path / "e"), "--only", "nats"]) == 1
    cap = capsys.readouterr()
    assert "is not the upstream image" in cap.err
    assert "provenance ok" not in cap.out and "anonymous pull ok" not in cap.out, cap.out
    assert not (tmp_path / "e").exists()


# ── the words a stranger reads ───────────────────────────────────────────────

def test_install_doc_does_not_send_a_stranger_to_docker_hub():
    doc = (ROOT / "docs/getting-started/install.md").read_text()
    row = next(ln for ln in doc.splitlines() if ln.startswith("| Network |"))
    before, _, vllm = row.partition("`registry-1.docker.io`")
    assert vllm, row
    assert "at install" in before and "only if you pick the vLLM backend" in vllm, row
