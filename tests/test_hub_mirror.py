# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The Docker Hub mirror: every Hub image we pull is mirrored, and used through it.

Every self-hosted runner sits behind one home IP and Docker Hub limits
anonymous pulls per IP: on 2026-10-09 rust-gateway, noo-cli and
standalone-smoke failed four attempts running on "toomanyrequests".
scripts/hub-mirror.py copies `.github/hub-mirror.txt` into GHCR (weekly) and
answers mirror-or-Hub at use. This file holds:

  * the declarations: every Docker Hub FROM goes through `${HUB_MIRROR}` and is
    in the inventory; every `ARG HUB_MIRROR=` default is the one prefix;
  * `sync` against a fake `docker` binary on PATH (the transport, not the
    script's functions): new / unchanged / changed copies, a downgrade
    refused, a pinned digest held, every digest recorded;
  * `prefix` / `ref` / `dockerfile`: mirror when present, docker.io with a
    warning when not, never a failure.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/hub-mirror.py"
INVENTORY = ROOT / ".github/hub-mirror.txt"
PREFIX = "ghcr.io/noomesh/mirror"   # what the script derives for this owner


def _rows() -> list[str]:
    return [ln.split("#", 1)[0].split()[0] for ln in INVENTORY.read_text().splitlines()
            if ln.split("#", 1)[0].strip()]


def _dockerfiles() -> list[Path]:
    files = subprocess.run(["git", "ls-files", "Dockerfile", "*Dockerfile*"], cwd=ROOT,
                           capture_output=True, text=True, check=True).stdout.split()
    return [ROOT / f for f in files if (ROOT / f).is_file() and f not in EXEMPT]


# Built OUTSIDE CI, by machines with no GHCR login: a mirror default would break them.
EXEMPT = {
    "node-agent-go/internal/docker/sandbox-base.Dockerfile":
        "embedded in the node agent and built ON the worker (arm64), which has no ghcr.io login",
}


def _is_hub(ref: str) -> bool:
    if ref.startswith("$") or ref == "scratch":
        return False
    first = ref.split("/", 1)[0]
    return "/" not in ref or not ("." in first or ":" in first or first == "localhost")


# ── declarations ──────────────────────────────────────────────────────────

def test_no_dockerfile_pulls_docker_hub_directly() -> None:
    stages, bad = set(), []
    for f in _dockerfiles():
        stages.clear()
        for ln in f.read_text().splitlines():
            m = re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", ln, re.I)
            if not m:
                continue
            ref = m.group(1)
            if ref not in stages and _is_hub(ref):
                bad.append(f"{f.relative_to(ROOT)}: FROM {ref}")
            if m.group(2):
                stages.add(m.group(2))
    assert not bad, ("Docker Hub FROMs outside the mirror — use ${HUB_MIRROR}/<path> and add the "
                     "image to .github/hub-mirror.txt:\n  " + "\n  ".join(bad))


def _mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location("hub_mirror", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_every_mirrored_from_is_in_the_inventory_and_one_prefix_is_declared() -> None:
    mod, inv, seen = _mod(), set(_rows()), 0
    for f in _dockerfiles():
        text = f.read_text()
        wanted = mod.dockerfile_rows(f)
        if not wanted:
            assert "${HUB_MIRROR}" not in text, f
            continue
        seen += 1
        assert set(wanted) <= inv, f"{f.relative_to(ROOT)}: {sorted(set(wanted) - inv)} not mirrored"
        defaults = re.findall(r"^ARG HUB_MIRROR=(\S+)", text, re.M)
        assert defaults == [PREFIX], f"{f.relative_to(ROOT)}: ARG HUB_MIRROR defaults {defaults}"
        first_from = re.search(r"^FROM ", text, re.M).start()
        assert text.index("ARG HUB_MIRROR=") < first_from, f"{f}: ARG must precede the first FROM"
    assert seen >= 7, f"only {seen} Dockerfiles use the mirror — did the parse break?"


def test_the_script_default_is_the_dockerfile_default() -> None:
    env = {"PATH": os.environ["PATH"], "GITHUB_REPOSITORY_OWNER": "noomesh"}
    os.environ.pop("HUB_MIRROR", None)
    old = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(env)
        assert _mod().default_prefix() == PREFIX
    finally:
        os.environ.clear()
        os.environ.update(old)


def test_the_cargo_image_is_mirrored() -> None:
    text = (ROOT / "scripts/cargo-docker.sh").read_text()
    m = re.search(r'IMAGE="\$\{CARGO_DOCKER_IMAGE:-([^}]+)\}"', text)
    assert m, "cargo-docker.sh's default image moved"
    assert f"library/{m.group(1)}" in _rows()


def test_inventory_rows_parse() -> None:
    mod = _mod()
    rows = _rows()
    assert rows and len(rows) == len(set(rows))
    for r in rows:
        mod.split(r)


def _wf(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def test_the_mirror_workflow_is_weekly_and_dispatchable() -> None:
    wf = _wf("mirror-hub-images.yml")
    on = wf[True]
    assert "workflow_dispatch" in on and on["schedule"][0]["cron"]
    assert wf["permissions"]["packages"] == "write"
    runs = " ".join(str(s.get("run", "")) for s in wf["jobs"]["mirror"]["steps"])
    assert "scripts/hub-mirror.py sync --record" in runs


def test_hub_login_fails_loud_when_secrets_are_present() -> None:
    steps = _wf("mirror-hub-images.yml")["jobs"]["mirror"]["steps"]
    run = next(s["run"] for s in steps if "Docker Hub" in str(s.get("name")))
    assert "::warning::docker.io login failed" not in run
    assert "::error::docker.io login failed" in run and "exit 1" in run
    assert "::notice::" in run


def test_images_mirror_is_throttled_and_retries() -> None:
    wf = _wf("mirror-images.yml")["jobs"]["mirror"]
    assert wf["strategy"]["max-parallel"] == 3 and wf["strategy"]["fail-fast"] is False
    copy = next(s["run"] for s in wf["steps"] if "multi-arch manifest copy" in str(s.get("name")))
    assert "for attempt in 1 2 3 4 5" in copy and "sleep $((20 * attempt))" in copy


def test_the_push_trigger_names_the_default_branch_of_both_repos() -> None:
    # The public repo's default branch is main, not dev: a push trigger on
    # dev alone never fires there (only the cron does).
    branches = _wf("mirror-hub-images.yml")[True]["push"]["branches"]
    assert {"dev", "main"} <= set(branches)


def test_rust_jobs_and_image_builds_use_the_mirror() -> None:
    ci = _wf("ci.yml")["jobs"]
    for job in ("rust-gateway", "sqlx-drift", "noo-cli", "standalone-smoke"):
        steps = ci[job]["steps"]
        i = next(n for n, s in enumerate(steps) if "hub-mirror.py\" ref library/rust:1-bookworm" in str(s.get("run", "")))
        # Absolute: noo-cli's steps default to working-directory noo-cli, where a
        # relative scripts/ path is missing and the image came back empty (#875).
        assert '"$GITHUB_WORKSPACE/scripts/hub-mirror.py"' in steps[i]["run"], job
        assert "ref=docker.io/library/rust:1-bookworm" in steps[i]["run"], f"{job}: no fallback for an empty answer"
        j = next(n for n, s in enumerate(steps) if "Rust toolchain id" in str(s.get("name", "")))
        assert i < j, job
        assert "vars.HUB_MIRROR_OFF" in str(steps[i].get("env")), job
    build = " ".join(str(s.get("run", "")) for s in ci["build"]["steps"])
    assert '"$GITHUB_WORKSPACE/scripts/hub-mirror.py" dockerfile "$GITHUB_WORKSPACE/Dockerfile"' in build and '--build-arg HUB_MIRROR="${HUB_PREFIX' in build
    rel = " ".join(str(s.get("run", "")) for s in _wf("images-release.yml")["jobs"]["images"]["steps"])
    assert '"$GITHUB_WORKSPACE/scripts/hub-mirror.py" dockerfile' in rel and '--build-arg HUB_MIRROR="$HUB_PREFIX"' in rel


# ── sync / prefix against a fake `docker` ─────────────────────────────────

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
state_path = os.environ["FAKE_REGISTRY"]
state = json.load(open(state_path))
a = sys.argv[1:]
with open(state_path + ".log", "a") as log:
    log.write(" ".join(a) + "\n")
if a[:3] == ["buildx", "imagetools", "inspect"]:
    ref, fmt = a[3], a[a.index("--format") + 1]
    img = state.get(ref)
    if img is None:
        sys.stderr.write(f"ERROR: {ref}: not found\n"); sys.exit(1)
    if img == "unreachable":
        sys.stderr.write("ERROR: dial tcp: i/o timeout\n"); sys.exit(1)
    if ".Manifest" in fmt:
        man = {"digest": img["digest"], "manifests": [
            {"digest": "sha256:" + "1" * 64, "annotations": {"org.opencontainers.image.version": img.get("version", "")}}]}
        print(json.dumps(man))
    else:
        print(json.dumps({"linux/amd64": {"created": img["created"], "config": {}}}))
    sys.exit(0)
if a[:3] == ["buildx", "imagetools", "create"]:
    flaky = os.environ.get("FAKE_429_TIMES")
    if flaky:
        cnt = state_path + ".429"
        n = int(open(cnt).read()) if os.path.exists(cnt) else 0
        if n < int(flaky):
            open(cnt, "w").write(str(n + 1))
            sys.stderr.write("ERROR: 429 Too Many Requests\nRetry-After: 1\n"); sys.exit(1)
    dst, src = a[a.index("--tag") + 1], a[-1]
    state[dst] = state[src.split("@")[0]] if "@" in src and src.split("@")[0] in state else state[src]
    json.dump(state, open(state_path, "w"))
    sys.exit(0)
sys.exit(2)
'''


@pytest.fixture
def registry(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    d = bindir / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(0o755)
    state = tmp_path / "registry.json"

    def run(images: dict, *args: str, inventory: list[str] | None = None, **env):
        state.write_text(json.dumps(images))
        (tmp_path / "registry.json.log").write_text("")
        e = {"PATH": f"{bindir}:{os.environ['PATH']}", "FAKE_REGISTRY": str(state),
             "GITHUB_REPOSITORY_OWNER": "noomesh", **env}
        argv = list(args)
        if inventory is not None:
            inv = tmp_path / "inv.txt"
            inv.write_text("\n".join(inventory) + "\n")
            argv += ["--inventory", str(inv)]
        r = subprocess.run([sys.executable, str(SCRIPT), *argv], capture_output=True, text=True, env=e)
        return r.returncode, r.stderr + r.stdout, json.loads(state.read_text()), \
            (tmp_path / "registry.json.log").read_text()

    run.tmp = tmp_path
    return run


SRC = "docker.io/library/rust:1-bookworm"
DST = f"{PREFIX}/library/rust:1-bookworm"
D1, D2 = "sha256:" + "a" * 64, "sha256:" + "b" * 64


def _img(digest, created, version=""):
    return {"digest": digest, "created": created, "version": version}


def test_sync_copies_a_new_image_and_records_its_digest(registry) -> None:
    rec = registry.tmp / "rec.txt"
    rc, out, state, log = registry({SRC: _img(D1, "2026-10-01T00:00:00Z")}, "sync", "--record", str(rec),
                                   inventory=["library/rust:1-bookworm"])
    assert rc == 0, out
    assert state[DST]["digest"] == D1 and "imagetools create --tag " + DST in log
    assert rec.read_text() == f"library/rust:1-bookworm {D1} 2026-10-01T00:00:00Z\n"


def test_sync_retries_a_rate_limited_copy(registry) -> None:
    rc, out, state, log = registry({SRC: _img(D1, "2026-10-01T00:00:00Z")}, "sync",
                                   inventory=["library/rust:1-bookworm"],
                                   FAKE_429_TIMES="2", HUB_MIRROR_BACKOFF="0")
    assert rc == 0, out
    assert "rate limited (attempt 2/5)" in out and state[DST]["digest"] == D1
    assert log.count("imagetools create") == 3


def test_sync_gives_up_after_bounded_rate_limit_retries(registry) -> None:
    rc, out, _, log = registry({SRC: _img(D1, "2026-10-01T00:00:00Z")}, "sync",
                               inventory=["library/rust:1-bookworm"],
                               FAKE_429_TIMES="99", HUB_MIRROR_BACKOFF="0")
    assert rc == 1 and log.count("imagetools create") == 5


def test_sync_leaves_an_unchanged_image_alone(registry) -> None:
    img = _img(D1, "2026-10-01T00:00:00Z")
    rc, out, _, log = registry({SRC: img, DST: img}, "sync", inventory=["library/rust:1-bookworm"])
    assert rc == 0 and "unchanged" in out and "create" not in log


def test_sync_copies_a_newer_image_and_prints_the_change(registry) -> None:
    rc, out, state, _ = registry({SRC: _img(D2, "2026-10-08T00:00:00Z", "1.90.1"),
                                  DST: _img(D1, "2026-10-01T00:00:00Z", "1.90.0")},
                                 "sync", inventory=["library/rust:1-bookworm"])
    assert rc == 0, out
    assert state[DST]["digest"] == D2 and f"{D1} -> {D2}" in out


def test_sync_refuses_an_older_image(registry) -> None:
    rc, out, state, log = registry({SRC: _img(D2, "2026-09-01T00:00:00Z"),
                                    DST: _img(D1, "2026-10-01T00:00:00Z")},
                                   "sync", inventory=["library/rust:1-bookworm"])
    assert rc == 1 and "DOWNGRADE?" in out and "NOT copied" in out
    assert state[DST]["digest"] == D1 and "create" not in log


def test_sync_refuses_a_lower_version_even_if_rebuilt_later(registry) -> None:
    rc, out, state, _ = registry({SRC: _img(D2, "2026-10-08T00:00:00Z", "1.89.0"),
                                  DST: _img(D1, "2026-10-01T00:00:00Z", "1.90.0")},
                                 "sync", inventory=["library/rust:1-bookworm"])
    assert rc == 1 and "version 1.90.0 -> 1.89.0" in out
    assert state[DST]["digest"] == D1


def test_one_bad_row_does_not_stop_the_others(registry) -> None:
    alp = "docker.io/library/alpine:3.22"
    rc, out, state, _ = registry({alp: _img(D1, "2026-10-01T00:00:00Z")}, "sync",
                                 inventory=["library/rust:1-bookworm", "library/alpine:3.22"])
    assert rc == 1 and "does not exist" in out
    assert f"{PREFIX}/library/alpine:3.22" in state


def test_a_pinned_row_must_resolve_to_its_digest(registry) -> None:
    src = f"docker.io/library/python:3.12-slim-bookworm@{D1}"
    rc, out, _, _ = registry({src: _img(D2, "2026-10-01T00:00:00Z")}, "sync",
                             inventory=[f"library/python:3.12-slim-bookworm@{D1}"])
    assert rc == 1 and "not the pinned digest" in out


def test_prefix_is_the_mirror_when_everything_is_there(registry) -> None:
    rc, out, _, _ = registry({DST: _img(D1, "x")}, "prefix", "library/rust:1-bookworm")
    assert rc == 0 and out.strip() == PREFIX


@pytest.mark.parametrize("images", [{}, {DST: "unreachable"}])
def test_a_missing_or_unreachable_mirror_falls_back_to_hub_with_a_warning(registry, images) -> None:
    rc, out, _, log = registry(images, "ref", "library/rust:1-bookworm")
    assert rc == 0
    assert out.strip().splitlines()[-1] == "docker.io/library/rust:1-bookworm"
    assert "::warning::" in out and "inspect " + DST in log


def test_the_kill_switch_answers_hub_without_asking(registry) -> None:
    rc, out, _, log = registry({DST: _img(D1, "x")}, "ref", "library/rust:1-bookworm", HUB_MIRROR_OFF="1")
    assert rc == 0 and out.strip().splitlines()[-1] == "docker.io/library/rust:1-bookworm"
    assert log == ""


def test_hub_mirror_variable_moves_the_prefix(registry) -> None:
    other = "ghcr.io/acme/mirror"
    rc, out, _, _ = registry({f"{other}/library/rust:1-bookworm": _img(D1, "x")}, "ref",
                             "library/rust:1-bookworm", HUB_MIRROR=other)
    assert out.strip() == f"{other}/library/rust:1-bookworm"


def test_dockerfile_mode_reads_the_froms(registry) -> None:
    whisper = ROOT / "docker/Dockerfile.whisper"
    row = _mod().dockerfile_rows(whisper)[0]
    mirror = f"{PREFIX}/{row.split('@')[0]}"
    rc, out, _, _ = registry({mirror: _img(D1, "x")}, "dockerfile", str(whisper))
    assert rc == 0 and out.strip() == PREFIX
    rc, out, _, _ = registry({}, "dockerfile", str(whisper))
    assert out.strip().splitlines()[-1] == "docker.io"


# --- the org's own GHCR mirror images: ONE declared expression -------------------

_MIRROR_OFF = ("vars.HUB_MIRROR_OFF != '' && vars.HUB_MIRROR_OFF != '0' "
               "&& vars.HUB_MIRROR_OFF != 'false'")
_PGVECTOR_IMAGE = ("${{ " + _MIRROR_OFF + " && 'pgvector/pgvector:pg18' || "
                   "format('ghcr.io/{0}/pgvector:pg18', github.repository_owner) }}")


def test_no_workflow_hardcodes_an_org_mirror_image_outside_the_declared_expression() -> None:
    """On the first push to a new org CI races the mirror workflow, so every consumer
    of a mirrored image carries the HUB_MIRROR_OFF fallback to the upstream Hub image
    (the same off-switch scripts/hub-mirror.py honours), in ONE spelling."""
    offenders = []
    uses = 0
    for wf in sorted((ROOT / ".github/workflows").glob("*.yml")):
        if wf.name.startswith("mirror-"):
            continue   # the publishers: they WRITE the mirror
        for n, line in enumerate(wf.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if re.search(r"ghcr\.io/(\$\{\{|noomesh|\{0\})[^\s'\"]*/(pgvector|mirror)\b", line):
                if line.strip() in (f"image: {_PGVECTOR_IMAGE}",):
                    uses += 1
                else:
                    offenders.append(f"{wf.name}:{n}: {line.strip()}")
    assert not offenders, "mirror image outside the declared expression:\n" + "\n".join(offenders)
    assert uses >= 2, "expected the declared pgvector expression on the service containers"


_SERVICE_CREDENTIALS = ("${{ fromJSON(!(" + _MIRROR_OFF + ") && format('{{\"username\":\"{0}\",\"password\":\"{1}\"}}', github.actor, secrets.GITHUB_TOKEN) || '{}') }}")


def test_service_containers_carry_the_fallback_and_no_ghcr_login_for_hub() -> None:
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    seen = 0
    for name, job in ci["jobs"].items():
        for svc, spec in (job.get("services") or {}).items():
            if "pgvector" in spec["image"]:
                seen += 1
                assert spec["image"] == _PGVECTOR_IMAGE, f"{name}.{svc}"
                # One expression for the whole mapping (proven on real runners):
                # an empty string is falsy in GitHub expressions, so per-field
                # `off && '' || token` still sent the GHCR token to Docker Hub,
                # and the runner rejects '' / null inside `credentials`.
                assert spec["credentials"] == _SERVICE_CREDENTIALS, (
                    f"{name}.{svc}: the GHCR token must not be sent to Docker Hub")
    assert seen >= 2
