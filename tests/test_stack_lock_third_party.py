# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Third-party images the stack runs by tag are pinned by the signed lock.

On the 0.6.3 -> 0.6.4 roll (2026-10-15) every image pulled by digest in
about ten seconds except `ollama/ollama:latest`: 91.6 s, a moved upstream
tag, and no release recorded which ollama ran. Compose now names a FIXED
version, the lock job resolves that tag's digest into a
`<name>@sha256:` row (scripts/stack-lock-third-party.py), the launcher
exports it like any image row, and the CLI never stages it for nodes.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

from tests.test_stack_lock_reader import LOCK, _exported_for

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "stack-lock-third-party.py"
D = "sha256:" + "a" * 64


def _mod():
    spec = importlib.util.spec_from_file_location("stack_lock_third_party", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = _mod()
COMPOSE = (ROOT / "docker-compose.cluster.yml").read_text()


def test_compose_names_one_fixed_nginx_version():
    v = M.compose_version("nginx", COMPOSE)
    assert re.fullmatch(r"[0-9][A-Za-z0-9._-]*", v), v


@pytest.mark.parametrize("text, why", [
    ("    image: ${NGINX_IMAGE:-nginx:latest${NOO_IMAGE_DIGEST_NGINX:-}}\n", "latest"),
    ("    image: ${NGINX_IMAGE:-nginx:1.0.0${NOO_IMAGE_DIGEST_NGINX:-}}\n"
     "    image: ${NGINX_IMAGE:-nginx:1.0.0}\n", "carry the"),
    ("    image: ${NGINX_IMAGE:-nginx:1.0.0${NOO_IMAGE_DIGEST_NGINX:-}}\n"
     "    image: ${NGINX_IMAGE:-nginx:1.0.1${NOO_IMAGE_DIGEST_NGINX:-}}\n", "several versions"),
    ("    image: nginx:latest\n", "no compose service"),
    ("    image: nginx:1.27-alpine\n", "no compose service"),
])
def test_a_compose_file_the_lock_cannot_pin_is_refused(text, why):
    with pytest.raises(M.LockError, match=why):
        M.compose_version("nginx", text)


def test_rows_writes_a_lock_row_from_the_resolved_digest(tmp_path, monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(M, "resolve", lambda ref: seen.append(ref) or D)
    compose = tmp_path / "c.yml"
    compose.write_text("    image: ${NGINX_IMAGE:-nginx:9.9.9${NOO_IMAGE_DIGEST_NGINX:-}}\n")
    assert M.main(["rows", "--out", str(tmp_path / "digests"), "--compose", str(compose), "--only", "nginx"]) == 0
    assert seen == ["docker.io/library/nginx:9.9.9"]
    assert (tmp_path / "digests" / "nginx").read_text() == f"nginx@{D}\n"


def test_rows_fails_the_job_on_latest(tmp_path):
    compose = tmp_path / "c.yml"
    compose.write_text("    image: ${NGINX_IMAGE:-nginx:latest${NOO_IMAGE_DIGEST_NGINX:-}}\n")
    assert M.main(["rows", "--out", str(tmp_path / "d"), "--compose", str(compose), "--only", "nginx"]) == 1
    assert not (tmp_path / "d").exists()


def test_the_launcher_exports_the_nginx_row():
    got = _exported_for(LOCK + f"nginx@{D}\n")
    assert got["NOO_IMAGE_DIGEST_NGINX"] == f"@{D}"


def test_the_lock_job_pins_third_party_rows_before_signing_and_without_the_seed():
    wf = yaml.safe_load((ROOT / ".github/workflows/images-release.yml").read_text())
    steps = wf["jobs"]["lock"]["steps"]
    names = [s.get("name", "") for s in steps]
    pin = next(i for i, s in enumerate(steps) if "stack-lock-third-party.py rows --out digests" in s.get("run", ""))
    sign = next(i for i, n in enumerate(names) if n.startswith("Assemble + sign"))
    download = max(i for i, s in enumerate(steps) if "download-artifact" in s.get("uses", ""))
    assert download < pin < sign, names
    assert "NOO_RELEASE_SIGNING_SEED" not in str(steps[pin]), "the seed belongs to the signing step alone"


def test_the_cli_never_stages_a_third_party_row():
    rs = (ROOT / "noo-cli/src/commands/image_stage.rs").read_text()
    rows = set(re.findall(r'"([a-z0-9-]+)"', re.search(r"THIRD_PARTY_LOCK_ROWS: &\[&str\] = &\[([^\]]*)\]", rs).group(1)))
    assert rows == set(M.THIRD_PARTY), (rows, set(M.THIRD_PARTY))


def test_no_third_party_service_runs_an_unpinned_latest():
    """Every image compose runs is a local build, one of our release/mirror
    images, or pinned: a version tag, or `latest` only with a digest (nats)."""
    files = [ROOT / "docker-compose.cluster.yml", ROOT / "docker-compose.dist.yml"]
    bad = []
    for f in files:
        for name, svc in (yaml.safe_load(f.read_text()).get("services") or {}).items():
            img = str((svc or {}).get("image", ""))
            if not img or "build" in (svc or {}) or img.startswith(("${NOO_IMAGE_PREFIX", "${NOO_BASE_REGISTRY", "noomesh/", "noo-")):
                continue
            # the effective default of `${VAR:-default}`
            default = re.sub(r"^\$\{[A-Z0-9_]+:-(.*)\}$", r"\1", img)
            if re.search(r":latest(\b|\$)", default) and "@sha256:" not in default:
                bad.append(f"{f.name}:{name}: {img}")
    assert not bad, f"third-party images on a moving tag (pin a version; see scripts/stack-lock-third-party.py): {bad}"


# ── every runtime third-party image is a lock row (image-pin) ──────────────

RUNTIME = {"nats", "nginx", "redis", "loki", "prometheus", "alertmanager", "grafana",
           "node-exporter", "tei", "tei-cpu", "vllm"}


def test_every_runtime_third_party_image_is_a_signed_lock_row():
    assert set(M.THIRD_PARTY) == RUNTIME
    for name in RUNTIME:
        v = M.compose_version(name, COMPOSE)   # raises unless every service carries the hook
        assert v != "latest", name


def test_compose_has_no_third_party_image_without_a_digest_hook():
    """A new `image:` of a third-party repository that is neither a lock row nor
    a local build fails here, so the lock cannot silently stop covering the stack."""
    services = yaml.safe_load(COMPOSE)["services"]
    unpinned = []
    for n, svc in services.items():
        img = str((svc or {}).get("image", ""))
        if not img or "build" in svc or "${NOO_IMAGE_PREFIX" in img or img.startswith(("noomesh/", "noo-")):
            continue
        if "NOO_IMAGE_DIGEST_" not in img:
            unpinned.append(f"{n}: {img}")
    assert not unpinned, unpinned


def test_nats_default_is_a_version_with_a_dev_digest_not_latest():
    services = yaml.safe_load(COMPOSE)["services"]
    img = services["nats"]["image"]
    assert "nats:latest" not in img and "${NOO_IMAGE_DIGEST_NATS:-@sha256:" in img, img
    assert M.compose_version("nats", COMPOSE) == re.search(r"nats:(\d+\.\d+\.\d+)", img).group(1)


def test_tei_gpu_and_cpu_are_separate_rows():
    assert M.compose_version("tei", COMPOSE) == "1.6"
    assert M.compose_version("tei-cpu", COMPOSE) == "cpu-1.6"


def test_the_gateway_forwards_the_locked_backend_refs_at_the_compose_version():
    env = yaml.safe_load(COMPOSE)["services"]["gateway"]["environment"]
    env = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in env if isinstance(e, str) and "=" in e}
    v = M.compose_version("vllm", COMPOSE)
    assert env["NOO_BACKEND_IMAGE_VLLM"] == f"${{VLLM_IMAGE:-vllm/vllm-openai:{v}${{NOO_IMAGE_DIGEST_VLLM:-}}}}"
    assert env["NOO_BACKEND_IMAGE_VLLM_SECONDARY"] == f"${{VLLM2_IMAGE:-vllm/vllm-openai:{v}${{NOO_IMAGE_DIGEST_VLLM:-}}}}"
    # Ollama on a node is OUR hardened image (docker/Dockerfile.ollama, lock row
    # `ollama`, staged on the rail); upstream is the agent's fallback only (i323).
    assert env["NOO_BACKEND_IMAGE_OLLAMA"] == (
        "${OLLAMA_IMAGE:-${NOO_IMAGE_PREFIX:-noomesh}/ollama:${NOO_IMAGE_TAG:-latest}${NOO_IMAGE_DIGEST_OLLAMA:-}}")



def test_node_defaults_name_the_compose_versions():
    go = (ROOT / "node-agent-go/internal/docker/backends.go").read_text()
    assert f"vllm/vllm-openai:{M.compose_version('vllm', COMPOSE)}" in go
    assert "vllm-openai:latest" not in go and "ollama/ollama:latest" not in go


def test_lock_job_signs_the_tag_into_the_lock():
    wf = (ROOT / ".github/workflows/images-release.yml").read_text()
    assert '{ echo "# stack $TAG"; echo "# mesh-migration-head $head"; cat digests/* | sort; } > "stack-$TAG.lock"' in wf


def test_lock_job_signs_the_migration_head_from_a_seedless_step():
    """The rollback preflight (rehearsal 0.6.7-rc.1 F2) trusts this line, so it
    is inside the signed bytes, computed before the signing CLI is fetched, and
    the signing step refuses a value that is not a revision id."""
    wf = (ROOT / ".github/workflows/images-release.yml").read_text()
    computed = wf.index("scripts/mesh-migration-head.sh > mesh-migration-head.txt")
    assert computed < wf.index("Fetch and verify the signing CLI")
    assemble = wf.index('echo "# mesh-migration-head $head"')
    assert wf.index('case "$head" in [0-9][0-9][0-9]_*)') < assemble
    assert assemble < wf.index('security release-sign "stack-$TAG.lock"')


def _lib_dist_fn(name):
    src = (ROOT / "scripts/lib-dist.sh").read_text()
    start = src.index(f"{name}() {{")
    return src[start:src.index("\n}\n", start) + 3]


def _run_third_party_check(pins, ref):
    import subprocess
    pin_arr = " ".join(f'"{p}"' for p in pins)
    script = (f"set -u\n_DIST_PINS=({pin_arr})\nDIST_TAG=v9.9.9\n"
              f"{_lib_dist_fn('dist_third_party_row')}\n{_lib_dist_fn('dist_assert_third_party_ref')}\n"
              f'dist_assert_third_party_ref "{ref}"\n')
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


def test_launcher_refuses_a_locked_third_party_ref_without_its_pin():
    pin = f"NOO_IMAGE_DIGEST_REDIS=@{D}"
    base = "ghcr.io/noomesh/dhi/redis:8.6-debian13-dev"
    assert _run_third_party_check([pin], f"{base}@{D}").returncode == 0
    r = _run_third_party_check([pin], base)                       # a bare tag: refused
    assert r.returncode == 1 and "no digest" in r.stderr, r.stderr
    other = "sha256:" + "b" * 64
    r = _run_third_party_check([pin], f"{base}@{other}")          # another release's digest
    assert r.returncode == 1 and "not in stack.lock" in r.stderr, r.stderr


def test_launcher_warns_but_starts_when_the_lock_predates_the_row():
    r = _run_third_party_check([f"NOO_IMAGE_DIGEST_GATEWAY=@{D}"], "ghcr.io/noomesh/dhi/redis:8.6-debian13-dev")
    assert r.returncode == 0 and "not pinned by stack.lock" in r.stderr, r.stderr


def test_the_launcher_no_longer_skips_the_base_registry():
    src = (ROOT / "scripts/lib-dist.sh").read_text()
    body = _lib_dist_fn("dist_assert_pull_refs")
    assert 'dist_assert_third_party_ref "$_ref"' in body
    assert body.index("dist_assert_third_party_ref") < body.index('case "$_ref" in "$_base"/*) continue')
    assert "TEI TEI_CPU" in src


def test_every_lock_row_maps_to_a_launcher_repository_name():
    src = (ROOT / "scripts/lib-dist.sh").read_text()
    rows = set(re.findall(r"echo \"?([A-Z_ ]+?)\"? ;;", _lib_dist_fn("dist_third_party_row")))
    flat = {r for x in rows for r in x.split()}
    assert flat == {M.digest_var(n).removeprefix("NOO_IMAGE_DIGEST_") for n in M.THIRD_PARTY}, flat
