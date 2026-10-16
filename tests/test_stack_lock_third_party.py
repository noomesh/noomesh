# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Third-party images the stack runs by tag are pinned by the signed lock.

On the 0.6.3 -> 0.6.4 roll (2026-10-15) every image pulled by digest in
about ten seconds except `ollama/ollama:latest`: 91.6 s, a moved upstream
tag, and no release recorded which ollama ran. Compose now names a FIXED
ollama version, the lock job resolves that tag's digest into an
`ollama@sha256:` row (scripts/stack-lock-third-party.py), the launcher
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


def test_compose_names_one_fixed_ollama_version():
    v = M.compose_version("ollama", COMPOSE)
    assert re.fullmatch(r"\d+\.\d+\.\d+", v), v
    services = yaml.safe_load(COMPOSE)["services"]
    runs = {n for n, s in services.items() if "ollama/ollama" in str(s.get("image", ""))}
    assert runs == {"ollama", "ollama-embed", "ollama-embed-cpu"}, runs
    for n in runs:
        assert services[n]["image"] == f"${{OLLAMA_IMAGE:-ollama/ollama:{v}${{NOO_IMAGE_DIGEST_OLLAMA:-}}}}", n


@pytest.mark.parametrize("text, why", [
    ("    image: ${OLLAMA_IMAGE:-ollama/ollama:latest${NOO_IMAGE_DIGEST_OLLAMA:-}}\n", "latest"),
    ("    image: ${OLLAMA_IMAGE:-ollama/ollama:1.0.0${NOO_IMAGE_DIGEST_OLLAMA:-}}\n"
     "    image: ${OLLAMA_IMAGE:-ollama/ollama:1.0.0}\n", "carry the"),
    ("    image: ${OLLAMA_IMAGE:-ollama/ollama:1.0.0${NOO_IMAGE_DIGEST_OLLAMA:-}}\n"
     "    image: ${OLLAMA_IMAGE:-ollama/ollama:1.0.1${NOO_IMAGE_DIGEST_OLLAMA:-}}\n", "several versions"),
    ("    image: ollama/ollama:latest\n", "no compose service"),
    ("    image: nginx:1.27-alpine\n", "no compose service"),
])
def test_a_compose_file_the_lock_cannot_pin_is_refused(text, why):
    with pytest.raises(M.LockError, match=why):
        M.compose_version("ollama", text)


def test_rows_writes_a_lock_row_from_the_resolved_digest(tmp_path, monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(M, "resolve", lambda ref: seen.append(ref) or D)
    compose = tmp_path / "c.yml"
    compose.write_text("    image: ${OLLAMA_IMAGE:-ollama/ollama:9.9.9${NOO_IMAGE_DIGEST_OLLAMA:-}}\n")
    assert M.main(["rows", "--out", str(tmp_path / "digests"), "--compose", str(compose)]) == 0
    assert seen == ["docker.io/ollama/ollama:9.9.9"]
    assert (tmp_path / "digests" / "ollama").read_text() == f"ollama@{D}\n"


def test_rows_fails_the_job_on_latest(tmp_path):
    compose = tmp_path / "c.yml"
    compose.write_text("    image: ${OLLAMA_IMAGE:-ollama/ollama:latest${NOO_IMAGE_DIGEST_OLLAMA:-}}\n")
    assert M.main(["rows", "--out", str(tmp_path / "d"), "--compose", str(compose)]) == 1
    assert not (tmp_path / "d").exists()


def test_the_launcher_exports_the_ollama_row():
    got = _exported_for(LOCK + f"ollama@{D}\n")
    assert got["NOO_IMAGE_DIGEST_OLLAMA"] == f"@{D}"


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
