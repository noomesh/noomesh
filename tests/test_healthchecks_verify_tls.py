# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No healthcheck turns TLS verification off.

A healthcheck decides whether Docker calls a container alive. One that
skips verification cannot tell the service from anything else that binds
the port in its namespace — and, worse, it is a `-k` that ships in the
product, read and copied by the next person who needs to reach the
service. Found 2026-09-29 in `dev`:

* the gateway's compose healthcheck ran `ssl._create_unverified_context()`
  OVER the image's own verified probe (`noo-gateway --health` checks the
  leaf against NOO_TLS_CA), so the verified probe never ran on a
  compose-started gateway;
* the nvidia-exporter healthcheck (compose and Dockerfile) set
  `check_hostname=False` / `CERT_NONE` and then fell back to plain
  `http://localhost:9400` — which that exporter refuses to serve, so the
  fallback only ever masked a broken TLS probe as "unhealthy" with no
  reason.

This guard reads every service's healthcheck across the composed
projection (base + every add-on overlay) and every `HEALTHCHECK` in the
tree's Dockerfiles, and refuses the verification-off idioms. Nothing is
allow-listed; an entry added later must name its reason, and a stale one
fails, so the list cannot rot.

Planted: `ctx.check_hostname=False` back into the nvidia-exporter compose
healthcheck → `test_no_compose_healthcheck_disables_verification` fails
naming it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._compose_projection import raw_services_union

ROOT = Path(__file__).resolve().parents[1]

# Verification-off idioms, any language a healthcheck is written in.
FORBIDDEN = (
    re.compile(r"_create_unverified_context"),
    re.compile(r"CERT_NONE"),
    re.compile(r"check_hostname\s*=\s*False"),
    re.compile(r"verify\s*=\s*False"),
    re.compile(r"(?<![\w-])curl\b[^|;&]*\s-k(?:\s|$)"),
    re.compile(r"--insecure\b"),
    re.compile(r"--no-check-certificate\b"),
    re.compile(r"insecure_skip_verify:\s*true"),
)

# file → the one substring that is allowed there, and why. Empty since the
# sandbox image dropped its verification-off probe (followups 510 + 1241 §3);
# the stale-entry check stays so a future entry cannot rot.
ALLOWED: dict[str, str] = {}


def _hits(text: str) -> list[str]:
    return [p.pattern for p in FORBIDDEN if p.search(text)]


def _dockerfiles() -> list[Path]:
    files = sorted(ROOT.glob("docker/Dockerfile*")) + sorted(ROOT.glob("docker/*/Dockerfile*"))
    files += sorted(p for p in ROOT.glob("src/noomesh/**/Dockerfile*") if ".worktrees" not in p.parts)
    return [p for p in files if p.is_file()]


def _healthcheck_instructions(dockerfile: Path) -> list[str]:
    """Each HEALTHCHECK instruction, continuation lines joined, comments out."""
    lines = [ln for ln in dockerfile.read_text().splitlines() if not ln.lstrip().startswith("#")]
    joined = re.sub(r"\\\n", " ", "\n".join(lines))
    return [m.group(0) for m in re.finditer(r"^HEALTHCHECK\b.*$", joined, re.M)]


def test_no_compose_healthcheck_disables_verification() -> None:
    svcs = raw_services_union()
    seen = 0
    for name, svc in sorted(svcs.items()):
        hc = svc.get("healthcheck")
        if not isinstance(hc, dict) or not hc.get("test"):
            continue
        seen += 1
        test = hc["test"]
        text = " ".join(test) if isinstance(test, list) else str(test)
        assert not _hits(text), f"{name} healthcheck turns verification off: {_hits(text)}\n  {text}"
    assert seen >= 6, f"only {seen} healthchecks found — vacuous"


def test_the_gateway_runs_its_images_verified_probe() -> None:
    """No compose override: the image's HEALTHCHECK (`noo-gateway --health`,
    which verifies against NOO_TLS_CA) is the probe. An override here — even
    a verified one — is a second declaration of the same fact."""
    svcs = raw_services_union()
    assert "healthcheck" not in svcs["gateway"], "the gateway service overrides the image's verified probe"
    df = (ROOT / "docker/Dockerfile.gateway-rust").read_text()
    hc = _healthcheck_instructions(ROOT / "docker/Dockerfile.gateway-rust")
    assert hc, "the gateway image has no HEALTHCHECK — with the compose override gone, nothing probes it"
    assert any('"--health"' in h and "noo-gateway" in h for h in hc), hc
    assert "healthcheck: disable" not in df


def test_no_dockerfile_healthcheck_disables_verification() -> None:
    files = _dockerfiles()
    assert len(files) >= 4, files
    stale_allow = set(ALLOWED)
    for df in files:
        rel = df.relative_to(ROOT).as_posix()
        for instr in _healthcheck_instructions(df):
            if rel in ALLOWED and ALLOWED[rel] in instr:
                stale_allow.discard(rel)
                continue
            assert not _hits(instr), f"{rel}: HEALTHCHECK turns verification off: {_hits(instr)}\n  {instr}"
    assert not stale_allow, f"allow-list entries no longer match anything — remove them: {sorted(stale_allow)}"


def test_the_nvidia_exporter_probes_with_its_own_leaf_and_no_plaintext_fallback() -> None:
    """Both copies of the probe (compose and image): CA from NOO_TLS_CA,
    hostname checked (default), the container's leaf presented, and no
    `http://` anywhere — the exporter refuses to serve it."""
    svcs = raw_services_union()
    test = svcs["nvidia-exporter"]["healthcheck"]["test"]
    compose_probe = " ".join(test)
    image_probe = " ".join(_healthcheck_instructions(ROOT / "docker/Dockerfile.nvidia-exporter"))
    for where, probe in (("compose", compose_probe), ("Dockerfile", image_probe)):
        assert "http://" not in probe, f"{where}: a plaintext fallback is back"
        assert "NOO_TLS_CA" in probe and "NOO_TLS_CERT" in probe and "NOO_TLS_KEY" in probe, f"{where}: {probe}"
        assert "load_cert_chain" in probe and "cafile=" in probe, f"{where}: {probe}"
        assert "https://localhost:9400" in probe, f"{where}: {probe}"


@pytest.mark.parametrize("pattern", ["curl -k https://x", "curl --insecure https://x", "wget --no-check-certificate", "verify=False", "insecure_skip_verify: true"])
def test_the_idioms_are_actually_matched(pattern: str) -> None:
    """The guard is only as good as its regexes: each idiom must hit."""
    assert _hits(pattern), pattern


def test_ordinary_flags_are_not_false_positives() -> None:
    assert not _hits("curl -sk-free https://x"), "-sk-free is not -k"
    assert not _hits("wget -qO- http://127.0.0.1:8084/healthz")


def test_the_sandbox_has_one_probe_and_it_verifies_over_mtls() -> None:
    """The sandbox image declares no probe (it once shipped one with
    verification off, on a port nothing listened on); compose holds the only
    one, and it checks the server against the CA and presents the sandbox's
    own leaf, on the port the uvicorn command actually binds. Both executor
    services share it."""
    assert _healthcheck_instructions(ROOT / "docker/Dockerfile.sandbox") == ["HEALTHCHECK NONE"]
    svcs = raw_services_union()
    for name in ("sandbox", "sandbox-extra"):
        svc = svcs[name]
        cmd = svc["command"]
        port = cmd[cmd.index("--port") + 1]
        probe = " ".join(svc["healthcheck"]["test"])
        assert "cafile='/tls/ca.crt'" in probe, (name, probe)
        assert "load_cert_chain('/tls/services/sandbox/service.crt','/tls/services/sandbox/service.key')" in probe, (name, probe)
        assert f"https://localhost:{port}/health" in probe, (name, port, probe)
        assert "http://" not in probe, (name, probe)
