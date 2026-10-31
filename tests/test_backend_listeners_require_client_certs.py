# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every compose-run inference backend on the controller requires a client
certificate at the door a caller reaches, and no backend port is published.

Until 2026-09-28 the controller's vLLM served TLS only when `NOO_VLLM_TLS`
was set, and even then asked for no client certificate (`--ssl-ca-certs`
without `--ssl-cert-reqs`), and llama.cpp served plaintext on the compose
network: any process on `noo-cluster` could read every prompt and reply.
Ollama, TEI and the reranker were already behind stunnel sidecars with
`verify = 2`.

What this pins, from the shipped files (the compose projection with every
profile on, plus `docker/stunnel-*.conf`):

  1. every service in BACKEND_SERVICES is fronted by a `stunnel-<x>`
     service whose conf says `verify = 2` — or it is in PLAINTEXT_EXCEPTIONS
     with a reason. vLLM terminated its own TLS (`--ssl-cert-reqs 2`) until
     its compose services moved behind doors like the agent's (#522);
  1a. (door generation 3) the fronted backend runs in its sidecar's
     network namespace, bound to 127.0.0.1; the sidecar accepts on its own
     hostname and connects to loopback — so it is the ONLY door;
  2. no backend publishes a host port, and no sidecar does either — except
     the mTLS doors in SIDECAR_LOOPBACK_DOORS (stunnel-ollama-embed on
     loopback, for the controller's own host agent — an earlier change), which
     must publish exactly that and no more;
  3. every URL in compose (base + overlays) that names vllm or llamacpp is
     https, points llama.cpp at its sidecar, and the service carrying it
     holds a client certificate (NOO_TLS_CERT + NOO_TLS_KEY);
  4. the list of backends here is the list in the compose file — a new
     backend service is caught, not silently unguarded.

The noo-cli row `noo cluster verify --controller` → `backend tls` reads the
same files on the running controller (`cluster_verify.rs::backend_listener_check`);
this test is the build-time half.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from tests._compose_projection import ADDON_OVERLAYS, full_projection, load_raw, untag

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.cluster.yml"

# Every compose service that serves inference (chat, embeddings, rerank).
# Pinned against the file below: a service that looks like a backend (a
# vllm/llama/ollama/tei image, or a `noo-<x>` name in BACKEND_HINTS) and is
# not listed here fails test 4.
BACKEND_SERVICES = {
    "vllm": "stunnel-vllm",
    "vllm-secondary": "stunnel-vllm-secondary",
    "llamacpp": "stunnel-llamacpp",
    "ollama": "stunnel-ollama",
    "ollama-embed": "stunnel-ollama-embed",
    "ollama-embed-cpu": "stunnel-ollama-embed-cpu",
    "tei": "stunnel-tei",
    "tei-gpu": "stunnel-tei-gpu",
    "reranker": "stunnel-reranker",
    "airllm": "native",
}

# Backends that still serve plaintext, each with why it is named rather
# than fixed. This list is meant to be empty; every entry is a decision
# someone has to defend in a diff.
PLAINTEXT_EXCEPTIONS = {
    # Opt-in, undocumented as a served backend (docs/models/backends.md lists
    # it with no health path); the same private-network step covers it —
    # the design F.
    "airllm": "opt-in experimental backend — an earlier change",
}

# A sidecar allowed to publish its mTLS door on ONE loopback port, and why.
# The controller's own HOST agent has no compose DNS, so it reaches the
# standalone embedder at the sidecar's loopback publish, presenting its node
# leaf (node-agent-go backendrt/native.go laneTransport; provision renders
# OLLAMA_URL=https://127.0.0.1:11434 once this file declares the publish).
# the earlier change the RAW ollama-embed published 127.0.0.1:11434 in
# plaintext for that reader; a backend never publishes now. `noo cluster
# verify` → `backend tls` allows any loopback-only sidecar publish; this
# build-time half pins the one that exists.
SIDECAR_LOOPBACK_DOORS = {
    "stunnel-ollama-embed": "127.0.0.1:11434:11434",
}

# Image / name fragments that mark a service as an inference backend, for
# test 4's completeness check.
BACKEND_HINTS = ("vllm", "llama", "ollama", "text-embeddings-inference", "airllm")


@pytest.fixture(scope="module")
def services() -> dict:
    return full_projection()["services"]


def _command_text(svc: dict) -> str:
    """The command as code: an `sh -c` script's comment lines are dropped, so
    a comment that explains what used to gate TLS does not read as the gate."""
    cmd = svc.get("command") or []
    text = cmd if isinstance(cmd, str) else "\n".join(str(c) for c in cmd)
    return "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))


def _stunnel_conf(sidecar: str) -> str:
    name = sidecar.removeprefix("stunnel-")
    path = ROOT / "docker" / f"stunnel-{name}.conf"
    assert path.is_file(), f"{sidecar} has no {path.name}"
    return path.read_text()


def _conf_requires_client_cert(conf: str) -> bool:
    for line in conf.splitlines():
        code = line.split(";")[0].strip().replace(" ", "")
        if code == "verify=2":
            return True
    return False


def _mounts(svc: dict) -> list[str]:
    out = []
    for v in svc.get("volumes") or []:
        out.append(v if isinstance(v, str) else f"{v.get('source', '')}:{v.get('target', '')}")
    return out


def test_every_backend_door_requires_a_client_certificate(services):
    checked = 0
    for name, front in sorted(BACKEND_SERVICES.items()):
        svc = services.get(name)
        assert svc is not None, f"{name} vanished from the compose projection — update BACKEND_SERVICES"
        if name in PLAINTEXT_EXCEPTIONS:
            continue
        checked += 1
        assert front != "native", f"{name} has no door in front of it: every backend is fronted or a named exception"
        sidecar = services.get(front)
        assert sidecar is not None, f"{name} is fronted by {front}, which is not in the compose file"
        assert set(sidecar.get("profiles") or []) == set(svc.get("profiles") or []), (
            f"{front} and {name} carry different profiles — one could run without the other"
        )
        conf_mounts = [m for m in _mounts(sidecar) if "/etc/stunnel/stunnel.conf" in m]
        assert conf_mounts, f"{front} mounts no stunnel.conf"
        assert _conf_requires_client_cert(_stunnel_conf(front)), (
            f"docker/{front}.conf does not set verify = 2: the sidecar admits a caller with no client certificate"
        )
        conf = _stunnel_conf(front)
        # Door generation 3 (F-ii): the backend lives in the sidecar's
        # network namespace on loopback, so the sidecar is the ONLY door.
        assert re.search(r"^\s*connect\s*=\s*127\.0\.0\.1:\d+\s*$", conf, re.M), (
            f"docker/{front}.conf does not forward to the backend on loopback"
        )
        assert svc.get("network_mode") == f"service:{front}", (
            f"{name} is not in {front}'s network namespace (network_mode: service:{front}): "
            "its plain port is reachable by every container on its network"
        )
        assert not svc.get("networks") and not svc.get("ports"), f"{name} joins a network or publishes a port of its own"
        hostname = sidecar.get("hostname")
        assert hostname and re.search(rf"^\s*accept\s*=\s*{re.escape(hostname)}:\d+\s*$", conf, re.M), (
            f"docker/{front}.conf must accept on the sidecar's hostname ({hostname!r}, its bridge address), "
            "never 0.0.0.0, which would also take the backend's loopback port"
        )
        # The bind is an env var (llama.cpp, Ollama, TEI) or, for vLLM, the
        # command line it builds.
        bind = f"{svc.get('environment')} {_command_text(svc)}"
        assert "0.0.0.0" not in bind, f"{name} binds 0.0.0.0"
        assert "127.0.0.1" in bind, f"{name} does not bind its listener to 127.0.0.1"
    assert checked >= 6, f"only {checked} backend doors checked — the parse is not looking at the file it was written for"


def test_a_door_restart_restarts_its_backend(services):
    """i317 e1: a backend in its door's network namespace stays in the OLD
    namespace when the door alone restarts, alive and unreachable. Compose
    restarts it with the door only when the dependency says `restart: true`
    (a restart outside compose is the node agent's door_children.go)."""
    checked = 0
    for name, front in sorted(BACKEND_SERVICES.items()):
        svc = services.get(name)
        if svc is None or svc.get("network_mode") != f"service:{front}":
            continue
        checked += 1
        deps = svc.get("depends_on")
        assert isinstance(deps, dict) and front in deps, (
            f"{name} must depend on {front} in the long form, with restart: true"
        )
        assert deps[front].get("restart") is True, (
            f"{name}'s depends_on {front} lacks restart: true: restarting the door strands {name}"
        )
    assert checked >= 6, f"only {checked} fronted backends checked — the parse is not looking at the file it was written for"


def _published(svc: dict) -> list[str]:
    out = []
    for p in svc.get("ports") or []:
        if isinstance(p, str):
            out.append(p)
        else:
            out.append(f"{p.get('host_ip', '')}:{p.get('published', '')}:{p.get('target', '')}")
    return out


def _publish_problems(services: dict) -> list[str]:
    """Every publish rule 2 forbids, as messages (empty = the rule holds)."""
    problems = []
    for name in sorted(BACKEND_SERVICES):
        if name in PLAINTEXT_EXCEPTIONS:
            continue
        ports = _published(services[name])
        if ports:
            problems.append(f"{name} publishes a host port: {ports}")
        front = BACKEND_SERVICES[name]
        if front == "native":
            continue
        sports = _published(services[front])
        allowed = SIDECAR_LOOPBACK_DOORS.get(front)
        if allowed is None:
            if sports:
                problems.append(f"{front} publishes a host port: {sports}")
        elif sports != [allowed]:
            problems.append(
                f"{front} may publish exactly its loopback mTLS door {allowed} and nothing else; it publishes {sports}"
            )
    return problems


def test_no_backend_or_sidecar_publishes_a_host_port(services):
    assert not _publish_problems(services), _publish_problems(services)
    # And the door the host agent dials IS published (the parse is not vacuous).
    for sidecar, bind in SIDECAR_LOOPBACK_DOORS.items():
        assert _published(services[sidecar]) == [bind], f"{sidecar} does not publish {bind}"
        assert bind.startswith("127.0.0.1:"), f"{sidecar}'s door is not a loopback bind: {bind}"


def test_the_publish_rule_catches_each_regression(services):
    """Planted: the pre-1245 plaintext publish, a LAN bind on the door, a second port."""
    import copy

    pre_1245 = copy.deepcopy(services)
    pre_1245["ollama-embed"]["ports"] = pre_1245["stunnel-ollama-embed"].pop("ports")
    assert any("ollama-embed publishes a host port" in p for p in _publish_problems(pre_1245))
    for bad in (["0.0.0.0:11434:11434"], ["11434:11434"], ["127.0.0.1:11434:11434", "127.0.0.1:11435:11435"]):
        planted = copy.deepcopy(services)
        planted["stunnel-ollama-embed"]["ports"] = bad
        assert _publish_problems(planted), f"{bad} passed the publish rule"


def test_the_exception_lists_name_only_services_that_exist(services):
    for name in PLAINTEXT_EXCEPTIONS:
        assert name in BACKEND_SERVICES, f"{name} is excepted but is not a backend service"
        assert name in services, f"{name} is excepted but not in the compose file — drop the exception"
    for sidecar in SIDECAR_LOOPBACK_DOORS:
        assert sidecar in BACKEND_SERVICES.values(), f"{sidecar} is not a backend's sidecar"
        assert sidecar in services, f"{sidecar} is allowed a door but not in the compose file"


def _url_env_values() -> list[tuple[str, str, str, dict]]:
    """(service, key, value, service dict) for every env value naming vllm or llamacpp, from
    the projection (overlay env is inherited at compose time)."""
    out = []
    for name, svc in full_projection()["services"].items():
        env = svc.get("environment") or {}
        items = env.items() if isinstance(env, dict) else (str(e).partition("=")[::2] for e in env)
        for k, v in items:
            v = "" if v is None else str(v)
            if re.search(r"(noo-)?(vllm|llamacpp)(-secondary)?:\d+", v):
                out.append((name, k, v, svc))
    return out


def test_every_vllm_and_llamacpp_url_in_compose_is_https_with_a_client_cert():
    found = _url_env_values()
    # Since i145 no service is handed a backend URL at all (the worker's
    # PAGEINDEX_LLM_URL was the last): every LLM call goes through the
    # gateway. The parse is checked on a sample so an empty result means
    # "none", not "blind".
    sample = "https://noo-vllm:8000"
    assert re.search(r"(noo-)?(vllm|llamacpp)(-secondary)?:\d+", sample), "the URL parse is blind"
    for name, key, value, svc in found:
        env = svc.get("environment") or {}
        env = env if isinstance(env, dict) else dict(str(e).partition("=")[::2] for e in env)
        for url in re.findall(r"[a-z]+://[^\s'\"}]+", value):
            assert url.startswith("https://"), f"{name}.{key} dials {url} in plaintext"
            if "llamacpp" in url:
                assert "noo-stunnel-llamacpp:" in url, f"{name}.{key} dials llama.cpp's plain port, not its sidecar: {url}"
        assert env.get("NOO_TLS_CERT") and env.get("NOO_TLS_KEY"), (
            f"{name} carries {key} but holds no client certificate (NOO_TLS_CERT/NOO_TLS_KEY) — "
            "the listener requires one"
        )


def test_the_backend_list_is_the_compose_file(services):
    """A new inference service must be listed here (and fronted), not slip in unguarded."""
    looks_like_backend = set()
    for name, svc in services.items():
        if name.startswith("stunnel-"):
            continue
        blob = f"{svc.get('image', '')} {name}"
        if any(h in blob for h in BACKEND_HINTS):
            looks_like_backend.add(name)
    unlisted = looks_like_backend - set(BACKEND_SERVICES)
    assert not unlisted, f"inference services not in BACKEND_SERVICES: {sorted(unlisted)}"
    assert looks_like_backend == set(BACKEND_SERVICES), (
        f"BACKEND_SERVICES lists services the file does not carry as backends: "
        f"{sorted(set(BACKEND_SERVICES) - looks_like_backend)}"
    )


def test_the_checker_catches_an_open_door():
    """The rule itself, planted: a conf without verify = 2 is refused."""
    assert _conf_requires_client_cert("[x]\nverify = 2\n")
    assert _conf_requires_client_cert("[x]\nverify=2 ; trailing comment\n")
    assert not _conf_requires_client_cert("[x]\n; verify = 2\nverify = 0\n")
    assert not _conf_requires_client_cert("[x]\ncert = /tls/x.crt\n")


def test_the_overlays_as_written_name_no_plaintext_backend_url():
    """Overlays as written too (a site copy of one is read on its own)."""
    for overlay in ADDON_OVERLAYS:
        text = (ROOT / overlay).read_text()
        for m in re.finditer(r"http://[^\s'\"}]*(noo-)?(vllm|llamacpp)[^\s'\"}]*", text):
            pytest.fail(f"{overlay} names a plaintext backend URL: {m.group(0)}")
    text = COMPOSE.read_text()
    code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
    for m in re.finditer(r"http://[^\s'\"}]*(noo-)?(vllm|llamacpp)[^\s'\"}]*", code):
        pytest.fail(f"docker-compose.cluster.yml names a plaintext backend URL: {m.group(0)}")
