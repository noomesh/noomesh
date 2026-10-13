# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every backend the node agent starts requires a client certificate at the
door a caller reaches — the same set of doors the controller's compose file
fronts, and no raw backend port published on the host.

`tests/test_backend_listeners_require_client_certs.py` (#538) pins the
COMPOSE side: vLLM with `--ssl-cert-reqs 2`, everything else behind a
`stunnel-<x>` sidecar with `verify = 2`. Until 2026-09-29 the NODE side was
left behind: the agent-started vLLM got `--ssl-certfile` without
`--ssl-cert-reqs` (TLS, any client accepted) and only under `NOO_VLLM_TLS`,
and llama.cpp / ollama / TEI / the reranker served plaintext on the bridge.

What this pins, from the Go source (`node-agent-go/internal/docker/`):

  1. the agent-started vLLM script passes `--ssl-cert-reqs 2`, has no
     `NOO_VLLM_TLS` switch, and exits rather than serving plain;
  2. every other backend compose fronts is in the agent's door table
     (`backendDoors`) WITH a sidecar, the sidecar conf template says
     `verify = 2`, and the door ports match compose's accept ports;
  3. the node set equals the compose set (mapped by service name) minus
     the same named plaintext exceptions — a backend added to one side is
     caught on the other;
  4. `config.BackendTLSFlags` names exactly the fronted backends (the
     retired switches whose `false` refuses the agent's start), and
     `SchemeFor` reads no env;
  5. no backend or sidecar spec publishes a host port directly; the one
     binding is `doorpublish.go`'s, which publishes the DOOR on
     127.0.0.1 only (macOS, where Docker Desktop cannot route to a bridge
     IP) — never 0.0.0.0, never the raw port of a sidecar-fronted backend;
  6. the reconciler folds `BackendDoorGeneration` into the spec hash, so a
     pre-door container is recreated after the binary rolls.

Cross-language guard: reads Go source with regexes, no Go toolchain.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.test_backend_listeners_require_client_certs import BACKEND_SERVICES, PLAINTEXT_EXCEPTIONS

ROOT = Path(__file__).resolve().parents[1]
GO = ROOT / "node-agent-go" / "internal"
BACKENDS_GO = GO / "docker" / "backends.go"
CLIENT_GO = GO / "docker" / "client.go"
SIDECAR_GO = GO / "docker" / "sidecar.go"
CONFIG_GO = GO / "config" / "config.go"
RECONCILE_GO = GO / "reconcile" / "reconcile.go"

# compose service -> node backend key ("" = compose-only, no node counterpart)
COMPOSE_TO_NODE = {
    "vllm": "vllm",
    "vllm-secondary": "vllm",  # one spec on a node
    "llamacpp": "llamacpp",
    "ollama": "ollama",
    "tei": "embedding",
    "tei-gpu": "embedding",
    "reranker": "reranker",
    "ollama-embed": "",  # the standalone controller's loopback embedder; compose-only
    "ollama-embed-cpu": "",  # the optional CPU embedder (profile embed-cpu); compose-only
    "airllm": "airllm",
}

# Node-side plaintext exceptions: the same decision as the compose side, for
# the same reason. Meant to be empty.
NODE_PLAINTEXT_EXCEPTIONS = {
    "airllm": "opt-in experimental backend — an earlier change (same exception as compose)",
}


def _go_script(name: str, src: str) -> str:
    """The body of a Go raw-string const, comment lines (# …) dropped."""
    m = re.search(rf"const {name} = `(.*?)`", src, re.S)
    assert m, f"{name} not found"
    return "\n".join(l for l in m.group(1).splitlines() if not l.strip().startswith("#"))


def _go_map_entries(name: str, src: str) -> dict[str, str]:
    m = re.search(rf"var {name} = map\[string\]\w+\{{(.*?)\n\}}", src, re.S)
    assert m, f"{name} not found"
    return dict(re.findall(r'^\s*"([^"]+)":\s*(.*?),?\s*$', m.group(1), re.M))


def _backend_doors() -> dict[str, dict]:
    src = CLIENT_GO.read_text()
    entries = _go_map_entries("backendDoors", src)
    out = {}
    for key, body in entries.items():
        side = re.search(r'Sidecar:\s*"([^"]*)"', body)
        port = re.search(r"\bPort:\s*(\d+)", body)
        assert port, f"backendDoors[{key}] has no Port"
        out[key] = {"sidecar": side.group(1) if side else "", "port": int(port.group(1))}
    return out


def _compose_node_set() -> set[str]:
    out = set()
    for svc in BACKEND_SERVICES:
        if svc in PLAINTEXT_EXCEPTIONS:
            continue
        node = COMPOSE_TO_NODE.get(svc)
        assert node is not None, f"compose backend {svc} has no node mapping — add it to COMPOSE_TO_NODE"
        if node:
            out.add(node)
    return out


def test_the_agent_started_vllm_requires_a_client_certificate():
    script = _go_script("vllmEntrypointScript", BACKENDS_GO.read_text())
    assert "--ssl-cert-reqs 2" in script, "the node vLLM listener admits a caller with no client certificate"
    assert "NOO_VLLM_TLS" not in script, "the node vLLM gates TLS on NOO_VLLM_TLS — the listener must have no plaintext switch"
    assert "--ssl-certfile /app/pki/services/vllm/service.crt" in script
    assert re.search(r"exit 78", script), "a missing leaf must exit, not serve plain"
    spec = re.search(r'"vllm": \{(.*?)\n\t\},', BACKENDS_GO.read_text(), re.S).group(1)
    assert '"NOO_VLLM_TLS"' not in spec, "the vllm spec still passes NOO_VLLM_TLS into the container"
    assert "HealthcheckCmd: vllmHealthcheckCmd" in spec
    hc = re.search(r"const vllmHealthcheckCmd = `(.*?)`", BACKENDS_GO.read_text(), re.S).group(1)
    assert "load_cert_chain('/app/pki/services/vllm/service.crt'" in hc, "the healthcheck must present the container's own leaf"


def test_every_fronted_backend_has_a_sidecar_door_with_verify_2():
    doors = _backend_doors()
    conf = re.search(r'return fmt\.Sprintf\(`(.*?)`', SIDECAR_GO.read_text(), re.S).group(1)
    assert re.search(r"^verify = 2$", conf, re.M), "the sidecar conf template does not set verify = 2"
    assert "CAfile = /tls/ca.crt" in conf and "cert = /tls/services/%s/service.crt" in conf
    fronted = {k: v for k, v in doors.items() if v["sidecar"]}
    assert set(fronted) == {"llamacpp", "ollama", "embedding", "reranker"}, fronted
    # Door ports are compose's stunnel accept ports, so one URL reaches either.
    for key, d in fronted.items():
        svc = d["sidecar"]
        c = (ROOT / "docker" / f"stunnel-{svc}.conf").read_text()
        accept = re.search(r"^\s*accept\s*=\s*[\d.]+:(\d+)", c, re.M)
        assert accept, f"docker/stunnel-{svc}.conf has no accept line"
        assert int(accept.group(1)) == d["port"], f"{key}: node door port {d['port']} != compose stunnel-{svc} accept {accept.group(1)}"
    assert doors["vllm"]["sidecar"] == "" and doors["vllm"]["port"] == 8000


def test_the_node_door_set_is_the_compose_door_set():
    doors = _backend_doors()
    node_set = set(doors) - {"vllm-secondary"}
    compose_set = _compose_node_set()
    for name in NODE_PLAINTEXT_EXCEPTIONS:
        assert name in COMPOSE_TO_NODE.values(), f"{name} is excepted but is not a backend"
        assert name not in doors, f"{name} is excepted AND has a door — drop the exception"
    assert node_set == compose_set, (
        f"node doors {sorted(node_set)} != compose-fronted backends {sorted(compose_set)}: "
        "a backend fronted on one side is not on the other"
    )
    # And every backend the agent can start is either fronted or excepted.
    specs = set(re.findall(r'^\t"([a-z]+)": ', BACKENDS_GO.read_text(), re.M))
    assert specs >= {"vllm", "llamacpp", "ollama", "embedding", "reranker", "airllm"}, specs
    for b in specs:
        assert b in doors or b in NODE_PLAINTEXT_EXCEPTIONS, f"backend spec {b} has no door and no named exception"


def test_the_tls_flags_are_retired_and_name_the_fronted_backends():
    flags = _go_map_entries("BackendTLSFlags", CONFIG_GO.read_text())
    doors = _backend_doors()
    assert set(flags) == set(doors) - {"vllm-secondary"}, (flags, doors)
    assert flags["embedding"] == '"NOO_TEI_TLS"' and flags["reranker"] == '"NOO_RERANKER_TLS"'
    client = CLIENT_GO.read_text()
    fn = re.search(r"func SchemeFor\(backend string\) string \{(.*?)\n\}", client, re.S).group(1)
    assert "os.Getenv" not in fn, "SchemeFor reads an env switch again — the door is TLS by default"
    assert 'return "https"' in fn
    cfg = CONFIG_GO.read_text()
    assert "BackendTLSDowngradeAsked" in cfg and '"false", "0", "no", "off"' in cfg
    tls_fn = re.search(r"func \(c \*Config\) TLSServerConfig\(\).*?\n\}", cfg, re.S).group(0)
    assert "c.BackendTLSDowngradeAsked != \"\"" in tls_fn, "a false backend flag must refuse the start"


def test_no_backend_or_sidecar_publishes_a_host_port():
    for p in (BACKENDS_GO, SIDECAR_GO, CLIENT_GO):
        src = p.read_text()
        assert "PortBindings" not in src and "PublishAllPorts" not in src, f"{p.name} publishes a host port"


def test_the_only_publish_is_the_door_on_loopback():
    src = (GO / "docker" / "doorpublish.go").read_text()
    assert "PublishAllPorts" not in src and "0.0.0.0" not in src
    binds = re.findall(r'HostIP:\s*netip\.MustParseAddr\("([^"]+)"\)', src)
    assert binds == ["127.0.0.1"], f"doorpublish.go binds {binds}; the door is loopback-only"
    fn = re.search(r"func LoopbackDoorPublish\(\) bool \{(.*?)\}", src, re.S)
    assert fn and 'runtime.GOOS == "darwin"' in fn.group(1), "the loopback publish is the macOS answer only"
    # Callers publish the DOOR port: vLLM's own (Sidecar == ""), the sidecar's accept port.
    assert 'door.Sidecar == "" && LoopbackDoorPublish()' in BACKENDS_GO.read_text()
    assert "applyLoopbackDoor(cfg, hostCfg, door.Port)" in SIDECAR_GO.read_text()


def test_the_spec_hash_carries_the_door_generation():
    rec = RECONCILE_GO.read_text()
    fn = re.search(r"func specHash\(p placement\) string \{(.*?)\n\}", rec, re.S).group(1)
    assert "dockerpkg.BackendDoorGeneration" in fn, "a pre-door container would never be recreated after the binary rolls"
    gen = re.search(r"const BackendDoorGeneration = (\d+)", SIDECAR_GO.read_text())
    assert gen and int(gen.group(1)) >= 2


def test_the_door_check_runs_before_the_running_container_is_touched():
    src = BACKENDS_GO.read_text()
    fn = re.search(r"func \(c \*Client\) StartBackendSDK\(.*?\n\}\n", src, re.S).group(0)
    check = fn.index("backendDoorCheck(backend, mounts)")
    remove = fn.index("ContainerRemove(ctx, spec.ContainerName")
    assert check < remove, "a refused door would already have removed the running backend"


def test_the_parser_finds_what_it_is_written_for():
    assert len(_backend_doors()) >= 5
    assert len(_go_map_entries("BackendTLSFlags", CONFIG_GO.read_text())) == 5
    assert _go_script("vllmEntrypointScript", BACKENDS_GO.read_text()).count("\n") > 10
