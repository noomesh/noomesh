# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The standalone profile's embedder (`ollama-embed`) is dialled by every
container through its mTLS sidecar, never on its plain port.

Until 2026-09-29 `ollama-embed` was the named plaintext exception in
tests/test_backend_listeners_require_client_certs.py and in `noo cluster
verify`'s `backend tls` row: `OLLAMA_HOST=0.0.0.0` on the shared
`noo-cluster` network, and the gateway, the worker and trellion's embedder
pointed at `http://ollama-embed:11434` by onboard's topology env and the
launchers' default. Every prompt, every embedded document, readable by
any container on that network (grafana, loki, prometheus images included).

Now a `stunnel-ollama-embed` sidecar (`docker/stunnel-ollama-embed.conf`,
`verify = 2`, its own `ollama-embed` leaf) is the door, at
`https://noo-stunnel-ollama-embed:11434`. What this pins, from the shipped
files:

  1. the ONE URL onboard writes for the two standalone pointers
     (`PAGEINDEX_EMBEDDING_URL`, `OLLAMA_URL`; no LLM pointer since i145) and the
     launchers' default are that https door — and the plaintext literal is
     gone from every code line that used to write it;
  2. the leaf: `ollama-embed` is issued by onboard (SVC_LIST), its SANs carry
     the door's hostname, the key-reader table has its row, the conf is in
     the standalone deploy slice;
  3. the sidecar: same profile as the backend, forwards to it, mounts its own
     leaf, and its healthcheck presents THAT leaf through the door;
  4. no compose env value (base + overlays) names ollama-embed over http.

The loopback publish `127.0.0.1:11434` is the SIDECAR's:
the controller's own HOST agent (no compose DNS) dials the door there with
its node leaf, at the `OLLAMA_URL=https://127.0.0.1:11434` provision renders
once the compose file declares that publish; `ollama-embed` itself publishes
nothing. Until 1245 the raw container published it in plaintext for that
reader, whose ollama client presented no leaf.

The sibling test owns the door/port/conf rules that hold for every backend;
this one owns what is specific to the standalone path.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from tests._compose_projection import full_projection

ROOT = Path(__file__).resolve().parents[1]
STEPS = ROOT / "noo-cli/src/onboard/steps.rs"
PKI = ROOT / "noo-cli/src/pki.rs"
BUILD_RS = ROOT / "noo-cli/build.rs"
CONF = ROOT / "docker/stunnel-ollama-embed.conf"
LAUNCHERS = ("scripts/noomesh-start.sh", "scripts/noomesh-restart.sh")

DOOR = "https://noo-stunnel-ollama-embed:11434"
PLAIN = "http://ollama-embed:11434"
LEAF = "ollama-embed"
SIDECAR = "stunnel-ollama-embed"
SIDECAR_HOST = "noo-stunnel-ollama-embed"  # its compose hostname: the address its conf accepts on


def _code_lines(text: str, comment: str) -> list[str]:
    return [l for l in text.splitlines() if not l.strip().startswith(comment)]


def _rust_str_const(src: str, name: str) -> str:
    m = re.search(rf'const {re.escape(name)}: &str = "([^"]+)";', src)
    assert m, f"{name} is not defined in steps.rs"
    return m.group(1)


@pytest.fixture(scope="module")
def steps_src() -> str:
    return STEPS.read_text()


@pytest.fixture(scope="module")
def services() -> dict:
    return full_projection()["services"]


# ── 1. the URL onboard writes and the launchers default to ───────────────


def test_onboard_writes_the_https_door_for_every_standalone_pointer(steps_src):
    assert _rust_str_const(steps_src, "STANDALONE_OLLAMA_EMBED_URL") == DOOR
    body = steps_src[steps_src.index("fn apply_topology_env") :]
    body = body[: body.index("\n}\n")]
    keys = re.findall(r'\("(PAGEINDEX_EMBEDDING_URL|OLLAMA_URL|PAGEINDEX_LLM_URL)", (\w+)\)', body)
    assert sorted(k for k, _ in keys) == ["OLLAMA_URL", "PAGEINDEX_EMBEDDING_URL"], (
        f"apply_topology_env no longer writes the two standalone pointers from the const: {keys}"
    )
    for key, value in keys:
        assert value == "STANDALONE_OLLAMA_EMBED_URL", f"{key} is written from {value}, not the door const"


def test_the_plaintext_literal_is_gone_from_code(steps_src):
    for line in _code_lines(steps_src, "//"):
        assert PLAIN not in line, f"steps.rs writes the plaintext door again: {line.strip()}"
    for rel in LAUNCHERS:
        text = (ROOT / rel).read_text()
        for line in _code_lines(text, "#"):
            # An assignment or export of the literal is a default; the WARN
            # line that names it as the thing being replaced is not.
            if re.search(rf'(export\s+)?[A-Z_]+="?{re.escape(PLAIN)}"?', line) and not line.strip().startswith("echo"):
                pytest.fail(f"{rel} defaults to the plaintext door: {line.strip()}")


def test_the_launchers_default_to_the_same_door(steps_src):
    door = _rust_str_const(steps_src, "STANDALONE_OLLAMA_EMBED_URL")
    for rel in LAUNCHERS:
        text = (ROOT / rel).read_text()
        defaults = re.findall(r'export OLLAMA_URL="([^"]+)"', text)
        assert defaults, f"{rel} no longer defaults OLLAMA_URL on standalone — the parse found nothing"
        assert defaults == [door], f"{rel} defaults OLLAMA_URL to {defaults}, onboard writes {door}"
        # The legacy-literal rewrite names the same door (an exported value
        # beats .env in compose interpolation; the file converges on
        # `noo onboard --only env`).
        assert f'"$_v={door}"' in text, f"{rel} rewrites the legacy literal to something other than the door"
        assert f'"{PLAIN}"' in text, f"{rel} no longer recognises the legacy plaintext literal to rewrite it"


# ── 2. the leaf ──────────────────────────────────────────────────────────


def test_the_leaf_is_issued_and_its_sans_carry_the_door(steps_src):
    svc_list = steps_src[steps_src.index("const SVC_LIST") :]
    svc_list = svc_list[: svc_list.index("];")]
    assert f'"{LEAF}"' in _rust_code(svc_list), "ollama-embed is not in onboard's SVC_LIST — no leaf is issued"
    m = re.search(rf'"{LEAF}" => &\[([^\]]+)\]', steps_src)
    assert m, "svc_extra_hostnames has no ollama-embed row"
    sans = set(re.findall(r'"([^"]+)"', m.group(1)))
    host = DOOR.removeprefix("https://").split(":")[0]
    assert host in sans, f"the ollama-embed leaf's SANs {sorted(sans)} do not carry the door's hostname {host}"
    assert SIDECAR in sans, f"the compose alias {SIDECAR} is not in the SANs"


def _rust_code(src: str) -> str:
    return "\n".join(_code_lines(src, "//"))


def test_the_key_reader_table_has_the_row():
    assert re.search(rf'\("{LEAF}", KeyReader::ContainerUid\(65532\)\)', PKI.read_text()), (
        "pki.rs SERVICE_KEY_READERS has no ollama-embed row (the stunnel door runs as uid 65532, i132)"
    )


def test_the_conf_ships_in_the_standalone_slice():
    src = BUILD_RS.read_text()
    block = src[src.index("STANDALONE_FILES") : src.index("STANDALONE_DIRS")]
    assert '"docker/stunnel-ollama-embed.conf",' in block, "the sidecar conf is not in STANDALONE_FILES"


# ── 3. the sidecar ───────────────────────────────────────────────────────


def test_the_conf_requires_a_client_certificate_and_presents_its_own_leaf():
    code = [l.split(";")[0].strip() for l in CONF.read_text().splitlines()]
    code = [l for l in code if l]
    assert "verify = 2" in [l.replace("=", " = ").replace("  ", " ") for l in code] or any(
        l.replace(" ", "") == "verify=2" for l in code
    ), "docker/stunnel-ollama-embed.conf does not set verify = 2"
    # Door generation 3: ollama-embed lives in the sidecar's namespace on loopback.
    assert any(l.replace(" ", "") == "connect=127.0.0.1:11434" for l in code), "the conf does not forward to ollama-embed on loopback"
    assert any(l.replace(" ", "") == f"accept={SIDECAR_HOST}:11434" for l in code), "the conf does not accept on the sidecar's own address"
    assert any(l.replace(" ", "") == f"cert=/tls/services/{LEAF}/service.crt" for l in code), "the conf presents a leaf other than ollama-embed's"
    assert any(l.replace(" ", "") == "CAfile=/tls/ca.crt" for l in code), "the conf verifies against something other than the cluster CA"


def test_the_sidecar_fronts_the_backend_on_the_same_profile(services):
    backend, sidecar = services.get("ollama-embed"), services.get(SIDECAR)
    assert backend is not None and sidecar is not None, "ollama-embed or its sidecar vanished from the projection"
    assert set(sidecar.get("profiles") or []) == set(backend.get("profiles") or []) == {"standalone"}
    # The backend lives in the sidecar's network namespace, so it is the
    # backend that depends on the sidecar now (door generation 3).
    assert backend.get("network_mode") == f"service:{SIDECAR}", "ollama-embed is not in its door's namespace"
    assert SIDECAR in (backend.get("depends_on") or {}), "the backend does not depend on its door"
    assert sidecar.get("hostname") == SIDECAR_HOST, "the sidecar's hostname is not the name its conf accepts on"
    mounts = [v if isinstance(v, str) else f"{v.get('source')}:{v.get('target')}" for v in sidecar.get("volumes") or []]
    assert any(f"/tls/services/{LEAF}" in m and f"services/{LEAF}" in m for m in mounts), (
        f"the sidecar does not mount the {LEAF} leaf: {mounts}"
    )
    ports = [p if isinstance(p, str) else f"{p.get('host_ip', '')}:{p.get('published', '')}:{p.get('target', '')}" for p in sidecar.get("ports") or []]
    assert ports == ["127.0.0.1:11434:11434"], (
        f"the sidecar must publish exactly its loopback door for the host agent: {ports}"
    )
    assert not backend.get("ports"), f"ollama-embed publishes a host port — the plaintext door is back: {backend['ports']}"


def test_provision_points_the_self_node_at_the_door_only_once_it_is_declared():
    """The self-node's OLLAMA_URL is rendered by ONE function, which reads
    the compose declaration; neither render site carries a
    literal URL of its own any more."""
    text = (ROOT / "noo-cli/src/commands/provision.rs").read_text()
    sites = [l for l in _code_lines(text, "//") if 'vars.insert("ollama_url"' in l]
    assert len(sites) == 2, f"expected the two render sites (bundle + --local), found {sites}"
    for m in re.finditer(r'vars\.insert\("ollama_url",[^;]*;', text, re.S):
        assert "self_node_ollama_url(" in m.group(0), f"a render site bypasses self_node_ollama_url: {m.group(0)}"
        assert "http://" not in m.group(0), f"a render site hardcodes a URL: {m.group(0)}"
    fn = text[text.index("fn self_node_ollama_url("):]
    fn = fn[: fn.index("\n}\n")]
    assert '"https://127.0.0.1:11434"' in fn and "compose_publishes(" in fn and '"stunnel-ollama-embed"' in fn, fn
    assert ".noo-standalone" in fn, "the door is only run by the standalone profile"


def test_the_agent_lane_dials_an_https_base_with_the_node_leaf():
    """node-agent-go: the stack lane, its pull client and the inference proxy
    follow the base's scheme; none is a bare client for an https base."""
    native = (ROOT / "node-agent-go/internal/backendrt/native.go").read_text()
    code = "\n".join(_code_lines(native, "//"))
    assert "func laneTransport(" in code and "HTTPTransport()" in code, "the lane builds no TLS transport"
    assert "&http.Client{Timeout: 2 * time.Hour}" not in code, "the pull client is bare again"
    assert "Transport: n.client.Transport" in code, "the pull client does not share the lane's transport"
    assert re.search(r"&http\.Client\{Timeout: 2 \* time\.Second\}", code) is None, "a lane probe client is bare again"
    proxy = "\n".join(_code_lines((ROOT / "node-agent-go/internal/api/inference_proxy.go").read_text(), "//"))
    assert "nativeDialScheme(base)" in proxy, "the proxy forces plaintext for an adopted lane again"


def test_the_sidecar_healthcheck_presents_its_own_leaf_through_the_door(services):
    hc = services[SIDECAR].get("healthcheck") or {}
    test = hc.get("test") or []
    text = test if isinstance(test, str) else " ".join(str(t) for t in test)
    assert text, "the sidecar has no healthcheck"
    assert "openssl s_client" in text, "the healthcheck does not open a TLS session"
    # The door is on the sidecar's own address; 127.0.0.1:11434 is the plain backend.
    assert f"-connect {SIDECAR_HOST}:11434" in text, "the healthcheck does not dial the door"
    assert f"-cert /tls/services/{LEAF}/service.crt" in text and f"-key /tls/services/{LEAF}/service.key" in text, (
        "the healthcheck does not present the sidecar's own leaf — it would prove the door admits a bare caller"
    )
    assert "-CAfile /tls/ca.crt" in text and "-verify_return_error" in text, "the healthcheck does not verify the server against the cluster CA"
    assert "HTTP/1.[01] 200" in text, "the healthcheck does not require a 200 from the upstream through the door"
    dockerfile = (ROOT / "docker/Dockerfile.stunnel").read_text()
    assert re.search(r"apk add [^\n]*\bopenssl\b", dockerfile), "docker/Dockerfile.stunnel has no openssl CLI — the healthcheck cannot run"


# ── 4. compose names it only over https ───────────────────────────────────


def test_no_compose_env_value_dials_ollama_embed_in_plaintext(services):
    """Nothing in the projection points at the plain port. (The standalone
    values come from .env — pinned above at their source — so an empty
    scan here is expected; the guard is that nothing NEW names it.)"""
    for name, svc in services.items():
        env = svc.get("environment") or {}
        items = env.items() if isinstance(env, dict) else (str(e).partition("=")[::2] for e in env)
        for k, v in items:
            v = "" if v is None else str(v)
            for url in re.findall(r"[a-z]+://[^\s'\"}]+", v):
                if "ollama-embed" in url:
                    assert url.startswith("https://") and "stunnel-ollama-embed" in url, (
                        f"{name}.{k} dials ollama-embed's plain port: {url}"
                    )
    raw = yaml.safe_load((ROOT / "docker-compose.cluster.yml").read_text())
    text = (ROOT / "docker-compose.cluster.yml").read_text()
    for line in _code_lines(text, "#"):
        assert PLAIN not in line, f"docker-compose.cluster.yml names the plaintext door: {line.strip()}"
    assert SIDECAR in raw["services"], "the sidecar is not in the compose file as written"


def test_dist_pulls_the_sidecar_image():
    """A --dist install never builds; the sidecar runs on every standalone
    install, so its image must come from the registry (the dist tests pin
    the matrix entry behind this row)."""
    dist = yaml.safe_load((ROOT / "docker-compose.dist.yml").read_text())["services"]
    row = dist.get(SIDECAR)
    assert row, f"docker-compose.dist.yml has no {SIDECAR} row — a --dist standalone install would try to build it"
    assert row.get("pull_policy") == "missing"
    assert "/stunnel:" in row.get("image", ""), row.get("image")
