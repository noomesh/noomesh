# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The model-weight store must never serve a credential, must never
enumerate itself to strangers (§3f R28), and — since an earlier change —
must serve its data plane only to a node or the controller, by certificate.

``docker/model-cache.nginx.conf`` holds the listeners; the served tree is
ONE include (``docker/model-cache.locations.conf``) so every listener serves
the same paths. The fetcher on the other end
(``node-agent-go/internal/preseed/preseed.go``) builds its transport from
the node's PKI and presents the node leaf. Three things are one edit away
from being lost:

* the ``/hf/`` alias is scoped to ``hub/``. ``huggingface_hub`` writes
  ``token`` and ``stored_tokens`` at the HF_HOME *root* — one level above.
  Widening the alias to ``/hf-store/`` would publish the HuggingFace token.
* ``autoindex`` was on server-wide, so ``/gguf/``, ``/images/`` and ``/bin/``
  each answered a full listing of the controller's stores. Only ``/hf/``
  needs one, because ``preseed.Mirror`` genuinely walks that tree.
* every PUBLISHED port maps to a listener that requires a client
  certificate and filters on its org. Phase 1 exempted the plaintext 8083
  port by date; phase 2 (2026-09-29) deleted the listener, the port and
  the exemption. ``tests/test_model_cache_mtls_only.py`` pins the
  single-port shape; this file keeps the "published ⇒ verified" rule.
"""

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CONF = REPO_ROOT / "docker" / "model-cache.nginx.conf"
LOCATIONS = REPO_ROOT / "docker" / "model-cache.locations.conf"
COMPOSE = REPO_ROOT / "docker-compose.cluster.yml"

def _strip_comments(text: str) -> str:
    # Both files argue with themselves at length, and every forbidden
    # string appears in the prose explaining why it is forbidden.
    return "\n".join(re.sub(r"#.*$", "", line) for line in text.splitlines())


@pytest.fixture(scope="module")
def conf():
    """The served tree (the include) — where every location lives."""
    return _strip_comments(LOCATIONS.read_text())


@pytest.fixture(scope="module")
def listeners():
    """The listener file, comments stripped."""
    return _strip_comments(CONF.read_text())


def _locations(conf_text):
    """{location pattern: body} for each location block."""
    out = {}
    for m in re.finditer(r"location\s+([^\{]+?)\s*\{(.*?)\n\}", conf_text, re.S):
        out[m.group(1).strip()] = m.group(2)
    return out


def _servers(listeners_text):
    """The body of every top-level `server {}` block, in file order."""
    return re.findall(r"^server\s*\{(.*?)^\}", listeners_text, re.S | re.M)


def _listen_ports(server_body):
    """[(port, is_ssl)] for each `listen` line; `127.0.0.1:8084` keeps its host."""
    out = []
    for m in re.finditer(r"^\s*listen\s+([^;]+);", server_body, re.M):
        parts = m.group(1).split()
        out.append((parts[0], "ssl" in parts[1:]))
    return out


def test_the_hf_alias_stays_below_the_token(conf):
    locs = _locations(conf)
    hf = locs.get("/hf/")
    assert hf is not None, "the /hf/ location vanished — update this test"
    alias = re.search(r"alias\s+(\S+);", hf).group(1)
    assert alias == "/hf-store/hub/", (
        f"the /hf/ alias is {alias!r}. It must stay inside hub/: HF_CACHE_DIR is "
        "mounted at /hf-store as the HF_HOME ROOT, and huggingface_hub writes "
        "`token` and `stored_tokens` there, one level up."
    )


def test_credential_filenames_are_denied_outright(conf):
    # Belt as well as braces: the alias above is correct today, and this is
    # what keeps it from mattering if someone widens it.
    assert re.search(r"location\s+~\s+/\(token\|stored_tokens\)\$", conf), (
        "the deny block for `token` / `stored_tokens` is gone"
    )


def test_autoindex_is_off_except_where_a_client_walks_the_tree(conf):
    server_level = conf.split("location", 1)[0]
    assert re.search(r"^\s*autoindex\s+off;", server_level, re.M), (
        "the server-level default must be `autoindex off` — with it on, "
        "/gguf/, /images/ and /bin/ list the controller's whole store"
    )
    locs = _locations(conf)
    listing = {k for k, v in locs.items() if re.search(r"autoindex\s+on;", v)}
    # Two blocks serve the hub tree: the prefix `/hf/` that preseed walks,
    # and an exact `= /hf/` whose only extra job is turning the 404 from a
    # missing hub/ into a message naming the layout mistake. Same tree, same
    # alias — so both legitimately list, and neither widens what is served.
    assert listing == {"/hf/", "= /hf/"}, (
        f"{sorted(listing)} enable directory listing. Only the /hf/ blocks "
        "need it (preseed.Mirror recurses that tree); everything else is "
        "fetched by exact filename from the gateway's artifact manifest."
    )
    # Both must point at hub/, or the exact block's message would contradict
    # what the prefix block actually serves.
    for k in ("/hf/", "= /hf/"):
        assert re.search(r"alias\s+/hf-store/hub/;", locs[k]), f"{k}: alias moved"


def test_there_is_no_models_location_only_gguf(conf):
    # the design D: PullModelArtifact asked for /models/<name>, which no
    # location served. MODELS_DIR is /gguf/ and nothing else; a /models/
    # location here would let the wrong path work again by accident.
    locs = _locations(conf)
    assert "/gguf/" in locs and re.search(r"alias\s+/models/;", locs["/gguf/"]), "the /gguf/ → /models/ alias is gone"
    assert not any(k.rstrip("/").endswith("/models") for k in locs), sorted(locs)


# ── The listeners (the design C-i) ───────────────────────────────────


def _model_cache_service():
    return yaml.safe_load(COMPOSE.read_text())["services"]["model-cache"]


def _published_container_ports():
    """{container port: published spec} from the compose service's `ports`."""
    out = {}
    for spec in _model_cache_service()["ports"]:
        spec = str(spec)
        # `${BIND}:${HOST:-8443}:8443` → the last field is the container port.
        out[spec.rsplit(":", 1)[1]] = spec
    return out


def test_every_published_port_is_confined_to_the_bind_address():
    ports = _published_container_ports()
    assert ports, "model-cache publishes nothing — update this test"
    for cport, spec in ports.items():
        assert spec.startswith("${NOO_BIND_ADDR"), (
            f"model-cache publishes {spec!r} (container :{cport}). Without a bind "
            "address docker publishes on 0.0.0.0."
        )


def test_the_mtls_listener_requires_a_node_or_gateway_leaf(listeners):
    servers = [s for s in _servers(listeners) if any(ssl for _, ssl in _listen_ports(s))]
    assert servers, "no `listen … ssl` server block — the mTLS data plane is gone"
    for body in servers:
        assert re.search(r"^\s*ssl_verify_client\s+on;", body, re.M), "ssl_verify_client is not `on`"
        assert re.search(r"^\s*ssl_client_certificate\s+/tls/ca\.crt;", body, re.M), "the client CA is not the cluster CA"
        assert re.search(r"^\s*ssl_certificate\s+/tls/services/model-cache/service\.crt;", body, re.M), (
            "the listener must present the model-cache SERVICE leaf, not another identity"
        )
        assert re.search(r"if\s*\(\s*\$mc_peer_ok\s*=\s*0\s*\)\s*\{\s*return\s+403;", body), (
            "the org filter (`if ($mc_peer_ok = 0) { return 403; }`) is missing — any "
            "CA-signed leaf (prometheus, grafana, loki) would be served weights"
        )
    # The map: nodes and the controller, matched as a whole org component,
    # and nothing else by default.
    m = re.search(r"map\s+\$ssl_client_s_dn\s+\$mc_peer_ok\s*\{(.*?)\n\}", listeners, re.S)
    assert m, "the $mc_peer_ok map is gone"
    body = m.group(1)
    assert re.search(r'O=Mesh Cluster Node\(,\|\$\)"\s+1;', body), "O=Mesh Cluster Node is not admitted"
    assert re.search(r'O=Mesh Cluster Gateway\(,\|\$\)"\s+1;', body), "O=Mesh Cluster Gateway is not admitted"
    assert re.search(r"^\s*default\s+0;", body, re.M), "the map's default must be 0 (deny)"
    assert "Mesh Cluster Service" not in body, "a SERVICE leaf must not be admitted to the data plane"


def test_every_published_port_maps_to_an_mtls_listener(listeners):
    """A published port is a data-plane port; it authenticates by
    certificate or it is not published. No exemptions since phase 2."""
    verified, plain = set(), set()
    for body in _servers(listeners):
        ports = _listen_ports(body)
        if not ports:
            continue
        if re.search(r"^\s*ssl_verify_client\s+on;", body, re.M) and all(ssl for _, ssl in ports):
            verified.update(p for p, _ in ports)
        else:
            plain.update(p for p, _ in ports)
    assert verified, "no listener requires a client certificate at all"

    for cport in _published_container_ports():
        assert cport in verified, (
            f"model-cache publishes container port {cport} and no `listen {cport} ssl` + "
            "`ssl_verify_client on` server answers it. A published port is a data-plane "
            "port; it authenticates by certificate or it is not published."
        )
    # The only plain listener is the loopback healthz.
    assert all(p.startswith("127.0.0.1:") for p in plain), (
        f"plaintext listener(s) {sorted(plain)} — phase 2 of an earlier change removed the last one"
    )


def test_the_healthz_listener_is_loopback_only_and_unpublished(listeners):
    health = [b for b in _servers(listeners) if re.search(r"location\s*=\s*/healthz", b)]
    assert len(health) == 1, "exactly one server block may answer /healthz"
    ports = _listen_ports(health[0])
    assert ports and all(p.startswith("127.0.0.1:") for p, _ in ports), (
        f"the healthz listener binds {ports}; it must be 127.0.0.1 only"
    )
    hport = ports[0][0].split(":")[1]
    assert hport not in _published_container_ports(), "the healthz listener is published"
    # The data-plane listeners answer no probe; the compose healthcheck
    # must use the loopback one.
    check = " ".join(_model_cache_service()["healthcheck"]["test"])
    assert f"127.0.0.1:{hport}/healthz" in check, check


def test_the_data_plane_listener_serves_the_shared_include(listeners):
    # The served tree is defined once, in the include. A location declared
    # in a server block instead is a drift the next listener would not see.
    data = [b for b in _servers(listeners) if not re.search(r"location\s*=\s*/healthz", b)]
    assert len(data) == 1, f"expected the single 8443 server block (phase 2), found {len(data)}"
    for body in data:
        assert re.search(r"^\s*include\s+/etc/nginx/model-cache\.locations\.conf;", body, re.M), (
            "a data-plane server block does not include the shared locations file"
        )
        assert not re.search(r"^\s*location\b", body, re.M), (
            "a data-plane server block declares its own location — put it in the include"
        )
    mounts = [str(v) for v in _model_cache_service()["volumes"]]
    assert any(m.startswith("./docker/model-cache.locations.conf:/etc/nginx/model-cache.locations.conf") for m in mounts), (
        "the locations include is not mounted where the server blocks include it"
    )
    assert not any("/etc/nginx/conf.d/model-cache.locations" in m for m in mounts), (
        "the include must not live under conf.d/ — nginx would load it as a top-level config"
    )


def test_the_model_cache_holds_only_its_own_identity():
    # tests/test_pki_mounts_are_narrow.py enforces this for every service;
    # restated here so the reason is next to the listener that needs it.
    mounts = [str(v) for v in _model_cache_service()["volumes"]]
    pki = [m for m in mounts if "NOO_PKI_DIR" in m]
    assert len(pki) == 2, pki
    assert any(m.endswith("/ca.crt:/tls/ca.crt:ro") for m in pki), pki
    assert any("/services/model-cache:/tls/services/model-cache:ro" in m for m in pki), pki
    for m in mounts:
        assert "gateway/" not in m and "nodes/" not in m and "ca.key" not in m, m


# ── The bare-hub layout guard ────────────────────────────────────────────
#
# An operator pointed HF_CACHE_DIR at a bare hub archive (models--* at the
# top level, no hub/). Everything started; nothing served. nginx 404s a
# directory it cannot alias, the node's preseed reports "list …: HTTP 404",
# the backends find no models — and not one of those says "wrong level".
#
# Two things now say it: an exact-match `= /hf/` block whose 404 carries the
# layout, and a check in the launcher. Both are small enough to delete by
# accident, so both are asserted.


def test_the_hf_404_explains_the_layout(conf):
    locs = _locations(conf)
    assert "error_page 404 = @hf_layout;" in locs.get("= /hf/", ""), (
        "the exact `= /hf/` block no longer routes its 404 to the layout "
        "message; a missing hub/ is silent again"
    )
    msg = locs.get("@hf_layout")
    assert msg is not None, "the @hf_layout named location is gone"
    assert "HF_HOME" in msg and "hub/" in msg, (
        f"the message must name the expected layout, got: {msg!r}"
    )


def test_the_layout_message_keeps_the_404_status(conf):
    # Load-bearing: preseed.Client treats any non-200 as an error
    # (preseed.go list()). A 200 carrying an explanation would be decoded as
    # an empty model list and read as success — the exact silence being fixed.
    msg = _locations(conf)["@hf_layout"]
    assert re.search(r"return\s+404\s", msg), (
        f"the layout message must be a 404, not a 200: {msg!r}"
    )


def test_only_the_top_level_listing_claims_a_layout_error(conf):
    # `/hf/` 404s only when /hf-store/hub/ is absent — an empty hub is a 200
    # with `[]`. Sub-paths must keep a plain 404: a missing model is not a
    # misconfigured mount, and saying so would send operators after the
    # wrong thing.
    for loc, body in _locations(conf).items():
        if loc in ("= /hf/", "@hf_layout"):
            continue
        assert "@hf_layout" not in body, (
            f"{loc} routes to the layout message; only the exact /hf/ may"
        )


def test_the_launcher_warns_on_a_bare_hub_layout():
    launcher = (REPO_ROOT / "scripts" / "noomesh-start.sh").read_text()
    assert "HF_CACHE_DIR looks like a bare hub archive" in launcher, (
        "the launcher's bare-hub warning is gone"
    )
    # The models--* probe is what separates "wrong level" from "nothing here
    # yet": without it an empty or fresh cache dir would warn on every start
    # and the warning would be trained away.
    assert "-name 'models--*'" in launcher, (
        "the launcher check no longer distinguishes a wrong layout from an "
        "empty cache, so it will warn on fresh installs"
    )
    assert '[ ! -d "$_hf_dir/hub" ]' in launcher, (
        "the launcher check no longer tests for the missing hub/ level"
    )
