# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The bus has one config, it is mTLS, and nothing defaults to plaintext.

Two escape hatches used to exist beside the mTLS bus and the mTLS node
agent, both silent:

  - `monitoring/nats/nats.conf` (no `tls {}` block, `http_port` monitoring)
    could be selected with `NOO_NATS_CONFIG=nats.conf` in `.env`, and every
    client whose default URL was `nats://` connected to it in the clear;
  - the Go node agent, given no `NOO_TLS_CERT`, served its control API in
    PLAINTEXT on :8081, and `NOO_MTLS_NODES=false` relaxed the handshake
    even with a certificate.

Both are closed at the source (the config and the selector are deleted,
the agent refuses to start). This pins the closure across the languages
that would otherwise drift back independently:

  - no plaintext NATS config file, no selector in any compose file, the one
    shipped config requires a client certificate;
  - every client's DEFAULT bus/redis URL is a TLS scheme (`tls://`,
    `rediss://`) — compose, env templates, the YAML example, the Python
    settings, the Rust gateway, the Go agent, the CLI's onboard writes;
  - the launcher refuses a `.env` that still names `NOO_NATS_CONFIG`;
  - the Go agent has no plaintext `ListenAndServe()` branch and no
    `VerifyClientCertIfGiven`, and the Go tests that prove the refusal are
    still there by name (they are what a plant trips first).

Every scan asserts it found the TLS form, so a moved file or a renamed
variable fails loudly instead of passing an empty search.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATS_DIR = ROOT / "monitoring/nats"
COMPOSE_FILES = sorted(ROOT.glob("docker-compose*.yml"))


def _code(text: str, comment: str = "#") -> str:
    """Drop whole-line comments (the prose is allowed to name the old forms)."""
    return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith(comment))


def _go_code(text: str) -> str:
    return _code(text, "//")


def _service_block(compose: str, name: str) -> str:
    lines = compose.splitlines()
    out: list[str] = []
    inside = False
    for ln in lines:
        is_key = ln.startswith("  ") and not ln.startswith("   ") and ln.rstrip().endswith(":") and not ln.strip().startswith("#")
        if is_key:
            if inside:
                break
            inside = ln.strip() == f"{name}:"
            continue
        if inside:
            out.append(ln)
    assert inside, f"no `{name}` service in the compose file"
    return "\n".join(out)


# ── the bus ────────────────────────────────────────────────────────────


def test_the_plaintext_nats_config_is_gone_and_the_tls_one_verifies_clients() -> None:
    assert not (NATS_DIR / "nats.conf").exists(), "monitoring/nats/nats.conf is back — the plaintext bus config was deleted on purpose"
    tls = _code((NATS_DIR / "nats-tls.conf").read_text())
    assert re.search(r"^tls\s*\{", tls, re.M), "nats-tls.conf has no tls block"
    assert re.search(r"^\s*verify:\s*true\s*$", tls, re.M), "nats-tls.conf does not require a client certificate (verify: true)"
    assert re.search(r"^https_port:\s*8222", tls, re.M), "monitoring is not on https_port — it would be plain HTTP"
    assert not re.search(r"^http_port:", tls, re.M), "nats-tls.conf opens a plain http_port"
    # And nothing else under monitoring/nats/ is a second server config.
    others = {p.name for p in NATS_DIR.glob("*.conf")} - {"nats-tls.conf", "users.conf"}
    assert not others, f"unexpected NATS configs: {others} — one config, no profiles"


def test_compose_runs_the_tls_config_with_no_selector_and_no_plain_mount() -> None:
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    nats = _code(_service_block(compose, "nats"))
    cmd = [ln for ln in nats.splitlines() if "command:" in ln]
    assert cmd, "the nats service has no command: line — the parse found nothing"
    assert "/etc/nats/nats-tls.conf" in cmd[0], f"nats does not run nats-tls.conf: {cmd[0].strip()}"
    assert "${" not in cmd[0], f"the nats command is interpolated — a config selector is a plaintext escape hatch: {cmd[0].strip()}"
    assert "/nats.conf" not in nats, "the nats service still mounts nats.conf"
    assert "nats-tls.conf:/etc/nats/nats-tls.conf" in nats, "the TLS config is not mounted"
    for f in COMPOSE_FILES:
        assert "NOO_NATS_CONFIG" not in _code(f.read_text()), f"{f.name} still reads NOO_NATS_CONFIG"


def test_the_launcher_refuses_a_stale_nats_config_selector() -> None:
    start = (ROOT / "scripts/noomesh-start.sh").read_text()
    m = re.search(r'NOO_NATS_CONFIG=\$_nats_cfg.*?exit 1', start, re.S)
    assert m, "noomesh-start.sh no longer refuses a .env that sets NOO_NATS_CONFIG"
    assert "nats-tls.conf) ;;" in start, "the launcher must accept the TLS file's own name as inert"
    bind = _code((ROOT / "scripts/lib-bind-addr.sh").read_text())
    assert "NOO_NATS_CONFIG" not in bind, "lib-bind-addr.sh still picks the monitoring scheme from NOO_NATS_CONFIG"
    assert 'https://localhost:${NOO_PORT_NATS_MON' in bind, "the printed NATS monitoring URL is not https"
    steps = _code((ROOT / "noo-cli/src/onboard/steps.rs").read_text(), "//")
    assert "NOO_NATS_CONFIG" not in steps, "onboard still writes NOO_NATS_CONFIG into .env"


# ── every client default is a TLS scheme ───────────────────────────────

# (file, the TLS default it must carry, the plaintext literals it must not)
CLIENT_DEFAULTS = [
    ("docker-compose.cluster.yml", "tls://nats:4222", ["nats://", "redis://"]),
    ("noomesh.yaml.example", "tls://nats:4222", ["nats://", "redis://"]),
    ("node-agent-go/deploy/noo-node-agent.env.tmpl", "nats_url", ["nats://", "redis://"]),
    ("src/noomesh/config.py", 'default="tls://nats:4222"', ['"nats://nats:4222"', '"redis://redis:6379"']),
    ("src/noomesh/gateway/worker_pool.py", '"tls://nats:4222"', ['"nats://nats:4222"', '"redis://redis:6379"']),
    ("src/noomesh/gateway/proactive_agent.py", '"rediss://redis:6379"', ['"redis://redis:6379"']),
    ("src/noomesh/gateway/heartbeat.py", '"rediss://redis:6379"', ['"redis://redis:6379"']),
    ("src/noomesh/cluster/scheduler.py", '"rediss://redis:6379"', ['"redis://redis:6379"']),
    ("gateway-rust/src/state.rs", '"tls://nats:4222"', ['"nats://nats:4222"', '"redis://redis:6379"']),
    ("gateway-rust/src/preflight.rs", '"tls://nats:4222"', ['"nats://nats:4222"']),
    ("node-agent-go/internal/config/config.go", '"tls://nats:4222"', ['"nats://nats:4222"']),
    ("noo-cli/src/onboard/steps.rs", '"tls://nats:4222"', ['"nats://nats:4222"', '"redis://redis:6379"']),
    ("noo-cli/src/commands/provision.rs", 'tls://{ctrl_host}:4222', ['nats://{ctrl_host}']),
]


def test_every_client_default_for_the_bus_and_redis_is_a_tls_scheme() -> None:
    for rel, tls_form, plain_forms in CLIENT_DEFAULTS:
        text = (ROOT / rel).read_text()
        comment = "//" if rel.endswith((".rs", ".go")) else "#"
        code = _code(text, comment)
        assert tls_form in code, f"{rel}: the TLS default {tls_form!r} is gone — the scan would otherwise prove nothing"
        for plain in plain_forms:
            assert plain not in code, f"{rel}: plaintext default {plain!r} is back"


def test_the_compose_env_lines_for_the_bus_and_redis_default_to_tls() -> None:
    for f in COMPOSE_FILES:
        code = _code(f.read_text())
        found = 0
        for var, scheme in (("NATS_URL", "tls://"), ("REDIS_URL", "rediss://")):
            for m in re.finditer(rf"{var}=\$\{{{var}:-([^}}]*)\}}", code):
                found += 1
                default = m.group(1)
                assert default == "" or default.startswith(scheme), f"{f.name}: {var} defaults to {default!r}, not {scheme}"
        if f.name == "docker-compose.cluster.yml":
            assert found >= 2, "the cluster compose no longer sets NATS_URL/REDIS_URL with defaults — the parse found nothing"


# ── the node agent ─────────────────────────────────────────────────────

GO = ROOT / "node-agent-go"


def test_the_node_agent_control_api_has_no_plaintext_listener() -> None:
    server = _go_code((GO / "internal/api/server.go").read_text())
    assert "ListenAndServeTLS(" in server, "server.go no longer serves TLS — the parse found nothing"
    assert not re.search(r"\bserver\.ListenAndServe\(\)", server), "server.go has a plaintext ListenAndServe() branch again"
    assert "plaintext" not in server.lower() or "no plaintext" in server.lower()
    config = _go_code((GO / "internal/config/config.go").read_text())
    assert "tls.RequireAndVerifyClientCert" in config, "config.go no longer requires a client certificate"
    assert "VerifyClientCertIfGiven" not in config, "the client-certificate downgrade is back in config.go"
    assert "return nil, nil" not in config.split("func (c *Config) TLSServerConfig")[1].split("\nfunc ")[0], (
        "TLSServerConfig returns (nil, nil) — that was the signal the plaintext branch keyed on"
    )
    for test_file, names in (
        ("internal/api/listen_refuses_plaintext_test.go", ["TestListenAndServeRefusesWithoutTLSMaterial", "TestListenAndServeRefusesTheRetiredDowngrade"]),
        ("internal/config/config_test.go", ["TestTLSServerConfigRefusesWithoutMaterial", "TestTLSServerConfigRefusesTheRetiredDowngrade"]),
    ):
        src = (GO / test_file).read_text()
        for name in names:
            assert f"func {name}(" in src, f"{test_file}: the Go test {name} was removed"


def test_the_gateway_dials_node_agents_over_https_only() -> None:
    """Every `{scheme}://{ip}:<agent port>` URL is built in `node_link.rs`
    (`tests/test_node_link_is_the_only_node_door.py` keeps the others out), and
    none of them switches on NOO_TLS_CA: a node agent has no plaintext listener
    to dial. The controller-local fallback in admin.rs stays https as well."""
    link = _code((ROOT / "gateway-rust/src/node_link.rs").read_text(), "//").split("#[cfg(test)]")[0]
    built = re.findall(r'format!\("(\w+)://\{ip\}:\{AGENT_PORT\}"\)', link)
    assert len(built) >= 2, f"expected the for_node and for_ip URL builders, found {len(built)} — the parse found too little"
    assert set(built) == {"https"}, f"a node-agent URL can still be http: {built}"
    assert 'format!("http://' not in link
    admin = _code((ROOT / "gateway-rust/src/routes/admin.rs").read_text(), "//")
    m = re.search(r'let proto = ([^;]+);\s*(?://[^\n]*)?\n[^\n]*format!\("\{proto\}://node-agent', admin)
    assert m and m.group(1).strip() == '"https"', "the local agent fallback can be http"
