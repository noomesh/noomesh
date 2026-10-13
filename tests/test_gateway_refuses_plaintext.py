# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The gateway has ONE listener, and nothing in the tree dials a stack door in the clear.

Until 2026-09-29 `gateway-rust/src/main.rs` bound `0.0.0.0:8080` over plain
HTTP whenever `NOO_TLS_CERT` was unset, behind a `warn!` — a wizard run with
`--skip-security` produced a working-looking install whose every login
crossed the wire unencrypted. Beside it sat a dozen "scheme follows
NOO_TLS_CERT / NOO_TLS_CA" sites (self-dials, backend URLs, the CLI's default
gateway URL, Redis/NATS defaults) that each independently picked `http://`
when the variable was absent — naming doors that are mTLS-only and do not
answer plaintext.

The operator's rule: "TLS and https default everywhere, fail loud." So the
plain branch is deleted (not gated), the start-up refusal names every
missing file, and every scheme site is unconditional. This pins all three:

  1. `main.rs` has no plaintext bind — no `TcpListener::bind` and no
     `axum::serve(` outside its test module — and calls the refusal;
  2. the refusal text names the listener's absence and the remedy;
  3. no `http://` literal aimed at a stack service name survives in
     `gateway-rust/src`, `src/noomesh` or `noo-cli/src` outside comments and
     test modules, except the allow-listed sites below — each of which names
     the reason it is still plain and the followup that owns it. An
     allow-list entry that no longer matches is itself a failure: the
     exemption must go when the site does.

an earlier change carries the deferred sites.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "gateway-rust/src/main.rs"
TLS = ROOT / "gateway-rust/src/tls.rs"
SCAN_ROOTS = ("gateway-rust/src", "src/noomesh", "noo-cli/src")

# A stack service name a plaintext URL must never target. `ollama-embed` is
# carved out of `ollama` on purpose: it is the standalone profile's named
# plaintext exception (see the allow-list) and a sibling PR fronts it.
SERVICE = (
    r"(?:noo-[a-z0-9-]+|stunnel-[a-z0-9-]+|gateway|vllm(?:-secondary)?|ollama(?!-embed)|tei|"
    r"reranker|llamacpp|redis|nats|postgres|loki|prometheus|grafana|alertmanager|model-cache|"
    r"sandbox|whisper|piper|browser|evolve|trellion|"
    # Loopback is a stack door too when the port is the gateway's (:8080)
    # or the node agent's (:8081): both are TLS-only listeners.
    r"(?:localhost|127\.0\.0\.1):808[01](?![0-9]))"
)
# Quoted, then the scheme, then a service name, then something that ends a
# host (port, path, closing quote). Unquoted matches are prose.
PLAIN_URL = re.compile(r"""["'`]http://""" + SERVICE + r"""(?=[:/"'`])""")

# (relative path, literal that must still be present) -> why it is still plain.
ALLOW: dict[tuple[str, str], str] = {
    ("gateway-rust/src/tools.rs", "http://sandbox:9000"):
        "the sandbox executor's compose door — deferred by the operator",
    ("src/noomesh/config.py", "http://sandbox:9000"):
        "the same sandbox door, in the settings field's description string",
    ("gateway-rust/src/stt_client.rs", "http://noo-whisper:8000"):
        "voice (whisper STT) — deferred by the operator",
    ("gateway-rust/src/tts_client.rs", "http://noo-piper:8000"):
        "voice (piper TTS) — deferred by the operator",
    ("noo-cli/src/onboard/steps.rs", "http://gateway:"):
        "not a dial: `starts_with(\"http://gateway:\")` is the REWRITE that upgrades a stale "
        "CONTROLLER_URL to https during enrollment",
}


def _strip_test_modules(text: str) -> str:
    """Remove every `#[cfg(test)] mod … { … }` block (brace-matched — some
    files carry a test module mid-file, not only at the end). Test modules
    dial ephemeral loopback listeners and are not a door."""
    out: list[str] = []
    i = 0
    while True:
        j = text.find("#[cfg(test)]", i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        k = text.find("{", j)
        if k < 0:
            break
        depth, n = 0, k
        while n < len(text):
            if text[n] == "{":
                depth += 1
            elif text[n] == "}":
                depth -= 1
                if depth == 0:
                    break
            n += 1
        i = n + 1
    return "".join(out)


def _code_only(path: Path, text: str) -> str:
    """Drop comment lines and, for Rust, the test modules."""
    if path.suffix == ".rs":
        text = _strip_test_modules(text)
        return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("//"))
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _sources() -> dict[str, str]:
    out: dict[str, str] = {}
    for root in SCAN_ROOTS:
        for p in sorted((ROOT / root).rglob("*")):
            if p.suffix not in (".rs", ".py") or "/tests/" in p.as_posix():
                continue
            out[p.relative_to(ROOT).as_posix()] = _code_only(p, p.read_text(encoding="utf-8", errors="replace"))
    assert len(out) > 100, f"the scan found only {len(out)} sources — a moved tree would pass an empty search"
    return out


def test_main_has_no_plaintext_bind_and_calls_the_refusal() -> None:
    code = _code_only(MAIN, MAIN.read_text())
    assert "TcpListener::bind" not in code, "main.rs binds a raw TcpListener — the plaintext branch is back"
    assert "axum::serve(" not in code, "main.rs serves without the TLS acceptor — the plaintext branch is back"
    refusal = code.find("tls::require_server_material()")
    assert refusal >= 0, "main.rs no longer refuses to start without TLS material"
    # Refuse before the process touches the database: a gateway that cannot
    # bind must not run migrations first and die afterwards.
    migrate = code.find("config::load_config()")
    assert migrate >= 0, "main.rs no longer loads config — the ordering check checks nothing"
    assert refusal < migrate, "the TLS refusal runs after config/migrations — refuse first"
    assert "RustlsAcceptor::new(" in code, "the TLS acceptor is gone from main.rs — the parse found no listener at all"
    # The probe has exactly one scheme to be right with.
    assert '"https://localhost:8080/health"' in code, "the --health probe no longer dials https unconditionally"
    assert 'if tls::' not in code or 'if tls::mtls_enabled()' in code, "a TLS predicate still chooses a listener"
    assert "server_tls_configured" not in code and "peer_identity_available" not in code, (
        "the TLS-or-plain predicate is back in main.rs"
    )


def test_the_refusal_names_the_listener_and_the_remedy() -> None:
    tls = TLS.read_text()
    m = re.search(r"pub fn plaintext_refusal\(.*?\n}\n", tls, re.S)
    assert m, "tls.rs no longer has plaintext_refusal — the refusal text moved and this checks nothing"
    body = m.group(0)
    for phrase in ("refusing to start", "no plaintext listener", "noo onboard --only enrollment", "noo upgrade --stack"):
        assert phrase in body, f"the refusal lost {phrase!r}"
    assert 'SERVER_MATERIAL_ENV: [&str; 3] = ["NOO_TLS_CERT", "NOO_TLS_KEY", "NOO_TLS_CA"]' in tls, (
        "the required material is no longer all three of cert, key and CA"
    )


def test_no_plaintext_url_targets_a_stack_service_outside_the_allow_list() -> None:
    sources = _sources()
    seen_allow: set[tuple[str, str]] = set()
    offenders: list[str] = []
    for rel, code in sources.items():
        for m in PLAIN_URL.finditer(code):
            # The allow-listed literal must start exactly where the match does.
            key = next((k for k in ALLOW if k[0] == rel and code.startswith(k[1], m.start() + 1)), None)
            if key:
                seen_allow.add(key)
                continue
            line = code[: m.start()].count("\n") + 1
            offenders.append(f"{rel}:{line}: {m.group(0)}")
    assert not offenders, (
        "plaintext URL(s) aimed at a stack service (every such door is mTLS-only; the gateway "
        "cannot even start without the CA):\n  " + "\n  ".join(offenders)
    )
    stale = sorted(k for k in ALLOW if k not in seen_allow)
    assert not stale, (
        "allow-list entries that no longer match anything — remove the exemption with the site:\n  "
        + "\n  ".join(f"{p}: {lit} ({ALLOW[(p, lit)]})" for p, lit in stale)
    )


def test_the_scheme_sites_that_used_to_follow_the_env_are_unconditional() -> None:
    """Each site that picked http:// when NOO_TLS_CERT / NOO_TLS_CA was absent.
    Naming them one by one so that a re-introduced predicate at ANY of them
    fails with its file, not just the generic scan."""
    sites = {
        "gateway-rust/src/coordinator/backend.rs": 'format!("https://{host}:{port}")',
        "gateway-rust/src/routes/other.rs": '"https://stunnel-ollama:11434"',
        "gateway-rust/src/routes/cluster.rs": '"https://stunnel-ollama:11434"',
        "gateway-rust/src/embedding_client.rs": '"https://stunnel-ollama:11434"',
        "gateway-rust/src/mcp_external.rs": 'format!("https://127.0.0.1:{port}")',
        # operator_alert.rs left this list with its URL: it calls the channel
        # adapter in process the earlier change, so it builds no scheme.
        "src/noomesh/gateway/helpers.py": 'return f"https://127.0.0.1:{port}"',
        "src/noomesh/cli_utils.py": 'return "https://localhost:8080"',
        "src/noomesh/workers/graph.py": '"https://noo-vllm:8000"',
        "src/noomesh/_providers/backend_resolver.py": 'return f"https://{ip}:{port}"',
        "src/noomesh/cluster/messaging.py": '"tls://localhost:4222"',
        "src/noomesh/secrets.py": '"rediss://localhost:6379"',
        "src/noomesh/cache.py": 'if url.startswith("redis://"):',
        "src/noomesh/gateway/constants.py": 'scheme = "https"',
        "src/noomesh/mcp/tool_models.py": '"https://localhost:8080"',
        "src/noomesh/cluster/default_locations.py": '_GW = f"https://127.0.0.1:{_gw_port}"',
        "src/noomesh/pipeline/llm.py": "return f\"https://127.0.0.1:{os.getenv('GATEWAY_PORT', '8080')}\"",
        "noo-cli/src/envfile.rs": 'format!("https://localhost:{port}")',
        "noo-cli/src/onboard/mod.rs": '"https://localhost:8080/health"',
        "noo-cli/src/onboard/web.rs": 'let proto = "https";',
        "noo-cli/src/onboard/steps.rs": '"https://localhost:8080/health"',
    }
    for rel, needle in sites.items():
        code = _code_only(ROOT / rel, (ROOT / rel).read_text())
        assert needle in code, f"{rel}: the unconditional TLS form {needle!r} is gone"
        assert 'if tls { "https" } else { "http" }' not in code, f"{rel}: a scheme predicate is back"
        assert '"https" if' not in code, f"{rel}: a scheme predicate is back"
    # The one place NOO_TLS_CERT may still be consulted in the CLI's onboard
    # services step is to EXPLAIN the refusal, not to pick a scheme.
    steps = (ROOT / "noo-cli/src/onboard/steps.rs").read_text()
    assert "refuses to start without it (there is no plaintext listener)" in steps, (
        "the wizard's services step no longer explains the refusal"
    )


def test_cache_refuses_a_plaintext_redis_url_and_says_why() -> None:
    """Redis is TLS-only (port 0 / tls-port 6379): a `redis://` URL is refused
    with the reason, never sent as-is (it used to be upgraded only when
    NOO_REDIS_TLS happened to be set, and otherwise died as a bare reset)."""
    import pytest

    from noomesh.cache import _apply_redis_tls

    with pytest.raises(ValueError, match=r"plaintext \(redis://\).*TLS only.*rediss://"):
        _apply_redis_tls("redis://redis:6379")
    assert _apply_redis_tls("rediss://redis:6379") == "rediss://redis:6379"
