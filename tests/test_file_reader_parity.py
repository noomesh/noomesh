# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""G3 — the file-backed-secret manifests agree with each other and with compose.

Every tier-1 secret reader goes through ONE helper per language
(`gateway-rust/src/secret_env.rs`, `src/noomesh/secret_env.py`, and — since
an earlier change — the Go node agent's `node-agent-go/internal/config/secretenv.go`),
each of which exports the names it reads. Three things must hold, and nothing in a
compiler checks any of them:

1. the two manifests agree on the names delivered to BOTH the gateway and
   the worker (`NOO_CLUSTER_SECRET`, `NOO_CONTROLLER_SECRET`, ...) — one side
   learning `_FILE` and the other not is exactly the skew the compose flip
   would then ship;
2. every name in a manifest is delivered by compose as env to that
   container today, or is on a dated "file later / read elsewhere"
   allowlist with a reason — a manifest entry nothing delivers is a reader
   nobody exercises;
3. (the direction that matters) every secret-shaped variable compose hands
   to the gateway or the worker is in that side's manifest, or on an
   explicit allowlist with a reason. A new secret cannot be added to the
   container without its reader learning `_FILE`.

The manifests are PARSED from source, not imported: the Rust one cannot be
imported, and parsing both the same way keeps the guard from trusting the
Python package it is checking (same approach as
`test_fleet_secret_declarations.py::fleet_keys`).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from tests._compose_projection import env_of, full_projection
from tests.test_no_secrets_on_compose_command_lines import SECRETY

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "gateway-rust/src/secret_env.rs"
PY = ROOT / "src/noomesh/secret_env.py"
GO = ROOT / "node-agent-go/internal/config/secretenv.go"
APPLIER = ROOT / "scripts/noo-apply.sh"
DARWIN_APPLIER = ROOT / "noo-cli/src/commands/agent_secret_files.rs"
AGENT_ENV_TMPL = ROOT / "node-agent-go/deploy/noo-node-agent.env.tmpl"


def rust_manifest() -> list[str]:
    src = RUST.read_text()
    m = re.search(r"pub const FILE_BACKED_SECRETS: &\[&str\] = &\[(.*?)\n\];", src, re.S)
    assert m, "FILE_BACKED_SECRETS not found in secret_env.rs — this guard is reading the wrong thing"
    names = re.findall(r'"([A-Z0-9_]+)"', m.group(1))
    assert len(names) >= 10, f"Rust manifest parsed suspiciously short: {names}"
    return names


def python_manifest() -> list[str]:
    src = PY.read_text()
    m = re.search(r"FILE_BACKED_SECRETS: tuple\[str, \.\.\.\] = \((.*?)\n\)", src, re.S)
    assert m, "FILE_BACKED_SECRETS not found in secret_env.py — this guard is reading the wrong thing"
    names = re.findall(r'"([A-Z0-9_]+)"', m.group(1))
    assert len(names) >= 10, f"Python manifest parsed suspiciously short: {names}"
    return names


def go_manifest(src: str | None = None) -> list[str]:
    src = GO.read_text() if src is None else src
    m = re.search(r"var FileBackedSecrets = \[\]string\{(.*?)\n\}", src, re.S)
    assert m, "FileBackedSecrets not found in secretenv.go — this guard is reading the wrong thing"
    names = re.findall(r'"([A-Z0-9_]+)"', m.group(1))
    assert len(names) >= 3, f"Go manifest parsed suspiciously short: {names}"
    return names


# ── the add-on readers ─────────────────────────────────
#
# The add-on images carry a SECOND reader beside noomesh's: trellion's
# `trellion/live/secret_env.py` (in noo-trellion and noo-trellion-intel,
# whose process entry is noomesh's worker_pool — so noomesh's manifest applies
# there too) and the evolve add-on's `noo_evolve/secret_env.py` (the whole of
# noo-evolve). Their manifests live in sibling repos CI does not check out, so
# they are PINNED here — the names each reader reads through its helper at the
# sha stack-v0.2.80's lock records (trellion 4d445003, evolve
# 8e2f5d0c) — and `test_the_pinned_add_on_manifests_match_the_sibling_checkouts`
# re-reads them from a sibling checkout wherever one sits beside this repo.
ADDON_MANIFESTS: dict[str, tuple[str, str, frozenset[str]]] = {
    # service → (sibling repo, manifest path in it, pinned names)
    # both dropped NOO_CONTROLLER_SECRET / NOO_CLUSTER_SECRET
    # with their HMAC fallbacks (trellion / evolve
    # security/no-hmac-fallback). the earlier change the trellion pair no
    # longer receive the controller secret either (their worker_pool verifies
    # bus principals with its own NOO_BUS_KEY); they still receive the fleet
    # secret for noomesh's browser door; noo-evolve receives neither.
    "trellion": (
        "trellion",
        "src/trellion/live/secret_env.py",
        frozenset({"NOO_GATEWAY_KEY"}),
    ),
    "noo-evolve": (
        "pai-evolve",
        "src/noo_evolve/secret_env.py",
        frozenset({"NOO_GATEWAY_KEY"}),
    ),
}
# The containers that run noomesh's Python (and so read through
# src/noomesh/secret_env.py): the worker, its replica, and the trellion pair.
PYTHON_CONTAINERS = ("worker", "worker-extra", "trellion", "trellion-intel")


def addon_reader_manifest(service: str) -> set[str]:
    """Every name a reader in `service`'s container reads through a
    `_FILE`-aware helper: noomesh's manifest plus trellion's for the
    trellion pair, evolve's alone for noo-evolve."""
    if service in ("trellion", "trellion-intel"):
        return set(python_manifest()) | set(ADDON_MANIFESTS["trellion"][2])
    if service == "noo-evolve":
        return set(ADDON_MANIFESTS["noo-evolve"][2])
    raise KeyError(service)


def _sibling_checkout(repo: str) -> Path | None:
    candidates = []
    if os.environ.get("NOO_SIBLINGS_DIR"):
        candidates.append(Path(os.environ["NOO_SIBLINGS_DIR"]) / repo)
    candidates.append(ROOT.parent / repo)
    if ROOT.parent.name == ".worktrees":
        candidates.append(ROOT.parents[2] / repo)
    return next((c for c in candidates if c.is_dir()), None)


def sibling_manifest(src: str) -> list[str]:
    m = re.search(r"FILE_BACKED_SECRETS: tuple\[str, \.\.\.\] = \((.*?)\n\)", src, re.S)
    assert m, "FILE_BACKED_SECRETS not found — the sibling's reader moved or was renamed"
    names = re.findall(r'"([A-Z0-9_]+)"', m.group(1))
    assert names, "the sibling's FILE_BACKED_SECRETS parsed empty — this guard is reading the wrong thing"
    return names


@pytest.mark.parametrize("service", sorted(ADDON_MANIFESTS))
def test_the_pinned_add_on_manifests_match_the_sibling_checkouts(service: str) -> None:
    """The pin above against the sibling's own manifest, read from a checkout
    beside this repo (a worktree's main clone counts). CI has no sibling:
    skipped there with a reason (tests/ci_skip_allowlist.txt). A sibling
    that ADDS a name is fine only once the pin learns it; one that DROPS a
    name compose points at would boot that add-on without the secret."""
    repo, path, pinned = ADDON_MANIFESTS[service]
    base = _sibling_checkout(repo)
    if base is None or not (base / path).is_file():
        if os.environ.get("NOO_REQUIRE_SIBLINGS") == "1":
            pytest.fail(f"NOO_REQUIRE_SIBLINGS=1 and no {repo} checkout with {path} was found")
        pytest.skip(f"no {repo} checkout beside this one carries {path} (set NOO_SIBLINGS_DIR)")
    got = sibling_manifest((base / path).read_text())
    assert len(got) == len(set(got)), got
    assert set(got) == pinned, (
        f"{repo}/{path} reads {sorted(got)} through its helper; this file pins {sorted(pinned)}. "
        "Update ADDON_MANIFESTS (and, if a name was dropped, stop pointing compose at it)"
    )


def test_the_sibling_manifest_parser_catches_what_it_is_for() -> None:
    src = 'FILE_BACKED_SECRETS: tuple[str, ...] = (\n    "NOO_GATEWAY_KEY",\n    "NOO_CLUSTER_SECRET",\n)\n'
    assert sibling_manifest(src) == ["NOO_GATEWAY_KEY", "NOO_CLUSTER_SECRET"]
    with pytest.raises(AssertionError):
        sibling_manifest("FILE_BACKED = ()\n")


def _secrety(env: dict[str, str]) -> set[str]:
    return {k for k in env if any(m in k.upper() for m in SECRETY)}


def delivered_to(service: dict) -> dict[str, str]:
    """What a container is handed, by SECRET name: a plain `NAME=` entry, or
    a `NAME_FILE=` pointer (compose `secrets:` delivery since 2026-09-29) —
    both mean the container's reader must know NAME. `PGPASSFILE` and the
    native pointers are not `_FILE`-suffixed and stay under their own name."""
    return {(k[: -len("_FILE")] if k.endswith("_FILE") else k): v for k, v in env_of(service).items()}


# Secret-shaped variables the GATEWAY receives that are deliberately NOT in
# the Rust manifest. Each has a reason; a name here that compose no longer
# delivers fails `test_allowlists_are_not_stale`.
GATEWAY_NOT_TIER1: dict[str, str] = {
    # The tier-2 provider / channel keys (ANTHROPIC_API_KEY, TAVILY_API_KEY,
    # TELEGRAM_BOT_TOKEN, GOOGLE_CHAT_CREDENTIALS_JSON, …) used to be listed
    # here as "still env"; the design moved their readers onto
    # secret_env and compose delivers them as files, so they are in the
    # manifest now and a plain one fails the checks below.
    "GOOGLE_CHAT_CREDENTIALS": "a PATH to the service-account file (the key itself is "
    "GOOGLE_CHAT_CREDENTIALS_JSON, file-backed)",
    # secret-SHAPED names that carry no secret
    "NOO_TLS_KEY": "a PATH to the PEM, not the key",
    "NOO_GRAFANA_SSO_KEY": "a PATH to the PEM, not the key",
    "NOO_REFRESH_TOKEN_DAYS": "a number",
    "NOO_TOKEN_EXPIRE_MINUTES": "a number",
    "NOO_STT_API_KEY_ENV": "the NAME of a variable, not a value",
    "NOO_TTS_API_KEY_ENV": "the NAME of a variable, not a value",
    "NOO_SELF_CALL_SHARED_SECRET": "a posture bridge flag (\"0\" closes it) that posture "
    "applies with set_var at boot — a _FILE for it would trip the both-set refusal",
}

# Same for the WORKER and the Python manifest.
WORKER_NOT_TIER1: dict[str, str] = {
    "GOOGLE_CHAT_CREDENTIALS": "a PATH to the service-account file (the key itself is "
    "GOOGLE_CHAT_CREDENTIALS_JSON, file-backed)",
    "NOO_TLS_KEY": "a PATH to the PEM, not the key",
}

# Same for the add-on containers and their readers.
ADDON_NOT_TIER1: dict[str, dict[str, str]] = {
    "trellion": dict(WORKER_NOT_TIER1),
    "trellion-intel": dict(WORKER_NOT_TIER1),
    "noo-evolve": {"NOO_EVOLVE_TLS_KEY": "a PATH to evolve's listener PEM, not the key"},
}

# Manifest names compose does not deliver to that container as env today.
# Each is read there for a reason that is not "compose forgot".
RUST_NOT_DELIVERED: dict[str, str] = {
    "NATS_NODE_PASSWORD": "the node's own bus password: read by the node-hosted harness "
    "(`noo-gateway harness`, harness_main.rs) from /etc/noo-harness.env, which the applier "
    "converts to a `_FILE` pointer — never delivered to the gateway container",
}
PYTHON_NOT_DELIVERED: dict[str, str] = {
    "NOO_APP_DB_PASSWORD": "read by alembic migration 033 (`role_password`); the chain "
    "runs in the memory lane (`NOO_MIGRATIONS_ENVS`, `noo db`), never in the worker",
    "NOO_EVOLVE_DB_PASSWORD": "read by alembic migration 034, same lane",
    "NOO_TRELLION_DB_PASSWORD": "read by alembic migration 038, same lane",
    "NOO_CLUSTER_SECRET": "delivered to the gateway and the node agents ONLY since an earlier change: "
    "the fleet secret is a node's credential, and the worker plane's last use of it (the browser "
    "door) has its own key, NOO_BROWSER_KEY. Python still names it for the host-side `security_cli` "
    "scan and cluster_auth's node-side `require_cluster_auth` — neither runs in a controller service",
    "NOO_JWT_SECRET": "delivered to the gateway ONLY since an earlier change (the worker acts as a "
    "user with the per-dispatch token the gateway mints). Python still names it for the host-side "
    "`security_cli` scan, audit_log's retired-derivation fallback (#589 removes it) and the dead "
    "gateway/auth.py import (#587 removes it) — none runs in a container that should hold it",
    # (The cloud-provider keys and NOO_NODE_AGENT_TOKEN used to be listed
    # here: nothing handed them to noo-worker. They are delivered as files to
    # noo-trellion / noo-trellion-intel the earlier change, and the
    # "delivered" side below counts every container that runs noomesh's
    # Python, so they need no entry.)
}

# DSNs carry a password inside a URL. They are NOT file-backed in this phase
# (a `_FILE` for a URL is the wrong shape — the plan splits the password out
# first) and their names are not secret-shaped, so they never reach the
# checks below; they are listed so the exclusion is a decision, not an
# accident.
DSN_NOT_IN_SCOPE = ("DATABASE_URL", "REDIS_URL", "NATS_URL")


def test_the_parsers_found_both_manifests() -> None:
    assert len(rust_manifest()) >= 10
    assert len(python_manifest()) >= 10
    for n in DSN_NOT_IN_SCOPE:
        assert not _secrety({n: ""}), f"{n} is secret-shaped now; decide whether it is tier-1"


def test_shared_names_are_in_both_manifests() -> None:
    """A name delivered to BOTH containers is read on both sides, and both
    sides must read it the same way."""
    p = full_projection()["services"]
    shared = _secrety(delivered_to(p["gateway"])) & _secrety(delivered_to(p["worker"]))
    shared -= set(GATEWAY_NOT_TIER1) | set(WORKER_NOT_TIER1)
    assert len(shared) >= 5, f"too few shared secrets for this to mean anything: {shared}"
    # NOT NOO_JWT_SECRET: the earlier change it reaches the gateway alone
    # (tests/test_jwt_secret_gateway_only.py).
    # NOT NOO_CONTROLLER_SECRET: the earlier change it reaches the gateway alone.
    # NOT NOO_CLUSTER_SECRET either: the earlier change the worker no longer
    # holds the fleet secret (the browser door has its own key).
    for must in ("REDIS_PASSWORD", "NOO_AUDIT_HMAC_KEY", "NOO_BROWSER_KEY"):
        assert must in shared, f"{must} is no longer delivered to both — rewrite this test's premise"
    rust, py = set(rust_manifest()), set(python_manifest())
    missing = {n: [s for s, has in (("rust", n in rust), ("python", n in py)) if not has] for n in shared}
    missing = {n: sides for n, sides in missing.items() if sides}
    assert not missing, f"delivered to gateway AND worker, but a reader does not know _FILE: {missing}"


def _python_delivered(p: dict) -> set[str]:
    """Everything delivered to a container that runs noomesh's Python."""
    return {n for s in PYTHON_CONTAINERS if s in p for n in delivered_to(p[s])}


def test_every_manifest_name_is_delivered_or_explained() -> None:
    p = full_projection()["services"]
    gw, wk = set(delivered_to(p["gateway"])), _python_delivered(p)
    bad = [n for n in rust_manifest() if n not in gw and n not in RUST_NOT_DELIVERED]
    assert not bad, f"Rust manifest names nothing delivers to the gateway: {bad}"
    bad = [n for n in python_manifest() if n not in wk and n not in PYTHON_NOT_DELIVERED]
    assert not bad, f"Python manifest names nothing delivers to the worker: {bad}"


def test_every_secret_shaped_env_reaching_the_gateway_is_in_the_rust_manifest() -> None:
    p = full_projection()["services"]
    delivered = _secrety(delivered_to(p["gateway"]))
    assert len(delivered) >= 20, delivered
    bad = sorted(delivered - set(rust_manifest()) - set(GATEWAY_NOT_TIER1))
    assert not bad, (
        "compose hands the gateway a secret its reader does not read through "
        "secret_env (so it cannot be delivered as a file): "
        f"{bad}. Move the reader onto crate::config::secret_env and add the "
        "name to FILE_BACKED_SECRETS, or allowlist it here WITH a reason."
    )


def test_every_secret_shaped_env_reaching_the_worker_is_in_the_python_manifest() -> None:
    p = full_projection()["services"]
    delivered = _secrety(delivered_to(p["worker"]))
    assert len(delivered) >= 8, delivered
    bad = sorted(delivered - set(python_manifest()) - set(WORKER_NOT_TIER1))
    assert not bad, (
        "compose hands the worker a secret its reader does not read through "
        f"noomesh.secret_env: {bad}. Move the reader onto secret_env.secret() "
        "and add the name to FILE_BACKED_SECRETS, or allowlist it here WITH a reason."
    )


@pytest.mark.parametrize("service", sorted(ADDON_NOT_TIER1))
def test_every_secret_shaped_env_reaching_an_add_on_is_read_through_a_file_aware_helper(service: str) -> None:
    """The add-on half of the direction that matters:
    every secret-shaped name compose hands noo-trellion / noo-trellion-intel
    / noo-evolve — plain or as `NAME_FILE` — is read in that container by a
    `_FILE`-aware helper (noomesh's and/or the add-on's own `secret_env`),
    so delivering it as a file cannot silently blank it."""
    p = full_projection()["services"]
    delivered = _secrety(delivered_to(p[service]))
    # noo-evolve is handed two the earlier change dropped the shared secrets
    # (its key and its TLS key path); the trellion pair still far more.
    assert len(delivered) >= (2 if service == "noo-evolve" else 3), (service, delivered)
    bad = sorted(delivered - addon_reader_manifest(service) - set(ADDON_NOT_TIER1[service]))
    assert not bad, (
        f"compose hands {service} {bad}, which no reader in that container reads through its "
        "`secret_env` helper — a file delivery would read as unset. Move the reader (a sibling "
        "repo's is a sibling PR) or stop delivering it."
    )


def test_allowlists_are_not_stale() -> None:
    """An allowlist entry for a name compose no longer delivers is a
    suppression that outlived its subject."""
    p = full_projection()["services"]
    gw, wk = set(delivered_to(p["gateway"])), set(delivered_to(p["worker"]))
    assert not (set(GATEWAY_NOT_TIER1) - gw), set(GATEWAY_NOT_TIER1) - gw
    for svc, allowed in ADDON_NOT_TIER1.items():
        assert not (set(allowed) - set(delivered_to(p[svc]))), (svc, set(allowed) - set(delivered_to(p[svc])))
    wk_any = _python_delivered(p)
    assert not (set(WORKER_NOT_TIER1) - wk), set(WORKER_NOT_TIER1) - wk
    # and the "not delivered" lists must indeed not be delivered — once
    # compose starts passing one, the reason above is wrong
    assert not (set(RUST_NOT_DELIVERED) & gw), set(RUST_NOT_DELIVERED) & gw
    assert not (set(PYTHON_NOT_DELIVERED) & wk_any), set(PYTHON_NOT_DELIVERED) & wk_any
    # every "not delivered" name is still in its manifest (else the entry is dead)
    assert set(RUST_NOT_DELIVERED) <= set(rust_manifest())
    assert set(PYTHON_NOT_DELIVERED) <= set(python_manifest())


def test_manifests_have_no_duplicates() -> None:
    for names in (rust_manifest(), python_manifest()):
        assert len(names) == len(set(names)), names


# ── no reader bypasses the one helper ─────────────────────────────────────
#
# A manifest entry says "this name is read through secret_env". A direct
# `std::env::var("NAME")` / `os.getenv("NAME")` elsewhere makes that a lie
# the moment compose delivers NAME as a file: the direct reader sees nothing
# (the value is in /run/secrets, only `NAME_FILE` is in the env) and the
# feature goes quietly dead — a search key "unset", a channel "not
# configured". #559 found three such NOO_JWT_SECRET reads by hand; followup
# 1252 §3 found eleven for the provider/channel keys. This makes the next one
# a test failure.

_RUST_TEST_MOD = re.compile(r"#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{")


def _strip_rust_test_modules(src: str) -> str:
    """The source without its `#[cfg(test)] mod … { … }` blocks (brace-matched;
    tests set and read the process env on purpose)."""
    out, pos = [], 0
    for m in _RUST_TEST_MOD.finditer(src):
        if m.start() < pos:
            continue
        out.append(src[pos:m.start()])
        depth, i = 1, m.end()
        while i < len(src) and depth:
            depth += {"{": 1, "}": -1}.get(src[i], 0)
            i += 1
        pos = i
    out.append(src[pos:])
    return "".join(out)


def _strip_line_comments(src: str, marker: str) -> str:
    return "\n".join(line.split(marker, 1)[0] if line.lstrip().startswith(marker) else line for line in src.splitlines())


def rust_bypasses(root: Path = ROOT / "gateway-rust/src", base: Path = ROOT) -> list[str]:
    names = set(rust_manifest())
    bad = []
    for f in sorted(root.rglob("*.rs")):
        if f.name == "secret_env.rs":
            continue
        src = _strip_line_comments(_strip_rust_test_modules(f.read_text()), "//")
        # a const naming a manifest entry, read through env::var(CONST)
        consts = {c for c, n in re.findall(r'const\s+([A-Z_][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([A-Z0-9_]+)"', src) if n in names}
        for n in sorted(names):
            if re.search(r'env::var(?:_os)?\(\s*"%s"\s*\)' % n, src):
                bad.append(f"{f.relative_to(base)}: env::var(\"{n}\")")
        for c in sorted(consts):
            if re.search(r"env::var(?:_os)?\(\s*%s\s*\)" % c, src):
                bad.append(f"{f.relative_to(base)}: env::var({c})")
    return bad


def python_bypasses(root: Path = ROOT / "src/noomesh", base: Path = ROOT) -> list[str]:
    names = set(python_manifest())
    bad = []
    for f in sorted(root.rglob("*.py")):
        if f.name == "secret_env.py":
            continue
        src = _strip_line_comments(f.read_text(), "#")
        for n in sorted(names):
            q = r"""["']%s["']""" % n
            if re.search(r"(?:os\.getenv|environ\.get)\(\s*%s" % q, src) or re.search(r"environ\[\s*%s\s*\](?!\s*=[^=])" % q, src):
                bad.append(f"{f.relative_to(base)}: reads {n} from the plain env")
    return bad


def test_no_rust_reader_bypasses_secret_env() -> None:
    bad = rust_bypasses()
    assert not bad, (
        "a gateway reader takes a FILE_BACKED_SECRETS name straight from the environment — "
        f"it sees nothing once compose delivers the name as a file: {bad}. "
        "Read it with crate::config::secret_env::{secret, secret_opt, secret_required}."
    )


def test_no_python_reader_bypasses_secret_env() -> None:
    bad = python_bypasses()
    assert not bad, (
        "a Python reader takes a FILE_BACKED_SECRETS name straight from os.environ — "
        f"it sees nothing once compose delivers the name as a file: {bad}. "
        "Read it with noomesh.secret_env.secret()/secret_or_empty()."
    )


def test_the_bypass_scanners_catch_what_they_are_for(tmp_path: Path) -> None:
    """Watch each scanner fail on a plant, and stay quiet on a test module
    and a comment."""
    rs = tmp_path / "r"
    rs.mkdir()
    (rs / "a.rs").write_text(
        '// std::env::var("TAVILY_API_KEY") in a comment\n'
        'fn f() { let _ = std::env::var("TAVILY_API_KEY"); }\n'
        'const K: &str = "TELEGRAM_BOT_TOKEN";\nfn g() { let _ = std::env::var(K); }\n'
        '#[cfg(test)]\nmod tests {\n    fn t() { let _ = std::env::var("NOO_JWT_SECRET"); }\n}\n'
    )
    found = rust_bypasses(rs, tmp_path)
    assert found == ['r/a.rs: env::var("TAVILY_API_KEY")', "r/a.rs: env::var(K)"], found

    py = tmp_path / "p"
    py.mkdir()
    (py / "a.py").write_text(
        '# os.getenv("TELEGRAM_BOT_TOKEN") in a comment\n'
        'x = os.getenv("TELEGRAM_BOT_TOKEN", "")\n'
        'os.environ["WHATSAPP_TOKEN"] = "set, not read"\n'
        'y = os.environ["ANTHROPIC_API_KEY"]\n'
    )
    found = python_bypasses(py, tmp_path)
    assert found == ["p/a.py: reads ANTHROPIC_API_KEY from the plain env", "p/a.py: reads TELEGRAM_BOT_TOKEN from the plain env"], found


# ── the Go node agent ──────────────────────────────────
#
# The agent reads NAME_FILE > NOO_SECRET_NAME > NAME through
# `internal/config/secretenv.go`. Its secrets reach it two ways: the opt-in
# containerised agent (`node-agent`, `node-agent-sensors`) gets compose
# `secrets:` files, and the HOST agent every node runs gets
# /etc/noo-node-agent.env, whose plain values the applier (noo-apply.sh
# `agent_secret_files`, and its macOS twin) moves into files once the
# installed binary can read them. Both appliers must move exactly the
# names the reader reads: a name the applier moves but the reader does not
# know boots the agent with that secret unset; a name the reader knows but
# the applier leaves stays plaintext in the env file.

NODE_AGENT_SERVICES = ("node-agent", "node-agent-sensors")

# Secret-shaped variables the containerised agent receives that its reader
# deliberately does not read through secretenv.go.
GO_NOT_TIER1: dict[str, str] = {
    "HF_TOKEN": "passed through to the backend containers the agent starts (third-party "
    "model images read it natively) — an earlier change keeps it env by decision",
    "NOO_TLS_KEY": "a PATH to the PEM, not the key",
}
# ...and in the host agent's env template.
GO_TMPL_NOT_TIER1: dict[str, str] = {
    "NOO_TLS_KEY": "a PATH to the PEM, not the key",
}


def applier_agent_secret_keys(src: str | None = None) -> list[str]:
    src = APPLIER.read_text() if src is None else src
    m = re.search(r'^AGENT_SECRET_KEYS="([^"]+)"', src, re.M)
    assert m, "AGENT_SECRET_KEYS not found in noo-apply.sh"
    return m.group(1).split()


def darwin_agent_secret_keys() -> list[str]:
    m = re.search(r"pub\(crate\) const AGENT_SECRET_KEYS: &\[&str\] =\s*&\[(.*?)\];", DARWIN_APPLIER.read_text(), re.S)
    assert m, "AGENT_SECRET_KEYS not found in agent_secret_files.rs"
    return re.findall(r'"([A-Z0-9_]+)"', m.group(1))


def _capability(src: str, pattern: str) -> str:
    m = re.search(pattern, src, re.M)
    assert m, pattern
    return m.group(1)


def test_both_appliers_move_exactly_what_the_go_reader_reads() -> None:
    go = go_manifest()
    assert len(go) == len(set(go)), go
    assert applier_agent_secret_keys() == go, "noo-apply.sh AGENT_SECRET_KEYS drifted from the Go manifest"
    assert darwin_agent_secret_keys() == go, "agent_secret_files.rs AGENT_SECRET_KEYS drifted from the Go manifest"


def test_the_appliers_look_for_the_marker_the_agent_carries() -> None:
    go = _capability(GO.read_text(), r'^const SecretFilesCapability = "([^"]+)"')
    assert _capability(APPLIER.read_text(), r'^AGENT_SECRET_CAPABILITY="([^"]+)"') == go
    assert _capability(DARWIN_APPLIER.read_text(), r'^pub\(crate\) const AGENT_SECRET_CAPABILITY: &str = "([^"]+)";') == go
    # ...and the agent logs it at startup, which is what keeps it in the binary.
    agent = (ROOT / "node-agent-go/internal/agent/agent.go").read_text()
    assert "config.SecretFilesCapability" in agent


def test_every_secret_in_the_host_agent_env_template_is_read_through_the_go_reader() -> None:
    keys = re.findall(r"^([A-Z][A-Z0-9_]*)=", AGENT_ENV_TMPL.read_text(), re.M)
    assert "NODE_ID" in keys and len(keys) >= 20, keys
    secrety = _secrety(dict.fromkeys(keys, ""))
    bad = sorted(secrety - set(go_manifest()) - set(GO_TMPL_NOT_TIER1))
    assert not bad, (
        f"the host agent env template renders {bad}, which the agent does not read through "
        "secretenv.go — the applier would leave it plaintext in /etc/noo-node-agent.env"
    )


@pytest.mark.parametrize("service", NODE_AGENT_SERVICES)
def test_every_secret_reaching_the_containerised_agent_is_in_the_go_manifest(service: str) -> None:
    p = full_projection()["services"]
    delivered = _secrety(delivered_to(p[service]))
    # noo-evolve is handed two the earlier change dropped the shared secrets
    # (its key and its TLS key path); the trellion pair still far more.
    assert len(delivered) >= (2 if service == "noo-evolve" else 3), (service, delivered)
    bad = sorted(delivered - set(go_manifest()) - set(GO_NOT_TIER1))
    assert not bad, f"compose hands {service} {bad}, which secretenv.go does not read"
    missing = sorted(set(go_manifest()) - set(delivered_to(p[service])))
    assert not missing, f"the Go manifest names {missing}, which compose never hands {service}"
    for n in go_manifest():
        assert n not in env_of(p[service]), f"{service} gets {n} as a plain env var, not a file"


def _strip_go_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return "\n".join(line.split("//", 1)[0] if not re.search(r'"[^"]*//', line) else line for line in src.splitlines())


def go_bypasses(root: Path = ROOT / "node-agent-go", base: Path = ROOT) -> list[str]:
    names = set(go_manifest())
    bad = []
    for f in sorted(root.rglob("*.go")):
        if f.name.endswith("_test.go") or f.name == "secretenv.go":
            continue
        src = _strip_go_comments(f.read_text())
        consts = {c for c, n in re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([A-Z0-9_]+)"', src) if n in names}
        for n in sorted(names):
            if re.search(r'os\.(?:Getenv|LookupEnv)\(\s*"%s"\s*\)' % n, src):
                bad.append(f"{f.relative_to(base)}: os.Getenv(\"{n}\")")
            if re.search(r"\$\{%s(?::-[^}]*)?\}" % n, src):
                bad.append(f"{f.relative_to(base)}: ${{{n}}} (resolveEnv reads the plain env)")
        for c in sorted(consts):
            if re.search(r"os\.(?:Getenv|LookupEnv)\(\s*%s\s*\)" % c, src):
                bad.append(f"{f.relative_to(base)}: os.Getenv({c})")
    return bad


def test_no_go_reader_bypasses_secretenv() -> None:
    bad = go_bypasses()
    assert not bad, (
        "a node-agent reader takes a FileBackedSecrets name straight from the environment — it sees "
        f"nothing once the applier moves the value into a file: {bad}. Read it with config.Secret / "
        "config.SecretLookup (or the Load()ed Config)."
    )


def test_the_go_scanner_and_parsers_catch_what_they_are_for(tmp_path: Path) -> None:
    g = tmp_path / "g"
    g.mkdir()
    (g / "a.go").write_text(
        '// os.Getenv("NOO_CLUSTER_SECRET") in a comment\n'
        'func f() string { return os.Getenv("NOO_CLUSTER_SECRET") }\n'
        'const pw = "NATS_NODE_PASSWORD"\nfunc g() string { return os.Getenv(pw) }\n'
        'var spec = map[string]string{"X": "${NOO_NODE_AGENT_TOKEN:-}"}\n'
    )
    (g / "a_test.go").write_text('func t() { os.Getenv("NOO_CLUSTER_SECRET") }\n')
    found = go_bypasses(g, tmp_path)
    assert found == [
        'g/a.go: os.Getenv("NOO_CLUSTER_SECRET")',
        "g/a.go: ${NOO_NODE_AGENT_TOKEN} (resolveEnv reads the plain env)",
        "g/a.go: os.Getenv(pw)",
    ], found
    with pytest.raises(AssertionError):
        go_manifest("var Other = []string{\n}\n")
    assert applier_agent_secret_keys('AGENT_SECRET_KEYS="A B"\n') == ["A", "B"]


# ── the node-hosted harness ───────────────────────────────
#
# The harness is the gateway binary's `harness` subcommand, run on a node
# from /etc/noo-harness.env (Linux) / ~/noomesh/harness.env (macOS). It
# reads its secrets through secret_env, and both appliers convert that env
# to `_FILE` pointers once the installed gateway binary carries the
# harness's marker. The same three-way agreement as the agent's: the Rust
# list, the shell list, the macOS list, and the marker all four places.

HARNESS_RS = ROOT / "gateway-rust/src/harness_main.rs"
HARNESS_ENV_TMPL = ROOT / "node-agent-go/deploy/noo-harness.env.tmpl"


def harness_manifest(src: str | None = None) -> list[str]:
    src = HARNESS_RS.read_text() if src is None else src
    m = re.search(r"pub const HARNESS_SECRET_KEYS: &\[&str\] =\s*&\[(.*?)\];", src, re.S)
    assert m, "HARNESS_SECRET_KEYS not found in harness_main.rs — this guard is reading the wrong thing"
    names = re.findall(r'"([A-Z0-9_]+)"', m.group(1))
    assert len(names) >= 2, f"harness manifest parsed suspiciously short: {names}"
    return names


def applier_harness_secret_keys() -> list[str]:
    m = re.search(r'^HARNESS_SECRET_KEYS="([^"]+)"', APPLIER.read_text(), re.M)
    assert m, "HARNESS_SECRET_KEYS not found in noo-apply.sh"
    return m.group(1).split()


def darwin_harness_secret_keys() -> list[str]:
    m = re.search(r"pub\(crate\) const HARNESS_SECRET_KEYS: &\[&str\] =\s*&\[(.*?)\];", DARWIN_APPLIER.read_text(), re.S)
    assert m, "HARNESS_SECRET_KEYS not found in agent_secret_files.rs"
    return re.findall(r'"([A-Z0-9_]+)"', m.group(1))


def test_both_appliers_move_exactly_what_the_harness_reads() -> None:
    h = harness_manifest()
    assert len(h) == len(set(h)), h
    assert "NATS_NODE_PASSWORD" in h, "the harness's own bus password is the reason this list exists"
    assert applier_harness_secret_keys() == h, "noo-apply.sh HARNESS_SECRET_KEYS drifted from harness_main.rs"
    assert darwin_harness_secret_keys() == h, "agent_secret_files.rs HARNESS_SECRET_KEYS drifted from harness_main.rs"
    # ...and every one is read through secret_env, so the bypass scan and
    # preflight's file check cover it.
    assert not (set(h) - set(rust_manifest())), set(h) - set(rust_manifest())


def test_the_appliers_look_for_the_marker_the_harness_carries() -> None:
    src = HARNESS_RS.read_text()
    rs = _capability(src, r'^pub const HARNESS_SECRET_FILES_CAPABILITY: &str = "([^"]+)";')
    assert rs != _capability(GO.read_text(), r'^const SecretFilesCapability = "([^"]+)"'), (
        "the harness and the agent are different binaries on different rolls — one marker for both "
        "would convert the harness env on the strength of the AGENT binary"
    )
    assert _capability(APPLIER.read_text(), r'^HARNESS_SECRET_CAPABILITY="([^"]+)"') == rs
    assert _capability(DARWIN_APPLIER.read_text(), r'^pub\(crate\) const HARNESS_SECRET_CAPABILITY: &str = "([^"]+)";') == rs
    # logged at harness startup — what keeps it in the binary — and the
    # boot check runs before the bus credential is read.
    run = src[src.index("pub async fn run()"):]
    assert "capability = HARNESS_SECRET_FILES_CAPABILITY" in run
    assert run.index("check_harness_secrets(") < run.index("bus_credential_from(")


def test_every_secret_in_the_harness_env_template_is_read_through_secret_env() -> None:
    keys = re.findall(r"^([A-Z][A-Z0-9_]*)=", HARNESS_ENV_TMPL.read_text(), re.M)
    assert "NODE_ID" in keys and "NATS_NODE_PASSWORD" in keys, keys
    secrety = _secrety(dict.fromkeys(keys, ""))
    bad = sorted(secrety - set(harness_manifest()) - {"NOO_TLS_KEY"})
    assert not bad, (
        f"the harness env template renders {bad}, which the harness does not read through secret_env "
        "(HARNESS_SECRET_KEYS) — the applier would leave it plaintext in /etc/noo-harness.env"
    )


def test_the_harness_reads_its_bus_pair_through_secret_env() -> None:
    src = _strip_line_comments(_strip_rust_test_modules(HARNESS_RS.read_text()), "//")
    assert 'secret_env::secret_from("NATS_NODE_PASSWORD", get)' in src
    assert not re.search(r"std::env::var\(\s*[pu]\s*\)", src), "the pair is read from the plain env again"


def test_no_second_converter_survives_the_swap_retirement() -> None:
    """hostd's swap-agent kept its own copy of the inlining decision. an earlier change A3 retired the swap, so the appliers are the only
    converters left — a revived copy in hostd would be a fourth list to drift."""
    assert not (ROOT / "node-agent-go/internal/hostd/swap_secrets.go").exists()
    ops = (ROOT / "node-agent-go/internal/hostd/worker_ops.go").read_text()
    assert "secretsForCandidate" not in ops


def test_the_harness_parser_catches_what_it_is_for() -> None:
    assert harness_manifest('pub const HARNESS_SECRET_KEYS: &[&str] =\n    &["A_B", "C"];\n') == ["A_B", "C"]
    with pytest.raises(AssertionError):
        harness_manifest("pub const OTHER: &[&str] = &[];\n")
