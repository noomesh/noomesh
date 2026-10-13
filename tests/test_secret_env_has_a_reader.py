# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every secret compose hands a container is read by something IN that container.

The operator's rule is "always sops, never plaintext". The cheapest reduction
in plaintext exposure is not a better store — it is to stop delivering a
secret to a process that never reads it. "Reads" includes a config another
component RENDERS for it: the nats server's users.conf is written by
`nats_users.rs`, which wrote `$NATS_USER` / `$NATS_PASSWORD` for the legacy
principal until an earlier change retired it — and removing those two on the
evidence of the repo's `monitoring/nats` alone, while the renderer still
emitted them, took the bus down on the stack-v0.2.78 roll. A value in a container's environment
is visible to every `docker inspect`, every `/proc/<pid>/environ`, every crash
dump and every child process, whether or not the code ever looks at it.

Found 2026-09-29, against the composed projection: noo-evolve was handed `NOO_EVOLVE_DB_PASSWORD` beside the DSN that
already carries it, and the trellion anchor — inherited by trellion-intel via
`extends` — carried `NOO_MCP_TOKEN` and `NOO_ADMIN_PASSWORD` (readers: the
Rust gateway only), the Tailscale OAuth client (reader: `routes/cluster.rs`
only), and `SLACK_BOT_TOKEN` / `TELEGRAM_SECRET_TOKEN`, which nothing in any
tree reads at all. Each had been "mirrored so the two blocks stay diffable".

The rule: for every service in the composed projection (base + every add-on
overlay), every environment key whose name says "credential" (the SECRETY
tuple `test_no_secrets_on_compose_command_lines` judges command lines by)
must have a READER — the literal variable name, outside comments — in the
code tree that runs inside that container, or in the service's own
`command:` / `entrypoint:`, or be a variable NATIVE to a third-party image
(`POSTGRES_PASSWORD`, `GF_SECURITY_ADMIN_PASSWORD`, …) named in an allow-list
here.

Trees that live in a sibling checkout (trellion, trellion-intel,
evolve) are searched when the checkout is beside this one and SKIPPED
with a printed reason when it is not — CI has no sibling. A pair the in-repo
trees cannot settle and the sibling is absent for is reported as unverified,
never as passed.

Plant (2026-09-29): re-adding `NOO_MCP_TOKEN` to `x-trellion-env` fails
naming `trellion` and `trellion-intel`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from tests._compose_projection import ROOT, env_of, full_projection
from tests.test_no_secrets_on_compose_command_lines import SECRETY

# Source extensions a reader can live in. JSON is deliberately absent: the
# generated OpenAPI spec under gateway/static names credentials in prose.
SOURCE_SUFFIXES = {".rs", ".py", ".go", ".sh", ".conf", ".toml", ".yml", ".yaml", ".ini", ".j2"}

# Files that NAME credentials without reading them. Each has a reason; a
# file here is excluded from every tree it sits under.
NOT_READERS: dict[str, str] = {
    # The Docker-secrets filename → env map: it WRITES os.environ from
    # /run/secrets files (nothing mounts them), and names keys such as
    # NOO_MCP_TOKEN and NOO_ADMIN_PASSWORD that no Python reads.
    "src/noomesh/secrets.py": "_SECRET_FILE_TO_ENV writes env from /run/secrets; it reads nothing",
}

# The code tree that runs inside each service's container, relative to ROOT.
# `docker/entrypoint.py` is the Python images' entrypoint (it remaps the PKI
# paths), so it runs in every Python container. The gateway also reads the
# systems manifest `noo systems enable` writes (`NOO_SYSTEMS_MANIFEST`): its
# `password_env` / `ddl_password_env` fields NAME the variable the broker
# reads (`system_provision.rs::ensure_role` → `std::env::var(password_env)`),
# so the literal lives in the manifest's writer, `commands/systems.rs`.
IN_REPO_TREES: dict[str, tuple[str, ...]] = {
    "gateway": (
        "gateway-rust/src",
        "docker/entrypoint.py",
        "src/noomesh/db",
        "noo-cli/src/commands/systems.rs",
    ),
    "worker": ("src/noomesh", "docker/entrypoint.py"),
    "worker-extra": ("src/noomesh", "docker/entrypoint.py"),
    "browser": ("src/noomesh", "docker/entrypoint.py"),
    "trellion": ("src/noomesh", "docker/entrypoint.py"),
    "trellion-intel": ("src/noomesh", "docker/entrypoint.py"),
    "noo-evolve": (),
    # The server's users.conf is RENDERED on the controller by nats_users.rs
    # (which wrote the legacy `$NATS_USER` / `$NATS_PASSWORD` principal until
    # the design). Searching only monitoring/nats is how #543 removed two
    # variables the server then needed and took the bus down on v0.2.78.
    "nats": ("monitoring/nats", "noo-cli/src/commands/nats_users.rs"),
    "redis": ("docker/redis-entrypoint.sh",),
    "node-agent": ("node-agent-go",),
    "node-agent-sensors": ("node-agent-go",),
    "nvidia-exporter": ("docker",),
    "postgres": (),
    "grafana": (),
    "vllm": (),
    "vllm-secondary": (),
    "tei": (),
    "tei-gpu": (),
    "whisper": (),
    "reranker": (),
}

# Sibling checkouts (name beside this repo → sub-path) per service. Searched
# when present; a miss with the sibling absent is "unverified", not "ok".
SIBLING_TREES: dict[str, tuple[tuple[str, str], ...]] = {
    "trellion": (("trellion", "src"),),
    "trellion-intel": (("trellion", "src"), ("pai-trellion-intel", "src")),
    "noo-evolve": (("pai-evolve", "src"),),
}

# Variables a THIRD-PARTY image reads natively — there is no code of ours to
# grep. Each names the image's own variable, not a noomesh spelling.
NATIVE: dict[str, dict[str, str]] = {
    "postgres": {"POSTGRES_PASSWORD": "postgres image: the superuser password at initdb"},
    "grafana": {
        "GF_SECURITY_ADMIN_PASSWORD": "grafana image: [security] admin_password",
        "GF_SERVER_CERT_KEY": "grafana image: [server] cert_key",
    },
    "vllm": {
        "HF_TOKEN": "huggingface_hub: gated model pulls",
        "HUGGING_FACE_HUB_TOKEN": "huggingface_hub: legacy spelling of HF_TOKEN",
    },
    "vllm-secondary": {
        "HF_TOKEN": "huggingface_hub: gated model pulls",
        "HUGGING_FACE_HUB_TOKEN": "huggingface_hub: legacy spelling of HF_TOKEN",
    },
    "tei": {"HUGGING_FACE_HUB_TOKEN": "text-embeddings-inference: gated model pulls"},
    "tei-gpu": {"HUGGING_FACE_HUB_TOKEN": "text-embeddings-inference: gated model pulls"},
    "whisper": {"HUGGING_FACE_HUB_TOKEN": "faster-whisper image: gated model pulls"},
    "reranker": {"HUGGING_FACE_HUB_TOKEN": "text-embeddings-inference: gated model pulls"},
}

# A word-bounded match: NOO_MCP_TOKEN must not be satisfied by
# NOO_MCP_TOKEN_PREVIOUS, nor NATS_PASSWORD by NATS_NODE_PASSWORD.
_BOUNDARY = r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])"

_LINE_COMMENT = re.compile(r"^\s*(#|//|\*|/\*)")
_TRAIL_HASH = re.compile(r"\s#.*$")
_TRAIL_SLASH = re.compile(r"(^|\s)//.*$")


def _code_lines(path: Path) -> str:
    """The file with whole-line and trailing comments removed."""
    out = []
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return ""
    for line in text.splitlines():
        if _LINE_COMMENT.match(line):
            continue
        if path.suffix in {".rs", ".go"}:
            line = _TRAIL_SLASH.sub("", line)
        else:
            line = _TRAIL_HASH.sub("", line)
        out.append(line)
    return "\n".join(out)


def _files_under(base: Path, rel: str) -> list[Path]:
    p = base / rel
    if p.is_file():
        return [p]
    if not p.is_dir():
        return []
    return [f for f in p.rglob("*") if f.is_file() and f.suffix in SOURCE_SUFFIXES]


def _reader_in(files: list[Path], key: str) -> Path | None:
    pat = re.compile(_BOUNDARY % re.escape(key))
    for f in files:
        rel = f.relative_to(ROOT).as_posix() if f.is_relative_to(ROOT) else None
        if rel in NOT_READERS:
            continue
        if pat.search(_code_lines(f)):
            return f
    return None


def sibling_dirs() -> list[Path]:
    """Where a sibling checkout may sit: `NOO_SIBLINGS_DIR`, the repo's
    parent, and — for a `.worktrees/<slug>` checkout — the main clone's
    parent."""
    out = []
    if os.environ.get("NOO_SIBLINGS_DIR"):
        out.append(Path(os.environ["NOO_SIBLINGS_DIR"]))
    out.append(ROOT.parent)
    if ROOT.parent.name == ".worktrees":
        out.append(ROOT.parents[2])
    return out


def _sibling(name: str) -> Path | None:
    for d in sibling_dirs():
        if (d / name).is_dir():
            return d / name
    return None


def _argv_text(service: dict) -> str:
    parts = []
    for field in ("command", "entrypoint"):
        v = service.get(field)
        if isinstance(v, list):
            parts.extend(str(x) for x in v)
        elif v:
            parts.append(str(v))
    return "\n".join(parts)


def _secret_keys(service: dict) -> list[str]:
    return sorted(k for k in env_of(service) if any(m in k.upper() for m in SECRETY))


@pytest.fixture(scope="module")
def services() -> dict:
    doc = full_projection()
    svcs = doc.get("services") or {}
    assert svcs, "the projection has zero services"
    return svcs


def test_every_secret_env_key_has_a_reader_in_its_container(services: dict) -> None:
    checked = 0
    unverified: list[str] = []
    missing: list[str] = []
    for name, svc in sorted(services.items()):
        keys = _secret_keys(svc)
        if not keys:
            continue
        assert name in IN_REPO_TREES, (
            f"service `{name}` receives {keys} but this guard has no tree for it — "
            "add it to IN_REPO_TREES (the code that runs in that container), "
            "SIBLING_TREES or NATIVE, with the reason"
        )
        in_repo = [f for rel in IN_REPO_TREES[name] for f in _files_under(ROOT, rel)]
        argv = _argv_text(svc)
        native = NATIVE.get(name, {})
        siblings = SIBLING_TREES.get(name, ())
        for key in keys:
            checked += 1
            # A `NAME_FILE` pointer (compose `secrets:` delivery, 2026-09-29)
            # is read by whatever reads NAME: the one-reader helpers build the
            # `_FILE` name from NAME, so the literal pointer name never appears
            # in code. The pointer counts as read only if NAME has a reader.
            key = key.removesuffix("_FILE")
            if key in native:
                continue
            pat = re.compile(_BOUNDARY % re.escape(key))
            if pat.search(argv) or _reader_in(in_repo, key):
                continue
            absent = []
            found = False
            for sib, sub in siblings:
                base = _sibling(sib)
                if base is None:
                    absent.append(sib)
                    continue
                if _reader_in(_files_under(base, sub), key):
                    found = True
                    break
            if found:
                continue
            if absent:
                unverified.append(f"  {name}.{key}: no in-repo reader; sibling {absent} absent")
                continue
            searched = list(IN_REPO_TREES[name]) + [f"../{s}/{p}" for s, p in siblings] + ["command/entrypoint"]
            missing.append(f"  {name}: {key}  (searched {searched})")

    print(f"\nsecret-env readers: {checked} (service, key) pairs checked, {len(unverified)} unverified")
    for line in unverified:
        print(line)
    assert checked >= 20, f"only {checked} (service, key) pairs checked — the projection or SECRETY parse is wrong"
    assert not missing, (
        "a secret is delivered to a container whose code never reads it:\n"
        + "\n".join(missing)
        + "\n\nRemove it from that service's environment (for a trellion-anchor key, "
        "from `x-trellion-env`, which trellion-intel inherits). If a reader exists "
        "under another spelling, name the reading file's tree in IN_REPO_TREES, "
        "or the image's native variable in NATIVE."
    )


def test_the_boundary_match_does_not_accept_a_longer_name(tmp_path: Path) -> None:
    f = tmp_path / "x.rs"
    f.write_text('let a = std::env::var("NOO_MCP_TOKEN_PREVIOUS");\n// NOO_MCP_TOKEN in a comment\n')
    assert _reader_in([f], "NOO_MCP_TOKEN") is None
    f.write_text('let a = std::env::var("NOO_MCP_TOKEN");\n')
    assert _reader_in([f], "NOO_MCP_TOKEN") == f


def test_not_readers_still_exist() -> None:
    for rel, why in NOT_READERS.items():
        assert (ROOT / rel).is_file(), f"NOT_READERS names {rel} ({why}) but it is gone — drop the entry"
