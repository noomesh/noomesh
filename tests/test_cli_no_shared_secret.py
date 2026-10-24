# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No CLI signs with the cluster (fleet) or controller secret.

The Python CLI's `cli_httpx_kwargs` used to fall back to an HMAC minted from
`NOO_CLUSTER_SECRET` as actor `cli` whenever `NOO_TOKEN` was unset — a CLI
presenting a shared secret that names nobody. That fallback is removed: the
operator's own login (`NOO_TOKEN`) or a refusal naming the Rust `noo` verb.

Two halves:

- a STATIC guard over the CLI modules under `src/noomesh` (AST, so prose
  in docstrings does not count) for anything that mints a shared-secret
  bearer;
- the refusal itself, driven through `cli_httpx_kwargs` under a stubbed
  click context — never by invoking a real command, which can act on the
  host.

The pointer is honest only if every Python command has a native Rust
equivalent under the same words; that is pinned too, against
`noo-cli/src/main.rs`'s NATIVE table.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import click
import pytest

from noomesh import cli_utils
from noomesh.cli_utils import cli_httpx_kwargs, rust_cli_pointer

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "noomesh"

# Names that mint a shared-secret bearer (cluster/cluster_auth.py,
# channels/gateway_client.py). A CLI module must reach none of them.
MINTERS = {"create_cluster_token", "internal_gateway_headers", "_self_call_secret"}
FORBIDDEN_MODULES = {"hmac", "noomesh.channels.gateway_client"}


def _cli_modules() -> list[Path]:
    out = [p for p in SRC.rglob("*.py")
           if p.name in ("cli.py", "cli_utils.py") or p.name.endswith("_cli.py")]
    return sorted(out)


def minting_sites(path: Path, source: str | None = None) -> list[str]:
    """Every place in one module that mints, or imports a minter of, a
    shared-secret bearer."""
    tree = ast.parse(source if source is not None else path.read_text())
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in FORBIDDEN_MODULES or a.name.split(".")[-1] == "hmac":
                    hits.append(f"{path.name}:{node.lineno} import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in FORBIDDEN_MODULES or mod.endswith("gateway_client") or mod == "hmac":
                hits.append(f"{path.name}:{node.lineno} from {mod}")
            for a in node.names:
                if a.name in MINTERS:
                    hits.append(f"{path.name}:{node.lineno} imports {a.name}")
        elif isinstance(node, ast.Name) and node.id in MINTERS:
            hits.append(f"{path.name}:{node.lineno} uses {node.id}")
        elif isinstance(node, ast.Attribute) and node.attr in MINTERS:
            hits.append(f"{path.name}:{node.lineno} uses .{node.attr}")
    return hits


def test_the_scan_sees_the_cli() -> None:
    mods = _cli_modules()
    names = {p.name for p in mods}
    assert len(mods) >= 20, f"found only {len(mods)} CLI modules — the glob is wrong"
    assert {"cli.py", "cli_utils.py", "approval_cli.py"} <= names


def test_the_scan_catches_a_signer() -> None:
    """The guard must be able to fail: the removed fallback, verbatim."""
    planted = (
        "from .cluster.cluster_auth import create_cluster_token\n"
        "token = create_cluster_token('cli', secret=secret)\n"
    )
    assert len(minting_sites(Path("planted_cli.py"), planted)) == 2


def test_no_cli_module_mints_a_shared_secret_bearer() -> None:
    hits = [h for p in _cli_modules() for h in minting_sites(p)]
    assert not hits, (
        "a CLI module mints (or imports a minter of) a cluster/controller-secret "
        "bearer. The CLI authenticates as the operator ($NOO_TOKEN / the Rust "
        f"noo's login), never with a shared secret: {hits}"
    )


# ── The refusal ──────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _no_repo_env(monkeypatch):
    monkeypatch.setattr(cli_utils, "ensure_repo_env", lambda *a, **k: None)
    monkeypatch.delenv("NOO_TOKEN", raising=False)
    monkeypatch.setenv("NOO_CLUSTER_SECRET", "fleet-secret")
    monkeypatch.setenv("NOO_CONTROLLER_SECRET", "controller-secret")


def _in_context(words: list[str], fn):
    """Run `fn` inside a stubbed click context chain `noo-py <words…>` —
    the shape typer builds — without any real command."""
    from contextlib import ExitStack

    with ExitStack() as stack:
        ctx = stack.enter_context(click.Context(click.Group("noo-py"), info_name="noo-py"))
        for w in words:
            ctx = stack.enter_context(click.Context(click.Command(w), parent=ctx, info_name=w))
        return fn()


def _python_command_paths() -> list[list[str]]:
    """Every leaf command path of the Python CLI (built, never invoked)."""
    from typer.main import get_command

    from noomesh.cli import app

    def walk(cmd, path):
        if hasattr(cmd, "commands"):
            for n, c in cmd.commands.items():
                yield from walk(c, path + [n])
        else:
            yield path

    # Command groups an installed add-on contributes through the extension seam
    # are the add-on's own surface, not the core Python CLI this test pins.
    from noomesh.addon_roles import CLI_GROUPS, extensions

    contributed = {name for name, _ in extensions(CLI_GROUPS)}
    return [p for p in walk(get_command(app), []) if not (p and p[0] in contributed)]


def _rust_native_paths() -> set[str]:
    src = (ROOT / "noo-cli/src/main.rs").read_text()
    table = src[src.index("const NATIVE: &[(&[&str], Handler)] = &["):]
    table = table[: table.index("\n];")]
    out = set()
    for m in re.finditer(r'^\s*\(&\[([^\]]*)\]', table, re.M):
        out.add(" ".join(re.findall(r'"([^"]+)"', m.group(1))))
    assert len(out) > 100, f"parsed {len(out)} NATIVE entries — the table moved"
    return out


def test_every_python_command_has_a_rust_verb_under_the_same_words() -> None:
    """The refusal sends the operator to `noo <same words>`. If a Python
    command had no native twin, that pointer would land on an unknown
    command (the Rust `noo` execs no Python any more) — so such a command
    must instead be routed through the gateway with the operator's login,
    and this test is where that decision gets forced."""
    native = _rust_native_paths()
    paths = _python_command_paths()
    assert len(paths) > 100, f"walked only {len(paths)} Python commands"
    missing = [" ".join(p) for p in paths if " ".join(p) not in native]
    assert not missing, f"Python commands with no Rust twin: {missing}"


@pytest.mark.parametrize("words", [
    ["cluster", "nodes"],
    ["approval", "approve"],
    ["memory", "search"],
    ["security", "posture", "set"],
])
def test_a_command_with_no_login_refuses_with_its_rust_verb(words, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        _in_context(words, cli_httpx_kwargs)
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert f"run: noo {' '.join(words)}" in err, err
    assert "no longer signs" in err


def test_every_python_command_refuses_with_its_own_pointer(capsys) -> None:
    """Every command path, through the one choke point every signing
    command uses — nothing is sent, nothing signed, and the pointer names
    that command's own words."""
    for words in _python_command_paths():
        with pytest.raises(SystemExit):
            _in_context(words, cli_httpx_kwargs)
        assert f"run: noo {' '.join(words)}" in capsys.readouterr().err, words


def test_the_refusal_is_not_swallowed_by_except_exception() -> None:
    """Many CLI modules wrap requests in `except Exception`; the refusal
    must not turn into a misleading 'gateway unreachable'."""
    try:
        try:
            cli_httpx_kwargs()
        except Exception:  # noqa: BLE001 — the point of the test
            pytest.fail("the refusal was caught by `except Exception`")
    except SystemExit:
        pass


def test_the_operators_own_login_still_works() -> None:
    import os
    os.environ["NOO_TOKEN"] = "jwt-op"
    try:
        h = cli_httpx_kwargs()["headers"]["Authorization"]
    finally:
        del os.environ["NOO_TOKEN"]
    assert h == "Bearer jwt-op"


def test_outside_a_command_the_pointer_is_generic() -> None:
    assert rust_cli_pointer() == "noo <the same command>"
