# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No caller sends the static node-agent token.

`NOO_NODE_AGENT_TOKEN` is one secret that every node holds. A node agent
admits the controller by its client certificate (`auth.ControllerLeafOrToken`)
and a node's own harness by that node's certificate
(`auth.OwnHarnessLeafOrToken`). A bearer made from this token proves only
"something that holds a fleet secret", so each caller that sent it was moved:

- the gateway's node-agent calls: `node_agent_auth::header_for`, per agent
  (#655), and the harness (#674);
- `tools/browser_tool.py`, `skills/skill_executor.py` and the
  `gateway/helpers.py` node-agent helpers in the worker: these dialled
  `https://localhost:8081`, which inside the worker container is the worker
  itself. They now refuse with a reason that names the gateway route;
- `noo skills run`: it now always goes through the gateway;
- the gateway's browser start/stop routes: no `localhost:8081` fallback.

This guard reads the source for anything that READS the token's value (a call
with the name as its argument, or a subscript such as `os.environ[...]`).
Comments, docstrings and secret-name lists are not reads. Every reader must be
on ALLOWED with the reason it is not an agent call, or with the reason it is
still kept. The one kept sender is the gateway's transitional bearer for
agents that have not yet reported `controller_leaf_only`, which retirement
step 4 of an earlier change removes.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "NOO_NODE_AGENT_TOKEN"

PY_ROOTS = [ROOT / "src" / "noomesh"]
RS_ROOTS = [ROOT / "gateway-rust" / "src", ROOT / "noo-cli" / "src"]

# file (relative to the repo root) -> why reading the token there is not an
# agent call, or why it is still kept. A stale entry fails the guard too.
ALLOWED: dict[str, str] = {
    # The one kept SENDER. Sent only to an agent that has not reported
    # `controller_leaf_only` (or, for the harness, `own_harness_leaf_only`),
    # so the gateway and agents can roll in either order. Removed by
    # retirement step 4 of the design, after a week of zero static_token.
    "gateway-rust/src/node_agent_auth.rs": "kept: transitional per-agent bearer for agents that have not reported leaf-only",
    # Not senders.
    "src/noomesh/cluster/cluster_auth.py": "inbound: verifies a presented token; sends nothing",
    "noo-cli/src/commands/security_local.rs": "posture audit: checks the secret is set; sends nothing",
    "noo-cli/src/commands/provision.rs": "provisioning: writes the secret into a node's env; calls no agent",
}

# Rust: an identifier applied to the literal, e.g. `secret_opt("…")`,
# `std::env::var("…")`, `get("…")`. Writes in test setup are not reads.
_RS_READ = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*"' + TOKEN + r'"')
_RS_NOT_READS = {"set_var", "remove_var"}


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _python_reads(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if any(isinstance(a, ast.Constant) and a.value == TOKEN for a in node.args):
                lines.append(node.lineno)
        elif isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and node.slice.value == TOKEN:
                lines.append(node.lineno)
    return lines


def _strip_rust_comment(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith("//"):
        return ""
    # A trailing `// …` comment. URLs in strings (`https://…`) have no space
    # before the slashes, so they survive.
    idx = line.find(" //")
    return line if idx < 0 else line[:idx]


def _rust_reads(path: Path) -> list[int]:
    lines: list[int] = []
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        code = _strip_rust_comment(raw)
        for m in _RS_READ.finditer(code):
            if m.group(1) not in _RS_NOT_READS:
                lines.append(n)
    return lines


def readers() -> dict[str, list[int]]:
    """Every file that reads the token's value, with the lines."""
    found: dict[str, list[int]] = {}
    for root in PY_ROOTS:
        for path in sorted(root.rglob("*.py")):
            if "tests" in path.relative_to(root).parts:
                continue
            hits = _python_reads(path)
            if hits:
                found[_rel(path)] = hits
    for root in RS_ROOTS:
        for path in sorted(root.rglob("*.rs")):
            hits = _rust_reads(path)
            if hits:
                found[_rel(path)] = hits
    return found


def test_the_scan_finds_the_reads_it_is_meant_to_find() -> None:
    """A scan that finds nothing passes for the wrong reason. The kept
    sender and the inbound verifier are real reads in both languages."""
    found = readers()
    assert "gateway-rust/src/node_agent_auth.rs" in found, found
    assert "src/noomesh/cluster/cluster_auth.py" in found, found


def test_no_caller_sends_the_static_node_agent_token() -> None:
    found = readers()
    unexpected = {f: lines for f, lines in found.items() if f not in ALLOWED}
    assert not unexpected, (
        "these read NOO_NODE_AGENT_TOKEN, and a read of it is how a caller "
        "sends it to a node agent:\n"
        + "\n".join(f"  {f}:{','.join(map(str, lines))}" for f, lines in sorted(unexpected.items()))
        + "\nNode agents admit the controller's certificate. Route the "
        "call through the gateway, present a leaf the agent accepts, or delete the call. "
        "Never substitute the fleet HMAC: it is the same shared secret. If the read is not "
        "an agent call, add it to ALLOWED with the reason."
    )


def test_every_allowed_entry_still_reads_the_token() -> None:
    """An entry for a file that no longer reads the token would hide a new
    sender appearing under that name. Remove it when its read goes."""
    found = readers()
    stale = sorted(set(ALLOWED) - set(found))
    assert not stale, f"ALLOWED names files that no longer read {TOKEN}: {stale}"


def test_the_moved_python_callers_hold_no_node_agent_credential() -> None:
    """The three worker-side modules keep no node-agent signer of any kind,
    including the fleet-HMAC fallback they had beside the token."""
    for rel in (
        "src/noomesh/tools/browser_tool.py",
        "src/noomesh/skills/skill_executor.py",
        "src/noomesh/gateway/helpers.py",
    ):
        tree = ast.parse((ROOT / rel).read_text(encoding="utf-8-sig"))
        defs = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        assert "_node_agent_headers" not in defs, f"{rel} has a node-agent header builder again"
        assert "_resolve_agent_url" not in defs, f"{rel} resolves a node-agent address again"


# ── Each moved Python caller refuses loudly, and calls nothing ─────────────
#
# The transport is the thing that must not happen, so the tests fail any
# socket the code would open (mock the transport, not the call).


def _no_network(monkeypatch) -> None:
    import socket

    def refuse(*_a, **_k):
        raise AssertionError("a moved caller opened a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


async def test_a_sandbox_capability_refuses_with_the_gateway_route(monkeypatch) -> None:
    """`skill_execute` (worker.tool.generic) and pipeline `sandbox.*` steps
    share this path; both must see the reason, not a connection error."""
    _no_network(monkeypatch)
    from noomesh.gateway.tools_executor import SkillToolExecutor

    res = await SkillToolExecutor().execute("text_summarizer", text="hi", style="brief")
    assert not res.success
    assert "/api/skills/text_summarizer/run" in res.error, res.error
    assert "static node-agent token" in res.error, res.error


async def test_a_sandbox_pipeline_step_raises_the_reason(monkeypatch) -> None:
    _no_network(monkeypatch)
    import pytest

    from noomesh.pipeline.sandbox_capabilities import run_sandbox_capability

    with pytest.raises(RuntimeError, match="/api/skills/text_summarizer/run"):
        await run_sandbox_capability("text_summarizer", {"text": "abc", "style": "brief"})


async def test_the_browser_tool_refuses_with_the_gateway_route(monkeypatch) -> None:
    _no_network(monkeypatch)
    import pytest

    from noomesh.gateway.tools_executor import BrowserToolExecutor
    from noomesh.tools.browser_tool import BrowserTool

    with pytest.raises(RuntimeError, match="/api/tools/browser/action"):
        await BrowserTool().start_session(node_id="host3")

    # Through the agent tool bridge: an auto-start on the first action.
    ex = BrowserToolExecutor()
    ex._tool = BrowserTool()
    res = await ex.execute(action="navigate", url="https://example.com")
    assert not res.success
    assert "/api/tools/browser/action" in res.error, res.error


async def test_old_constructor_arguments_do_not_crash(monkeypatch) -> None:
    """`init_*` callers that still pass an agent address get the refusal,
    not a TypeError."""
    _no_network(monkeypatch)
    from noomesh.skills.skill_executor import SandboxExecutor
    from noomesh.tools.browser_tool import BrowserTool

    res = await SandboxExecutor(default_agent_url="https://localhost:8081").run_container(
        "noo-sandbox-base:latest", ["true"], skill_name="x"
    )
    assert not res.success and "/api/skills/x/run" in res.error
    BrowserTool(default_agent_url="https://localhost:8081", http_context=None)
