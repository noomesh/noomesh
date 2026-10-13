# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every heartbeat action the Python registry knows has a destructive/not row in the gateway.

`gateway-rust/src/task_guard.rs::ACTION_CLASSES` is the one declaration of which heartbeat actions
delete data. An AI acting through an MCP door cannot create such a task, a person must approve it, and
an action with no row is treated as one that deletes. The Rust test pins the Rust lists and the
console's list; this pins the Python registry (`_dispatch`, `ACTION_DESCRIPTIONS`), which names a few
actions the Rust lists do not (audit_log_rotate, pipeline, structured_research, ...). A new action
there with no row would silently turn every task of it into a proposal.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _classified() -> set[str]:
    src = (ROOT / "gateway-rust" / "src" / "task_guard.rs").read_text()
    m = re.search(r"pub const ACTION_CLASSES[^=]*=\s*&\[(.*?)\n\];", src, re.S)
    assert m, "ACTION_CLASSES not found"
    return set(re.findall(r'^\s*\("([a-z_]+)",\s*Class::', m.group(1), re.M))


def _python_actions() -> set[str]:
    py = (ROOT / "src" / "noomesh" / "gateway" / "heartbeat.py").read_text()
    m = re.search(r"_dispatch: Dict\[str, Any\] = \{(.*?)\n        \}", py, re.S)
    assert m, "_dispatch map not found"
    dispatch = set(re.findall(r'"([a-z_]+)": self\.', m.group(1)))
    start = py.index("ACTION_DESCRIPTIONS")
    block = py[start : py.index("ACTION_CONFIG_SCHEMAS", start)]
    described = set(re.findall(r'^    "([a-z_]+)": "', block, re.M))
    return dispatch | described


def test_every_python_registered_action_is_classified():
    missing = sorted(_python_actions() - _classified())
    assert not missing, (
        f"heartbeat actions with no row in task_guard.rs ACTION_CLASSES (every task of them would be "
        f"treated as deleting data and need a person's approval): {missing}"
    )


def test_the_new_scheduled_cleanup_is_classified_as_apply_only():
    src = (ROOT / "gateway-rust" / "src" / "task_guard.rs").read_text()
    assert '("entity_cleanup", Class::OnlyWhenApply(' in src


def _py_llm_set() -> set[str]:
    py = (ROOT / "src" / "noomesh" / "gateway" / "heartbeat.py").read_text()
    m = re.search(r"_LLM_ACTIONS = frozenset\(\{(.*?)\}\)", py, re.S)
    return set(re.findall(r'"([a-z_]+)"', re.sub(r"#.*", "", m.group(1))))


def test_the_python_pipeline_llm_set_matches_the_gateway_agent_actions():
    rs = (ROOT / "gateway-rust" / "src" / "heartbeat_actions.rs").read_text()
    m = re.search(r"const RUST_LLM_ACTIONS: &\[&str\] = &\[(.*?)\];", rs, re.S)
    rust = set(re.findall(r'"([a-z_]+)"', re.sub(r"//.*", "", m.group(1))))
    tg = (ROOT / "gateway-rust" / "src" / "task_guard.rs").read_text()
    m = re.search(r"pub const AGENT_TURN_EXTRA: &\[&str\] = &\[(.*?)\];", tg, re.S)
    extra = set(re.findall(r'"([a-z_]+)"', m.group(1)))
    assert _py_llm_set() == rust | extra


def test_every_python_handler_that_runs_an_agent_turn_is_an_llm_action():
    """A handler that calls the coordinator (or POSTs /api/agent/run or /api/inference) runs model text
    with tools. It must be in _LLM_ACTIONS so a pipeline step cannot run it unchecked."""
    py = (ROOT / "src" / "noomesh" / "gateway" / "heartbeat.py").read_text()
    m = re.search(r"_dispatch: Dict\[str, Any\] = \{(.*?)\n        \}", py, re.S)
    handlers = dict(re.findall(r'"([a-z_]+)": self\.(_[a-z_]+)', m.group(1)))
    llm = _py_llm_set()
    offenders = []
    for action, fn in handlers.items():
        bm = re.search(rf"async def {fn}\(self.*?(?=\n    async def |\n    def )", py, re.S)
        body = bm.group(0) if bm else ""
        if any(k in body for k in ("self.coordinator.run", "/api/agent/run", "/api/inference")) and action not in llm:
            offenders.append(action)
    assert not offenders, f"agent-turn handlers missing from _LLM_ACTIONS: {offenders}"
