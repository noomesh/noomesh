# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for the sandbox-capability fold (container skills → pipeline capabilities)."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from noomesh.pipeline import (
    Pipeline,
    Step,
    get_capability,
    register_capabilities,
    registered_capabilities,
    run_pipeline,
)
from noomesh.pipeline.sandbox_capabilities import (
    execute_sandbox_capability,
    register_sandbox_capabilities,
    run_sandbox_capability,
    sandbox_capability_names,
)
from noomesh.skills import (
    SandboxCapabilityRegistry,
    SandboxExecutor,
    SandboxResult,
    SkillExecutor,
    SkillRegistry,
    SkillResult,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_PY = REPO_ROOT / "skills" / "builtins" / "text_summarizer" / "run.py"


# ── Registry / rename compat ────────────────────────────────────────────

def test_backward_compat_aliases():
    assert SkillRegistry is SandboxCapabilityRegistry
    assert SkillExecutor is SandboxExecutor
    assert SkillResult is SandboxResult


def test_registry_scans_builtins():
    reg = SandboxCapabilityRegistry(builtin_dir=REPO_ROOT / "skills" / "builtins",
                                    user_dir=Path("/nonexistent"))
    n = reg.scan()
    assert n >= 3
    names = set(reg.names())
    assert {"text_summarizer", "file_converter", "data_extractor"} <= names
    m = reg.get("text_summarizer")
    assert m.required_inputs() == ["text"]
    assert {p.name for p in m.outputs} == {"summary", "word_count"}


# ── Fold: manifests become @capability entries ──────────────────────────

def test_register_capabilities_registers_sandbox_and_builtins():
    names = register_capabilities(force=True)
    assert "sandbox_run" in names
    assert "sandbox.text_summarizer" in names
    assert "kb_query" in names  # built-in module eagerly imported
    assert "web_search" in names
    assert set(sandbox_capability_names()) <= set(names)


def test_register_sandbox_capabilities_idempotent():
    n1 = register_sandbox_capabilities()
    n2 = register_sandbox_capabilities()
    assert n1 == n2 >= 3


# ── Execution path (mocked sandbox) ─────────────────────────────────────

@pytest.fixture
def mock_run_container(monkeypatch):
    """Intercept the node-agent call; capture the container spec."""
    calls = {}

    async def fake_run_container(self, image, command, **kwargs):
        calls["image"] = image
        calls["command"] = command
        calls.update(kwargs)
        payload = json.loads(kwargs["env"]["SKILL_INPUT"])
        return SandboxResult(success=True, output={"echo": payload})

    monkeypatch.setattr(SandboxExecutor, "run_container", fake_run_container)
    return calls


async def test_run_sandbox_capability_success(mock_run_container):
    out = await run_sandbox_capability("text_summarizer", {"text": "hello world"})
    assert out == {"echo": {"text": "hello world"}}
    # manifest honored: image, command, and /skill mount
    assert mock_run_container["image"] == "noo-sandbox-base:latest"
    assert mock_run_container["command"] == ["python", "/skill/run.py"]
    vols = mock_run_container["volumes"]
    assert list(vols.values()) == ["/skill"]
    assert list(vols.keys())[0].endswith("text_summarizer")


async def test_run_sandbox_capability_ships_inline_files(mock_run_container):
    """execute_skill must attach the capability files inline (base64) so
    node-agents on OTHER hosts can materialize /skill without a
    controller-local bind mount."""
    import base64

    await run_sandbox_capability("text_summarizer", {"text": "hello world"})
    files = mock_run_container["files"]
    assert files, "expected inline files alongside the volumes fallback"
    assert "run.py" in files
    assert "manifest.yml" in files
    decoded = base64.b64decode(files["run.py"]).decode()
    assert "SKILL_INPUT" in decoded  # real run.py content round-trips


def test_collect_skill_files_skips_hidden_and_oversized(tmp_path):
    import base64

    from noomesh.skills.skill_executor import (
        MAX_SKILL_FILE_BYTES,
        _collect_skill_files,
    )

    (tmp_path / "run.py").write_text("print('hi')")
    (tmp_path / ".hidden").write_text("secret")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "util.py").write_text("pass")
    (tmp_path / "huge.bin").write_bytes(b"\0" * (MAX_SKILL_FILE_BYTES + 1))

    files = _collect_skill_files(str(tmp_path))
    assert set(files) == {"run.py", os.path.join("lib", "util.py")}
    assert base64.b64decode(files["run.py"]) == b"print('hi')"


def test_collect_skill_files_missing_dir_is_none():
    from noomesh.skills.skill_executor import _collect_skill_files

    assert _collect_skill_files("/nonexistent/skill/dir") is None


async def test_run_sandbox_capability_missing_required_input(mock_run_container):
    with pytest.raises(RuntimeError, match="Missing required inputs: text"):
        await run_sandbox_capability("text_summarizer", {"style": "brief"})


async def test_execute_sandbox_capability_unknown_name():
    res = await execute_sandbox_capability("no_such_capability", {})
    assert not res.success
    assert res.error == "Unknown skill: no_such_capability"


async def test_sandbox_capability_as_pipeline_step(mock_run_container):
    register_capabilities()
    pipe = Pipeline(name="t", steps=[
        Step(capability="sandbox.text_summarizer",
             config={"style": "bullet_points"},
             inputs={"text": "article"},
             output="summary_out"),
    ])
    result = await run_pipeline(pipe, {"article": "some long text"})
    assert result.ok, result.summary()
    assert result.ctx["summary_out"] == {"echo": {"text": "some long text", "style": "bullet_points"}}


async def test_generic_sandbox_run_capability(mock_run_container):
    cap = get_capability("sandbox_run")
    out = await cap({}, {"name": "text_summarizer", "text": "abc"})
    assert out == {"echo": {"text": "abc"}}
    with pytest.raises(ValueError, match="requires config\\['name'\\]"):
        await cap({}, {"text": "abc"})


# ── worker.tool.skill bridge byte-compat ────────────────────────────────

async def test_skill_tool_executor_success_format(mock_run_container):
    from noomesh.gateway.tools_executor import SkillToolExecutor
    res = await SkillToolExecutor().execute("text_summarizer", text="hi")
    assert res.success
    # byte-compatible: json.dumps(output, indent=2, default=str)
    assert res.output == json.dumps({"echo": {"text": "hi"}}, indent=2, default=str)


async def test_skill_tool_executor_unknown_skill():
    from noomesh.gateway.tools_executor import SkillToolExecutor
    res = await SkillToolExecutor().execute("definitely_not_a_skill")
    assert not res.success
    assert res.error == "Unknown skill: definitely_not_a_skill"


# ── The example implementation honors its manifest I/O ──────────────────

def _run_example(inputs: dict):
    env = dict(os.environ, SKILL_INPUT=json.dumps(inputs))
    proc = subprocess.run([sys.executable, str(RUN_PY)], env=env,
                          capture_output=True, text=True, timeout=30)
    return proc


def test_example_run_py_brief():
    text = " ".join(
        f"Sentence number {i} talks about pipelines, capabilities and sandboxes repeatedly."
        for i in range(12)
    )
    proc = _run_example({"text": text, "max_length": 30, "style": "brief"})
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert set(out) == {"summary", "word_count"}
    assert isinstance(out["summary"], str) and out["summary"]
    assert out["word_count"] <= 30


def test_example_run_py_bullet_points():
    proc = _run_example({"text": "Alpha is first. Beta follows alpha. Gamma ends it.",
                         "style": "bullet_points"})
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["summary"].startswith("- ")


def test_example_run_py_missing_text_fails():
    proc = _run_example({"style": "brief"})
    assert proc.returncode != 0
    assert "text" in proc.stderr
