# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for run_pipeline pre-run input validation (fail fast, no silent None)."""
import pytest

from noomesh.pipeline import (
    Pipeline,
    PipelineValidationError,
    Step,
    capability,
    run_pipeline,
)


@capability("test.echo_cfg")
async def _echo_cfg(ctx, config):
    return dict(config)


@capability("test.const")
async def _const(ctx, config):
    return config.get("value", 42)


def _pipe(steps):
    return Pipeline(name="validation-test", steps=steps)


async def test_missing_input_fails_with_clear_message():
    pipe = _pipe([
        Step(capability="test.echo_cfg", inputs={"text": "does_not_exist"}, output="out"),
    ])
    with pytest.raises(PipelineValidationError) as ei:
        await run_pipeline(pipe, {"something_else": 1})
    msg = str(ei.value)
    assert "does_not_exist" in msg
    assert "test.echo_cfg" in msg
    assert "something_else" in msg  # lists available initial ctx keys


async def test_input_satisfied_by_initial_ctx():
    pipe = _pipe([
        Step(capability="test.echo_cfg", inputs={"text": "article"}, output="out"),
    ])
    result = await run_pipeline(pipe, {"article": "hello"})
    assert result.ok
    assert result.ctx["out"] == {"text": "hello"}


async def test_input_satisfied_by_earlier_step_output():
    pipe = _pipe([
        Step(capability="test.const", config={"value": "abc"}, output="first"),
        Step(capability="test.echo_cfg", inputs={"data": "first"}, output="second"),
    ])
    result = await run_pipeline(pipe)
    assert result.ok
    assert result.ctx["second"] == {"data": "abc"}


async def test_later_step_output_does_not_satisfy_earlier_input():
    pipe = _pipe([
        Step(capability="test.echo_cfg", inputs={"data": "made_later"}, output="a"),
        Step(capability="test.const", output="made_later"),
    ])
    with pytest.raises(PipelineValidationError):
        await run_pipeline(pipe)


async def test_validate_inputs_false_escape_hatch():
    """Capabilities that write ctx directly can opt out of pre-validation."""
    @capability("test.writes_ctx")
    async def _writes_ctx(ctx, config):
        ctx["side_channel"] = "written"
        return None

    pipe = _pipe([
        Step(capability="test.writes_ctx"),
        Step(capability="test.echo_cfg", inputs={"x": "side_channel"}, output="out"),
    ])
    # Default: rejected (side_channel is not a declared output).
    with pytest.raises(PipelineValidationError):
        await run_pipeline(pipe)
    # Escape hatch: runs, and the direct ctx write is visible.
    result = await run_pipeline(pipe, validate_inputs=False)
    assert result.ok
    assert result.ctx["out"] == {"x": "written"}


async def test_skip_and_continue_outputs_count_as_available():
    """A failing step with on_error=skip/continue still setdefaults its output."""
    @capability("test.boom")
    async def _boom(ctx, config):
        raise RuntimeError("boom")

    pipe = _pipe([
        Step(capability="test.boom", output="maybe", on_error="skip"),
        Step(capability="test.echo_cfg", inputs={"v": "maybe"}, output="out"),
    ])
    result = await run_pipeline(pipe)  # must not raise at validation time
    assert result.ctx["out"] == {"v": None}


def test_research_pipeline_validates_cleanly():
    """The shipped research composition passes the new pre-run validation."""
    from noomesh.pipeline.core import _validate_pipeline_inputs
    from noomesh.pipeline.research import build_research_pipeline

    pipe = build_research_pipeline("test topic")
    _validate_pipeline_inputs(pipe, {})  # must not raise
