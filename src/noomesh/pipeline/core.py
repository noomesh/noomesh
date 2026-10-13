# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Modular capability-pipeline framework.

The pattern: the model/agent is the
*intelligence*; the harness supplies deterministic *capabilities*; tasks are
declarative *compositions* of capabilities. This is the opposite of the
agentic loop where a (weak, local) model must orchestrate multi-step tool use
itself — instead, code drives the sequence and the model is invoked only for
narrow, single-shot tasks it is reliable at (extract these facts / synthesize
these points), ideally with guided/structured decoding.

A **capability** is a named async runner ``(ctx, config) -> value``. A
**pipeline** is an ordered list of **steps**, each naming a capability, its
config, where to read inputs from the shared context, and where to write its
output. The executor threads the context, retries, validates, and honors
per-step error policy. The same capabilities compose into research, digest,
monitoring, investigation, … — different pipelines, one toolbox.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

import structlog

log = structlog.get_logger("pipeline")

# A capability: async (ctx, config) -> value. ctx is the shared, mutable
# pipeline context; config is the step's static configuration.
Capability = Callable[[Dict[str, Any], Dict[str, Any]], Awaitable[Any]]

_REGISTRY: Dict[str, Capability] = {}


def capability(name: str) -> Callable[[Capability], Capability]:
    """Register a named capability. Names are the composable vocabulary."""
    def _wrap(fn: Capability) -> Capability:
        _REGISTRY[name] = fn
        return fn
    return _wrap


class PipelineValidationError(ValueError):
    """A pipeline is mis-wired: a step reads a ctx key nothing provides."""


def get_capability(name: str) -> Capability:
    fn = _REGISTRY.get(name)
    if fn is None:
        raise KeyError(f"unknown capability '{name}' (have: {sorted(_REGISTRY)})")
    return fn


def registered_capabilities() -> List[str]:
    return sorted(_REGISTRY)


# A validator: (value, ctx) -> (ok, reason). Registered like capabilities so
# quality floors are reusable too.
Validator = Callable[[Any, Dict[str, Any]], "tuple[bool, str]"]
_VALIDATORS: Dict[str, Validator] = {}


def validator(name: str) -> Callable[[Validator], Validator]:
    def _wrap(fn: Validator) -> Validator:
        _VALIDATORS[name] = fn
        return fn
    return _wrap


@dataclass
class Step:
    """One composable step in a pipeline."""
    capability: str
    # Static config for the capability.
    config: Dict[str, Any] = field(default_factory=dict)
    # ctx keys to pull into config at run time as {config_key: ctx_key}. Lets
    # a step consume an earlier step's output without hard-coding values.
    inputs: Dict[str, str] = field(default_factory=dict)
    # Where to store this step's output in ctx (None = don't store).
    output: Optional[str] = None
    # Retry the capability up to N times if it raises or fails validation.
    retries: int = 0
    # Registered validator name enforcing a quality floor on the output.
    validate: Optional[str] = None
    # 'stop' aborts the pipeline, 'skip' drops this step, 'continue' proceeds
    # with output=None.
    on_error: str = "stop"
    # Human label (defaults to capability name).
    name: Optional[str] = None

    @property
    def label(self) -> str:
        return self.name or self.capability


@dataclass
class Pipeline:
    name: str
    steps: List[Step]


@dataclass
class StepResult:
    step: str
    ok: bool
    error: Optional[str] = None
    duration_ms: float = 0.0
    attempts: int = 1


@dataclass
class PipelineResult:
    name: str
    ok: bool
    steps: List[StepResult] = field(default_factory=list)
    ctx: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0

    def summary(self) -> str:
        parts = [f"{s.step}:{'ok' if s.ok else 'FAIL'}" for s in self.steps]
        return f"[{self.name}] {'OK' if self.ok else 'FAILED'} — " + ", ".join(parts)


def _validate_pipeline_inputs(pipeline: Pipeline, ctx: Dict[str, Any]) -> None:
    """Fail fast when a step's declared inputs can never be satisfied.

    Each ``Step.inputs`` maps {config_key: ctx_key}. A ctx_key is satisfiable
    if it is in the initial ctx or is the ``output`` of an *earlier* step
    (regardless of that step's error policy — skip/continue still setdefault
    the key). Anything else would previously resolve to a silent ``None``.
    """
    available = set(ctx)
    problems: List[str] = []
    for i, step in enumerate(pipeline.steps):
        for cfg_key, ctx_key in step.inputs.items():
            if ctx_key not in available:
                problems.append(
                    f"step {i + 1} '{step.label}': input '{cfg_key}' reads "
                    f"ctx['{ctx_key}'], which is neither in the initial ctx "
                    f"nor the output of an earlier step"
                )
        if step.output:
            available.add(step.output)
    if problems:
        raise PipelineValidationError(
            f"pipeline '{pipeline.name}' has unsatisfiable step inputs:\n  - "
            + "\n  - ".join(problems)
            + "\n(available initial ctx keys: " + (", ".join(sorted(ctx)) or "none")
            + "; pass validate_inputs=False to run_pipeline if a capability "
            "populates ctx keys directly)"
        )


async def run_pipeline(
    pipeline: Pipeline,
    ctx: Optional[Dict[str, Any]] = None,
    *,
    validate_inputs: bool = True,
) -> PipelineResult:
    """Execute a pipeline, threading the shared context through its steps.

    ``validate_inputs`` (default on) pre-checks that every Step's declared
    inputs are satisfiable, raising :class:`PipelineValidationError` with a
    precise message instead of silently passing ``None`` at run time. Set it
    to False only when capabilities write ctx keys directly (not via
    ``Step.output``).
    """
    ctx = dict(ctx or {})
    if validate_inputs:
        _validate_pipeline_inputs(pipeline, ctx)
    result = PipelineResult(name=pipeline.name, ok=True, ctx=ctx)
    t0 = time.time()

    for step in pipeline.steps:
        cap = get_capability(step.capability)
        # Merge static config with any ctx-sourced inputs.
        cfg = dict(step.config)
        for cfg_key, ctx_key in step.inputs.items():
            cfg[cfg_key] = ctx.get(ctx_key)

        sr = StepResult(step=step.label, ok=False)
        s0 = time.time()
        last_err: Optional[str] = None

        for attempt in range(step.retries + 1):
            sr.attempts = attempt + 1
            try:
                value = await cap(ctx, cfg)
                if step.validate:
                    v = _VALIDATORS.get(step.validate)
                    if v is None:
                        raise KeyError(f"unknown validator '{step.validate}'")
                    ok, reason = v(value, ctx)
                    if not ok:
                        last_err = f"validation failed: {reason}"
                        log.info("pipeline.step_retry", step=step.label,
                                 attempt=attempt + 1, reason=reason)
                        continue
                if step.output:
                    ctx[step.output] = value
                sr.ok = True
                last_err = None
                break
            except Exception as e:  # noqa: BLE001 — capability isolation
                last_err = str(e)[:300]
                log.info("pipeline.step_error", step=step.label,
                         attempt=attempt + 1, error=last_err)

        sr.duration_ms = (time.time() - s0) * 1000.0
        sr.error = last_err
        result.steps.append(sr)

        if not sr.ok:
            if step.on_error == "stop":
                result.ok = False
                log.warning("pipeline.aborted", pipeline=pipeline.name, step=step.label, error=last_err)
                break
            elif step.on_error == "skip":
                if step.output:
                    ctx.setdefault(step.output, None)
                continue
            else:  # continue
                if step.output:
                    ctx.setdefault(step.output, None)

    result.duration_ms = (time.time() - t0) * 1000.0
    result.ctx = ctx
    return result
