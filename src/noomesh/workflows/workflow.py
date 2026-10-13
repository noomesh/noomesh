# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Workflow automation for multi-step agent tasks"""
from __future__ import annotations

import ast
import asyncio
import operator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from ..agent import Agent


# ---------------------------------------------------------------------------
# Safe expression evaluator (replaces eval() for workflow conditions)
# ---------------------------------------------------------------------------

_SAFE_OPS = {
    ast.Gt: operator.gt,
    ast.Lt: operator.lt,
    ast.GtE: operator.ge,
    ast.LtE: operator.le,
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.And: lambda a, b: a and b,
    ast.Or: lambda a, b: a or b,
    ast.Not: operator.not_,
    ast.Add: operator.add,
    ast.Sub: operator.sub,
}

_SAFE_FUNCS = {"len": len, "bool": bool, "int": int, "float": float, "str": str}


def _safe_eval(expr: str, variables: Dict[str, Any]) -> Any:
    """Evaluate a simple condition expression safely.

    Supports: comparisons, boolean logic, ``len()``, numeric literals,
    string literals, and variable references.  Raises ``ValueError``
    for anything more complex.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise ValueError(f"Invalid condition syntax: {e}") from e

    def _eval_node(node: ast.AST) -> Any:
        if isinstance(node, ast.Expression):
            return _eval_node(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in variables:
                return variables[node.id]
            if node.id in ("True", "False", "None"):
                return {"True": True, "False": False, "None": None}[node.id]
            raise ValueError(f"Unknown variable: {node.id}")
        if isinstance(node, ast.Compare):
            left = _eval_node(node.left)
            for op_node, comparator in zip(node.ops, node.comparators):
                op_func = _SAFE_OPS.get(type(op_node))
                if op_func is None:
                    raise ValueError(f"Unsupported operator: {type(op_node).__name__}")
                right = _eval_node(comparator)
                if not op_func(left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.BoolOp):
            op_func = _SAFE_OPS.get(type(node.op))
            if op_func is None:
                raise ValueError(f"Unsupported bool op: {type(node.op).__name__}")
            result = _eval_node(node.values[0])
            for val in node.values[1:]:
                result = op_func(result, _eval_node(val))
            return result
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                return not _eval_node(node.operand)
            raise ValueError(f"Unsupported unary op: {type(node.op).__name__}")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise ValueError("Only simple function calls allowed")
            fname = node.func.id
            if fname not in _SAFE_FUNCS:
                raise ValueError(f"Function not allowed: {fname}")
            args = [_eval_node(a) for a in node.args]
            return _SAFE_FUNCS[fname](*args)
        if isinstance(node, ast.BinOp):
            op_func = _SAFE_OPS.get(type(node.op))
            if op_func is None:
                raise ValueError(f"Unsupported binary op: {type(node.op).__name__}")
            return op_func(_eval_node(node.left), _eval_node(node.right))
        raise ValueError(f"Unsupported expression: {type(node).__name__}")

    return _eval_node(tree)


class StepStatus(Enum):
    """Workflow step status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class WorkflowStep(BaseModel):
    """Single step in a workflow"""
    name: str
    agent_prompt: str
    tools_required: List[str] = []
    condition: Optional[str] = None  # Python expression
    on_error: str = "stop"  # stop | skip | continue
    timeout: Optional[float] = None


class Workflow(BaseModel):
    """Complete workflow definition"""
    name: str
    description: str
    steps: List[WorkflowStep]
    initial_context: Dict[str, Any] = {}


@dataclass
class WorkflowStepResult:
    """Result of a workflow step execution"""
    step_name: str
    status: StepStatus
    output: Optional[str] = None
    error: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class WorkflowResult:
    """Complete workflow execution result"""
    workflow_name: str
    status: StepStatus
    steps: List[WorkflowStepResult] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    total_duration_ms: float = 0.0


class WorkflowExecutor:
    """Execute multi-step workflows with conditional branching"""

    def __init__(self, agent: Agent):
        """
        Initialize workflow executor

        Args:
            agent: Agent instance to use for execution
        """
        self.agent = agent

    async def execute(
        self,
        workflow: Workflow,
        inputs: Optional[Dict[str, Any]] = None
    ) -> WorkflowResult:
        """
        Execute workflow

        Args:
            workflow: Workflow to execute
            inputs: Input variables for workflow

        Returns:
            Workflow execution result
        """
        import time

        start_time = time.time()

        # Initialize context
        context = {**workflow.initial_context}
        if inputs:
            context.update(inputs)

        result = WorkflowResult(
            workflow_name=workflow.name,
            status=StepStatus.RUNNING,
            context=context
        )

        # Execute steps
        session = self.agent.new_session()

        for step in workflow.steps:
            step_result = await self._execute_step(
                step,
                session,
                context
            )

            result.steps.append(step_result)

            # Update context with step output
            if step_result.status == StepStatus.COMPLETED and step_result.output:
                context[step.name] = step_result.output

            # Handle errors
            if step_result.status == StepStatus.FAILED:
                if step.on_error == "stop":
                    result.status = StepStatus.FAILED
                    break
                elif step.on_error == "skip":
                    continue
                # else: continue

        # Finalize result
        if result.status == StepStatus.RUNNING:
            result.status = StepStatus.COMPLETED

        result.context = context
        result.total_duration_ms = (time.time() - start_time) * 1000

        return result

    async def _execute_step(
        self,
        step: WorkflowStep,
        session,
        context: Dict[str, Any]
    ) -> WorkflowStepResult:
        """
        Execute single workflow step

        Args:
            step: Step to execute
            session: Agent session
            context: Execution context

        Returns:
            Step execution result
        """
        import time

        start_time = time.time()

        # Check condition (safe evaluation — no arbitrary code execution)
        if step.condition:
            try:
                should_run = _safe_eval(step.condition, context)
                if not should_run:
                    return WorkflowStepResult(
                        step_name=step.name,
                        status=StepStatus.SKIPPED,
                        duration_ms=(time.time() - start_time) * 1000
                    )
            except Exception as e:
                return WorkflowStepResult(
                    step_name=step.name,
                    status=StepStatus.FAILED,
                    error=f"Condition evaluation failed: {e}",
                    duration_ms=(time.time() - start_time) * 1000
                )

        # Format prompt with context
        try:
            prompt = step.agent_prompt.format(**context)
        except KeyError as e:
            return WorkflowStepResult(
                step_name=step.name,
                status=StepStatus.FAILED,
                error=f"Prompt formatting failed: Missing variable {e}",
                duration_ms=(time.time() - start_time) * 1000
            )

        # Execute with agent (run sync step in thread to avoid blocking event loop)
        try:
            coro = asyncio.to_thread(
                self.agent.step,
                session,
                prompt,
                pinned_tools=step.tools_required or None,
            )
            # Enforce step timeout if configured
            if step.timeout:
                output = await asyncio.wait_for(coro, timeout=step.timeout)
            else:
                output = await coro

            return WorkflowStepResult(
                step_name=step.name,
                status=StepStatus.COMPLETED,
                output=output,
                duration_ms=(time.time() - start_time) * 1000
            )

        except asyncio.TimeoutError:
            return WorkflowStepResult(
                step_name=step.name,
                status=StepStatus.FAILED,
                error=f"Step timed out after {step.timeout}s",
                duration_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            return WorkflowStepResult(
                step_name=step.name,
                status=StepStatus.FAILED,
                error=str(e),
                duration_ms=(time.time() - start_time) * 1000
            )


# Example workflows

RESEARCH_WORKFLOW = Workflow(
    name="deep_research",
    description="Research a topic thoroughly",
    steps=[
        WorkflowStep(
            name="initial_search",
            agent_prompt="Search for information about: {topic}",
            tools_required=["web_search"]
        ),
        WorkflowStep(
            name="summarize",
            agent_prompt="Summarize these search results concisely:\n{initial_search}",
            tools_required=[]
        ),
        WorkflowStep(
            name="deep_dive",
            agent_prompt="Research specific aspects of {topic} that need more detail based on:\n{summarize}",
            tools_required=["web_search"],
            condition="len(summarize) > 100"  # Only if summary is substantial
        ),
        WorkflowStep(
            name="final_report",
            agent_prompt="Create a comprehensive report on {topic} using all findings",
            tools_required=[]
        )
    ]
)

CODE_DEVELOPMENT_WORKFLOW = Workflow(
    name="code_development",
    description="Plan, implement, and test code",
    steps=[
        WorkflowStep(
            name="requirements",
            agent_prompt="Analyze requirements for: {task}",
            tools_required=[]
        ),
        WorkflowStep(
            name="design",
            agent_prompt="Design implementation approach for:\n{requirements}",
            tools_required=[]
        ),
        WorkflowStep(
            name="implement",
            agent_prompt="Implement the following design:\n{design}",
            tools_required=["python_exec", "local_files"]
        ),
        WorkflowStep(
            name="test",
            agent_prompt="Test this implementation:\n{implement}",
            tools_required=["python_exec"],
            on_error="continue"  # Continue even if tests fail
        ),
        WorkflowStep(
            name="review",
            agent_prompt="Review code quality and suggest improvements:\n{implement}",
            tools_required=[]
        )
    ]
)

DATA_ANALYSIS_WORKFLOW = Workflow(
    name="data_analysis",
    description="Load, analyze, and visualize data",
    steps=[
        WorkflowStep(
            name="load_data",
            agent_prompt="Load data from: {data_source}",
            tools_required=["python_exec", "local_files"]
        ),
        WorkflowStep(
            name="explore",
            agent_prompt="Perform exploratory data analysis on:\n{load_data}",
            tools_required=["python_exec"]
        ),
        WorkflowStep(
            name="analyze",
            agent_prompt="Analyze patterns and trends in the data:\n{explore}",
            tools_required=["python_exec"]
        ),
        WorkflowStep(
            name="visualize",
            agent_prompt="Create visualizations for insights found:\n{analyze}",
            tools_required=["python_exec"]
        ),
        WorkflowStep(
            name="report",
            agent_prompt="Generate analysis report with key findings",
            tools_required=[]
        )
    ]
)
