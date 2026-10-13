# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for workflow data models."""

from noomesh.workflows.workflow import (
    StepStatus,
    Workflow,
    WorkflowResult,
    WorkflowStep,
    WorkflowStepResult,
)


class TestStepStatus:
    """Test StepStatus enum."""

    def test_values(self):
        assert StepStatus.PENDING.value == "pending"
        assert StepStatus.RUNNING.value == "running"
        assert StepStatus.COMPLETED.value == "completed"
        assert StepStatus.FAILED.value == "failed"
        assert StepStatus.SKIPPED.value == "skipped"


class TestWorkflowStep:
    """Test WorkflowStep model."""

    def test_creation_minimal(self):
        step = WorkflowStep(name="test", agent_prompt="Do something")
        assert step.name == "test"
        assert step.tools_required == []
        assert step.condition is None
        assert step.on_error == "stop"
        assert step.timeout is None

    def test_creation_full(self):
        step = WorkflowStep(
            name="search",
            agent_prompt="Search for {topic}",
            tools_required=["web_search"],
            condition="len(topic) > 5",
            on_error="skip",
            timeout=30.0,
        )
        assert step.tools_required == ["web_search"]
        assert step.on_error == "skip"
        assert step.timeout == 30.0


class TestWorkflow:
    """Test Workflow model."""

    def test_creation(self):
        wf = Workflow(
            name="research",
            description="Research a topic",
            steps=[
                WorkflowStep(name="s1", agent_prompt="Step 1"),
                WorkflowStep(name="s2", agent_prompt="Step 2"),
            ],
        )
        assert wf.name == "research"
        assert len(wf.steps) == 2
        assert wf.initial_context == {}

    def test_with_initial_context(self):
        wf = Workflow(
            name="test",
            description="Test workflow",
            steps=[],
            initial_context={"topic": "AI"},
        )
        assert wf.initial_context["topic"] == "AI"


class TestWorkflowStepResult:
    """Test WorkflowStepResult dataclass."""

    def test_completed_result(self):
        r = WorkflowStepResult(
            step_name="search",
            status=StepStatus.COMPLETED,
            output="Found 10 results",
            duration_ms=150.0,
        )
        assert r.step_name == "search"
        assert r.status == StepStatus.COMPLETED
        assert r.output == "Found 10 results"
        assert r.error is None

    def test_failed_result(self):
        r = WorkflowStepResult(
            step_name="search",
            status=StepStatus.FAILED,
            error="Connection refused",
            duration_ms=5000.0,
        )
        assert r.status == StepStatus.FAILED
        assert r.error == "Connection refused"

    def test_defaults(self):
        r = WorkflowStepResult(step_name="x", status=StepStatus.PENDING)
        assert r.output is None
        assert r.error is None
        assert r.duration_ms == 0.0


class TestWorkflowResult:
    """Test WorkflowResult dataclass."""

    def test_creation(self):
        r = WorkflowResult(
            workflow_name="research",
            status=StepStatus.COMPLETED,
            total_duration_ms=500.0,
        )
        assert r.workflow_name == "research"
        assert r.steps == []
        assert r.context == {}

    def test_with_steps(self):
        step1 = WorkflowStepResult(step_name="s1", status=StepStatus.COMPLETED, output="done")
        step2 = WorkflowStepResult(step_name="s2", status=StepStatus.SKIPPED)
        r = WorkflowResult(
            workflow_name="test",
            status=StepStatus.COMPLETED,
            steps=[step1, step2],
            context={"s1": "done"},
        )
        assert len(r.steps) == 2
        assert r.context["s1"] == "done"


class TestPredefinedWorkflows:
    """Test that predefined workflows are valid."""

    def test_research_workflow(self):
        from noomesh.workflows.workflow import RESEARCH_WORKFLOW
        assert RESEARCH_WORKFLOW.name == "deep_research"
        assert len(RESEARCH_WORKFLOW.steps) == 4

    def test_code_development_workflow(self):
        from noomesh.workflows.workflow import CODE_DEVELOPMENT_WORKFLOW
        assert CODE_DEVELOPMENT_WORKFLOW.name == "code_development"
        assert len(CODE_DEVELOPMENT_WORKFLOW.steps) == 5

    def test_data_analysis_workflow(self):
        from noomesh.workflows.workflow import DATA_ANALYSIS_WORKFLOW
        assert DATA_ANALYSIS_WORKFLOW.name == "data_analysis"
        assert len(DATA_ANALYSIS_WORKFLOW.steps) == 5
