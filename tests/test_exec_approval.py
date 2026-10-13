# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for the Exec Approval Manager (risk-based tool gating)."""
import asyncio

import pytest

from noomesh.gateway.exec_approval import (
    ApprovalResult,
    ApprovalStatus,
    ExecApprovalManager,
    RiskLevel,
    ToolCall,
    get_approval_manager,
    init_approval_manager,
)


# -- ToolCall ------------------------------------------------------------------


class TestToolCall:
    def test_qualified_name_without_action(self):
        tc = ToolCall(name="web_search")
        assert tc.qualified_name == "web_search"

    def test_qualified_name_with_action(self):
        tc = ToolCall(name="local_files", action="write")
        assert tc.qualified_name == "local_files_write"


# -- Risk classification -------------------------------------------------------


class TestClassification:
    def test_low_risk_tools(self):
        mgr = ExecApprovalManager()
        for tool in ["web_search", "rag_query", "memory_search", "cluster_status"]:
            tc = ToolCall(name=tool)
            assert mgr.classify(tc) == RiskLevel.LOW

    def test_medium_risk_tools(self):
        mgr = ExecApprovalManager()
        for tool in ["python_tool", "browser", "rag_ingest", "channel_send"]:
            tc = ToolCall(name=tool)
            assert mgr.classify(tc) == RiskLevel.MEDIUM

    def test_high_risk_tools(self):
        mgr = ExecApprovalManager()
        for tool in ["local_files_write", "local_files_delete", "shell"]:
            tc = ToolCall(name=tool)
            assert mgr.classify(tc) == RiskLevel.HIGH

    def test_qualified_name_lookup(self):
        mgr = ExecApprovalManager()
        tc = ToolCall(name="local_files", action="delete")
        assert mgr.classify(tc) == RiskLevel.HIGH

    def test_unknown_tool_is_medium(self):
        mgr = ExecApprovalManager()
        tc = ToolCall(name="unknown_tool_xyz")
        assert mgr.classify(tc) == RiskLevel.MEDIUM

    def test_custom_risk_overrides(self):
        mgr = ExecApprovalManager(
            high_risk_tools=["python_tool"],
            medium_risk_tools=["web_search"],
        )
        assert mgr.classify(ToolCall(name="python_tool")) == RiskLevel.HIGH
        assert mgr.classify(ToolCall(name="web_search")) == RiskLevel.MEDIUM


# -- Approval checks -----------------------------------------------------------


class TestApprovalCheck:
    @pytest.mark.asyncio
    async def test_low_risk_auto_approved(self):
        mgr = ExecApprovalManager()
        result = await mgr.check(ToolCall(name="web_search"))
        assert result.approved
        assert result.status == ApprovalStatus.APPROVED

    @pytest.mark.asyncio
    async def test_medium_risk_auto_approved(self):
        mgr = ExecApprovalManager()
        result = await mgr.check(ToolCall(name="python_tool"))
        assert result.approved

    @pytest.mark.asyncio
    async def test_high_risk_strict_denied(self):
        mgr = ExecApprovalManager(mode="strict")
        result = await mgr.check(ToolCall(name="shell"))
        assert not result.approved
        assert result.status == ApprovalStatus.DENIED
        assert "Strict mode" in result.reason

    @pytest.mark.asyncio
    async def test_high_risk_auto_approved_on_timeout(self):
        mgr = ExecApprovalManager(mode="auto", timeout=0)
        result = await mgr.check(ToolCall(name="shell"))
        assert result.approved

    @pytest.mark.asyncio
    async def test_high_risk_approval_mode_approved(self):
        mgr = ExecApprovalManager(mode="approval", timeout=5)
        tc = ToolCall(name="shell")

        async def approve_soon():
            await asyncio.sleep(0.05)
            pending = mgr.get_pending()
            assert len(pending) == 1
            await mgr.approve(pending[0].id, approved_by="test")

        asyncio.get_event_loop().create_task(approve_soon())
        result = await mgr.check(tc)
        assert result.approved

    @pytest.mark.asyncio
    async def test_high_risk_approval_mode_denied(self):
        mgr = ExecApprovalManager(mode="approval", timeout=5)
        tc = ToolCall(name="shell")

        async def deny_soon():
            await asyncio.sleep(0.05)
            pending = mgr.get_pending()
            assert len(pending) == 1
            await mgr.deny(pending[0].id, reason="not allowed")

        asyncio.get_event_loop().create_task(deny_soon())
        result = await mgr.check(tc)
        assert not result.approved
        assert "not allowed" in result.reason

    @pytest.mark.asyncio
    async def test_high_risk_approval_mode_timeout_denied(self):
        mgr = ExecApprovalManager(mode="approval", timeout=0)
        result = await mgr.check(ToolCall(name="shell"))
        assert not result.approved
        assert "timed out" in result.reason.lower()


# -- Pending requests ----------------------------------------------------------


class TestPending:
    @pytest.mark.asyncio
    async def test_get_pending_empty(self):
        mgr = ExecApprovalManager()
        assert mgr.get_pending() == []

    @pytest.mark.asyncio
    async def test_approve_unknown_id(self):
        mgr = ExecApprovalManager()
        await mgr.approve("nonexistent")  # should not raise

    @pytest.mark.asyncio
    async def test_deny_unknown_id(self):
        mgr = ExecApprovalManager()
        await mgr.deny("nonexistent")  # should not raise


# -- ApprovalResult ------------------------------------------------------------


class TestApprovalResult:
    def test_approved_property(self):
        r = ApprovalResult(status=ApprovalStatus.APPROVED)
        assert r.approved

    def test_denied_property(self):
        r = ApprovalResult(status=ApprovalStatus.DENIED)
        assert not r.approved

    def test_pending_not_approved(self):
        r = ApprovalResult(status=ApprovalStatus.PENDING)
        assert not r.approved


# -- Singleton -----------------------------------------------------------------


class TestSingleton:
    def test_init_and_get(self):
        mgr = init_approval_manager(mode="strict", timeout=10)
        assert get_approval_manager() is mgr
        assert mgr.mode == "strict"
        assert mgr.timeout == 10
