# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for channel adapters (Telegram, base ChannelMessage)."""

from noomesh.channels.base import ChannelMessage


# -- ChannelMessage dataclass --------------------------------------------------


class TestChannelMessage:
    def test_create_message(self):
        msg = ChannelMessage(
            channel="telegram",
            sender_id="42",
            sender_name="Alice",
            text="Hello",
            thread_id=None,
            raw={"text": "Hello"},
        )
        assert msg.channel == "telegram"
        assert msg.sender_id == "42"
        assert msg.text == "Hello"
        assert msg.thread_id is None

    def test_message_with_thread(self):
        msg = ChannelMessage(
            channel="google_chat",
            sender_id="user-1",
            sender_name="Bob",
            text="Reply",
            thread_id="thread-abc",
            raw={},
        )
        assert msg.thread_id == "thread-abc"

    def test_message_metadata(self):
        msg = ChannelMessage(
            channel="whatsapp",
            sender_id="+1234567890",
            sender_name="Charlie",
            text="Test",
            thread_id=None,
            raw={},
            metadata={"mentioned": True},
        )
        assert msg.metadata["mentioned"] is True


# -- Telegram adapter ---------------------------------------------------------


# Adapter / ChannelManager / GoogleChat formatting tests left with the
# code they tested: the Python adapters removed in
# the task #23 sweep, 2026-08-12 (history in git log before 2026-08-08) —
# outbound is routes/communication.rs, exercised by its own Rust tests,
# and the trellion-side client by tests/test_gateway_channel_client.py.
# Only the still-live base contract (ChannelMessage) is pinned here.
