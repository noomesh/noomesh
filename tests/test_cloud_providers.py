# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for cloud model provider manager (routing, failover, availability)."""
import pytest

from noomesh.gateway.cloud_providers import (
    ANTHROPIC_SDK_AVAILABLE,
    GOOGLE_SDK_AVAILABLE,
    OPENAI_SDK_AVAILABLE,
    AnthropicProvider,
    CloudProviderManager,
    GoogleProvider,
    OpenAIProvider,
    init_cloud_providers,
)


# -- Provider availability (no API keys set in CI) ----------------------------


class TestProviderAvailability:
    def test_anthropic_unavailable_without_key(self):
        p = AnthropicProvider(api_key="")
        assert not p.is_available()

    def test_openai_unavailable_without_key(self):
        p = OpenAIProvider(api_key="")
        assert not p.is_available()

    def test_google_unavailable_without_key(self):
        p = GoogleProvider(api_key="")
        assert not p.is_available()

    def test_anthropic_available_with_key(self):
        if not ANTHROPIC_SDK_AVAILABLE:
            pytest.skip("anthropic SDK not installed")
        p = AnthropicProvider(api_key="sk-test-key")
        assert p.is_available()

    def test_openai_available_with_key(self):
        if not OPENAI_SDK_AVAILABLE:
            pytest.skip("openai SDK not installed")
        p = OpenAIProvider(api_key="sk-test-key")
        assert p.is_available()

    def test_google_available_with_key(self):
        if not GOOGLE_SDK_AVAILABLE:
            pytest.skip("google-generativeai SDK not installed")
        p = GoogleProvider(api_key="test-key")
        assert p.is_available()


# -- Provider names and defaults -----------------------------------------------


class TestProviderMetadata:
    def test_anthropic_name(self):
        assert AnthropicProvider.name == "anthropic"

    def test_openai_name(self):
        assert OpenAIProvider.name == "openai"

    def test_google_name(self):
        assert GoogleProvider.name == "google"

    def test_anthropic_model_prefixes(self):
        assert ("claude-",) == AnthropicProvider.MODEL_PREFIXES

    def test_openai_model_prefixes(self):
        assert "gpt-" in OpenAIProvider.MODEL_PREFIXES

    def test_google_model_prefixes(self):
        assert ("gemini-",) == GoogleProvider.MODEL_PREFIXES


# -- CloudProviderManager -----------------------------------------------------


class TestCloudProviderManager:
    def _make_manager(self, **kwargs) -> CloudProviderManager:
        mgr = CloudProviderManager(enabled=True, **kwargs)
        mgr.register(AnthropicProvider(api_key="test"))
        mgr.register(OpenAIProvider(api_key="test"))
        mgr.register(GoogleProvider(api_key="test"))
        return mgr

    def test_register_providers(self):
        mgr = CloudProviderManager(enabled=True)
        mgr.register(AnthropicProvider(api_key="test"))
        assert mgr.get_provider("anthropic") is not None

    def test_get_available_providers(self):
        mgr = self._make_manager()
        available = mgr.get_available_providers()
        # Depends on which SDKs are installed, but at least returns a list
        assert isinstance(available, list)

    def test_resolve_by_model_prefix_claude(self):
        mgr = self._make_manager()
        provider = mgr.resolve_provider("claude-sonnet-4-20250514")
        if ANTHROPIC_SDK_AVAILABLE:
            assert provider is not None
            assert provider.name == "anthropic"

    def test_resolve_by_model_prefix_gpt(self):
        mgr = self._make_manager()
        provider = mgr.resolve_provider("gpt-4o")
        if OPENAI_SDK_AVAILABLE:
            assert provider is not None
            assert provider.name == "openai"

    def test_resolve_by_model_prefix_gemini(self):
        mgr = self._make_manager()
        provider = mgr.resolve_provider("gemini-2.0-flash")
        if GOOGLE_SDK_AVAILABLE:
            assert provider is not None
            assert provider.name == "google"

    def test_resolve_uses_default_provider(self):
        mgr = self._make_manager(default_provider="openai")
        # With no model prefix match, should use default
        provider = mgr.resolve_provider("some-unknown-model")
        if OPENAI_SDK_AVAILABLE:
            assert provider is not None
            assert provider.name == "openai"

    def test_resolve_disabled_returns_none(self):
        mgr = CloudProviderManager(enabled=False)
        mgr.register(AnthropicProvider(api_key="test"))
        assert mgr.resolve_provider("claude-sonnet-4-20250514") is None

    def test_is_cloud_model(self):
        mgr = self._make_manager()
        assert mgr.is_cloud_model("claude-sonnet-4-20250514")
        assert mgr.is_cloud_model("gpt-4o")
        assert mgr.is_cloud_model("gemini-2.0-flash")
        assert not mgr.is_cloud_model("llama3:8b")
        assert not mgr.is_cloud_model("mistral:7b")
        assert not mgr.is_cloud_model("")

    def test_get_status(self):
        mgr = self._make_manager()
        status = mgr.get_status()
        assert "enabled" in status
        assert "providers" in status
        assert "anthropic" in status["providers"]
        assert "openai" in status["providers"]
        assert "google" in status["providers"]

    @pytest.mark.asyncio
    async def test_inference_disabled_raises(self):
        mgr = CloudProviderManager(enabled=False)
        with pytest.raises(RuntimeError, match="not enabled"):
            async for _ in mgr.inference("hello"):
                pass

    @pytest.mark.asyncio
    async def test_chat_completion_disabled_raises(self):
        mgr = CloudProviderManager(enabled=False)
        with pytest.raises(RuntimeError, match="not enabled"):
            async for _ in mgr.chat_completion([{"role": "user", "content": "hi"}]):
                pass

    @pytest.mark.asyncio
    async def test_inference_no_providers_raises(self):
        mgr = CloudProviderManager(enabled=True)
        # No providers registered
        with pytest.raises(RuntimeError, match="No cloud providers"):
            async for _ in mgr.inference("hello"):
                pass

    @pytest.mark.asyncio
    async def test_close(self):
        mgr = self._make_manager()
        await mgr.close()  # should not raise


# -- init_cloud_providers factory ----------------------------------------------


class TestInitFactory:
    def test_creates_manager(self):
        mgr = init_cloud_providers(enabled=True)
        assert isinstance(mgr, CloudProviderManager)
        assert mgr.enabled

    def test_registers_all_providers(self):
        mgr = init_cloud_providers(enabled=True)
        assert mgr.get_provider("anthropic") is not None
        assert mgr.get_provider("openai") is not None
        assert mgr.get_provider("google") is not None

    def test_custom_fallback_order(self):
        mgr = init_cloud_providers(
            enabled=True,
            fallback_order=["google", "anthropic"],
        )
        assert mgr.fallback_order == ["google", "anthropic"]
