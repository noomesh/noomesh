# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cloud model provider support (Anthropic, OpenAI, Google Gemini).

Routes inference requests to cloud APIs alongside existing local backends.
Local-first philosophy: prefer local backends when available; use cloud
as an explicit choice or failover.

Each provider uses import guards so missing SDKs degrade gracefully.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional, Protocol, runtime_checkable

import structlog

from ..secret_env import secret_or_empty

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Optional SDK imports (import-guarded)
# ---------------------------------------------------------------------------

try:
    import anthropic
    ANTHROPIC_SDK_AVAILABLE = True
except ImportError:
    anthropic = None  # type: ignore[assignment]
    ANTHROPIC_SDK_AVAILABLE = False

try:
    import openai
    OPENAI_SDK_AVAILABLE = True
except ImportError:
    openai = None  # type: ignore[assignment]
    OPENAI_SDK_AVAILABLE = False

try:
    import google.generativeai as genai
    GOOGLE_SDK_AVAILABLE = True
except ImportError:
    genai = None  # type: ignore[assignment]
    GOOGLE_SDK_AVAILABLE = False


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class CloudProvider(Protocol):
    """Interface that every cloud provider must implement."""

    name: str

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        model: str,
        *,
        stream: bool = False,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Yield text chunks for a chat completion."""
        ...

    async def list_models(self) -> List[str]:
        """Return model IDs available from this provider."""
        ...

    def is_available(self) -> bool:
        """Return True if SDK is installed and API key is configured."""
        ...


# ---------------------------------------------------------------------------
# Anthropic provider
# ---------------------------------------------------------------------------

class AnthropicProvider:
    """Claude models via Anthropic API."""

    name: str = "anthropic"

    MODEL_PREFIXES = ("claude-",)
    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self._api_key = api_key or secret_or_empty("ANTHROPIC_API_KEY")
        self._base_url = base_url
        self._client: Any = None

    def _ensure_client(self) -> Any:
        if self._client is None:
            if not ANTHROPIC_SDK_AVAILABLE:
                raise RuntimeError("anthropic SDK not installed. pip install anthropic")
            kwargs: Dict[str, Any] = {"api_key": self._api_key}
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = anthropic.AsyncAnthropic(**kwargs)
        return self._client

    def is_available(self) -> bool:
        return ANTHROPIC_SDK_AVAILABLE and bool(self._api_key)

    async def list_models(self) -> List[str]:
        if not self.is_available():
            return []
        return [
            "claude-opus-4-20250514",
            "claude-sonnet-4-20250514",
            "claude-haiku-3-5-20241022",
        ]

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        model: str,
        *,
        stream: bool = False,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        client = self._ensure_client()
        model = model or self.DEFAULT_MODEL

        system_parts: List[str] = []
        api_messages: List[Dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") == "system":
                system_parts.append(msg.get("content", ""))
            else:
                api_messages.append({"role": msg["role"], "content": msg.get("content", "")})

        api_kwargs: Dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": api_messages,
        }
        if system_parts:
            api_kwargs["system"] = "\n\n".join(system_parts)

        if stream:
            async with client.messages.stream(**api_kwargs) as stream_resp:
                async for text in stream_resp.text_stream:
                    yield text
        else:
            response = await client.messages.create(**api_kwargs)
            for block in response.content:
                if hasattr(block, "text"):
                    yield block.text

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None


# ---------------------------------------------------------------------------
# OpenAI provider (also works for any OpenAI-compatible endpoint)
# ---------------------------------------------------------------------------

class OpenAIProvider:
    """GPT models via OpenAI API (or any OpenAI-compatible endpoint)."""

    name: str = "openai"

    MODEL_PREFIXES = ("gpt-", "o1-", "o3-", "o4-")
    DEFAULT_MODEL = "gpt-4o"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self._api_key = api_key or secret_or_empty("OPENAI_API_KEY")
        # `or None` — a compose ${VAR:-} passthrough injects "" for unset
        # vars, and base_url="" must not reach the OpenAI client.
        self._base_url = base_url or os.getenv("OPENAI_BASE_URL") or None
        self._client: Any = None

    def _ensure_client(self) -> Any:
        if self._client is None:
            if not OPENAI_SDK_AVAILABLE:
                raise RuntimeError("openai SDK not installed. pip install openai")
            kwargs: Dict[str, Any] = {"api_key": self._api_key}
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = openai.AsyncOpenAI(**kwargs)
        return self._client

    def is_available(self) -> bool:
        return OPENAI_SDK_AVAILABLE and bool(self._api_key)

    async def list_models(self) -> List[str]:
        if not self.is_available():
            return []
        try:
            client = self._ensure_client()
            resp = await client.models.list()
            return [m.id for m in resp.data]
        except Exception as e:
            logger.warning("openai_list_models_failed", error=str(e))
            return ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o4-mini"]

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        model: str,
        *,
        stream: bool = False,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        client = self._ensure_client()
        model = model or self.DEFAULT_MODEL

        api_kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": stream,
        }

        if stream:
            stream_resp = await client.chat.completions.create(**api_kwargs)
            async for chunk in stream_resp:
                delta = chunk.choices[0].delta if chunk.choices else None
                if delta and delta.content:
                    yield delta.content
        else:
            response = await client.chat.completions.create(**api_kwargs)
            text = response.choices[0].message.content or ""
            yield text

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None


# ---------------------------------------------------------------------------
# Google Gemini provider
# ---------------------------------------------------------------------------

class GoogleProvider:
    """Gemini models via Google Generative AI SDK."""

    name: str = "google"

    MODEL_PREFIXES = ("gemini-",)
    DEFAULT_MODEL = "gemini-2.0-flash"

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or secret_or_empty("GOOGLE_API_KEY")
        self._configured = False

    def _ensure_configured(self) -> None:
        if not self._configured:
            if not GOOGLE_SDK_AVAILABLE:
                raise RuntimeError(
                    "google-generativeai SDK not installed. pip install google-generativeai"
                )
            genai.configure(api_key=self._api_key)
            self._configured = True

    def is_available(self) -> bool:
        return GOOGLE_SDK_AVAILABLE and bool(self._api_key)

    async def list_models(self) -> List[str]:
        if not self.is_available():
            return []
        return [
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
        ]

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        model: str,
        *,
        stream: bool = False,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        import asyncio

        self._ensure_configured()
        model = model or self.DEFAULT_MODEL

        system_instruction = None
        gemini_contents: List[Dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                system_instruction = content
            elif role == "assistant":
                gemini_contents.append({"role": "model", "parts": [content]})
            else:
                gemini_contents.append({"role": "user", "parts": [content]})

        gen_config = genai.types.GenerationConfig(
            max_output_tokens=max_tokens,
            temperature=temperature,
        )

        model_kwargs: Dict[str, Any] = {"model_name": model}
        if system_instruction:
            model_kwargs["system_instruction"] = system_instruction

        gm = genai.GenerativeModel(**model_kwargs)

        if stream:
            def _stream_sync():
                resp = gm.generate_content(
                    gemini_contents,
                    generation_config=gen_config,
                    stream=True,
                )
                chunks = []
                for chunk in resp:
                    if chunk.text:
                        chunks.append(chunk.text)
                return chunks

            loop = asyncio.get_running_loop()
            chunks = await loop.run_in_executor(None, _stream_sync)
            for chunk in chunks:
                yield chunk
        else:
            def _generate_sync():
                return gm.generate_content(
                    gemini_contents,
                    generation_config=gen_config,
                )

            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(None, _generate_sync)
            if response.text:
                yield response.text

    async def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Provider registry / manager
# ---------------------------------------------------------------------------

_MODEL_PREFIX_MAP: Dict[str, str] = {}


@dataclass
class CloudProviderManager:
    """Central registry for cloud providers with routing and failover.

    Usage:
        manager = CloudProviderManager()
        manager.register(AnthropicProvider(api_key="sk-..."))
        manager.register(OpenAIProvider(api_key="sk-..."))

        async for chunk in manager.inference("Hello", model="claude-sonnet-4-20250514"):
            print(chunk, end="")
    """

    _providers: Dict[str, CloudProvider] = field(default_factory=dict)
    default_provider: Optional[str] = None
    fallback_order: List[str] = field(default_factory=lambda: ["anthropic", "openai", "google"])
    enabled: bool = False

    def register(self, provider: CloudProvider) -> None:
        """Register a cloud provider."""
        self._providers[provider.name] = provider
        for prefix in getattr(provider, "MODEL_PREFIXES", ()):
            _MODEL_PREFIX_MAP[prefix] = provider.name
        logger.info(
            "cloud_provider_registered",
            provider=provider.name,
            available=provider.is_available(),
        )

    def get_provider(self, name: str) -> Optional[CloudProvider]:
        return self._providers.get(name)

    def get_available_providers(self) -> List[str]:
        return [
            name for name, p in self._providers.items()
            if p.is_available()
        ]

    def resolve_provider(self, model: Optional[str] = None) -> Optional[CloudProvider]:
        """Resolve which provider to use for a given model.

        Resolution order:
        1. Match model name prefix (claude-* -> anthropic, gpt-* -> openai, etc.)
        2. Use default_provider if set
        3. First available in fallback_order
        """
        if not self.enabled:
            return None

        if model:
            for prefix, provider_name in _MODEL_PREFIX_MAP.items():
                if model.startswith(prefix):
                    provider = self._providers.get(provider_name)
                    if provider and provider.is_available():
                        return provider

        if self.default_provider:
            provider = self._providers.get(self.default_provider)
            if provider and provider.is_available():
                return provider

        for name in self.fallback_order:
            provider = self._providers.get(name)
            if provider and provider.is_available():
                return provider

        return None

    def is_cloud_model(self, model: str) -> bool:
        """Check if a model name should be routed to a cloud provider."""
        if not model:
            return False
        for prefix in _MODEL_PREFIX_MAP:
            if model.startswith(prefix):
                return True
        return False

    async def inference(
        self,
        prompt: str,
        *,
        model: Optional[str] = None,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        stream: bool = False,
    ) -> AsyncIterator[str]:
        """Run inference through cloud providers with failover."""
        if not self.enabled:
            raise RuntimeError("Cloud providers are not enabled")

        messages: List[Dict[str, Any]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        providers_to_try: List[CloudProvider] = []
        primary = self.resolve_provider(model)
        if primary:
            providers_to_try.append(primary)

        for name in self.fallback_order:
            p = self._providers.get(name)
            if p and p.is_available() and p not in providers_to_try:
                providers_to_try.append(p)

        if not providers_to_try:
            raise RuntimeError(
                "No cloud providers available. Install SDKs and set API keys."
            )

        last_error: Optional[Exception] = None
        for provider in providers_to_try:
            try:
                provider_model = model
                if not provider_model or not any(
                    provider_model.startswith(p)
                    for p in getattr(provider, "MODEL_PREFIXES", ())
                ):
                    provider_model = getattr(provider, "DEFAULT_MODEL", model)

                logger.info(
                    "cloud_inference_attempt",
                    provider=provider.name,
                    model=provider_model,
                    stream=stream,
                )
                start = time.monotonic()

                async for chunk in provider.chat_completion(
                    messages,
                    provider_model,
                    stream=stream,
                    max_tokens=max_tokens,
                    temperature=temperature,
                ):
                    yield chunk

                elapsed = time.monotonic() - start
                logger.info(
                    "cloud_inference_success",
                    provider=provider.name,
                    model=provider_model,
                    elapsed_s=round(elapsed, 2),
                )
                return

            except Exception as e:
                last_error = e
                logger.warning(
                    "cloud_inference_failed",
                    provider=provider.name,
                    model=model,
                    error=str(e),
                    remaining_fallbacks=len(providers_to_try) - providers_to_try.index(provider) - 1,
                )
                continue

        raise RuntimeError(
            f"All cloud providers failed. Last error: {last_error}"
        )

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        *,
        model: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        stream: bool = False,
    ) -> AsyncIterator[str]:
        """Run chat completion through cloud providers with failover."""
        if not self.enabled:
            raise RuntimeError("Cloud providers are not enabled")

        providers_to_try: List[CloudProvider] = []
        primary = self.resolve_provider(model)
        if primary:
            providers_to_try.append(primary)

        for name in self.fallback_order:
            p = self._providers.get(name)
            if p and p.is_available() and p not in providers_to_try:
                providers_to_try.append(p)

        if not providers_to_try:
            raise RuntimeError(
                "No cloud providers available. Install SDKs and set API keys."
            )

        last_error: Optional[Exception] = None
        for provider in providers_to_try:
            try:
                provider_model = model
                if not provider_model or not any(
                    provider_model.startswith(p)
                    for p in getattr(provider, "MODEL_PREFIXES", ())
                ):
                    provider_model = getattr(provider, "DEFAULT_MODEL", model)

                logger.info(
                    "cloud_chat_attempt",
                    provider=provider.name,
                    model=provider_model,
                    stream=stream,
                )

                async for chunk in provider.chat_completion(
                    messages,
                    provider_model,
                    stream=stream,
                    max_tokens=max_tokens,
                    temperature=temperature,
                ):
                    yield chunk

                return
            except Exception as e:
                last_error = e
                logger.warning(
                    "cloud_chat_failed",
                    provider=provider.name,
                    error=str(e),
                )
                continue

        raise RuntimeError(f"All cloud providers failed. Last error: {last_error}")

    def get_status(self) -> Dict[str, Any]:
        """Return status info for all registered providers."""
        providers_status = {}
        for name, provider in self._providers.items():
            providers_status[name] = {
                "available": provider.is_available(),
                "sdk_installed": _sdk_installed(name),
                "api_key_set": _has_api_key(name),
            }
        return {
            "enabled": self.enabled,
            "default_provider": self.default_provider,
            "fallback_order": self.fallback_order,
            "providers": providers_status,
            "available_providers": self.get_available_providers(),
        }

    async def close(self) -> None:
        """Close all provider clients."""
        for provider in self._providers.values():
            try:
                await provider.close()
            except Exception as e:
                logger.warning(
                    "cloud_provider_close_error",
                    provider=provider.name,
                    error=str(e),
                )


def _sdk_installed(provider_name: str) -> bool:
    return {
        "anthropic": ANTHROPIC_SDK_AVAILABLE,
        "openai": OPENAI_SDK_AVAILABLE,
        "google": GOOGLE_SDK_AVAILABLE,
    }.get(provider_name, False)


def _has_api_key(provider_name: str) -> bool:
    env_keys = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "google": "GOOGLE_API_KEY",
    }
    key = env_keys.get(provider_name, "")
    # Through secret_env: the keys may arrive as `<NAME>_FILE` files.
    return bool(key) and bool(secret_or_empty(key))


# ---------------------------------------------------------------------------
# Module-level singleton (set by gateway lifespan)
# ---------------------------------------------------------------------------

_cloud_manager: Optional[CloudProviderManager] = None


def get_cloud_manager() -> Optional[CloudProviderManager]:
    """Return the global cloud provider manager (None if not initialized)."""
    return _cloud_manager


def init_cloud_providers(
    *,
    enabled: bool = False,
    anthropic_api_key: Optional[str] = None,
    openai_api_key: Optional[str] = None,
    openai_base_url: Optional[str] = None,
    google_api_key: Optional[str] = None,
    default_provider: Optional[str] = None,
    fallback_order: Optional[List[str]] = None,
) -> CloudProviderManager:
    """Initialize cloud provider manager from config/secrets.

    Called during gateway lifespan startup.
    """
    global _cloud_manager

    manager = CloudProviderManager(
        enabled=enabled,
        default_provider=default_provider,
        fallback_order=fallback_order or ["anthropic", "openai", "google"],
    )

    manager.register(AnthropicProvider(api_key=anthropic_api_key))
    manager.register(OpenAIProvider(api_key=openai_api_key, base_url=openai_base_url))
    manager.register(GoogleProvider(api_key=google_api_key))

    _cloud_manager = manager
    return manager
