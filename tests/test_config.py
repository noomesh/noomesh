# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Test configuration loading and validation"""
import pytest
from noomesh.config import load_config, AppConfig
from pydantic import ValidationError


def test_load_default_config():
    """Test loading default configuration"""
    config, path = load_config(None, None)
    assert isinstance(config, AppConfig)
    assert config.ollama.model is not None


def test_config_validation():
    """Test config validation"""
    # Valid config
    config = AppConfig(
        ollama={"model": "test", "base_url": "http://localhost:11434"}
    )
    assert config.ollama.model == "test"

    # Invalid base_url
    with pytest.raises(ValidationError):
        AppConfig(ollama={"model": "test", "base_url": "invalid-url"})


def test_config_overrides():
    """Test configuration overrides"""
    config, _ = load_config(
        None,
        {"ollama": {"model": "override-model"}}
    )
    assert config.ollama.model == "override-model"


def test_tool_selection_mode_validation():
    """Test tool selection mode validation"""
    # Valid modes
    config = AppConfig(tools={"selection_mode": "smart"})
    assert config.tools.selection_mode == "smart"

    config = AppConfig(tools={"selection_mode": "all"})
    assert config.tools.selection_mode == "all"

    # Invalid mode
    with pytest.raises(ValidationError):
        AppConfig(tools={"selection_mode": "invalid"})


# ---------------------------------------------------------------------------
# 2026-09-16: an unset embedding backend is gateway delegation. The validator
# assumed `ollama` and demanded a model, so a fleet whose embedder is a
# placement (the model is declared there, not restated in yaml) failed the
# whole AppConfig — and the worker's exec-approval gate and audit logger,
# which both init from get_config(), never came up.
# ---------------------------------------------------------------------------

_EMBED_ENV = ("PAGEINDEX_EMBEDDING_BACKEND", "PAGEINDEX_EMBEDDING_MODEL",
              "PAGEINDEX_EMBEDDING_URL", "EMBEDDING_MODEL", "TEI_URL")


def _clear_embed_env(monkeypatch):
    for k in _EMBED_ENV:
        monkeypatch.delenv(k, raising=False)


def test_memory_with_an_unset_embedder_delegates_to_the_gateway(monkeypatch):
    _clear_embed_env(monkeypatch)
    cfg = AppConfig(memory={"enabled": True})
    assert cfg.memory.enabled
    assert not cfg.services.embedding_model


def test_memory_with_a_client_side_backend_still_needs_a_model(monkeypatch):
    _clear_embed_env(monkeypatch)
    import pytest

    for backend in ("ollama", "openai"):
        with pytest.raises(ValueError, match=f"{backend} embedding backend"):
            AppConfig(
                memory={"enabled": True},
                services={"embedding_backend": backend, "embedding_url": "http://e:1"},
            )
        AppConfig(  # with a model it validates
            memory={"enabled": True},
            services={"embedding_backend": backend, "embedding_url": "http://e:1",
                      "embedding_model": "harrier"},
        )


def test_memory_with_a_non_gateway_backend_still_needs_a_url(monkeypatch):
    _clear_embed_env(monkeypatch)
    import pytest

    with pytest.raises(ValueError, match="no embedding endpoint URL"):
        AppConfig(memory={"enabled": True}, services={"embedding_backend": "tei", "embedding_url": ""})
