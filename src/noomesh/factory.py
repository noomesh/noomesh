# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from __future__ import annotations

import structlog
from pathlib import Path
from typing import Dict, Optional

from .agent import Agent
from .config import AppConfig
from .llm import OllamaClient
from .llm.base import LLMClient
from .secrets import get_secret
from .plugins import PluginManager

from .memory import (
    ContextLoader,
    MemoryConfig,
    MemorySystem,
    PGVectorConfig,
    PGVectorStore,
)
from .tools import (
    ToolRegistry,
    build_local_files_tool,
    build_python_tool,
    build_web_search_tool,
)

_logger = structlog.get_logger(__name__)

# Global plugin manager (accessible for CLI and hooks)
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> Optional[PluginManager]:
    """Return the global plugin manager, if initialized."""
    return _plugin_manager


def build_llm_client(
    base_url: str,
    model: str,
    backend_type: str = "ollama",
    options: Optional[Dict] = None,
) -> LLMClient:
    """Create the right LLM client based on backend type.

    Registry-driven: the ``api_format`` of the backend's
    :class:`~noomesh.backends.BackendProfile` decides the client class —
    ``"openai"`` → :class:`OpenAICompatClient`, anything else (including an
    unregistered backend_type, preserving the historical default) →
    :class:`OllamaClient`. OpenAI-compatible HTTP is the primary extension
    point: registering a new profile with ``api_format="openai"`` makes this
    factory work for it with no code change.

    Args:
        base_url: HTTP base URL of the inference server.
        model: Model identifier.
        backend_type: e.g. ``"ollama"``, ``"vllm"``, ``"llamacpp"``.
        options: Extra generation options (temperature, etc.).

    Returns:
        An :class:`LLMClient` instance.
    """
    from .backends import api_format
    if api_format(backend_type) == "openai":
        from .llm.openai_compat import OpenAICompatClient
        return OpenAICompatClient(
            base_url=base_url,
            model=model,
            options=options or {},
        )
    # Default: Ollama (also the fallback for unknown backend types).
    return OllamaClient(
        base_url=base_url,
        model=model,
        options=options or {},
    )


def build_agent(config: AppConfig, llm_override: Optional[LLMClient] = None) -> Agent:
    llm: LLMClient = llm_override or OllamaClient(
        base_url=config.ollama.base_url,
        model=config.ollama.model,
        options=config.ollama.options,
    )

    tools = ToolRegistry()
    enabled = set(config.tools.enabled)
    if "web_search" in enabled:
        tools.register(
            build_web_search_tool(
                provider=config.web_search.provider,
                max_results=config.web_search.max_results,
            )
        )
    if "python_exec" in enabled:
        sandbox_url = get_secret("NOO_SANDBOX_URL") or config.sandbox.url
        tools.register(build_python_tool(sandbox_url=sandbox_url))
    if "local_files" in enabled:
        from .config import get_file_allowed_paths
        allowed = get_file_allowed_paths(config)
        host_map = config.watched_folders.dir_mapping if config.watched_folders.enabled else {}
        labels = config.watched_folders.labeled_dirs if config.watched_folders.enabled else []
        writable = config.watched_folders.writable_mount_paths if config.watched_folders.enabled else []
        if config.workspace.path:
            writable = list(writable) + [config.workspace.path]
        tools.register(build_local_files_tool(
            allowed_paths=allowed or None,
            host_to_mount=host_map or None,
            labeled_dirs=labels or None,
            writable_paths=writable or None,
        ))

    context_loader = ContextLoader(config.context.files)

    memory_manager = _build_memory_manager(config, llm)


    # Load plugins (graceful — bad plugins don't crash the app)
    _load_plugins(tools)

    return Agent(
        llm=llm,
        tools=tools,
        system_prompt=config.agent.system_prompt,
        context_loader=context_loader,
        memory_manager=memory_manager,
        tool_selection_mode=config.tools.selection_mode,
        tool_selection_max=config.tools.max_selected,
        tool_selection_min_score=config.tools.min_score,
        tool_selection_scoring=config.tools.selection_scoring,
        tool_selection_always=config.tools.always_include,
        tool_mode=config.agent.tool_mode,
        max_tool_loops=config.agent.max_tool_loops,
    )


def _build_memory_manager(config: AppConfig, llm: OllamaClient) -> MemorySystem | None:
    if not config.memory.enabled:
        return None

    if config.memory.pgvector.enabled and not config.memory.embedding_model:
        raise ValueError("pgvector enabled but memory.embedding_model is not set.")

    global_path = config.memory.global_path
    if not global_path:
        global_path = str(
            Path.home() / ".config" / "mesh" / "memory.jsonl"
        )

    mem_config = MemoryConfig(
        enabled=config.memory.enabled,
        include_session=config.memory.include_session,
        include_global=config.memory.include_global,
        session_top_k=config.memory.session_top_k,
        global_top_k=config.memory.global_top_k,
        min_score=config.memory.min_score,
        retrieval_scoring=config.memory.retrieval_scoring,
        max_chars=config.memory.max_chars,
        max_session_items=config.memory.max_session_items,
        max_global_items=config.memory.max_global_items,
        global_path=Path(global_path) if global_path else None,
        embedding_model=config.memory.embedding_model,
        embedding_base_url=config.memory.embedding_base_url,
        pgvector=PGVectorConfig(
            dsn=config.memory.pgvector.dsn or "",
            table=config.memory.pgvector.table,
            dim=config.memory.pgvector.dim or 0,
            create_extension=config.memory.pgvector.create_extension,
            create_index=config.memory.pgvector.create_index,
        ),
    )
    vector_store = _build_pgvector_store(config)
    embedder = _build_embedder(config, llm) if vector_store else None
    return MemorySystem(mem_config, embedder=embedder, vector_store=vector_store)


def _build_embedder(config: AppConfig, llm: OllamaClient):
    model = config.memory.embedding_model
    if not model:
        return None

    base_url = config.memory.embedding_base_url
    if base_url:
        embed_client = OllamaClient(base_url=base_url, model=model)
    else:
        embed_client = llm

    def _embed(text: str) -> list[float]:
        return embed_client.embed(text, model=model)

    return _embed


def _build_pgvector_store(config: AppConfig) -> PGVectorStore | None:
    pg = config.memory.pgvector
    if not pg.enabled:
        return None
    if not pg.dsn or not pg.dim:
        raise ValueError("pgvector enabled but dsn or dim not set in config.")
    return PGVectorStore(
        PGVectorConfig(
            dsn=pg.dsn,
            table=pg.table,
            dim=pg.dim,
            create_extension=pg.create_extension,
            create_index=pg.create_index,
        )
    )


def _load_plugins(tools: ToolRegistry) -> None:
    """Discover and load plugins from the plugin directory."""
    global _plugin_manager

    plugin_dir_str = get_secret("NOO_PLUGIN_DIR") or str(
        Path.home() / ".noo" / "plugins"
    )
    plugin_dir = Path(plugin_dir_str)
    plugin_dir.mkdir(parents=True, exist_ok=True)

    _plugin_manager = PluginManager(plugin_dir=plugin_dir)
    discovered = _plugin_manager.discover_plugins()
    if not discovered:
        return

    for name in discovered:
        try:
            plugin = _plugin_manager.load_plugin(name, registry=tools)
            if plugin:
                _logger.info("Plugin loaded: %s (v%s)", name, plugin.metadata.version)
            else:
                _logger.warning("Plugin discovered but failed to load: %s", name)
        except Exception as e:
            _logger.warning("Plugin %s error: %s", name, e)
