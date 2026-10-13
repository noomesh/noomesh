# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""
Mesh - Models Management CLI
Commands for browsing, searching, and managing models with live HuggingFace data.
"""

import typer
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from typing import Optional

from ..cli_utils import console, is_json_output, output_json, print_error, print_warning, print_hint, get_gateway_url
from .model_catalog import ModelCatalog
from .model_placement import model_is_cached

models_app = typer.Typer(help="🤖 Browse and manage [bold]AI models[/]", rich_markup_mode="rich")

_catalog = ModelCatalog()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TIER_DESC = {
    1: "High-end GPU (RTX 3080+, V100, A100) — >=10GB VRAM",
    2: "Mid-tier GPU (RTX 2060, 1660 Ti) — 4-10GB VRAM",
    3: "CPU only (no GPU)",
    4: "Edge board (Jetson, RPi5, RK3588) — GGUF via llama.cpp",
    5: "Companion device (phone, tablet) — tiny GGUF only",
}

ALL_BACKENDS = ["vllm", "llamacpp", "ollama", "airllm"]


def _gated_badge(gated: str) -> Text:
    """Colored badge for gated status."""
    if gated == "Open":
        return Text("Open", style="green")
    if gated == "Login":
        return Text("Login", style="yellow")
    return Text("Gated", style="red bold")


def _fmt_downloads(n: int | None) -> str:
    if not n:
        return "0"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _backends_str(backends: list[str] | None) -> str:
    if not backends:
        return "?"
    return ", ".join(backends)


def _show_gated_hint(model_id: str, gated: str) -> None:
    """Print actionable info for gated models."""
    if gated == "Login":
        print_warning("This model requires a HuggingFace token (auto-approved)")
        console.print(f"  1. Visit: [link]https://huggingface.co/{model_id}[/link]")
        console.print("  2. Set HF_TOKEN env var or run: [bold]huggingface-cli login[/bold]\n")
    elif gated == "Gated":
        print_warning("This model requires HuggingFace approval")
        console.print(f"  1. Visit: [link]https://huggingface.co/{model_id}[/link]")
        console.print("  2. Accept the license agreement")
        console.print("  3. Set HF_TOKEN env var or run: [bold]huggingface-cli login[/bold]\n")


def _detect_cluster_tier() -> int | None:
    """Try to auto-detect best tier from cluster node capabilities."""
    import httpx
    from ..cli_utils import cli_http_verify, cli_client_cert, cli_auth_headers
    try:
        url = get_gateway_url()
        # verify + mTLS cert + cluster-HMAC auth header — the gateway 401s
        # without the header (it's behind require_any_auth).
        with httpx.Client(timeout=5, verify=cli_http_verify(), cert=cli_client_cert(),
                          headers=cli_auth_headers()) as client:
            resp = client.get(f"{url}/api/cluster/nodes")
            if resp.status_code != 200:
                return None
            nodes = resp.json()
        best_vram = 0.0
        for n in nodes:
            caps = n.get("capabilities", {})
            vram = caps.get("vram_gb", 0) or 0
            if vram > best_vram:
                best_vram = vram
        if best_vram >= 10:
            return 1
        if best_vram >= 4:
            return 2
        return 3
    except Exception:
        return None


def _cached_models() -> list[dict]:
    """Models already cached/running across the cluster (best-effort), each
    ``{"name", "backend", "size"}``.

    Used to prefer — and inject — recommendations the cluster can preseed over
    the LAN instead of pulling from HuggingFace. Empty on any error."""
    import httpx
    from ..cli_utils import cli_http_verify, cli_client_cert, cli_auth_headers
    try:
        url = get_gateway_url()
        # verify + mTLS cert + cluster-HMAC auth header (else the gateway 401s).
        with httpx.Client(timeout=5, verify=cli_http_verify(), cert=cli_client_cert(),
                          headers=cli_auth_headers()) as client:
            resp = client.get(f"{url}/api/models/cached")
            if resp.status_code != 200:
                return []
            data = resp.json()
        out = []
        for m in data.get("models", []):
            name = m.get("name", "")
            backend = m.get("backend", "")
            # Skip degenerate entries where the "name" is just the backend type
            # (e.g. an idle ollama with no model), and non-inferable backends.
            if name and name != backend:
                out.append({"name": name, "backend": backend, "size": m.get("size", "?")})
        return out
    except Exception:
        return []


def _cached_model_ids() -> list[str]:
    """Flat list of cached model names (see :func:`_cached_models`)."""
    return [m["name"] for m in _cached_models() if m.get("name")]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@models_app.command("list")
def list_models(
    backend: Optional[str] = typer.Option(None, "--backend", "-b", help="Filter by backend (vllm, ollama, llamacpp, airllm)"),
    tier: Optional[int] = typer.Option(None, "--tier", "-t", help="Filter by tier (1, 2, 3)"),
    limit: int = typer.Option(15, "--limit", "-n", help="Models per backend"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch from HuggingFace"),
):
    """📚 List popular models from HuggingFace"""

    console.print("\n[bold cyan]📚 Mesh - Model Catalog[/bold cyan]\n")

    backends = [backend] if backend else ALL_BACKENDS

    for b in backends:
        if b not in ALL_BACKENDS:
            print_error(f"Unknown backend: {b}")
            continue

        with console.status(f"Fetching {b} models..."):
            models = _catalog.fetch_models(b, tier=tier, limit=limit, refresh=refresh)

        if not models:
            console.print(f"[dim]No models found for {b}" + (f" tier {tier}" if tier else "") + "[/dim]\n")
            continue

        if is_json_output():
            output_json({"backend": b, "models": models})
            continue

        table = Table(title=f"{b.upper()}", show_header=True, header_style="bold magenta", title_style="bold yellow")
        table.add_column("Model", style="cyan", no_wrap=False, max_width=50)
        table.add_column("Size", style="green", justify="right", width=8)
        table.add_column("Downloads", style="white", justify="right", width=10)
        table.add_column("Gated", justify="center", width=7)
        table.add_column("Tier", style="blue", justify="center", width=5)
        table.add_column("Description", style="dim", max_width=40)

        for m in models:
            table.add_row(
                m.get("id", "?"),
                m.get("size_estimate", "?"),
                _fmt_downloads(m.get("downloads")),
                _gated_badge(m.get("gated", "Open")),
                str(m.get("tier", "?")),
                m.get("desc", "")[:40],
            )

        console.print(table)
        console.print()

    cache_age = _catalog.cache_age_text(backends[0])
    print_hint(f"Catalog updated {cache_age}. Use --refresh to update.")
    print_hint("Tip: Use 'noo models search <keyword>' to find specific models\n")


@models_app.command("search")
def search_models(
    query: str = typer.Argument(..., help="Search query (model name, keyword)"),
    backend: Optional[str] = typer.Option(None, "--backend", "-b", help="Filter by backend"),
    limit: int = typer.Option(15, "--limit", "-n", help="Max results"),
):
    """🔍 Search HuggingFace for models"""

    console.print(f"\n[bold cyan]🔍 Searching HuggingFace for: {query}[/bold cyan]\n")

    with console.status("Searching HuggingFace..."):
        results = _catalog.search_models(query, backend=backend, limit=limit)

    if not results:
        console.print(f"[yellow]No models found matching '{query}'[/yellow]\n")
        print_hint("Try broader terms like: qwen instruct, llama gguf, mistral awq\n")
        return

    if is_json_output():
        output_json(results)
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Model", style="cyan", no_wrap=False, max_width=55)
    table.add_column("Size", style="green", justify="right", width=8)
    table.add_column("Downloads", style="white", justify="right", width=10)
    table.add_column("Gated", justify="center", width=7)
    table.add_column("Backends", style="yellow", width=18)
    table.add_column("Description", style="dim", max_width=35)

    for m in results:
        table.add_row(
            m.get("id", "?"),
            m.get("size_estimate", "?"),
            _fmt_downloads(m.get("downloads")),
            _gated_badge(m.get("gated", "Open")),
            _backends_str(m.get("backends")),
            m.get("desc", "")[:35],
        )

    console.print(table)
    console.print(f"\n[green]Found {len(results)} model(s)[/green]\n")


@models_app.command("info")
def model_info(
    model: str = typer.Argument(..., help="HuggingFace model ID (e.g. meta-llama/Llama-3.1-8B-Instruct)"),
):
    """📋 Show detailed information about a model"""

    console.print(f"\n[bold cyan]📋 Fetching info for: {model}[/bold cyan]\n")

    with console.status("Querying HuggingFace..."):
        info = _catalog.model_info(model)

    if not info:
        print_error(f"Could not find model '{model}' on HuggingFace")
        print_hint("Make sure to use the full model ID (e.g. meta-llama/Llama-3.1-8B-Instruct)\n")
        return

    if is_json_output():
        output_json(info)
        return

    gated = info.get("gated", "Open")
    params = info.get("params_b")
    params_str = f"{params}B" if params else "Unknown"
    tier = info.get("tier", "?")
    backends = _backends_str(info.get("backends"))
    formats = ", ".join(info.get("formats", [])) or "Unknown"
    license_str = info.get("license", "Unknown")
    size = info.get("size_estimate", "?")

    panel_content = (
        f"[bold cyan]Model:[/bold cyan]      {info['id']}\n"
        f"[bold cyan]Author:[/bold cyan]     {info.get('author', '?')}\n"
        f"[bold cyan]Parameters:[/bold cyan] {params_str}\n"
        f"[bold cyan]Size:[/bold cyan]       {size}\n"
        f"[bold cyan]Tier:[/bold cyan]       {tier} ({TIER_DESC.get(tier, '')})\n"
        f"[bold cyan]Gated:[/bold cyan]      {gated}\n"
        f"[bold cyan]License:[/bold cyan]    {license_str}\n"
        f"[bold cyan]Backends:[/bold cyan]   {backends}\n"
        f"[bold cyan]Formats:[/bold cyan]    {formats}\n"
        f"[bold cyan]Downloads:[/bold cyan]  {_fmt_downloads(info.get('downloads'))}\n"
        f"[bold cyan]Likes:[/bold cyan]      {info.get('likes', 0):,}\n"
        f"\n[bold yellow]Quick Start:[/bold yellow]\n"
    )

    # Suggest a quick-start command for the first compatible backend
    compat_backends = info.get("backends", [])
    if compat_backends and compat_backends[0] != "unknown":
        panel_content += f"  noo cluster up {compat_backends[0]} {info['id']}\n"
    else:
        panel_content += f"  noo cluster up vllm {info['id']}\n"

    console.print(Panel(panel_content, title="📋 Model Information", border_style="cyan"))

    _show_gated_hint(info["id"], gated)


@models_app.command("recommended")
def recommended_models(
    tier: Optional[int] = typer.Option(None, "--tier", "-t", help="Hardware tier (1-5). Auto-detected if omitted."),
    arch: Optional[str] = typer.Option(None, "--arch", help="CPU arch (e.g. x86_64, aarch64). arm nodes get GGUF-only recs."),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch from HuggingFace"),
):
    """🎯 Show recommended models for a node's hardware tier + architecture.

    Tiers: 1 GPU worker, 2 small GPU, 3 CPU, 4 edge (Jetson/RPi/RK3588),
    5 companion. arm/aarch64 nodes are offered GGUF backends only (no vLLM)."""

    # Auto-detect tier from cluster if not specified
    if tier is None:
        with console.status("Detecting cluster capabilities..."):
            detected = _detect_cluster_tier()
        if detected:
            tier = detected
            if not is_json_output():
                console.print(f"[green]Auto-detected tier {tier}[/green] from cluster nodes\n")
        else:
            tier = 1
            if not is_json_output():
                console.print("[dim]Could not detect cluster — defaulting to tier 1[/dim]\n")

    if tier not in (1, 2, 3, 4, 5):
        print_error(f"Invalid tier: {tier}. Use 1-5")
        return

    if not is_json_output():
        arch_note = f" · {arch}" if arch else ""
        if arch and ModelCatalog.is_arm(arch):
            arch_note += " (arm → GGUF only)"
        console.print(f"[bold cyan]🎯 Recommended Models for Tier {tier}{arch_note}[/bold cyan]")
        console.print(f"[dim]{TIER_DESC.get(tier, '')}[/dim]\n")

    # Backends + model size-class from the node's tier & arch (single source of
    # truth in ModelCatalog, shared with auto-placement).
    backends = ModelCatalog.backends_for(tier, arch)
    model_class = ModelCatalog.model_class_for(tier)

    # Prefer models already in the cluster cache — a cached model preseeds over
    # the LAN (see the model-weight cache) instead of a fresh HuggingFace pull.
    cached_models = _cached_models()
    cached = [m["name"] for m in cached_models if m.get("name")]

    def _ranked(models: list[dict]) -> list[dict]:
        """Cached models first (stable), then original popularity order; tag each."""
        for m in models:
            m["cached"] = model_is_cached(m.get("id", ""), cached)
        return sorted(models, key=lambda m: not m["cached"])

    def _candidates(b: str) -> list[dict]:
        """Top picks for backend ``b``: the catalog's popular models PLUS any
        cache-resident model for this backend that the catalog didn't surface
        (so a LAN-preseedable model like a local GGUF still wins), cached-first,
        capped at 3."""
        fetched = _catalog.fetch_models(b, tier=model_class, limit=6, refresh=refresh)
        present = [m.get("id", "") for m in fetched]
        for cm in cached_models:
            if cm.get("backend") != b:
                continue
            name = cm["name"]
            if model_is_cached(name, present):
                continue  # already represented in the catalog list
            fetched.insert(0, {
                "id": name,
                "size_estimate": cm.get("size", "?"),
                "downloads": None,
                "desc": "already cached on the cluster",
            })
            present.insert(0, name)
        return _ranked(fetched)[:3]

    if is_json_output():
        result = {"tier": tier, "arch": arch, "cached_preferred": bool(cached), "backends": {}}
        for b in backends:
            models = _candidates(b)
            if models:
                result["backends"][b] = models
        output_json(result)
        return

    for b in backends:
        with console.status(f"Fetching top {b} models..."):
            models = _candidates(b)

        if not models:
            continue

        console.print(f"[bold yellow]{b.upper()}:[/bold yellow]")
        for m in models:
            gated = m.get("gated", "Open")
            gated_mark = ""
            if gated == "Login":
                gated_mark = " [yellow](HF login required)[/yellow]"
            elif gated == "Gated":
                gated_mark = " [red](gated — approval required)[/red]"
            cached_mark = " [green]✓ in cluster cache — preseeds over LAN[/green]" if m.get("cached") else ""

            console.print(f"  Model: [cyan]{m['id']}[/cyan]{gated_mark}{cached_mark}")
            console.print(f"  Size:  [green]{m.get('size_estimate', '?')}[/green]  Downloads: {_fmt_downloads(m.get('downloads'))}")
            console.print(f"  Start: [dim]noo cluster up {b} {m['id']}[/dim]")
            console.print()

    cache_age = _catalog.cache_age_text("vllm")
    print_hint(f"Catalog updated {cache_age}. Use --refresh to update.\n")


@models_app.command("pull")
def pull_model(
    model: str = typer.Argument(..., help="Model name (e.g. qwen2.5:14b, gemma2:2b)"),
    backend: str = typer.Option("ollama", "--backend", "-b", help="Backend to pull from"),
):
    """⬇️  Pull a model to a backend"""
    import httpx

    if backend != "ollama":
        print_error(f"Pull not yet supported for backend '{backend}' — only ollama")
        raise typer.Exit(1)

    url = get_gateway_url()
    console.print(f"\n[bold cyan]⬇️  Pulling {model} via Ollama[/bold cyan]\n")

    try:
        with httpx.stream(
            "POST",
            f"{url}/api/terminal/ollama/pull",
            json={"model": model},
            timeout=600,
        ) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line.startswith("data: "):
                    continue
                import json
                try:
                    d = json.loads(line[6:])
                except Exception:
                    continue
                if d.get("error"):
                    print_error(d["error"])
                    raise typer.Exit(1)
                if d.get("done"):
                    console.print(f"[green]✓ {model} pulled successfully[/green]\n")
                    return
                status = d.get("status", "")
                total = d.get("total", 0)
                completed = d.get("completed", 0)
                if total and completed:
                    pct = int(completed / total * 100)
                    console.print(f"  {status} — {pct}%", end="\r")
                elif status:
                    console.print(f"  {status}")
    except httpx.ConnectError:
        print_error(f"Cannot connect to gateway at {url}")
        print_hint("Is the stack running? Try: noo stack start\n")
        raise typer.Exit(1)
    except httpx.HTTPStatusError as e:
        print_error(f"Gateway returned {e.response.status_code}")
        raise typer.Exit(1)


@models_app.command("ollama")
def list_ollama_models(
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch"),
):
    """🦙 List popular Ollama-compatible models"""

    console.print("\n[bold cyan]🦙 Ollama-Compatible Models[/bold cyan]\n")

    with console.status("Fetching Ollama models..."):
        models = _catalog.fetch_models("ollama", limit=limit, refresh=refresh)

    if not models:
        console.print("[yellow]Could not fetch models[/yellow]")
        print_hint("Visit https://ollama.com/library to browse models\n")
        return

    if is_json_output():
        output_json(models)
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Model", style="cyan", no_wrap=False, max_width=55)
    table.add_column("Size", style="green", justify="right", width=8)
    table.add_column("Downloads", style="white", justify="right", width=10)
    table.add_column("Gated", justify="center", width=7)
    table.add_column("Params", style="blue", justify="right", width=7)

    for m in models:
        params = m.get("params_b")
        params_str = f"{params}B" if params else "?"
        table.add_row(
            m.get("id", "?"),
            m.get("size_estimate", "?"),
            _fmt_downloads(m.get("downloads")),
            _gated_badge(m.get("gated", "Open")),
            params_str,
        )

    console.print(table)
    cache_age = _catalog.cache_age_text("ollama")
    console.print(f"\n[dim]Catalog updated {cache_age}. Use --refresh to update.[/dim]")
    print_hint("Pull: ollama pull <model-name>")
    print_hint("Full catalog: https://ollama.com/library\n")


@models_app.command("huggingface")
def search_huggingface(
    query: str = typer.Argument("mistral instruct awq", help="Search query"),
    limit: int = typer.Option(10, "--limit", "-n", help="Number of results"),
):
    """🤗 Search HuggingFace for models (vLLM, llama.cpp)"""

    console.print(f"\n[bold cyan]🔍 Searching HuggingFace for: {query}[/bold cyan]\n")

    with console.status("Searching HuggingFace..."):
        results = _catalog.search_models(query, limit=limit)

    if not results:
        console.print("[yellow]No models found[/yellow]\n")
        return

    if is_json_output():
        output_json(results)
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Model", style="cyan", no_wrap=False, max_width=55)
    table.add_column("Downloads", style="green", justify="right", width=10)
    table.add_column("Likes", style="yellow", justify="right", width=7)
    table.add_column("Gated", justify="center", width=7)
    table.add_column("Backends", style="blue", width=18)

    for m in results:
        table.add_row(
            m.get("id", "?"),
            _fmt_downloads(m.get("downloads")),
            str(m.get("likes", 0)),
            _gated_badge(m.get("gated", "Open")),
            _backends_str(m.get("backends")),
        )

    console.print(table)
    console.print(f"\n[dim]View on HuggingFace: https://huggingface.co/models?search={query.replace(' ', '%20')}[/dim]\n")


@models_app.command()
def refresh(
    backend: Optional[str] = typer.Option(None, "--backend", "-b", help="Refresh specific backend (vllm, llamacpp, ollama)"),
    use_llm: bool = typer.Option(False, "--llm", help="Use local LLM to analyze model quality and capabilities"),
):
    """Refresh model catalog from HuggingFace with auto-detected metadata.

    Fetches latest models, auto-detects tool_parser, reasoning_parser,
    quantization type, and VRAM estimates for each model.

    Use --llm to also have the coordinator LLM evaluate models for
    agentic quality (requires a running backend).
    """
    import asyncio

    backends = [backend] if backend else None

    with console.status("[bold cyan]Refreshing model catalog from HuggingFace..."):
        summary = asyncio.run(_catalog.refresh_catalog(
            backends=backends,
            use_llm=use_llm,
            gateway_url=get_gateway_url(),
        ))

    table = Table(title="Catalog Refresh Results", show_lines=True)
    table.add_column("Backend", style="cyan")
    table.add_column("Models", justify="right")
    table.add_column("Status", style="green")

    total = 0
    for be, info in summary.items():
        count = info.get("count", 0)
        status = info.get("status", "?")
        style = "green" if status == "refreshed" else "red"
        table.add_row(be, str(count), Text(status, style=style))
        total += count

    console.print(table)
    console.print(f"\n[bold]{total}[/bold] models cataloged across {len(summary)} backends")
    console.print(f"[dim]Cache: {_catalog.cache_file}[/dim]")

    if not use_llm:
        print_hint("Use --llm flag to also evaluate agentic quality via the coordinator")

    # Show a sample of enriched models
    if total > 0:
        console.print("\n[bold]Sample enriched models:[/bold]")
        sample_table = Table(show_lines=False, padding=(0, 1))
        sample_table.add_column("Model", style="cyan")
        sample_table.add_column("Params")
        sample_table.add_column("Quant")
        sample_table.add_column("Tool Parser", style="yellow")
        sample_table.add_column("Reasoning", style="magenta")
        sample_table.add_column("VRAM", justify="right")

        be = list(summary.keys())[0]
        cached = _catalog._read_cache(be, ignore_ttl=True) or []
        for m in cached[:8]:
            sample_table.add_row(
                m.get("id", "?")[:45],
                f"{m.get('params_b', '?')}B",
                m.get("quant") or "none",
                m.get("tool_parser", "?"),
                m.get("reasoning_parser") or "-",
                f"{m.get('vram_gb', '?')} GB" if m.get("vram_gb") else "?",
            )
        console.print(sample_table)


@models_app.command("switch")
def switch_model(
    model: str = typer.Argument(help="Model ID to switch to (e.g. google/gemma-4-E4B-it)"),
    backend: str = typer.Option("vllm", "--backend", "-b", help="Backend type"),
):
    """Switch the active model without rebuilding.

    Updates noomesh.yaml + .env, then restarts only the vLLM container.
    No Docker image rebuild needed.

    Example:
        noo models switch QuantTrio/Qwen3.5-9B-AWQ
        noo models switch google/gemma-4-E4B-it
    """
    import subprocess
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[3]
    yaml_path = project_root / "noomesh.yaml"
    env_path = project_root / ".env"

    # Detect tool parser and quantization
    tool_parser = _catalog.detect_tool_parser(model)
    reasoning_parser = _catalog.detect_reasoning_parser(model)
    quant = "awq" if "AWQ" in model.upper() else "gptq" if "GPTQ" in model.upper() else ""

    console.print(f"\n[bold cyan]Switching to:[/bold cyan] {model}")
    console.print(f"  Backend:          {backend}")
    console.print(f"  Tool parser:      {tool_parser}")
    console.print(f"  Reasoning parser: {reasoning_parser or 'none'}")
    console.print(f"  Quantization:     {quant or 'none (native)'}")

    # Update .env
    if env_path.exists():
        lines = env_path.read_text().splitlines()
        new_lines = []
        found_model = False
        for line in lines:
            if line.startswith("VLLM_MODEL=") or line.startswith("# VLLM_MODEL="):
                new_lines.append(f"VLLM_MODEL={model}")
                found_model = True
            else:
                new_lines.append(line)
        if not found_model:
            new_lines.append(f"VLLM_MODEL={model}")
        env_path.write_text("\n".join(new_lines) + "\n")
        console.print(f"  [green]Updated[/green] {env_path.name}")

    # Update noomesh.yaml
    if yaml_path.exists():
        import yaml
        with open(yaml_path) as f:
            config = yaml.safe_load(f) or {}

        backends = config.setdefault("cluster", {}).setdefault("backends", {})
        be_config = backends.setdefault(backend, {})
        be_config["model"] = model
        be_config["enabled"] = True
        if quant:
            be_config["quantization"] = quant
        elif "quantization" in be_config:
            del be_config["quantization"]

        # Update terminal default_model too
        terminal = config.setdefault("terminal", {})
        terminal["default_model"] = model

        with open(yaml_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=True)
        console.print(f"  [green]Updated[/green] {yaml_path.name}")

    # Restart the backend container (recreate, not rebuild) THROUGH the
    # dist-aware restart script, not raw compose (#43b): a bare single-file
    # `up` on a dist install renders `pull_policy: build` services without
    # the dist overlay and dies building unshipped Dockerfiles. restart.sh
    # owns the overlay/tag/profile logic; --force is its recreate path.
    console.print(f"\n[bold]Restarting {backend} container...[/bold]")
    compose_file = project_root / "docker-compose.cluster.yml"
    if compose_file.exists():
        cmd = ["bash", str(project_root / "scripts" / "noomesh-restart.sh"), "--force", backend]
        try:
            subprocess.run(cmd, cwd=str(project_root), check=True, capture_output=True)
            console.print("  [green]Container restarted[/green]")
        except subprocess.CalledProcessError as e:
            print_error(f"Failed to restart: {e.stderr.decode()[:200]}")
            return

    # Also restart gateway to pick up new YAML config
    try:
        subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "restart", "gateway"],
            cwd=str(project_root), check=True, capture_output=True
        )
        console.print("  [green]Gateway restarted[/green]")
    except Exception:
        print_warning("Could not restart gateway — restart manually: docker restart noo-gateway")

    console.print(f"\n[bold green]Switched to {model}[/bold green]")
    console.print("[dim]vLLM will take 2-5 min to load the model. Check: docker logs -f noo-vllm[/dim]\n")


if __name__ == "__main__":
    models_app()
