# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI sub-app for recall memory (System 1 compressed recall)."""

from __future__ import annotations


import typer

from .cli_utils import cli_auth_headers, cli_client_cert, cli_http_verify, console, get_gateway_url, is_json_output, output_json, print_error, print_info, run_async

recall_app = typer.Typer(
    help="[bold]Episodic recall[/] (System 1 memory)",
    rich_markup_mode="rich",
)

_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", timeout: float = 10.0, **kw):
    import httpx

    async with httpx.AsyncClient(timeout=timeout, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        fn = {"GET": c.get, "POST": c.post}[method]
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@recall_app.command()
def status() -> None:
    """Show recall memory system status."""
    run_async(_status())


async def _status() -> None:
    try:
        data = await _fetch("/api/v1/recall/status")
    except Exception as e:
        print_error(f"Failed to fetch status: {e}")
        return

    if is_json_output():
        output_json(data)
        return

    from rich.table import Table

    table = Table(title="Recall Memory Status", show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Started", str(data.get("started", False)))
    table.add_row("Enabled", str(data.get("enabled", False)))
    table.add_row("Storage", data.get("storage_dir", ""))
    table.add_row("Videos", str(data.get("video_count", 0)))
    table.add_row("Records", str(data.get("total_records", 0)))
    table.add_row("Size (MB)", str(data.get("total_size_mb", 0)))
    table.add_row("Embedding Dim", str(data.get("embedding_dim", 768)))
    table.add_row("Promotion Threshold", str(data.get("promotion_threshold", 0.6)))

    lc = data.get("lifecycle", {})
    if lc:
        table.add_row("", "")
        table.add_row("Live records", str(lc.get("live_records", 0)))
        table.add_row("Tombstoned", str(lc.get("tombstoned_records", 0)))
        table.add_row("Stale candidates", str(lc.get("stale_candidates", 0)))
        table.add_row("Elevation candidates", str(lc.get("elevation_candidates", 0)))
        table.add_row("Needs compaction", str(lc.get("needs_compaction", 0)))

    console.print(table)


@recall_app.command()
def search(
    query: str = typer.Argument(..., help="Search query."),
    top_k: int = typer.Option(5, "--top-k", "-k", help="Max results."),
) -> None:
    """Search recall memory by semantic similarity."""
    run_async(_search(query, top_k))


async def _search(query: str, top_k: int) -> None:
    try:
        data = await _fetch(
            "/api/v1/recall/search",
            method="POST",
            timeout=30.0,
            json={"query": query, "top_k": top_k},
        )
    except Exception as e:
        print_error(f"Search failed: {e}")
        return

    results = data.get("results", [])
    if is_json_output():
        output_json(data)
        return
    if not results:
        print_info("No results found.")
        return

    from rich.table import Table

    table = Table(title=f"Recall Memory Search: '{query}'")
    table.add_column("#", style="dim", width=3)
    table.add_column("Score", style="green", width=6)
    table.add_column("Prom.", style="yellow", width=6)
    table.add_column("Hits", style="cyan", width=5)
    table.add_column("Type", style="cyan", width=12)
    table.add_column("Preview", style="white")
    table.add_column("Video", style="dim", width=18)

    for i, r in enumerate(results, 1):
        table.add_row(
            str(i),
            f"{r.get('score', 0):.3f}",
            f"{r.get('prominence_score', 0):.3f}",
            str(r.get("access_count", 0)),
            r.get("record_type", "?"),
            r.get("text_preview", "")[:70],
            r.get("video_path", "").split("/")[-1] if r.get("video_path") else "",
        )

    console.print(table)


@recall_app.command()
def archive() -> None:
    """Trigger manual conversation archival to recall memory."""
    run_async(_archive())


async def _archive() -> None:
    with console.status("Archiving conversations..."):
        try:
            data = await _fetch("/api/v1/recall/archive", method="POST", timeout=120.0)
        except Exception as e:
            print_error(f"Archive failed: {e}")
            return

    archived = data.get("archived", 0)
    if archived == 0:
        print_info(data.get("message", "No conversations to archive."))
    else:
        print_info(
            f"Archived {archived} conversations to {data.get('video_path', '?')}"
        )


@recall_app.command()
def lifecycle(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview what would happen without mutating."),
) -> None:
    """Run lifecycle cycle: prune stale, elevate mature, compact."""
    if dry_run:
        run_async(_lifecycle_preview())
    else:
        run_async(_lifecycle())


async def _lifecycle() -> None:
    with console.status("Running lifecycle cycle..."):
        try:
            data = await _fetch("/api/v1/recall/lifecycle", method="POST", timeout=120.0)
        except Exception as e:
            print_error(f"Lifecycle failed: {e}")
            return

    from rich.table import Table

    table = Table(title="Lifecycle Results", show_header=False)
    table.add_column("Phase", style="cyan")
    table.add_column("Count", style="green")

    table.add_row("Prominence updated", str(data.get("prominence_updated", 0)))
    table.add_row("Pruned", str(data.get("pruned", 0)))
    table.add_row("Elevated", str(data.get("elevated", 0)))
    table.add_row("Compacted", str(data.get("compacted", 0)))

    errors = data.get("errors", [])
    if errors:
        table.add_row("Errors", ", ".join(errors))

    console.print(table)


async def _lifecycle_preview() -> None:
    try:
        data = await _fetch("/api/v1/recall/lifecycle-preview")
    except Exception as e:
        print_error(f"Lifecycle preview failed: {e}")
        return

    from rich.table import Table

    prune_list = data.get("would_prune", [])
    elevate_list = data.get("would_elevate", [])
    compact_list = data.get("would_compact", [])

    if not prune_list and not elevate_list and not compact_list:
        print_info("Nothing to do — all records are healthy.")
        return

    # Prune candidates
    if prune_list:
        table = Table(title=f"Would PRUNE ({len(prune_list)} records)")
        table.add_column("#", style="dim", width=3)
        table.add_column("Prom.", style="red", width=6)
        table.add_column("Hits", style="dim", width=5)
        table.add_column("Created", style="dim", width=12)
        table.add_column("Type", style="cyan", width=14)
        table.add_column("Preview", style="white")

        for i, r in enumerate(prune_list[:20], 1):
            table.add_row(
                str(i),
                f"{r.get('prominence', 0):.3f}",
                str(r.get("access_count", 0)),
                r.get("created_at", "")[:10],
                r.get("record_type", "?"),
                r.get("text_preview", "")[:50],
            )

        console.print(table)

    # Elevate candidates
    if elevate_list:
        table = Table(title=f"Would ELEVATE to System 2 ({len(elevate_list)} records)")
        table.add_column("#", style="dim", width=3)
        table.add_column("Prom.", style="yellow", width=6)
        table.add_column("Hits", style="cyan", width=5)
        table.add_column("Last Access", style="dim", width=12)
        table.add_column("Type", style="cyan", width=14)
        table.add_column("Preview", style="white")

        for i, r in enumerate(elevate_list[:20], 1):
            last_acc = r.get("last_accessed_at", "")
            table.add_row(
                str(i),
                f"{r.get('prominence', 0):.3f}",
                str(r.get("access_count", 0)),
                last_acc[:10] if last_acc else "never",
                r.get("record_type", "?"),
                r.get("text_preview", "")[:50],
            )

        console.print(table)

    # Compact candidates
    if compact_list:
        console.print(f"\n[bold]Would COMPACT[/bold] {len(compact_list)} video(s):")
        for v in compact_list:
            console.print(f"  - {v}")


@recall_app.command()
def stats() -> None:
    """Show lifecycle health metrics."""
    run_async(_stats())


async def _stats() -> None:
    try:
        data = await _fetch("/api/v1/recall/lifecycle-stats")
    except Exception as e:
        print_error(f"Failed to fetch stats: {e}")
        return

    if is_json_output():
        output_json(data)
        return

    from rich.table import Table

    table = Table(title="Lifecycle Stats", show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Live records", str(data.get("live_records", 0)))
    table.add_row("Tombstoned", str(data.get("tombstoned_records", 0)))
    table.add_row("Stale candidates", str(data.get("stale_candidates", 0)))
    table.add_row("Elevation candidates", str(data.get("elevation_candidates", 0)))
    table.add_row("Needs compaction", str(data.get("needs_compaction", 0)))

    prom = data.get("prominence", {})
    if prom:
        table.add_row("", "")
        table.add_row("[bold]Prominence[/]", "")
        table.add_row("  Min / Median / Max",
                       f"{prom.get('min', 0):.3f} / {prom.get('median', 0):.3f} / {prom.get('max', 0):.3f}")
        table.add_row("  High (>=0.4)", str(prom.get("high_count", 0)))
        table.add_row("  Low (<0.05)", str(prom.get("low_count", 0)))

    cfg = data.get("config", {})
    if cfg:
        table.add_row("", "")
        table.add_row("Prune after days", str(cfg.get("prune_after_days", "?")))
        table.add_row("Prune floor", str(cfg.get("prune_prominence_floor", "?")))
        table.add_row("Elevate ceiling", str(cfg.get("elevate_prominence_ceiling", "?")))
        table.add_row("Elevate min access", str(cfg.get("elevate_min_access", "?")))
        table.add_row("Compact ratio", str(cfg.get("compact_tombstone_ratio", "?")))
        table.add_row("Lifecycle interval (h)", str(cfg.get("lifecycle_interval_hours", "?")))

    console.print(table)


@recall_app.command()
def prominent(
    top_k: int = typer.Option(20, "--top-k", "-k", help="Max records to show."),
) -> None:
    """Show the most prominent records (strongest mental models)."""
    run_async(_prominent(top_k))


async def _prominent(top_k: int) -> None:
    try:
        data = await _fetch("/api/v1/recall/prominent", params={"top_k": top_k})
    except Exception as e:
        print_error(f"Failed to fetch prominent records: {e}")
        return

    records = data.get("records", [])
    if is_json_output():
        output_json(data)
        return
    if not records:
        print_info("No prominent records found.")
        return

    from rich.table import Table

    table = Table(title="Prominent Records (Mental Models)")
    table.add_column("#", style="dim", width=3)
    table.add_column("Prom.", style="yellow", width=6)
    table.add_column("Hits", style="cyan", width=5)
    table.add_column("Avg", style="green", width=5)
    table.add_column("Last Access", style="dim", width=12)
    table.add_column("Type", style="cyan", width=12)
    table.add_column("Preview", style="white")

    for i, r in enumerate(records, 1):
        last_acc = r.get("last_accessed_at", "")
        last_acc_short = last_acc[:10] if last_acc else "never"
        table.add_row(
            str(i),
            f"{r.get('prominence_score', 0):.3f}",
            str(r.get("access_count", 0)),
            f"{r.get('avg_relevance', 0):.2f}",
            last_acc_short,
            r.get("record_type", "?"),
            r.get("text_preview", "")[:60],
        )

    console.print(table)


@recall_app.command()
def refresh() -> None:
    """Full refresh: archive new conversations, then run lifecycle."""
    run_async(_refresh())


async def _refresh() -> None:
    with console.status("Running full refresh..."):
        try:
            data = await _fetch("/api/v1/recall/refresh", method="POST", timeout=180.0)
        except Exception as e:
            print_error(f"Refresh failed: {e}")
            return

    archive_data = data.get("archive", {})
    lifecycle_data = data.get("lifecycle", {})

    print_info(
        f"Archive: {archive_data.get('archived', 0)} conversations  |  "
        f"Lifecycle: pruned={lifecycle_data.get('pruned', 0)}, "
        f"elevated={lifecycle_data.get('elevated', 0)}, "
        f"compacted={lifecycle_data.get('compacted', 0)}"
    )


@recall_app.command()
def videos() -> None:
    """List video files with sizes and record counts."""
    run_async(_videos())


async def _videos() -> None:
    try:
        data = await _fetch("/api/v1/recall/videos")
    except Exception as e:
        print_error(f"Failed to list videos: {e}")
        return

    vids = data.get("videos", [])
    if is_json_output():
        output_json(data)
        return
    if not vids:
        print_info("No video files found.")
        return

    from rich.table import Table

    table = Table(title="Recall Memory Files")
    table.add_column("File", style="cyan")
    table.add_column("Records", style="green", justify="right")
    table.add_column("Size", style="white", justify="right")

    for v in vids:
        size_mb = v.get("size_bytes", 0) / (1024 * 1024)
        table.add_row(
            v.get("path", "?"),
            str(v.get("records", 0)),
            f"{size_mb:.1f} MB",
        )

    console.print(table)


@recall_app.command()
def test() -> None:
    """Self-test for the v2 path (Postgres+FAISS).

    The v1 MP4+QR self-test was removed in trellion v0.0.2 — those code paths no longer exist. This stub reports the
    new architecture and points to the v2 alternatives.
    """
    print_info(
        "Recall memory is now Postgres + FAISS (no MP4, no QR).\n"
        "  - For per-persona FAISS health: noo recall status\n"
        "  - For prominence lifecycle:    noo recall lifecycle\n"
        "  - For end-to-end smoke:        run a traversal + check trellion_traversal_records"
    )
