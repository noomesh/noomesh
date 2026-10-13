# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for PageIndex RAG system.

Provides document ingestion, RAG querying, and status inspection
via the gateway API.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from .ops_client import settle
from .cli_utils import (
    cli_auth_headers,
    cli_client_cert,
    cli_http_verify,
    console,
    get_gateway_url,
    is_json_output,
    output_json,
    print_error,
    print_success,
    run_async,
)

rag_app = typer.Typer(
    name="rag",
    help="[bold green]PageIndex RAG[/bold green] commands",
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


@rag_app.command("ingest")
def ingest(
    file_path: Path = typer.Argument(..., help="Path to document to ingest"),
    title: Optional[str] = typer.Option(None, "--title", "-t", help="Document title override"),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Ingest a document into PageIndex.

    Supports PDF, Markdown, HTML, and plain text files.
    """
    if not file_path.exists():
        print_error(f"File not found: {file_path}")
        raise typer.Exit(1)

    run_async(_ingest_async(file_path, title, gateway))


async def _ingest_async(file_path: Path, title: Optional[str], gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()

    with console.status(f"Ingesting {file_path.name}..."):
        try:
            async with httpx.AsyncClient(timeout=120.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
                with open(file_path, "rb") as f:
                    files = {"file": (file_path.name, f)}
                    resp = await c.post(f"{gw}/api/v1/docs/ingest", files=files)
                # A slow ingest is answered 202 with an operation handle: follow it to the end.
                resp = await settle(c, resp, gw)
                if resp.status_code == 202:
                    op = resp.json().get("op_id")
                    print_error(f"still ingesting after the wait; check `noo ops show {op}`")
                    return
                if resp.status_code >= 400:
                    print_error(str((resp.json() or {}).get("error", resp.status_code)))
                    return
                result = resp.json()
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            print_error(detail)
            return
        except Exception as e:
            print_error(str(e))
            return

    print_success(f"Ingested: doc_id={result['doc_id']}")


@rag_app.command("scan")
def scan(
    source: str = typer.Option(
        "all",
        "--source",
        "-s",
        help="Which ingest source to scan: folders, drives, or all",
    ),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Trigger an immediate ingest scan of watched_folders / watched_drives.

    Hits POST /api/v1/ingest/scan on the Rust gateway. Returns synchronously
    once each scan cycle has finished (download + ingest), so on a large
    batch this can take a while.
    """
    if source not in ("folders", "drives", "all"):
        print_error(f"Invalid --source '{source}' — use folders, drives, or all")
        raise typer.Exit(1)
    run_async(_scan_async(source, gateway))


async def _scan_async(source: str, gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()
    with console.status(f"Scanning {source}..."):
        try:
            async with httpx.AsyncClient(
                timeout=300.0,
                verify=cli_http_verify(),
                cert=cli_client_cert(),
            ) as c:
                resp = await c.post(
                    f"{gw}/api/v1/ingest/scan",
                    params={"source": source},
                )
                resp.raise_for_status()
                payload = resp.json()
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            print_error(detail)
            return
        except Exception as e:
            print_error(str(e))
            return

    if is_json_output():
        output_json(payload)
        return

    results = payload.get("results", [])
    if not results:
        print_error("No results returned")
        return

    for r in results:
        src = r.get("source", "?")
        skipped = r.get("skipped_reason")
        if skipped:
            console.print(f"[yellow]{src}[/yellow]: skipped — {skipped}")
            continue

        seen = r.get("seen", 0)
        new = r.get("new_count", 0)
        ingested = r.get("ingested", [])
        backfilled = r.get("backfilled", [])
        errors = r.get("errors", [])

        header = f"[bold cyan]{src}[/bold cyan]: {seen} seen, {new} new, {len(ingested)} ingested"
        if backfilled:
            header += f", [yellow]{len(backfilled)} metadata-backfilled[/yellow]"
        if errors:
            header += f", [red]{len(errors)} error(s)[/red]"
        console.print(header)

        if ingested:
            t = Table(show_header=True, header_style="bold")
            t.add_column("File")
            t.add_column("doc_id", style="dim")
            for entry in ingested:
                if isinstance(entry, list) and len(entry) >= 2:
                    name, doc_id = entry[0], entry[1]
                else:
                    name, doc_id = str(entry), ""
                t.add_row(name, doc_id[:16] if doc_id else "")
            console.print(t)

        for err in errors:
            console.print(f"  [red]✗[/red] {err}")


@rag_app.command("query")
def query(
    question: str = typer.Argument(..., help="Question to ask"),
    strategy: str = typer.Option("hybrid", "--strategy", "-s", help="Strategy: hybrid, lookup, graph_first"),
    persona_id: Optional[str] = typer.Option(None, "--persona", "-p", help="Persona ID for biased retrieval"),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Run a RAG query and display results."""
    run_async(_query_async(question, strategy, persona_id, gateway))


async def _query_async(
    question: str, strategy: str, persona_id: Optional[str], gateway: Optional[str],
) -> None:
    import httpx

    gw = gateway or _gw()

    body: dict = {"question": question, "strategy": strategy}
    if persona_id:
        body["persona_id"] = persona_id

    with console.status("Querying..."):
        try:
            async with httpx.AsyncClient(timeout=60.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
                resp = await c.post(f"{gw}/api/v1/rag/query", json=body)
                resp.raise_for_status()
                result = resp.json()
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            print_error(detail)
            return
        except Exception as e:
            print_error(str(e))
            return

    if is_json_output():
        output_json(result)
        return

    # Display strategy and intent
    meta_parts = [
        f"Strategy: {result['strategy_used']}",
        f"Intent: {result['intent']}",
        f"Evidence: {result['evidence_count']} pages",
    ]
    if result.get("persona_id"):
        meta_parts.append(f"Persona: {result['persona_id'][:12]}")
    console.print(f"[dim]{' | '.join(meta_parts)}[/dim]")

    # Display answer if present
    if result.get("answer"):
        console.print(Panel(result["answer"], title="Answer", border_style="green"))

    # Display verification result
    verification = result.get("verification")
    if verification:
        status = verification["status"]
        conf = verification["confidence"]
        style = {"approved": "green", "partial": "yellow", "rejected": "red"}.get(status, "dim")
        console.print(
            f"[{style}]Verification: {status} "
            f"(confidence: {conf:.1%}, "
            f"supported: {len(verification['supported_claims'])}, "
            f"unsupported: {len(verification['unsupported_claims'])})[/{style}]"
        )
        if verification.get("required_retrieval"):
            console.print(
                f"[dim]Retrieval hints: {', '.join(verification['required_retrieval'][:5])}[/dim]"
            )

    # Display hypotheses
    hypotheses = result.get("hypotheses", [])
    if hypotheses:
        table = Table(title="Hypotheses", show_lines=True)
        table.add_column("Confidence", style="green", justify="right", width=10)
        table.add_column("Path", style="cyan", max_width=30)
        table.add_column("Description", max_width=60)

        for h in hypotheses[:5]:
            table.add_row(
                f"{h['confidence']:.0%}",
                " > ".join(h["path"][:4]),
                h["description"][:80],
            )
        console.print(table)

    # Display citations
    citations = result.get("citations", [])
    if citations:
        table = Table(title="Citations", show_lines=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Document", style="cyan")
        table.add_column("Page", style="green", justify="right")
        table.add_column("Confidence", style="yellow", justify="right", width=10)
        table.add_column("Excerpt", max_width=50)

        for i, c in enumerate(citations, 1):
            conf = c.get("confidence", 0)
            excerpt = c.get("excerpt", "")
            table.add_row(
                str(i),
                c.get("title", ""),
                str(c.get("page_no", "")),
                f"{conf:.0%}" if conf else "",
                (excerpt[:100] + "...") if len(excerpt) > 100 else excerpt,
            )
        console.print(table)
    else:
        console.print("[yellow]No citations found.[/yellow]")


@rag_app.command("status")
def status(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Show PageIndex RAG system status."""
    run_async(_status_async(gateway))


async def _status_async(gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()

    with console.status("Fetching status..."):
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
                resp = await c.get(f"{gw}/api/v1/rag/status")
                resp.raise_for_status()
                result = resp.json()
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            print_error(detail)
            return
        except Exception as e:
            print_error(str(e))
            return

    if is_json_output():
        output_json(result)
        return

    if not result.get("started"):
        print_error("PageIndex RAG is not running")
        return

    table = Table(title="PageIndex RAG Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green", justify="right")

    table.add_row("Documents", str(result.get("doc_count", 0)))
    table.add_row("Pages", str(result.get("page_count", 0)))
    table.add_row("Embedded Pages", str(result.get("embedded_pages", 0)))
    table.add_row("Unembedded Pages", str(result.get("unembedded_pages", 0)))
    table.add_row("Chunks", str(result.get("chunk_count", 0)))
    table.add_row("Embedded Chunks", str(result.get("embedded_chunks", 0)))
    table.add_row("Entities", str(result.get("entity_count", 0)))
    table.add_row("Edges", str(result.get("edge_count", 0)))

    embedder = result.get("embedder_state")
    if embedder:
        table.add_row("Embedder State", embedder.get("state", "unknown"))

    console.print(table)


@rag_app.command("deduplicate")
def deduplicate(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Remove duplicate pages from PageIndex.

    Identifies pages that share the same (doc_id, page_no) and keeps
    only the most recent copy.  Run this once to clean up bloat from
    prior ingestion without deduplication.
    """
    run_async(_deduplicate_async(gateway))


async def _deduplicate_async(gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()

    with console.status("Deduplicating pages..."):
        try:
            async with httpx.AsyncClient(timeout=60.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
                resp = await c.post(f"{gw}/api/v1/rag/deduplicate")
                resp.raise_for_status()
                result = resp.json()
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            print_error(detail)
            return
        except Exception as e:
            print_error(str(e))
            return

    removed = result.get("removed", 0)
    if removed > 0:
        print_success(f"Removed {removed} duplicate pages")
    else:
        console.print("[green]No duplicates found — database is clean.[/green]")


@rag_app.command("docs")
def docs(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """List ingested documents."""
    run_async(_docs_async(gateway))


async def _docs_async(gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()

    with console.status("Fetching documents..."):
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
                resp = await c.get(f"{gw}/api/v1/docs")
                resp.raise_for_status()
                result = resp.json()
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            print_error(detail)
            return
        except Exception as e:
            print_error(str(e))
            return

    if is_json_output():
        output_json(result)
        return

    if not result:
        console.print("[yellow]No documents ingested yet.[/yellow]")
        return

    table = Table(title="Ingested Documents")
    table.add_column("Doc ID", style="dim", max_width=12)
    table.add_column("Title", style="cyan")
    table.add_column("Source", style="dim", max_width=40)
    table.add_column("Created", style="green")

    for doc in result:
        doc_id = doc.get("doc_id", "")
        table.add_row(
            doc_id[:12],
            doc.get("title", ""),
            doc.get("source_uri", "")[:40],
            doc.get("created_at", "")[:19],
        )
    console.print(table)
