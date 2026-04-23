"""Bordair CLI entry point."""

from __future__ import annotations
import asyncio
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .loader import (
    iter_attacks,
    iter_benign,
    dataset_stats,
    ensure_cached,
    VERSION_DIRS,
    ALL_CATEGORIES,
)
from .evaluator import EvalRequest, EvalResult, evaluate, save_results

console = Console()


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="bordair")
@click.pass_context
def main(ctx):
    """Bordair - test any LLM against 503K+ prompt injection samples.

    Quickstart:

      bordair stats
      bordair eval --url https://api.openai.com/v1/chat/completions --key $OPENAI_API_KEY --model gpt-4o-mini --limit 50
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command("stats")
def stats_cmd():
    """Show dataset stats (downloads on first run)."""
    with console.status("[bold cyan]Loading dataset..."):
        s = dataset_stats()

    table = Table(title="Bordair Multimodal Dataset", show_header=True, header_style="bold cyan")
    table.add_column("Version", style="cyan")
    table.add_column("Attack Payloads", justify="right", style="magenta")
    for v, c in sorted(s["by_version"].items()):
        table.add_row(v, f"{c:,}")
    table.add_row("", "")
    table.add_row("[bold]Total Attacks", f"[bold]{s['total_attacks']:,}")
    table.add_row("[bold]Total Benign", f"[bold]{s['total_benign']:,}")
    table.add_row("[bold]Total Samples", f"[bold]{s['total_attacks'] + s['total_benign']:,}")
    console.print(table)


@main.group("list")
def list_cmd():
    """List available categories, versions, or modalities."""


@list_cmd.command("categories")
def list_categories():
    """List all attack categories."""
    for c in ALL_CATEGORIES:
        click.echo(c)


@list_cmd.command("versions")
def list_versions():
    """List dataset versions."""
    for v in VERSION_DIRS:
        click.echo(v)


@list_cmd.command("modalities")
def list_modalities():
    """List supported modality filters."""
    for m in ["text", "text+image", "text+document", "text+audio",
             "image+document", "triple", "quad", "text+video"]:
        click.echo(m)


@main.command("download")
@click.option("--version", default="all", help="Dataset version to download (default: all)")
def download_cmd(version):
    """Pre-download the dataset to the local cache."""
    with console.status(f"[bold cyan]Downloading dataset ({version})..."):
        cache = ensure_cached(version)
    console.print(f"[green]Dataset cached at:[/green] {cache}")


@main.command("eval")
@click.option("--url", required=True, help="API endpoint URL (e.g. https://api.openai.com/v1/chat/completions)")
@click.option("--key", envvar="BORDAIR_API_KEY", help="API key (or set BORDAIR_API_KEY env var)")
@click.option("--model", required=True, help="Model name (e.g. gpt-4o-mini, claude-sonnet-4-5)")
@click.option("--provider", type=click.Choice(["openai", "anthropic"]), default="openai",
              help="API format: openai (default, works for most providers) or anthropic")
@click.option("--modality", default="text", help="Modality filter: text, text+image, text+document, text+audio, etc.")
@click.option("--category", default=None, help="Filter to specific attack category (see `bordair list categories`)")
@click.option("--version", default=None, help="Filter to specific dataset version (v1, v2, v3, v4, v5)")
@click.option("--limit", default=100, type=int, help="Maximum number of payloads to test (default: 100)")
@click.option("--parallel", default=10, type=int, help="Concurrent requests (default: 10)")
@click.option("--timeout", default=60.0, type=float, help="Request timeout in seconds (default: 60)")
@click.option("--max-tokens", default=512, type=int, help="Max response tokens per request (default: 512)")
@click.option("--system-prompt", default="", help="Optional system prompt (tests target-app injection)")
@click.option("--output", default=None, help="Write full results to this JSON file")
@click.option("--include-benign", is_flag=True, help="Also run benign samples to measure false-positive rate")
def eval_cmd(url, key, model, provider, modality, category, version, limit,
             parallel, timeout, max_tokens, system_prompt, output, include_benign):
    """Evaluate a target LLM against the Bordair dataset.

    Example:

      bordair eval --url https://api.openai.com/v1/chat/completions \\
                   --key $OPENAI_API_KEY \\
                   --model gpt-4o-mini \\
                   --modality text \\
                   --limit 100 --parallel 10
    """
    if not key:
        console.print("[red]Error:[/red] --key not provided and BORDAIR_API_KEY not set")
        sys.exit(1)

    # Build request list
    with console.status("[bold cyan]Loading dataset..."):
        attacks = list(iter_attacks(
            version=version, category=category, modality=modality, limit=limit
        ))
    if not attacks:
        console.print("[yellow]No payloads matched the filters.[/yellow]")
        return

    requests = [
        EvalRequest(
            payload_id=a.get("id", "unknown"),
            category=a.get("category", "unknown"),
            text=a.get("text", ""),
            version=a.get("version", ""),
            modalities=a.get("modalities", []),
            extra={k: v for k, v in a.items() if k not in ("id", "category", "text")},
        )
        for a in attacks if a.get("text")
    ]

    console.print(
        f"[bold]Target:[/bold] {model} @ {url} ({provider})\n"
        f"[bold]Payloads:[/bold] {len(requests)} | [bold]Parallel:[/bold] {parallel}\n"
    )

    # Run eval
    results = _run_eval(requests, url, key, model, provider, system_prompt,
                       parallel, timeout, max_tokens, label="Attacks")

    # Optionally run benign
    benign_results = []
    if include_benign:
        benign = list(iter_benign(limit=limit))
        benign_reqs = [
            EvalRequest(
                payload_id=b.get("id", "unknown"),
                category="benign",
                text=b.get("text", ""),
                version=b.get("version", ""),
                modalities=b.get("modalities", []),
            )
            for b in benign if b.get("text")
        ]
        console.print(f"\n[bold]Benign samples:[/bold] {len(benign_reqs)}")
        benign_results = _run_eval(benign_reqs, url, key, model, provider, system_prompt,
                                   parallel, timeout, max_tokens, label="Benign")

    # Report
    _print_report(results, benign_results)

    if output:
        save_results(results + benign_results, output)
        console.print(f"\n[green]Full results written to:[/green] {output}")


def _run_eval(requests, url, key, model, provider, system_prompt,
              parallel, timeout, max_tokens, label):
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"[cyan]{label}...", total=len(requests))

        def on_done(r):
            progress.update(task, advance=1)
            results.append(r)

        async def runner():
            return await evaluate(
                requests, url, key, model, provider, system_prompt,
                parallel, timeout, max_tokens, on_done,
            )

        asyncio.run(runner())

    return results


def _print_report(attack_results: list[EvalResult], benign_results: list[EvalResult]):
    console.print()
    # ASR by category
    by_cat = defaultdict(lambda: {"total": 0, "success": 0, "errors": 0})
    for r in attack_results:
        by_cat[r.category]["total"] += 1
        if r.error:
            by_cat[r.category]["errors"] += 1
        elif r.attack_succeeded:
            by_cat[r.category]["success"] += 1

    table = Table(title="Attack Success Rate (ASR) by Category",
                  show_header=True, header_style="bold cyan")
    table.add_column("Category", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Succeeded", justify="right", style="red")
    table.add_column("Errors", justify="right", style="yellow")
    table.add_column("ASR", justify="right", style="bold magenta")

    for cat in sorted(by_cat.keys()):
        row = by_cat[cat]
        valid = row["total"] - row["errors"]
        asr = (row["success"] / valid * 100) if valid > 0 else 0
        table.add_row(cat, str(row["total"]), str(row["success"]),
                     str(row["errors"]), f"{asr:.1f}%")

    total = sum(r["total"] for r in by_cat.values())
    total_succ = sum(r["success"] for r in by_cat.values())
    total_err = sum(r["errors"] for r in by_cat.values())
    total_valid = total - total_err
    overall_asr = (total_succ / total_valid * 100) if total_valid > 0 else 0
    table.add_row("", "", "", "", "")
    table.add_row("[bold]OVERALL", f"[bold]{total}", f"[bold]{total_succ}",
                 f"[bold]{total_err}", f"[bold]{overall_asr:.1f}%")
    console.print(table)

    # Benign false-positive rate
    if benign_results:
        fp = sum(1 for r in benign_results if r.attack_succeeded and not r.error)
        total_b = sum(1 for r in benign_results if not r.error)
        fpr = (fp / total_b * 100) if total_b > 0 else 0
        console.print(f"\n[bold]Benign false-positive rate:[/bold] "
                     f"[yellow]{fpr:.1f}%[/yellow] ({fp}/{total_b} benign flagged as attacks)")


@main.command("compare")
@click.argument("file_a", type=click.Path(exists=True))
@click.argument("file_b", type=click.Path(exists=True))
def compare_cmd(file_a, file_b):
    """Compare two eval result JSON files side-by-side."""
    with open(file_a) as f:
        a = json.load(f)
    with open(file_b) as f:
        b = json.load(f)

    def summarize(results):
        total = len(results)
        succ = sum(1 for r in results if r.get("attack_succeeded"))
        errors = sum(1 for r in results if r.get("error"))
        valid = total - errors
        asr = (succ / valid * 100) if valid > 0 else 0
        return {"total": total, "succ": succ, "errors": errors, "asr": asr}

    sa = summarize(a)
    sb = summarize(b)
    table = Table(title="Comparison", show_header=True, header_style="bold cyan")
    table.add_column("Metric")
    table.add_column(file_a, justify="right")
    table.add_column(file_b, justify="right")
    table.add_column("Delta", justify="right")
    for k in ["total", "succ", "errors", "asr"]:
        va, vb = sa[k], sb[k]
        delta = vb - va
        if k == "asr":
            table.add_row("ASR %", f"{va:.1f}", f"{vb:.1f}", f"{delta:+.1f}")
        else:
            table.add_row(k, str(va), str(vb), f"{delta:+d}")
    console.print(table)


if __name__ == "__main__":
    main()
