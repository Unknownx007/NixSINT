#!/usr/bin/env python3
"""
main.py - NixSINT entry point
An OSINT tool that checks a username against a live, merged database of
1000+ site definitions (Sherlock Project + WhatsMyName) using each
site's real detection logic - not a blind 404 guess.

Author: DEDSEC
Usage:  python3 main.py [--refresh] [--nsfw]
"""

import asyncio
import sys
import argparse

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from banner import print_banner, random_quote
from sources import load_sites
from core import scan_username, SiteResult

console = Console()


def get_username() -> str:
    console.print("[bold red][?][/bold red] Enter target username: ", end="")
    username = input().strip()
    while not username:
        console.print("[bold red][!] Username cannot be empty.[/bold red]")
        console.print("[bold red][?][/bold red] Enter target username: ", end="")
        username = input().strip()
    return username


async def run_scan(username: str, sites) -> list[SiteResult]:
    total = len(sites)
    found: list[SiteResult] = []

    with Progress(
        TextColumn("[bold red]NixSINT[/bold red]"),
        BarColumn(bar_width=40, complete_style="red", finished_style="red"),
        TextColumn("[white]{task.completed}/{task.total}[/white]"),
        TextColumn("[green]{task.fields[status]}[/green]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scan", total=total, status="starting...")

        def on_result(result: SiteResult) -> None:
            if result.skipped:
                status = f"[dim]skipped: {result.name}[/dim]"
            elif result.exists is True and result.uncertain:
                found.append(result)
                status = f"[yellow]blocked page, unverified: {result.name}[/yellow]"
            elif result.exists is True:
                found.append(result)
                status = f"[bold green]FOUND[/bold green] {result.name}"
            elif result.exists is False:
                status = f"[dim]not found: {result.name}[/dim]"
            else:
                status = f"[yellow]error/skip: {result.name}[/yellow]"
            progress.update(task, advance=1, status=status)

        results = await scan_username(username, sites, on_result=on_result)

    return results


def print_results(username: str, results: list[SiteResult]) -> None:
    confident = [r for r in results if r.exists is True and not r.uncertain]
    unverified = [r for r in results if r.exists is True and r.uncertain]
    not_found = [r for r in results if r.exists is False]
    skipped = [r for r in results if r.skipped]
    errors = [r for r in results if r.exists is None and not r.skipped]

    console.print()
    console.rule(f"[bold red]NixSINT results for '{username}'[/bold red]")

    def render_table(rows, title):
        table = Table(title=title, show_header=True, header_style="bold red")
        table.add_column("Platform", style="white")
        table.add_column("URL", style="cyan")
        table.add_column("Src", style="dim", width=4)
        for r in sorted(rows, key=lambda r: r.name.lower()):
            tag = "18+" if r.nsfw else ""
            table.add_row(f"{r.name} {tag}".strip(), r.url, r.source)
        console.print(table)

    if confident:
        render_table(confident, "Confident hits")
    else:
        console.print("[yellow]No confident profile matches found.[/yellow]")

    if unverified:
        console.print()
        console.print(
            "[yellow]The sites below returned a bot-block / CAPTCHA / challenge page "
            "instead of the real profile page, so NixSINT could not confirm the "
            "result. Open these manually to check - do NOT treat as confirmed:[/yellow]"
        )
        render_table(unverified, "Unverified (blocked response)")

    console.print()
    console.print(
        f"[bold]Summary:[/bold] "
        f"[green]{len(confident)} confident[/green]  "
        f"[yellow]{len(unverified)} unverified/blocked[/yellow]  "
        f"[dim]{len(not_found)} not found[/dim]  "
        f"[yellow]{len(errors)} errors/timeouts[/yellow]  "
        f"[dim]{len(skipped)} skipped (invalid username format for that site)[/dim]  "
        f"out of {len(results)} sites checked."
    )
    console.print(
        "[dim]Note: sites tagged 18+ are adult-content platforms. Even 'confident' hits "
        "are worth a quick manual click for anything that matters - no scripted checker "
        "is 100% against sites that actively fight bots.[/dim]"
    )


def parse_args():
    parser = argparse.ArgumentParser(description="NixSINT - OSINT username scanner by DEDSEC")
    parser.add_argument("--refresh", action="store_true", help="force re-download of the site database")
    parser.add_argument("username", nargs="?", help="username to scan (skips the prompt)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print_banner()

    console.print("[bold red][*][/bold red] Loading site database (Sherlock + WhatsMyName)...")
    sites, status_msg = asyncio.run(load_sites(force_refresh=args.refresh))
    console.print(f"[dim]{status_msg}[/dim]\n")

    if not sites:
        console.print("[bold red][!] No site database available. Check your internet connection and try again.[/bold red]")
        sys.exit(1)

    username = args.username or get_username()
    console.print(f"\n[bold red][*][/bold red] Scanning for username: [bold white]{username}[/bold white] "
                  f"[dim]across {len(sites)} sites[/dim]\n")

    try:
        results = asyncio.run(run_scan(username, sites))
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan interrupted by user.[/bold red]")
        sys.exit(1)

    print_results(username, results)

    console.print()
    console.rule("[bold red]DEDSEC[/bold red]")
    console.print(f"[italic]{random_quote()}[/italic]\n")


if __name__ == "__main__":
    main()
