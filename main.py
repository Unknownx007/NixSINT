#!/usr/bin/env python3
"""
main.py - NixSINT entry point

Author: DEDSEC
Usage:  python3 main.py [username] [--list-sites]
"""

import asyncio
import sys
import argparse

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from banner import print_banner, random_quote, PRIMARY, ACCENT, WARN
from sites import SITE_CHECKS, LOW_CONFIDENCE_CHECKS, EXCLUDED_SITES
from core import scan_username, SiteResult

console = Console()


def get_username() -> str:
    console.print(f"[bold {PRIMARY}][?][/bold {PRIMARY}] Enter target username: ", end="")
    username = input().strip()
    while not username:
        console.print(f"[bold {PRIMARY}][!] Username cannot be empty.[/bold {PRIMARY}]")
        console.print(f"[bold {PRIMARY}][?][/bold {PRIMARY}] Enter target username: ", end="")
        username = input().strip()
    return username


async def run_scan(username: str) -> list[SiteResult]:
    total = len(SITE_CHECKS) + len(LOW_CONFIDENCE_CHECKS)
    found: list[SiteResult] = []

    with Progress(
        TextColumn(f"[bold {PRIMARY}]NixSINT[/bold {PRIMARY}]"),
        BarColumn(bar_width=40, complete_style=PRIMARY, finished_style=PRIMARY),
        TextColumn("[white]{task.completed}/{task.total}[/white]"),
        TextColumn(f"[{ACCENT}]{{task.fields[status]}}[/{ACCENT}]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scan", total=total, status="starting...")

        def on_result(result: SiteResult) -> None:
            if result.exists is True:
                found.append(result)
                tag = "low-conf" if result.confidence == "low" else "FOUND"
                status = f"[bold {PRIMARY}]{tag}[/bold {PRIMARY}] {result.name}"
            elif result.exists is False:
                status = f"[dim]not found: {result.name}[/dim]"
            else:
                status = f"[{WARN}]unknown: {result.name}[/{WARN}]"
            progress.update(task, advance=1, status=status)

        results = await scan_username(username, on_result=on_result)

    return results


def print_results(username: str, results: list[SiteResult]) -> None:
    confident = [r for r in results if r.exists is True and r.confidence == "high"]
    low_conf_found = [r for r in results if r.exists is True and r.confidence == "low"]
    not_found = [r for r in results if r.exists is False]
    unknown = [r for r in results if r.exists is None]

    console.print()
    console.rule(f"[bold {PRIMARY}]NixSINT results for '{username}'[/bold {PRIMARY}]")

    def render_table(rows, title):
        table = Table(title=title, show_header=True, header_style=f"bold {PRIMARY}")
        table.add_column("Platform", style="white")
        table.add_column("URL", style=ACCENT)
        for r in sorted(rows, key=lambda r: r.name.lower()):
            table.add_row(r.name, r.url)
        console.print(table)

    if confident:
        render_table(confident, "Confident hits")
    else:
        console.print(f"[{WARN}]No confident profile matches found.[/{WARN}]")

    if low_conf_found:
        console.print()
        console.print(
            f"[{WARN}]The sites below returned what LOOKS like a hit, but they have no "
            f"reliable unauthenticated API (Instagram, Twitter/X, etc.) - the check used "
            f"an unofficial trick that can misfire. Open these manually before trusting "
            f"them:[/{WARN}]"
        )
        render_table(low_conf_found, "Low-confidence hits (verify manually)")

    console.print()
    console.print(
        f"[bold]Summary:[/bold] "
        f"[bold {PRIMARY}]{len(confident)} confident[/bold {PRIMARY}]  "
        f"[{WARN}]{len(low_conf_found)} low-confidence[/{WARN}]  "
        f"[dim]{len(not_found)} not found[/dim]  "
        f"[{WARN}]{len(unknown)} unknown[/{WARN}]  "
        f"out of {len(results)} sites checked."
    )
    if unknown:
        console.print(
            f"[dim]Unknown (timeout, rate-limit, or unexpected response - never guessed, You should manually check on them because you call your self a hacker (><) ): "
            f"{', '.join(sorted(r.name for r in unknown))}[/dim]"
        )


def parse_args():
    parser = argparse.ArgumentParser(description="NixSINT - curated OSINT username checker by DEDSEC")
    parser.add_argument("username", nargs="?", help="username to scan (skips the prompt)")
    parser.add_argument("--list-sites", action="store_true", help="print the checked/excluded site list and exit")
    return parser.parse_args()


def show_site_list():
    console.print(f"[bold {PRIMARY}]Confident-tier checks (real API/endpoint):[/bold {PRIMARY}]")
    for name in SITE_CHECKS:
        console.print(f"  - {name}")
    console.print(f"\n[bold {WARN}]Low-confidence checks (best-effort, unofficial trick):[/bold {WARN}]")
    for name in LOW_CONFIDENCE_CHECKS:
        console.print(f"  - {name}")
    console.print(f"\n[bold]Not included at all, and why:[/bold]")
    for name, reason in EXCLUDED_SITES.items():
        console.print(f"  - {name}: [dim]{reason}[/dim]")


def main() -> None:
    args = parse_args()
    print_banner()

    if args.list_sites:
        show_site_list()
        return

    total = len(SITE_CHECKS) + len(LOW_CONFIDENCE_CHECKS)
    console.print(
        f"[dim]Checking {total} sites ({len(SITE_CHECKS)} confident-tier, "
        f"{len(LOW_CONFIDENCE_CHECKS)} low-confidence-tier). "
        f"Run with --list-sites to see the full breakdown.[/dim]\n"
    )

    username = args.username or get_username()
    console.print(f"\n[bold {PRIMARY}][*][/bold {PRIMARY}] Scanning for username: [bold white]{username}[/bold white]\n")

    try:
        results = asyncio.run(run_scan(username))
    except KeyboardInterrupt:
        console.print(f"\n[bold {PRIMARY}][!] Scan interrupted by user.[/bold {PRIMARY}]")
        sys.exit(1)

    print_results(username, results)

    console.print()
    console.rule(f"[bold {PRIMARY}]DEDSEC[/bold {PRIMARY}]")
    console.print(f"[italic {ACCENT}]{random_quote()}[/italic {ACCENT}]\n")


if __name__ == "__main__":
    main()
