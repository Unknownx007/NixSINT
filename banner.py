"""
banner.py - DEDSEC-themed banner and quotes for NixSINT
"""

import random
from rich.console import Console

console = Console()

BANNER = r"""
[bold red] _   _ _        _____ _____ _   _ _____ 
| \ | (_)      / ____|_   _| \ | |_   _|
|  \| |___  __ | (___   | | |  \| | | |  
| . ` | \ \/ /  \___ \  | | | . ` | | |  
| |\  | |>  <   ____) |_| |_| |\  |_| |_ 
|_| \_|_/_/\_\ |_____/|_____|_| \_|_____|[/bold red]

[bold white]        by [bold red]D E D S E C[/bold red] — we own the network[/bold white]
[dim]        OSINT username reconnaissance tool[/dim]
"""

QUOTES = [
    "\"Privacy is a right, not a privilege.\" — DEDSEC",
    "\"Every account you make is a breadcrumb.\" — DEDSEC",
    "\"We don't hack for chaos. We hack for truth.\" — DEDSEC",
    "\"The trail always exists. You just need to look.\" — DEDSEC",
    "\"Data doesn't lie. People do.\" — DEDSEC",
    "\"Knowledge is the only real firewall.\" — DEDSEC",
]


def print_banner() -> None:
    console.print(BANNER)


def random_quote() -> str:
    return random.choice(QUOTES)
