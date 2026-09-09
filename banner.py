"""
banner.py - DEDSEC-themed banner and quotes for NixSINT
New theme: neon green / electric cyan "terminal" aesthetic.

The banner glyphs are built from a small per-letter font table and
assembled programmatically (rather than hand-typed ASCII art) so the
alignment can't drift or get garbled - each letter is a fixed 5x7 grid.
"""

import random
from rich.console import Console

console = Console()

PRIMARY = "#39FF14"    # neon green - brand color
ACCENT = "#00E5FF"     # electric cyan - links / secondary accent
WARN = "#FFB000"       # amber - low confidence / unknown

_FONT = {
    "N": [
        "█   █",
        "██  █",
        "█ █ █",
        "█  ██",
        "█   █",
        "█   █",
        "█   █",
    ],
    "I": [
        "█████",
        "  █  ",
        "  █  ",
        "  █  ",
        "  █  ",
        "  █  ",
        "█████",
    ],
    "X": [
        "█   █",
        " █ █ ",
        "  █  ",
        "  █  ",
        "  █  ",
        " █ █ ",
        "█   █",
    ],
    "S": [
        " ████",
        "█    ",
        "█    ",
        " ███ ",
        "    █",
        "    █",
        "████ ",
    ],
    "T": [
        "█████",
        "  █  ",
        "  █  ",
        "  █  ",
        "  █  ",
        "  █  ",
        "  █  ",
    ],
}


def _render_word(word: str, gap: str = "  ") -> str:
    rows = ["" for _ in range(7)]
    for ch in word:
        glyph = _FONT[ch]
        for i in range(7):
            rows[i] += glyph[i] + gap
    return "\n".join(rows)


def print_banner() -> None:
    logo = _render_word("NIXSINT")
    console.print(f"[bold {PRIMARY}]{logo}[/bold {PRIMARY}]")
    console.print(
        f"\n[bold]  by [bold black on {PRIMARY}] D E D S E C [/bold black on {PRIMARY}]  "
        f"[{ACCENT}]we own the network[/{ACCENT}][/bold]"
    )
    console.print(f"[dim {ACCENT}]  curated OSINT username reconnaissance[/dim {ACCENT}]\n")


QUOTES = [
    "\"Privacy is a right, not a privilege.\" — DEDSEC",
    "\"Every account you make is a breadcrumb.\" — DEDSEC",
    "\"We don't hack for chaos. We hack for truth.\" — DEDSEC",
    "\"The trail always exists. You just need to look.\" — DEDSEC",
    "\"Data doesn't lie. People do.\" — DEDSEC",
    "\"Knowledge is the only real firewall.\" — DEDSEC",
    "\"A confirmed hit beats ten guesses.\" — DEDSEC",
]


def random_quote() -> str:
    return random.choice(QUOTES)
