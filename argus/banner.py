
import random
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNERS = [
    r"""
       /\_/\
      ( o.o )
       > ^ <
    """,
    r"""
       .-.
      (o o)
      | O \
       \   \
        `~~~'
    """,
    r"""
       /\ 
      /  \
     / /\ \
    /_/  \_\
    """,
]

def show_banner():
    banner = random.choice(BANNERS)

    console.clear()

    console.print(
        Panel(
            Text(banner, style="bold cyan", justify="center"),
            title="[bold white]A R G U S[/bold white]",
            subtitle="[dim]Network Intelligence Framework[/dim]",
            border_style="bright_blue",
            padding=(1, 4)
        )
    )

    console.print(
        "[bold green]●[/bold green] ARGUS initialized successfully.",
        justify="center"
    )

    console.print(
        "[dim]See everything. Miss nothing.[/dim]\n",
        justify="center"
    )
