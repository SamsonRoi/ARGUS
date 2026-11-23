
import random
import textwrap
from pathlib import Path
from typing import Optional

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


console = Console()

BANNERS_DIR = Path(__file__).resolve().parent / "assets" / "banners"

THEMES = [
    {
        "name": "cyber",
        "art": "bold cyan",
        "border": "bright_blue",
        "accent": "bold white",
    },
    {
        "name": "crimson",
        "art": "bold red",
        "border": "red",
        "accent": "bold yellow",
    },
    {
        "name": "phosphor",
        "art": "bold bright_green",
        "border": "green",
        "accent": "bold white",
    },
    {
        "name": "synth",
        "art": "bold magenta",
        "border": "bright_cyan",
        "accent": "bold bright_white",
    },
    {
        "name": "amber",
        "art": "bold yellow",
        "border": "bright_yellow",
        "accent": "bold white",
    },
    {
        "name": "stealth",
        "art": "bold bright_white",
        "border": "bright_black",
        "accent": "bold cyan",
    },
]


TAGLINES = [
    "See everything. Miss nothing.",
    "One hundred eyes. Zero blind spots.",
    "Panoptes awakens. Every packet leaves a trace.",
    "Quiet on the wire. Loud in the logs.",
    "Always watching. Never blinking.",
    "No host hides forever.",
    "From shadows to signal.",
    "Constant vigilance across every subnet.",
    "Every open port tells a story.",
    "Hera's watchman, recompiled for the wire.",
    "Map the unseen. Own the perimeter.",
    "Passive optics. Surgical precision.",
]


STATIC_BANNERS = [
    # 1. Panoptes Cyber Iris
    r"""
                   _.--~~~~~--._
               _.-"   .-----.   "-._
            .-"     .'  .-.  '.     "-.
          .'      .'   / _ \   '.      '.
         /  ..---/    | (_) |    \---..  \
        <  <====|=====|  +  |=====|====>  >
         \  ''---\    | (_) |    /---''  /
          '.      '.   \   /   .'      .'
            '-.     '._ '-' _.'     .-'
               "-._    -----    _.-"
                   "--.......--"
              [ A R G U S :: ONLINE ]
    """,

    # 2. Heavy Block Wordmark
    r"""
         █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
        ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
        ███████║██████╔╝██║  ███╗██║   ██║███████╗
        ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
        ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
        ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
             ── NETWORK INTELLIGENCE FRAMEWORK ──
    """,

    # 3. The Hundred Eyes Grid
    r"""
        (o)         .-.         (0)         .-.         (o)
             .-.   ( @ )   .-.       .-.   ( @ )   .-.
            ( o )   '-'   ( o )     ( o )   '-'   ( o )
             '-'     |     '-'       '-'     |     '-'
        -------[-----+-----[  A R G U S  ]---+-----]-------
             .-.     |     .-.       .-.     |     .-.
            ( o )   .-.   ( o )     ( o )   .-.   ( o )
             '-'   ( @ )   '-'       '-'   ( @ )   '-'
        (o)         '-'         (0)         '-'         (o)
                 // 100 EYES OPEN :: 0 BLIND SPOTS //
    """,

    # 4. Tactical Radar Sweep
    r"""
                .---.               A R G U S
            .-'   |   '-.           ──────────────────────
          .'  .---|---.  '.         OPTICS : ALL-SPECTRUM
         /  .'    |  / '.  \        STATE  : WATCHING
        |  |   .--+-/    |  |       BLINKS : 0
        |--|---|--(+)----|--|
        |  |   '--|--'   |  |       "Never blinks.
         \  '.    |    .'  /         Never sleeps."
          '.  '---|---'  .'
            '-.   |   .-'
                '---'
    """,

    # 5. All-Seeing Watchtower Pyramid
    r"""
                      |
                   \  |  /
                    \ | /
                 --- /^\ ---
                    /   \
                   / .-. \
             ---  / ( @ ) \  ---
                 /   '-'   \
                /___________\
               /  A R G U S  \
              /_______________\
    """,

    # 6. Sharp Slant Wordmark
    r"""
            ___      ____    ______   __  __   _____
           /   |    / __ \  / ____/  / / / /  / ___/
          / /| |   / /_/ / / / __   / / / /   \__ \
         / ___ |  / _, _/ / /_/ /  / /_/ /   ___/ /
        /_/  |_| /_/ |_|  \____/   \____/   /____/
                // ALL-SEEING RECON ENGINE //
    """,

    # 7. Mesh Node Eye
    r"""
               [NODE]---------------[NODE]
                /  \                 /  \
               /    '---.       .---'    \
              /          '.   .'          \
        [HOST]======(  ((  (O)  ))  )======[HOST]
              \          .'   '.          /
               \    .---'       '---.    /
                \  /                 \  /
               [NODE]---------------[NODE]
                  :: ARGUS MESH WATCH ::
    """,

    # 8. Temple of Panoptes
    r"""
                        .-.
                   _.--'   '--._
              _.--'  A R G U S  '--._
         _.--'_______________________'--._
          ||  ||      .-~~~-.      ||  ||
          ||  ||    .'  (O)  '.    ||  ||
          ||  ||      '-...-'      ||  ||
          ||  ||  PANOPTES ENGINE  ||  ||
          ||  ||  [  100  EYES  ]  ||  ||
         _||__||___________________||__||_
        |_________________________________|
    """,

    # 9. Hex & Binary Overwatch
    r"""
        0x41 0x52 0x47 0x55 0x53 :: 01000001 01010010 01000111 01010101 01010011
        +----------------------------------------------------------------------+
        |   [  ((  O  ))  ]   A R G U S   //   NETWORK INTELLIGENCE SUITE      |
        +----------------------------------------------------------------------+
        0x50 0x41 0x4E 0x4F 0x50 :: SENSORS ARMED // PASSIVE & ACTIVE RECON
    """,

    # 10. Twin-Eye Cyber Visor
    r"""
             _.===========================._
          .-'   _________________________   '-.
         /    .'   ___             ___   '.    \
        |   |    .' _ '.         .' _ '.    |   |
        |   |   (  (O)  )  ===  (  (O)  )   |   |
        |   |    '._ _.'         '._ _.'    |   |
         \    '._________________________.'    /
          '-.__________ A R G U S __________.-'
    """,
]


_last_banner: Optional[str] = None


def _generate_panoptes_field() -> str:
    """Generate a random constellation of watching eyes."""

    tokens = [
        "   ",
        "   ",
        "   ",
        " · ",
        "(-)",
        "(o)",
        "(O)",
        "(@)",
    ]

    weights = [35, 20, 15, 10, 5, 8, 5, 2]

    cols, rows = 19, 9

    box_lines = {
        3: "+-------------------------+",
        4: "|  A R G U S :: PANOPTES  |",
        5: "+-------------------------+",
    }

    lines = []

    for row in range(rows):

        if row in box_lines:

            left = "".join(
                random.choices(tokens, weights=weights, k=5)
            )

            right = "".join(
                random.choices(tokens, weights=weights, k=5)
            )

            lines.append(
                f"{left}{box_lines[row]}{right}"
            )

        else:

            lines.append(
                "".join(
                    random.choices(tokens, weights=weights, k=cols)
                )
            )

    return "\n".join(lines)


def _load_external_banners() -> list[str]:
    """Load custom text banners from the external banner directory."""

    if not BANNERS_DIR.is_dir():
        return []

    loaded = []

    for path in sorted(BANNERS_DIR.glob("*.txt")):

        try:
            content = path.read_text(encoding="utf-8").strip("\n")

        except (OSError, UnicodeError):
            continue

        if content.strip():
            loaded.append(content)

    return loaded


def _get_banner_pool() -> list[str]:
    """Combine built-in, external and generated banners."""

    static = [
        textwrap.dedent(banner).strip("\n")
        for banner in STATIC_BANNERS
    ]

    external = _load_external_banners()

    generated = _generate_panoptes_field()

    return static + external + [generated]


def show_banner(
    version: str = "0.1.0",
    module_count: Optional[int] = None,
    clear: bool = True,
) -> None:
    """Display a random ARGUS banner with a random visual theme."""

    global _last_banner

    pool = _get_banner_pool()

    if not pool:
        return

    available_banners = [
        banner for banner in pool
        if banner != _last_banner
    ]

    if not available_banners:
        available_banners = pool

    art = random.choice(available_banners)

    _last_banner = art

    theme = random.choice(THEMES)
    tagline = random.choice(TAGLINES)

    if clear:
        console.clear()

    panel = Panel(
        Align.center(
            Text(art, style=theme["art"])
        ),
        title=(
            f"[{theme['accent']}]A R G U S[/{theme['accent']}] "
            f"[dim]v{version}[/dim]"
        ),
        subtitle="[dim]Network Intelligence Framework[/dim]",
        border_style=theme["border"],
        padding=(1, 3),
        expand=False,
    )

    console.print(Align.center(panel))

    stats = [
        "[bold green]●[/bold green] Online",
       
    ]

    if module_count is not None:
        stats.append(
            f"[dim]Modules:[/dim] {module_count}"
        )

    console.print(
        "  [dim]|[/dim]  ".join(stats),
        justify="center",
    )

    console.print(
        f"[dim italic]{tagline}[/dim italic]\n",
        justify="center",
    )
