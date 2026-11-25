"""Shows scan results in the terminal.

Everything that came from the network (host names, service banners and so
on) is untrusted text. safe_text() removes control characters and wraps the
text so Rich never treats it as formatting.
"""

import re

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from argus.modules.models import HostInfo, ScanResult


console = Console()

DEFAULT_DETAIL_LIMIT = 10

# Control characters (including the ESC that starts terminal escape codes).
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")

FOOTER = (
    "These results show only what responded during this scan. A host or "
    "port that is missing may be offline, filtered or out of range, so "
    "absence is not proof. Nothing here is a confirmed vulnerability."
)

STATE_STYLES = {
    "open": "green",
    "open|filtered": "yellow",
}


def safe_text(value, style: str = "") -> Text:
    """Turn any value into display-safe text. Empty values show as '-'."""
    if value is None or str(value).strip() == "":
        return Text("-", style="dim")

    cleaned = CONTROL_CHARACTERS.sub("", str(value))

    return Text(cleaned, style=style)


def _os_text(host: HostInfo) -> Text:
    if host.os_guess is None:
        return safe_text(None)

    return safe_text(f"{host.os_guess.name} ({host.os_guess.accuracy}% match)")


def _vendor_text(host: HostInfo) -> Text:
    if host.mac is None:
        return safe_text(None)

    if host.vendor:
        return safe_text(f"{host.vendor} ({host.mac})")

    return safe_text(host.mac)


def _summary_table(result: ScanResult) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column()

    duration = result.duration_seconds

    table.add_row("Targets", safe_text(", ".join(result.targets)))
    table.add_row("Scan type", safe_text(result.profile))
    table.add_row("Nmap version", safe_text(result.nmap_version))
    table.add_row(
        "Started",
        safe_text(result.started_at.strftime("%d %B %Y, %I:%M %p %Z")),
    )
    table.add_row(
        "Duration",
        safe_text(f"{duration:.1f} seconds" if duration is not None else None),
    )
    table.add_row("Hosts that responded", Text(str(len(result.up_hosts))))
    table.add_row("Open ports found", Text(str(result.total_open_ports)))

    return table


def _hosts_table(result: ScanResult) -> Table:
    table = Table(title="Hosts that responded", title_justify="left")

    table.add_column("IP address", style="bold")
    table.add_column("Hostname")
    table.add_column("Vendor (MAC)")
    table.add_column("Responded via")
    table.add_column("OS (estimate)")
    table.add_column("Open ports", justify="right")

    for host in result.up_hosts:
        table.add_row(
            safe_text(host.ip),
            safe_text(host.hostname),
            _vendor_text(host),
            safe_text(host.discovery_method),
            _os_text(host),
            Text(str(len(host.open_ports))),
        )

    return table


def _ports_table(host: HostInfo) -> Table:
    table = Table(title=f"Ports on {host.ip}", title_justify="left")

    table.add_column("Port", justify="right")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Version / details")

    for port in sorted(host.ports, key=lambda item: (item.protocol, item.port)):
        details = " | ".join(
            part for part in (port.version_text, port.extra_info) if part
        )

        table.add_row(
            safe_text(f"{port.port}/{port.protocol}"),
            safe_text(port.state, style=STATE_STYLES.get(port.state, "")),
            safe_text(port.service),
            safe_text(details or None),
        )

    return table


def show_scan_results(
    result: ScanResult,
    detail_limit: int | None = DEFAULT_DETAIL_LIMIT,
    output: Console | None = None,
) -> None:
    """Print a scan result. detail_limit=None shows port details for every host."""
    out = output or console

    out.print()
    out.print(Rule("SCAN RESULTS", style="cyan"))
    out.print(_summary_table(result))

    if result.warnings:
        warning_text = Text()

        for index, warning in enumerate(result.warnings):
            if index:
                warning_text.append("\n")

            warning_text.append("- ")
            warning_text.append_text(safe_text(warning))

        out.print()
        out.print(Panel(warning_text, title="Warnings", border_style="yellow"))

    out.print()

    if not result.up_hosts:
        out.print("[yellow]No hosts responded during this scan.[/yellow]")
    else:
        out.print(_hosts_table(result))

        hosts_with_ports = [host for host in result.up_hosts if host.ports]
        shown = hosts_with_ports if detail_limit is None else hosts_with_ports[:detail_limit]

        for host in shown:
            out.print()
            out.print(_ports_table(host))

        hidden = len(hosts_with_ports) - len(shown)

        if hidden > 0:
            out.print(
                f"\n[dim]Port details for {hidden} more host(s) are hidden. "
                "Open 'View Last Results' from the Current Session menu "
                "to see every host.[/dim]"
            )

    out.print()
    out.print(Text(FOOTER, style="dim"))

# ---------- comparing two scans ----------

COMPARISON_FOOTER = (
    "A host or port that is missing from the newer scan may be offline, "
    "filtered or blocking probes. 'Not re-checked' and 'not checked before' "
    "mean the scans looked at different ports, not that anything changed."
)


def show_comparison(
    comparison,
    older_label: str,
    newer_label: str,
    output: Console | None = None,
) -> None:
    """Print what changed between two scans (a ScanComparison)."""
    from argus.modules.compare import EVENT_KINDS

    out = output or console

    out.print()
    out.print(Rule("SCAN COMPARISON", style="cyan"))

    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold cyan")
    header.add_column()
    header.add_row("Older scan", safe_text(older_label))
    header.add_row("Newer scan", safe_text(newer_label))
    header.add_row("Hosts matched", Text(str(len(comparison.matches))))
    header.add_row("Confirmed changes", Text(str(len(comparison.confirmed_changes))))
    out.print(header)

    if comparison.notes:
        notes = Text()

        for index, note in enumerate(comparison.notes):
            if index:
                notes.append("\n")

            notes.append("- ")
            notes.append_text(safe_text(note))

        out.print()
        out.print(Panel(notes, title="What could be compared", border_style="yellow"))

    if not comparison.events:
        out.print("\n[green]No differences were found in what both scans checked.[/green]")
    else:
        counts = Table(title="Summary", title_justify="left")
        counts.add_column("Change")
        counts.add_column("Count", justify="right")

        for kind, (label, confirmed) in EVENT_KINDS.items():
            number = comparison.count(kind)

            if number:
                counts.add_row(
                    Text(label, style="" if confirmed else "dim"),
                    Text(str(number)),
                )

        out.print()
        out.print(counts)

        details = Table(title="Details", title_justify="left")
        details.add_column("Change")
        details.add_column("Host", style="bold")
        details.add_column("What happened")

        for event in comparison.events:
            details.add_row(
                Text(event.label, style="" if event.confirmed else "dim"),
                safe_text(event.ip),
                safe_text(event.summary),
            )

        out.print()
        out.print(details)

    if comparison.skipped_out_of_scope:
        out.print(
            f"\n[dim]{comparison.skipped_out_of_scope} host(s) were only inside "
            "one scan's targets and were not compared.[/dim]"
        )

    out.print()
    out.print(Text(COMPARISON_FOOTER, style="dim"))
