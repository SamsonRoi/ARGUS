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
from rich.tree import Tree

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

CONFIDENCE_STYLES = {"high": "bold", "medium": "", "low": "dim"}
CRITICALITY_STYLES = {"high": "bold red", "medium": "yellow", "low": "green"}

ASSETS_FOOTER = (
    "Roles are estimates worked out from open ports, software, MAC vendor "
    "and OS estimate. Check the evidence before relying on them."
)


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


def _role_text(host: HostInfo) -> Text:
    role = host.primary_role

    if role is None:
        return Text("Unknown", style="dim")

    text = safe_text(role.label, style=CONFIDENCE_STYLES[role.confidence])
    text.append(f" ({role.confidence})", style="dim")
    return text


def _hosts_table(result: ScanResult) -> Table:
    table = Table(title="Hosts that responded", title_justify="left")

    table.add_column("IP address", style="bold")
    table.add_column("Hostname")
    table.add_column("Vendor (MAC)")
    table.add_column("Responded via")
    table.add_column("OS (estimate)")
    table.add_column("Likely role")
    table.add_column("Open ports", justify="right")

    for host in result.up_hosts:
        table.add_row(
            safe_text(host.ip),
            safe_text(host.hostname),
            _vendor_text(host),
            safe_text(host.discovery_method),
            _os_text(host),
            _role_text(host),
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


# ---------- assets ----------

def show_assets(result: ScanResult, output: Console | None = None) -> None:
    """Print every host's likely role, criticality and the evidence for it."""
    out = output or console

    out.print()
    out.print(Rule("ASSETS", style="cyan"))

    if not result.up_hosts:
        out.print("[yellow]No hosts responded during this scan.[/yellow]")
        return

    summary = Table(title="Assets by criticality", title_justify="left")
    summary.add_column("Criticality")
    summary.add_column("Hosts", justify="right")

    for level in ("high", "medium", "low"):
        count = sum(1 for host in result.up_hosts if host.criticality == level)

        if count:
            summary.add_row(Text(level.title(), style=CRITICALITY_STYLES[level]), str(count))

    out.print(summary)

    table = Table(title="Assets", title_justify="left", show_lines=True)
    table.add_column("Host", style="bold")
    table.add_column("Likely role")
    table.add_column("Evidence")
    table.add_column("Also possible")
    table.add_column("Criticality")

    for host in result.up_hosts:
        name = Text(host.ip)

        if host.hostname:
            name.append("\n")
            name.append_text(safe_text(host.hostname, style="dim"))

        role = host.primary_role
        evidence = Text()

        if role is None:
            evidence = Text("Not enough evidence to tell", style="dim")
        else:
            for index, reason in enumerate(role.reasons):
                if index:
                    evidence.append("\n")

                evidence.append("- ")
                evidence.append_text(safe_text(reason))

        others = Text()

        for index, match in enumerate(host.roles[1:]):
            if index:
                others.append("\n")

            others.append_text(safe_text(match.label))
            others.append(f" ({match.confidence})", style="dim")

        criticality = Text(
            (host.criticality or "-").title(),
            style=CRITICALITY_STYLES.get(host.criticality, ""),
        )

        if host.criticality_reason:
            criticality.append("\n")
            criticality.append_text(safe_text(host.criticality_reason, style="dim"))

        table.add_row(
            name,
            _role_text(host),
            evidence,
            others if host.roles[1:] else safe_text(None),
            criticality,
        )

    out.print()
    out.print(table)
    out.print()
    out.print(Text(ASSETS_FOOTER, style="dim"))


# ---------- network map ----------

MAP_FOOTER = (
    "Observed links were seen by traceroute. Inferred links are worked out "
    "from addresses only and may not match the real wiring."
)


def _map_label(node, basis: str | None = None, reason: str | None = None) -> Text:
    text = safe_text(node.label, style="bold" if node.kind == "gateway" else "")

    if node.role_label:
        text.append("  ")
        text.append_text(safe_text(node.role_label))
        text.append(f" ({node.confidence})", style="dim")

    if node.criticality == "high":
        text.append("  [high criticality]", style=CRITICALITY_STYLES["high"])

    if basis:
        style = "green" if basis == "observed" else "yellow"
        text.append(f"  gateway, {basis}", style=style)

        if reason:
            text.append(f": {reason}", style="dim")

    return text


def show_network_map(network_map, output: Console | None = None) -> None:
    """Print a NetworkMap as a tree: subnet, then gateway, then hosts."""
    out = output or console

    out.print()
    out.print(Rule("NETWORK MAP", style="cyan"))

    if not network_map.subnets:
        out.print("[yellow]No hosts responded, so there is nothing to map.[/yellow]")
        return

    tree = Tree(Text("Scanned network", style="bold cyan"))

    for group in network_map.subnets:
        title = Text(group.network, style="bold")
        title.append(
            f"  {len(group.host_ips)} host{'s' if len(group.host_ips) != 1 else ''}",
            style="dim",
        )

        if group.assumed:
            title.append("  (subnet size assumed)", style="yellow")

        branch = tree.add(title)
        members = [ip for ip in group.host_ips if ip != group.gateway_ip]

        if group.gateway_ip:
            gateway_node = network_map.nodes[group.gateway_ip]
            parent = branch.add(
                _map_label(gateway_node, group.gateway_basis, group.gateway_reason)
            )

            if group.gateway_ip not in group.host_ips:
                parent.label.append("  (not in this scan's results)", style="dim")
        else:
            parent = branch

        for ip in members:
            parent.add(_map_label(network_map.nodes[ip]))

    out.print(tree)

    if network_map.paths:
        paths = Table(title="Traced paths", title_justify="left")
        paths.add_column("Host", style="bold")
        paths.add_column("Hops", justify="right")
        paths.add_column("Path from this computer")

        for ip, path in sorted(network_map.paths.items()):
            shown = " -> ".join(hop if hop else "*" for hop in path)
            paths.add_row(safe_text(ip), str(len(path)), safe_text(shown))

        out.print()
        out.print(paths)
        out.print("[dim]* = a hop that did not answer.[/dim]")

    links = Table.grid(padding=(0, 2))
    links.add_column(style="bold cyan")
    links.add_column()
    links.add_row("Observed links", str(len(network_map.observed_links)))
    links.add_row("Inferred links", str(len(network_map.inferred_links)))
    out.print()
    out.print(links)

    if network_map.notes:
        notes = Text()

        for index, note in enumerate(network_map.notes):
            if index:
                notes.append("\n")

            notes.append("- ")
            notes.append_text(safe_text(note))

        out.print()
        out.print(Panel(notes, title="About this map", border_style="yellow"))

    out.print()
    out.print(Text(MAP_FOOTER, style="dim"))


# ---------- risk analysis ----------

BAND_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
GRADE_STYLES = {
    "A": "bold green", "B": "green", "C": "yellow", "D": "bold red", "F": "bold white on red",
}
RISK_DETAIL_LIMIT = 8

RISK_FOOTER = (
    "Findings describe exposure seen from this computer. They are not "
    "confirmed vulnerabilities, and ARGUS did not try to exploit anything. "
    "Version-based findings come from service banners, which can be wrong "
    "or patched without a version change."
)


def _band_text(finding) -> Text:
    return Text(f"{finding.score:.1f} {finding.band}", style=BAND_STYLES[finding.band])


def _history_text(finding) -> Text:
    text = Text()

    if finding.new_since_baseline:
        text.append("NEW since baseline", style="bold magenta")

    if finding.streak and finding.streak > 1:
        if text:
            text.append("\n")
        text.append(f"open for {finding.streak} scans", style="yellow")

    if finding.first_seen_scan:
        if text:
            text.append("\n")
        text.append(f"first seen in #{finding.first_seen_scan}", style="dim")
    elif finding.seen_in_scans == 1 and finding.streak == 1 and not finding.new_since_baseline:
        if text:
            text.append("\n")
        text.append("first seen now", style="dim")

    return text if text else safe_text(None)


def _bulleted(lines) -> Text:
    text = Text()

    for index, line in enumerate(lines):
        if index:
            text.append("\n")
        text.append("- ")
        text.append_text(safe_text(line))

    return text


def show_risk_report(report, detail_limit: int | None = RISK_DETAIL_LIMIT,
                     output: Console | None = None) -> None:
    """Print a RiskReport: posture, fix-first plan, findings, paths and history."""
    from argus.modules.risk import CATEGORY_LABELS

    out = output or console

    out.print()
    out.print(Rule("RISK ANALYSIS", style="cyan"))

    # ----- posture -----
    posture = Table.grid(padding=(0, 2))
    posture.add_column(style="bold cyan")
    posture.add_column()
    grade = Text(f" {report.grade} ", style=GRADE_STYLES.get(report.grade, "bold"))
    grade.append(f"  {report.grade_reason}", style="")
    posture.add_row("Risk grade", grade)

    counts = Text()

    for band in ("critical", "high", "medium", "low", "info"):
        number = report.count(band)

        if number:
            if counts:
                counts.append("   ")
            counts.append(f"{number} {band}", style=BAND_STYLES[band])

    posture.add_row("Open findings", counts if counts else Text("none", style="green"))
    posture.add_row("Total risk", Text(f"{report.total_risk:.1f} points"))
    posture.add_row("Hosts with findings", Text(str(len(report.host_scores))))

    if report.accepted:
        posture.add_row("Accepted risks", Text(str(len(report.accepted))))

    if report.compared_with:
        moved = Text(f"vs scan #{report.compared_with}: ")
        new = sum(1 for finding in report.findings if finding.first_seen_scan is None
                  and finding.seen_in_scans == 1)
        moved.append(f"{new} new", style="magenta" if new else "")
        moved.append(", ")
        moved.append(f"{len(report.resolved)} resolved", style="green" if report.resolved else "")
        moved.append(f", {len(report.not_rechecked)} not re-checked", style="dim")
        posture.add_row("Since last scan", moved)

    posture.add_row("Rules", Text(f"version {report.rules_version}", style="dim"))
    out.print(posture)

    if not report.findings:
        out.print("\n[green]No open risk findings in what this scan could see.[/green]")
    else:
        # ----- fix-first plan -----
        plan = Table(title="Fix these first", title_justify="left")
        plan.add_column("#", justify="right", style="bold")
        plan.add_column("Fix")
        plan.add_column("Findings", justify="right")
        plan.add_column("Where")
        plan.add_column("Risk removed", justify="right")

        for number, action in enumerate(report.plan[:5], start=1):
            where = ", ".join(action.hosts[:4])

            if len(action.hosts) > 4:
                where += f" and {len(action.hosts) - 4} more"

            plan.add_row(
                str(number),
                safe_text(action.title, style=BAND_STYLES[action.worst]),
                str(action.findings),
                safe_text(where),
                f"{action.risk_removed:.1f}",
            )

        out.print()
        out.print(plan)

        if len(report.plan) > 5:
            out.print(f"[dim]{len(report.plan) - 5} more fix(es) are listed with the findings below.[/dim]")

        # ----- all findings -----
        table = Table(title="Findings (highest priority first)", title_justify="left")
        table.add_column("#", justify="right", style="bold")
        table.add_column("Priority", no_wrap=True)
        table.add_column("Finding")
        table.add_column("Where")
        table.add_column("History")

        for number, finding in enumerate(report.findings, start=1):
            title = safe_text(finding.title)
            title.append(f"\n{CATEGORY_LABELS.get(finding.category, finding.category)}", style="dim")
            table.add_row(
                str(number),
                _band_text(finding),
                title,
                safe_text(finding.where),
                _history_text(finding),
            )

        out.print()
        out.print(table)

        # ----- details -----
        shown = report.findings if detail_limit is None else report.findings[:detail_limit]

        for number, finding in enumerate(shown, start=1):
            body = Table.grid(padding=(0, 2))
            body.add_column(style="bold cyan", no_wrap=True)
            body.add_column()
            body.add_row("Where", safe_text(finding.host_label or finding.where))
            body.add_row("Evidence", _bulleted(finding.evidence))
            body.add_row("Why it matters", safe_text(finding.why))

            if finding.escalations:
                body.add_row("Raised because", _bulleted(finding.escalations))

            body.add_row("Score", safe_text(
                f"{finding.score:.1f} = " + " ".join(finding.score_factors)
            ))
            body.add_row("Confidence", safe_text(finding.confidence))
            body.add_row("How to fix", safe_text(finding.fix))

            if finding.references:
                body.add_row("References", safe_text("; ".join(finding.references)))

            out.print()
            out.print(Panel(
                body,
                title=Text(f"#{number}  {finding.title}", style=BAND_STYLES[finding.band]),
                title_align="left",
                border_style=BAND_STYLES[finding.band].replace("white on ", "").replace("bold ", ""),
            ))

        hidden = len(report.findings) - len(shown)

        if hidden > 0:
            out.print(
                f"\n[dim]Details for {hidden} more finding(s) are hidden. "
                "Choose 'Show every finding in detail' to see them.[/dim]"
            )

    # ----- attack paths -----
    if report.attack_paths:
        paths = Table(title="Possible attack paths", title_justify="left")
        paths.add_column("Starting point (weak)")
        paths.add_column("Why it is weak")
        paths.add_column("Could reach (critical)")
        paths.add_column("Basis")

        for path in report.attack_paths:
            paths.add_row(
                safe_text(path.entry_label),
                _bulleted(path.entry_reasons),
                safe_text(path.target_label, style="bold"),
                safe_text(path.basis, style="dim"),
            )

        out.print()
        out.print(paths)
        out.print(
            "[dim]Possible, not proven: ARGUS cannot see firewalls between "
            "hosts on the same subnet.[/dim]"
        )

    # ----- hosts -----
    if report.host_scores:
        hosts = Table(title="Highest-risk hosts", title_justify="left")
        hosts.add_column("Host", style="bold")
        hosts.add_column("Risk", justify="right")
        hosts.add_column("Findings", justify="right")

        for ip, score in list(report.host_scores.items())[:10]:
            count = sum(1 for finding in report.findings if finding.host_ip == ip)
            hosts.add_row(safe_text(ip), Text(f"{score:.1f}", style=BAND_STYLES[_score_band(score)]), str(count))

        out.print()
        out.print(hosts)

    # ----- what changed since the last scan -----
    if report.resolved:
        resolved = Table(title=f"Resolved since scan #{report.compared_with}", title_justify="left")
        resolved.add_column("Finding", style="green")
        resolved.add_column("Where")

        for finding in report.resolved:
            resolved.add_row(safe_text(finding.title), safe_text(finding.where))

        out.print()
        out.print(resolved)
        out.print("[dim]Resolved means this scan checked again and the problem was gone.[/dim]")

    if report.not_rechecked:
        unknown = Table(title="Not re-checked by this scan", title_justify="left")
        unknown.add_column("Finding", style="dim")
        unknown.add_column("Where", style="dim")

        for finding in report.not_rechecked:
            unknown.add_row(safe_text(finding.title), safe_text(finding.where))

        out.print()
        out.print(unknown)
        out.print(
            "[dim]These were open before, but this scan did not look at the same "
            "ports or host, so ARGUS cannot say whether they are fixed.[/dim]"
        )

    # ----- accepted -----
    if report.accepted:
        accepted = Table(title="Accepted risks (not counted in the grade)", title_justify="left")
        accepted.add_column("Finding")
        accepted.add_column("Where")
        accepted.add_column("Reason")
        accepted.add_column("Until")

        for finding in report.accepted:
            acceptance = finding.acceptance
            accepted.add_row(
                safe_text(finding.title),
                safe_text(finding.where),
                safe_text(acceptance.reason),
                safe_text(acceptance.expires_on.isoformat() if acceptance.expires_on else "no expiry"),
            )

        out.print()
        out.print(accepted)

    if report.notes:
        out.print()
        out.print(Panel(_bulleted(report.notes), title="What this analysis could not see",
                        border_style="yellow"))

    out.print()
    out.print(Text(RISK_FOOTER, style="dim"))


def _score_band(score: float) -> str:
    from argus.modules.risk import score_band

    return score_band(score)


def show_risk_changes(changes, output: Console | None = None) -> None:
    """Print new, resolved and not re-checked findings between two scans."""
    out = output or console

    out.print()
    out.print(Rule("RISK CHANGES", style="cyan"))

    if not (changes.new or changes.resolved or changes.not_rechecked):
        out.print("[green]No change in risk findings between these scans.[/green]")
        return

    table = Table(title_justify="left")
    table.add_column("Change")
    table.add_column("Finding")
    table.add_column("Where")

    for label, style, items in (
        ("New", "magenta", changes.new),
        ("Resolved", "green", changes.resolved),
        ("Not re-checked", "dim", changes.not_rechecked),
    ):
        for finding in items:
            table.add_row(Text(label, style=style), safe_text(finding.title), safe_text(finding.where))

    out.print(table)
    out.print(
        "[dim]Resolved only when the newer scan checked again. "
        "Not re-checked means unknown, not fixed.[/dim]"
    )
