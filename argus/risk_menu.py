"""Risk Analysis screens: run the analysis, read every finding, accept risks."""

from datetime import date

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from argus.modules.risk import analyze
from argus.modules.risk_history import analyze_with_history
from argus.results_display import safe_text, show_risk_report
from argus.storage.database import StorageError, connect
from argus.storage.repository import (
    accept_risk,
    list_acceptances,
    revoke_acceptance,
)
from argus.utils.prompts import (
    ask_yes_no,
    get_menu_choice,
    get_optional_text,
    get_text_input,
    wait_for_enter,
)


console = Console()


def build_report(result, scan_id=None, engagement_id=None):
    """Analyse a scan with history and accepted risks, or without if the
    history database cannot be opened. Returns (report, connection or None)."""
    try:
        connection = connect()
    except StorageError as error:
        console.print(
            f"\n[yellow]Scan history is unavailable ({escape(str(error))}), so "
            "the analysis runs without history or accepted risks.[/yellow]"
        )
        return analyze(result), None

    try:
        return analyze_with_history(connection, result, scan_id, engagement_id), connection
    except StorageError as error:
        console.print(f"\n[yellow]History could not be read: {escape(str(error))}[/yellow]")
        return analyze(result), connection


def _ask_expiry() -> date | None:
    while True:
        raw = get_optional_text("Accept until (YYYY-MM-DD, or Enter for no expiry):")

        if raw is None:
            return None

        try:
            chosen = date.fromisoformat(raw)
        except ValueError:
            print("\nUse the format YYYY-MM-DD, for example 2027-03-31.")
            continue

        if chosen < date.today():
            print("\nThat date is already in the past.")
            continue

        return chosen


def accept_finding(connection, report, engagement_id=None) -> bool:
    """Let the user mark one open finding as an accepted risk."""
    if not report.findings:
        print("\nThere are no open findings to accept.")
        return False

    numbers = list(range(1, len(report.findings) + 1))
    choice = get_menu_choice("Which finding do you accept? (#, or 0 to go back):", [0] + numbers)

    if choice == 0:
        return False

    finding = report.findings[choice - 1]

    print(f"\nAccepting: {finding.title} on {finding.where}")
    print("An accepted risk is left out of the grade until it expires.")
    print("It is still listed, so it is never forgotten.")

    reason = get_text_input("Why is this acceptable? (for example 'isolated lab device'):")
    accepted_by = get_optional_text("Accepted by (name and role, or Enter to skip):")
    expires_on = _ask_expiry()

    if expires_on is None and not ask_yes_no("Accept with no expiry date?"):
        expires_on = _ask_expiry()

    try:
        accept_risk(
            connection,
            finding,
            reason,
            accepted_by=accepted_by,
            expires_on=expires_on,
            engagement_id=engagement_id,
        )
    except StorageError as error:
        console.print(f"\n[bold red]{escape(str(error))}[/bold red]")
        return False

    print("\nThe risk was accepted.")
    return True


def risk_analysis_flow(result, scan_id=None, engagement_id=None) -> None:
    """Show the risk report, with options to see more and accept risks."""
    report, connection = build_report(result, scan_id, engagement_id)

    try:
        show_risk_report(report)

        while True:
            print("\nRISK ANALYSIS")
            print("-" * 35)
            print("1. Show every finding in detail")
            print("2. Accept a finding as a known risk")
            print("0. Back")

            choice = get_menu_choice("Your next move:", [0, 1, 2])

            if choice == 0:
                return

            if choice == 1:
                show_risk_report(report, detail_limit=None)
                continue

            if connection is None:
                print("\nAccepting risks needs the scan history database, which is unavailable.")
                continue

            if accept_finding(connection, report, engagement_id):
                report = analyze_with_history(connection, result, scan_id, engagement_id)
                show_risk_report(report)

    finally:
        if connection is not None:
            connection.close()


def accepted_risks_menu(connection) -> None:
    """List accepted risks and allow revoking them."""
    while True:
        records = list_acceptances(connection)

        print("\nACCEPTED RISKS")
        print("-" * 35)

        if not records:
            print("No risks have been accepted.")
            wait_for_enter("Press Enter to continue...")
            return

        table = Table(title_justify="left")
        table.add_column("#", justify="right", style="bold")
        table.add_column("Finding")
        table.add_column("Where")
        table.add_column("Reason")
        table.add_column("Accepted by")
        table.add_column("Until")

        for record in records:
            until = record.expires_on.isoformat() if record.expires_on else "no expiry"

            if not record.active():
                until += " (expired)"

            table.add_row(
                str(record.id),
                safe_text(record.title),
                safe_text(record.location),
                safe_text(record.reason),
                safe_text(record.accepted_by),
                safe_text(until, style="" if record.active() else "red"),
            )

        console.print()
        console.print(table)

        ids = [record.id for record in records]
        choice = get_menu_choice("Revoke which acceptance? (#, or 0 to go back):", [0] + ids)

        if choice == 0:
            return

        if ask_yes_no(f"Revoke acceptance #{choice}? The finding will count again."):
            revoke_acceptance(connection, choice)
            print(f"\nAcceptance #{choice} was revoked.")
