"""Scan History screens: saving scans, browsing them, comparing them,
choosing a baseline, and recording engagements."""

from datetime import date

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from argus.modules.compare import compare_scans
from argus.modules.risk_history import risk_changes
from argus.modules.topology import build_network_map
from argus.results_display import (
    safe_text,
    show_assets,
    show_comparison,
    show_network_map,
    show_risk_changes,
    show_scan_results,
)
from argus.risk_menu import accepted_risks_menu, risk_analysis_flow
from argus.storage.database import StorageError, connect, default_db_path
from argus.storage.repository import (
    create_engagement,
    delete_scan,
    get_baseline_id,
    list_engagements,
    list_scans,
    load_scan,
    save_scan,
    scan_engagement_id,
    set_baseline,
)
from argus.utils.prompts import (
    ask_yes_no,
    get_menu_choice,
    get_optional_text,
    get_text_input,
    wait_for_enter,
)
from argus.utils.validators import validate_cidr, validate_ip


console = Console()

HISTORY_LIST_LIMIT = 20


def open_history():
    """Open the history database, or print why it cannot be opened."""
    try:
        return connect()

    except StorageError as error:
        console.print(f"\n[bold red]Scan history is unavailable:[/bold red] {escape(str(error))}")
        return None


# ---------- saving ----------

def save_to_history(session, result) -> int | None:
    """Save a finished scan to the history. A failure never loses the result.

    The result stays in the session either way; only the history entry is
    missing if saving fails.
    """
    connection = open_history()

    if connection is None:
        return None

    try:
        scan_id = save_scan(connection, result, engagement_id=session.engagement_id)

    except StorageError as error:
        console.print(
            f"\n[bold red]The scan could not be saved to history:[/bold red] "
            f"{escape(str(error))}"
        )
        return None

    finally:
        connection.close()

    session.scan_id = scan_id
    console.print(f"\n[dim]Saved to scan history as scan #{scan_id}.[/dim]")

    return scan_id


# ---------- listing ----------

def _scan_label(summary) -> str:
    when = summary.started_at.strftime("%d %b %Y %H:%M")
    return f"#{summary.id} ({when}, {summary.profile})"


def show_scan_list(summaries) -> None:
    show_engagements = any(summary.engagement_name for summary in summaries)

    table = Table(title="Saved scans (newest first)", title_justify="left")

    table.add_column("#", justify="right", style="bold", no_wrap=True)
    table.add_column("Started", no_wrap=True)
    table.add_column("Type")
    table.add_column("Targets")
    table.add_column("Up", justify="right", no_wrap=True)
    table.add_column("Open", justify="right", no_wrap=True)

    if show_engagements:
        table.add_column("Engagement")

    table.add_column("Notes")

    for summary in summaries:
        notes = []

        if summary.is_baseline:
            notes.append("baseline")

        if summary.incomplete:
            notes.append("incomplete")

        row = [
            str(summary.id),
            summary.started_at.strftime("%Y-%m-%d %H:%M"),
            safe_text(summary.profile),
            safe_text(", ".join(summary.targets)),
            str(summary.hosts_up),
            str(summary.open_ports) if summary.kind == "port_scan" else "-",
        ]

        if show_engagements:
            row.append(safe_text(summary.engagement_name))

        row.append(", ".join(notes))
        table.add_row(*row)

    console.print()
    console.print(table)
    console.print("[dim]Up = hosts that responded. Open = open ports found.[/dim]")


def ask_scan_id(summaries, prompt: str) -> int | None:
    """Ask for one of the listed scan ids. 0 means Back."""
    ids = [summary.id for summary in summaries]
    choice = get_menu_choice(f"{prompt} (scan #, or 0 to go back):", [0] + ids)
    return None if choice == 0 else choice


# ---------- actions ----------

def view_scan(connection, summaries) -> None:
    scan_id = ask_scan_id(summaries, "Which scan do you want to view?")

    if scan_id is None:
        return

    result = load_scan(connection, scan_id)
    show_scan_results(result, detail_limit=None)
    show_assets(result)
    wait_for_enter("Press Enter to continue...")


def view_risk(connection, summaries) -> None:
    scan_id = ask_scan_id(summaries, "Which scan do you want to analyse?")

    if scan_id is None:
        return

    summary = next(item for item in summaries if item.id == scan_id)
    risk_analysis_flow(
        load_scan(connection, scan_id),
        scan_id=scan_id,
        engagement_id=summary.engagement_id,
    )


def view_network_map(connection, summaries) -> None:
    scan_id = ask_scan_id(summaries, "Which scan do you want to map?")

    if scan_id is None:
        return

    show_network_map(build_network_map(load_scan(connection, scan_id)))
    wait_for_enter("Press Enter to continue...")


def run_comparison(connection, older_id: int, newer_id: int) -> None:
    older = load_scan(connection, older_id)
    newer = load_scan(connection, newer_id)

    if older is None or newer is None:
        print("\nOne of those scans no longer exists.")
        return

    # Always compare in time order, whatever order the ids were given in.
    if newer.started_at < older.started_at:
        older, newer = newer, older
        older_id, newer_id = newer_id, older_id

    comparison = compare_scans(older, newer)

    show_comparison(
        comparison,
        f"#{older_id} - {older.profile} - {older.started_at:%d %b %Y %H:%M}",
        f"#{newer_id} - {newer.profile} - {newer.started_at:%d %b %Y %H:%M}",
    )
    show_risk_changes(risk_changes(older, newer))
    wait_for_enter("Press Enter to continue...")


def compare_two(connection, summaries) -> None:
    if len(summaries) < 2:
        print("\nAt least two saved scans are needed for a comparison.")
        return

    first = ask_scan_id(summaries, "First scan to compare")

    if first is None:
        return

    others = [summary for summary in summaries if summary.id != first]
    second = ask_scan_id(others, "Second scan to compare")

    if second is None:
        return

    run_comparison(connection, first, second)


def compare_latest_with_baseline(connection, summaries, session) -> None:
    """Compare the newest scan with the baseline of its engagement."""
    if not summaries:
        print("\nThere are no saved scans yet.")
        return

    latest = summaries[0]
    baseline_id = get_baseline_id(connection, latest.engagement_id)

    if baseline_id is None:
        print(
            "\nNo baseline is set for this scan's engagement. "
            "Choose 'Mark a scan as the baseline' first."
        )
        return

    if baseline_id == latest.id:
        print("\nThe newest scan is the baseline itself, so there is nothing to compare.")
        return

    run_comparison(connection, baseline_id, latest.id)


def mark_baseline(connection, summaries) -> None:
    scan_id = ask_scan_id(summaries, "Which scan should be the baseline?")

    if scan_id is None:
        return

    set_baseline(connection, scan_id)
    print(
        f"\nScan #{scan_id} is now the baseline"
        f"{' for its engagement' if scan_engagement_id(connection, scan_id) else ''}."
    )


def remove_scan(connection, summaries, session) -> None:
    scan_id = ask_scan_id(summaries, "Which scan do you want to delete?")

    if scan_id is None:
        return

    if not ask_yes_no(f"Delete scan #{scan_id} and its evidence permanently?"):
        print("\nNothing was deleted.")
        return

    if delete_scan(connection, scan_id):
        print(f"\nScan #{scan_id} was deleted.")

        if session.scan_id == scan_id:
            session.scan_id = None


# ---------- engagements ----------

def _ask_scope(session) -> list[str]:
    """Ask for the authorized targets. Empty input uses the session's targets."""
    default = list(session.target) if session.is_active else []
    hint = f" (Enter for {', '.join(default)})" if default else ""

    while True:
        raw = get_optional_text(f"Authorized scope: IPs or CIDR ranges, comma separated{hint}:")

        if raw is None:
            if default:
                return default

            print("\nAn engagement needs at least one address or range in scope.")
            continue

        scope, problems = [], []

        for item in (part.strip() for part in raw.split(",")):
            if not item:
                continue

            try:
                scope.append(validate_cidr(item) if "/" in item else validate_ip(item))
            except ValueError as error:
                problems.append(str(error))

        if problems or not scope:
            for problem in problems or ["No addresses were entered."]:
                print(f"- {problem}")
            continue

        return list(dict.fromkeys(scope))


def _ask_date(prompt: str) -> date | None:
    while True:
        raw = get_optional_text(f"{prompt} (YYYY-MM-DD, or Enter to skip):")

        if raw is None:
            return None

        try:
            return date.fromisoformat(raw)
        except ValueError:
            print("\nUse the format YYYY-MM-DD, for example 2026-12-01.")


def new_engagement(connection, session) -> None:
    print("\nNEW ENGAGEMENT")
    print("-" * 35)
    print("Record who authorized this work and what is in scope.")
    print("ARGUS stores this with every scan; it does not enforce it yet.")

    name = get_text_input("Engagement name (for example 'Office LAN - Dec 2026'):")
    authorized_by = get_optional_text("Authorized by (name and role, or Enter to skip):")
    scope = _ask_scope(session)
    starts_on = _ask_date("Start date")
    ends_on = _ask_date("End date")
    notes = get_optional_text("Notes (or Enter to skip):")

    try:
        engagement = create_engagement(
            connection,
            name,
            authorized_by=authorized_by,
            scope=scope,
            starts_on=starts_on,
            ends_on=ends_on,
            notes=notes,
        )
    except StorageError as error:
        console.print(f"\n[bold red]{escape(str(error))}[/bold red]")
        return

    print(f"\nEngagement #{engagement.id} '{engagement.name}' was created.")

    if ask_yes_no("File new scans in this session under it?"):
        session.engagement_id = engagement.id
        session.engagement_name = engagement.name


def choose_engagement(connection, session) -> None:
    engagements = list_engagements(connection)

    if not engagements:
        print("\nNo engagements have been recorded yet.")
        return

    table = Table(title="Engagements", title_justify="left")
    table.add_column("#", justify="right", style="bold")
    table.add_column("Name")
    table.add_column("Authorized by")
    table.add_column("Scope")
    table.add_column("Dates")

    for engagement in engagements:
        dates = " to ".join(
            item.isoformat() for item in (engagement.starts_on, engagement.ends_on) if item
        )
        table.add_row(
            str(engagement.id),
            safe_text(engagement.name),
            safe_text(engagement.authorized_by),
            safe_text(", ".join(engagement.scope or [])),
            dates or "-",
        )

    console.print()
    console.print(table)

    ids = [engagement.id for engagement in engagements]
    choice = get_menu_choice(
        "File new scans under which engagement? (#, or 0 for none):", [0] + ids
    )

    if choice == 0:
        session.engagement_id = None
        session.engagement_name = None
        print("\nNew scans will not be filed under an engagement.")
        return

    chosen = next(item for item in engagements if item.id == choice)
    session.engagement_id = chosen.id
    session.engagement_name = chosen.name
    print(f"\nNew scans will be filed under '{chosen.name}'.")


def engagements_menu(connection, session) -> None:
    while True:
        print("\nENGAGEMENTS")
        print("-" * 35)
        print(f"Current: {session.engagement_name or 'none'}")
        print("1. Create an engagement")
        print("2. Choose the current engagement")
        print("0. Back")

        choice = get_menu_choice("Your next move:", [0, 1, 2])

        if choice == 0:
            return

        if choice == 1:
            new_engagement(connection, session)
        else:
            choose_engagement(connection, session)


# ---------- the Scan History screen ----------

def scan_history_menu(session) -> None:
    connection = open_history()

    if connection is None:
        wait_for_enter("Press Enter to return to the main menu...")
        return

    try:
        while True:
            summaries = list_scans(connection, limit=HISTORY_LIST_LIMIT)

            print("\nSCAN HISTORY")
            print("-" * 35)
            print(f"Database: {default_db_path()}")

            if summaries:
                show_scan_list(summaries)
            else:
                print("No scans have been saved yet. Every scan you run is saved here.")

            print("\n1. View a saved scan (results and assets)")
            print("2. Network map of a saved scan")
            print("3. Risk analysis of a saved scan")
            print("4. Compare two scans")
            print("5. Compare the newest scan with its baseline")
            print("6. Mark a scan as the baseline")
            print("7. Delete a scan")
            print("8. Engagements")
            print("9. Accepted risks")
            print("0. Back")

            choice = get_menu_choice("Your next move:", list(range(0, 10)))

            if choice == 0:
                return

            if choice == 8:
                engagements_menu(connection, session)
                continue

            if choice == 9:
                accepted_risks_menu(connection)
                continue

            if not summaries:
                print("\nThere are no saved scans yet.")
                continue

            if choice == 1:
                view_scan(connection, summaries)
            elif choice == 2:
                view_network_map(connection, summaries)
            elif choice == 3:
                view_risk(connection, summaries)
            elif choice == 4:
                compare_two(connection, summaries)
            elif choice == 5:
                compare_latest_with_baseline(connection, summaries, session)
            elif choice == 6:
                mark_baseline(connection, summaries)
            elif choice == 7:
                remove_scan(connection, summaries, session)

    except StorageError as error:
        console.print(f"\n[bold red]Scan history error:[/bold red] {escape(str(error))}")
        wait_for_enter("Press Enter to return to the main menu...")

    finally:
        connection.close()
