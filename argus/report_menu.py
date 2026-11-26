"""Report screens: generate reports, verify report files, open them."""

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from argus.reports.generate import ReportError, default_reports_dir, generate_reports
from argus.reports.pdf_report import pdf_available
from argus.reports.verify import MODIFIED, VERIFIED, verify_report
from argus.results_display import safe_text
from argus.storage.database import StorageError, connect
from argus.storage.repository import list_reports
from argus.utils.prompts import ask_yes_no, get_menu_choice, get_text_input, wait_for_enter


console = Console()

FORMAT_CHOICES = {
    1: ("Everything (HTML, PDF, JSON and CSV)", ("html", "pdf", "json", "csv")),
    2: ("HTML only (interactive, opens in any browser)", ("html",)),
    3: ("HTML and PDF (for people)", ("html", "pdf")),
    4: ("JSON and CSV (for other tools and spreadsheets)", ("json", "csv")),
}

STATUS_STYLES = {VERIFIED: "bold green", MODIFIED: "bold red"}


def _open_history():
    try:
        return connect()
    except StorageError as error:
        console.print(
            f"\n[yellow]Scan history is unavailable ({escape(str(error))}). The report will "
            "not include history, accepted risks or the engagement, and cannot be verified later.[/yellow]"
        )
        return None


def open_path(path) -> bool:
    """Open a file or folder with the computer's default program."""
    try:
        if os.name == "nt":
            os.startfile(str(path))  # noqa: S606 - opens with the default app
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (OSError, AttributeError):
        return False


def open_reports_folder() -> None:
    folder = default_reports_dir()
    folder.mkdir(parents=True, exist_ok=True)

    if not open_path(folder):
        print(f"\nThe folder could not be opened automatically. It is here:\n{folder}")
    else:
        print(f"\nOpened {folder}")


def show_generated(output) -> None:
    table = Table(title="Report files", title_justify="left")
    table.add_column("Format", style="bold")
    table.add_column("File")
    table.add_column("SHA-256 (first 16)", style="dim")

    for item in output.files:
        table.add_row(item.format.upper(), safe_text(item.path.name), item.sha256[:16])

    console.print()
    console.print(table)
    console.print(f"\nSaved in: [bold]{escape(str(output.folder))}[/bold]")

    if output.redacted:
        console.print("[yellow]Redacted: addresses, hostnames and names are replaced with labels.[/yellow]")

    for warning in output.warnings:
        console.print(f"[yellow]{escape(warning)}[/yellow]")

    console.print(
        "[dim]Fingerprints are in SHA256SUMS in that folder and in the ARGUS database. "
        "Use 'Verify a report file' to check a report has not been changed.[/dim]"
    )


def generate_report_flow(result, scan_id=None, engagement_id=None) -> None:
    """Ask for formats and redaction, then write the report."""
    print("\nGENERATE REPORT")
    print("-" * 35)
    print(f"Reports are saved under: {default_reports_dir()}")

    for number, (label, formats) in FORMAT_CHOICES.items():
        note = "" if "pdf" not in formats or pdf_available() else "  (PDF needs Chrome or Edge)"
        print(f"{number}. {label}{note}")

    print("0. Back")

    choice = get_menu_choice("Which report?", [0, 1, 2, 3, 4])

    if choice == 0:
        return

    formats = FORMAT_CHOICES[choice][1]
    redact = ask_yes_no("Redact addresses, hostnames and names so the report can be shared?")

    connection = _open_history()

    try:
        with console.status("Writing the report..."):
            output = generate_reports(
                result,
                formats,
                connection=connection,
                scan_id=scan_id,
                engagement_id=engagement_id,
                redact=redact,
            )
    except (ReportError, StorageError) as error:
        console.print(f"\n[bold red]The report could not be written:[/bold red] {escape(str(error))}")
        wait_for_enter("Press Enter to continue...")
        return
    finally:
        if connection is not None:
            connection.close()

    show_generated(output)

    html = next((item.path for item in output.files if item.format == "html"), None)
    pdf = next((item.path for item in output.files if item.format == "pdf"), None)
    first = html or pdf

    if first is not None and ask_yes_no(f"Open the {first.suffix[1:].upper()} report now?"):
        if not open_path(first):
            print(f"\nIt could not be opened automatically. It is here:\n{first}")
        return

    wait_for_enter("Press Enter to continue...")


def show_verification(check) -> None:
    style = STATUS_STYLES.get(check.status, "bold yellow")
    labels = {
        VERIFIED: "VERIFIED: this file is exactly as ARGUS wrote it.",
        MODIFIED: "MODIFIED: this file has been changed since ARGUS wrote it.",
    }

    console.print(f"\n[{style}]{labels.get(check.status, 'UNKNOWN: ARGUS has no record of this file.')}[/{style}]")
    console.print(f"[dim]SHA-256: {check.sha256}[/dim]")

    for line in check.details:
        console.print(f"- {escape(line)}")


# ---------- verifying ----------

REPORT_LIST_LIMIT = 20
FORMAT_ORDER = {"html": 0, "pdf": 1, "json": 2, "csv": 3}
MISSING = "missing"


@dataclass
class ReportSet:
    """The files written together by one 'generate report'."""

    folder: Path
    created_at: object
    scan_id: int | None
    redacted: bool
    files: list = field(default_factory=list)

    @property
    def formats(self) -> str:
        names = sorted({item.format for item in self.files}, key=lambda name: FORMAT_ORDER.get(name, 9))
        return ", ".join(name.upper() for name in names)


def group_reports(records) -> list[ReportSet]:
    """Group report files by the folder they were written into, newest first."""
    sets: dict[Path, ReportSet] = {}

    for record in records:
        folder = Path(record.path).parent

        if folder not in sets:
            sets[folder] = ReportSet(folder, record.created_at, record.scan_id, record.redacted)

        sets[folder].files.append(record)

    for item in sets.values():
        item.files.sort(key=lambda record: (FORMAT_ORDER.get(record.format, 9), Path(record.path).name))

    return list(sets.values())


def show_report_list(sets) -> None:
    table = Table(title="Your reports (newest first)", title_justify="left")
    table.add_column("#", justify="right", style="bold")
    table.add_column("Made", no_wrap=True)
    table.add_column("Scan", justify="right")
    table.add_column("Formats")
    table.add_column("Files", justify="right")
    table.add_column("Folder")

    for number, item in enumerate(sets, start=1):
        folder = safe_text(item.folder.name)

        if item.redacted:
            folder.append("  redacted", style="yellow")

        if not item.folder.is_dir():
            folder.append("  (folder deleted)", style="dim")

        table.add_row(
            str(number),
            item.created_at.strftime("%Y-%m-%d %H:%M"),
            f"#{item.scan_id}" if item.scan_id else "-",
            item.formats,
            str(len(item.files)),
            folder,
        )

    console.print()
    console.print(table)


def verify_report_set(item, connection) -> list[tuple[Path, str, object]]:
    """Check every file of one report. Returns (path, status, check or None)."""
    results = []

    for record in item.files:
        path = Path(record.path)

        if not path.is_file():
            results.append((path, MISSING, None))
            continue

        check = verify_report(path, connection)
        results.append((path, check.status, check))

    return results


def show_set_results(item, results) -> None:
    table = Table(title=f"Checking {item.folder.name}", title_justify="left")
    table.add_column("File")
    table.add_column("Result")
    table.add_column("SHA-256 (first 16)", style="dim")

    labels = {
        VERIFIED: ("VERIFIED", "bold green"),
        MODIFIED: ("MODIFIED", "bold red"),
        MISSING: ("MISSING", "yellow"),
    }

    for path, status, check in results:
        label, style = labels.get(status, ("UNKNOWN", "bold yellow"))
        table.add_row(safe_text(path.name), f"[{style}]{label}[/{style}]", check.sha256[:16] if check else "-")

    console.print()
    console.print(table)

    modified = sum(1 for _, status, _ in results if status == MODIFIED)
    missing = sum(1 for _, status, _ in results if status == MISSING)
    verified = sum(1 for _, status, _ in results if status == VERIFIED)

    if modified:
        console.print(f"[bold red]{modified} file(s) were changed after ARGUS wrote them. Do not trust their contents.[/bold red]")
    if missing:
        console.print(f"[yellow]{missing} file(s) were moved or deleted, so they could not be checked.[/yellow]")
    if verified == len(results):
        console.print(f"[green]All {verified} file(s) are exactly as ARGUS wrote them.[/green]")


def verify_path_flow(connection=None) -> None:
    """Check any file by its path, such as a report someone sent you."""
    raw = get_text_input("Path of the report file to verify:")
    path = raw.strip().strip('"').strip("'")   # Windows "Copy as path" adds quotes

    try:
        check = verify_report(path, connection)
    except FileNotFoundError:
        console.print(f"\n[bold red]No such file:[/bold red] {escape(path)}")
        return

    show_verification(check)


def _ask_report_choice(count: int) -> str | int:
    """A report number, 'p' for a path, or 0 for back."""
    while True:
        raw = get_text_input(
            f"Report to verify (1-{count}), P to type a file path, or 0 to go back:"
        ).strip().lower()

        if raw in ("p", "path"):
            return "p"

        if raw.isdigit() and 0 <= int(raw) <= count:
            return int(raw)

        print(f"\nEnter a number from 0 to {count}, or P.")


def verify_report_flow() -> None:
    """Show the saved reports and verify the one the user picks."""
    connection = _open_history()

    try:
        if connection is None:
            verify_path_flow(None)
            wait_for_enter("Press Enter to continue...")
            return

        sets = group_reports(list_reports(connection))[:REPORT_LIST_LIMIT]

        print("\nVERIFY A REPORT")
        print("-" * 35)

        if not sets:
            print("ARGUS has not made any reports on this computer yet.")

            if ask_yes_no("Check a report file by its path instead?"):
                verify_path_flow(connection)

            wait_for_enter("Press Enter to continue...")
            return

        show_report_list(sets)
        choice = _ask_report_choice(len(sets))

        if choice == 0:
            return

        if choice == "p":
            verify_path_flow(connection)
        else:
            item = sets[choice - 1]
            show_set_results(item, verify_report_set(item, connection))

        wait_for_enter("Press Enter to continue...")

    finally:
        if connection is not None:
            connection.close()
