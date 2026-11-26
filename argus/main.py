"""ARGUS entry point.

    argus                         interactive menus
    argus scans                   list saved scans
    argus report 12               write every report format for scan #12
    argus report --latest -f html,pdf --redact --out ./reports
    argus verify report.html      check a report file has not been changed
"""

import argparse
import sys

from rich.console import Console
from rich.markup import escape

from argus import __version__


console = Console()

EXIT_OK = 0
EXIT_MODIFIED = 1
EXIT_UNKNOWN = 2
EXIT_ERROR = 3


def interactive() -> int:
    from argus.banner import show_banner
    from argus.menus import main_menu

    console.clear()
    show_banner(version=__version__, clear=False)
    main_menu()
    return EXIT_OK


def command_scans(args) -> int:
    from argus.history_menu import show_scan_list
    from argus.storage.database import connect
    from argus.storage.repository import list_scans

    connection = connect()

    try:
        summaries = list_scans(connection, limit=args.limit)
    finally:
        connection.close()

    if not summaries:
        console.print("No scans have been saved yet.")
        return EXIT_OK

    show_scan_list(summaries)
    return EXIT_OK


def _parse_formats(text: str) -> tuple[str, ...]:
    from argus.reports.generate import FORMATS

    chosen = [item.strip().lower() for item in text.split(",") if item.strip()]
    chosen = list(FORMATS) if chosen == ["all"] else chosen
    unknown = sorted(set(chosen) - set(FORMATS))

    if unknown or not chosen:
        raise argparse.ArgumentTypeError(
            f"choose from {', '.join(FORMATS)} or 'all' (got: {text})"
        )

    return tuple(dict.fromkeys(chosen))


def command_report(args) -> int:
    from argus.report_menu import show_generated
    from argus.reports.generate import ReportError, generate_reports
    from argus.storage.database import StorageError, connect
    from argus.storage.repository import list_scans, load_scan, scan_engagement_id

    connection = connect()

    try:
        scan_id = args.scan_id

        if args.latest:
            latest = list_scans(connection, limit=1)

            if not latest:
                console.print("[red]No scans have been saved yet.[/red]")
                return EXIT_ERROR

            scan_id = latest[0].id

        result = load_scan(connection, scan_id)

        if result is None:
            console.print(f"[red]There is no saved scan #{scan_id}. Run 'argus scans' to list them.[/red]")
            return EXIT_ERROR

        output = generate_reports(
            result,
            args.format,
            connection=connection,
            scan_id=scan_id,
            engagement_id=scan_engagement_id(connection, scan_id),
            out_dir=args.out,
            redact=args.redact,
        )

    except (ReportError, StorageError) as error:
        console.print(f"[red]The report could not be written: {escape(str(error))}[/red]")
        return EXIT_ERROR

    finally:
        connection.close()

    console.print(f"Report for scan #{scan_id}:")
    show_generated(output)
    return EXIT_OK


def command_verify(args) -> int:
    from argus.report_menu import show_verification
    from argus.reports.verify import MODIFIED, VERIFIED, verify_report
    from argus.storage.database import StorageError, connect

    try:
        connection = connect()
    except StorageError:
        connection = None

    worst = EXIT_OK

    try:
        for path in args.files:
            try:
                check = verify_report(path, connection)
            except FileNotFoundError:
                console.print(f"\n[red]No such file: {escape(path)}[/red]")
                worst = max(worst, EXIT_ERROR)
                continue

            console.print(f"\n[bold]{escape(path)}[/bold]")
            show_verification(check)

            if check.status == MODIFIED:
                worst = max(worst, EXIT_MODIFIED)
            elif check.status != VERIFIED:
                worst = max(worst, EXIT_UNKNOWN)
    finally:
        if connection is not None:
            connection.close()

    return worst


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="ARGUS - Network Attack Surface Mapper. Run without a command for the interactive menus.",
    )
    parser.add_argument("--version", action="version", version=f"ARGUS {__version__}")
    commands = parser.add_subparsers(dest="command")

    scans = commands.add_parser("scans", help="list saved scans")
    scans.add_argument("--limit", type=int, default=20, help="how many scans to list (default 20)")
    scans.set_defaults(handler=command_scans)

    report = commands.add_parser("report", help="write reports for a saved scan")
    which = report.add_mutually_exclusive_group(required=True)
    which.add_argument("scan_id", nargs="?", type=int, help="the scan number (see 'argus scans')")
    which.add_argument("--latest", action="store_true", help="use the newest saved scan")
    report.add_argument("-f", "--format", type=_parse_formats, default=_parse_formats("all"),
                        help="comma-separated: json,csv,html,pdf or all (default all)")
    report.add_argument("-o", "--out", help="folder to write into (default: ~/ARGUS-reports)")
    report.add_argument("--redact", action="store_true",
                        help="replace addresses, hostnames and names with labels, for sharing")
    report.set_defaults(handler=command_report)

    verify = commands.add_parser("verify", help="check report files have not been changed")
    verify.add_argument("files", nargs="+", help="report files to check")
    verify.set_defaults(handler=command_verify)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.command is None:
        return interactive()

    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
