"""Scan setup and execution screens."""

import ipaddress

from rich.console import Console
from rich.markup import escape

from argus.modules.nmap_runner import (
    InvalidScanRequestError,
    ScannerError,
    is_privileged,
)
from argus.modules.port_scan import TCP_PROFILES, validate_port_spec
from argus.modules.scan_manager import ScanOptions, run_scan_pipeline
from argus.results_display import show_scan_results
from argus.utils.prompts import (
    ask_yes_no,
    get_menu_choice,
    get_text_input,
    wait_for_enter,
)
from argus.utils.validators import get_scope_warnings


console = Console()


def describe_target(target: str) -> str:
    """Show a target, with the size of a network range."""
    if "/" in target:
        size = ipaddress.ip_network(target, strict=False).num_addresses
        return f"{target} ({size:,} addresses)"

    return target


def show_scope_check(targets: list[str]) -> None:
    """Show the targets and any scope warnings right before a scan."""
    print("\nSCOPE CHECK")
    print("-" * 35)

    for target in targets:
        print(f"Target: {describe_target(target)}")

    warnings_found = False

    for target in targets:
        for warning in get_scope_warnings(target):
            warnings_found = True
            print(f"\n[WARNING] {target}: {warning}")

    print("\nARGUS does not check whether you are authorized.")
    print("Only scan targets you own or have permission to assess.")

    if warnings_found:
        print("The warnings above do not confirm authorization.")


def ask_tcp_choice() -> tuple[str, str | None] | None:
    """Ask which TCP scan to run. Returns (profile_key, custom_ports) or None for Back."""
    profiles = list(TCP_PROFILES.values())
    custom_choice = len(profiles) + 1

    print("\nTCP PORT SCAN")

    for number, profile in enumerate(profiles, start=1):
        print(f"{number}. {profile.label} - {profile.description}")

    print(f"{custom_choice}. Custom ports")
    print("0. Back")

    choice = get_menu_choice(
        "Your next move:",
        [0] + list(range(1, custom_choice + 1)),
    )

    if choice == 0:
        return None

    if choice == custom_choice:
        while True:
            raw_ports = get_text_input(
                "Enter ports (for example 22,80,443 or 1-1024):"
            )

            try:
                return "standard", validate_port_spec(raw_ports)

            except InvalidScanRequestError as error:
                print(f"\n{error}")

    return profiles[choice - 1].key, None


def ask_scan_options() -> ScanOptions | None:
    """Ask the user what to run. Returns None if they chose Back."""
    selection = ask_tcp_choice()

    if selection is None:
        return None

    profile_key, ports = selection
    privileged = is_privileged()
    admin_note = "" if privileged else " (needs Administrator)"

    print("\nOPTIONAL EXTRAS")

    service_detection = ask_yes_no("Identify service versions on open ports?")
    udp_scan = ask_yes_no(f"Scan common UDP ports?{admin_note}")
    os_estimation = ask_yes_no(f"Estimate operating systems?{admin_note}")

    return ScanOptions(
        profile_key=profile_key,
        ports=ports,
        service_detection=service_detection,
        udp_scan=udp_scan,
        os_estimation=os_estimation,
    )


def show_scan_plan(targets: list[str], options: ScanOptions) -> None:
    """Summarize what is about to run."""
    privileged = is_privileged()

    print("\nSCAN PLAN")
    print("-" * 35)
    print(f"Targets: {', '.join(targets)}")
    print(f"Scan:    {options.describe()}")
    print(f"Running as Administrator/root: {'Yes' if privileged else 'No'}")

    if not privileged and (options.udp_scan or options.os_estimation):
        print(
            "\nNote: UDP scanning and OS estimation need Administrator. "
            "Without it, those steps will fail and be reported as warnings."
        )


def run_with_progress(targets: list[str], options: ScanOptions):
    """Run the scan while showing which step is running."""
    console.print("\n[dim]Press Ctrl+C to cancel the scan.[/dim]")

    with console.status("Starting scan...") as status:

        def progress(step: int, total: int, label: str) -> None:
            status.update(
                f"[bold cyan]Step {step}/{total}:[/bold cyan] {escape(label)}..."
            )

        return run_scan_pipeline(targets, options, progress)


def run_scan_flow(session) -> None:
    """The full scan screen: check scope, choose options, confirm, run, show results."""
    if not session.is_active:
        print("\nNo targets are stored. Choose a target first.")
        return

    targets = list(session.target)

    show_scope_check(targets)

    options = ask_scan_options()

    if options is None:
        print("\nScan setup cancelled.")
        return

    show_scan_plan(targets, options)

    if not ask_yes_no("Start the scan now?"):
        print("\nScan not started.")
        return

    try:
        result = run_with_progress(targets, options)

    except ScannerError as error:
        console.print(
            f"\n[bold red]The scan could not run:[/bold red] {escape(str(error))}"
        )
        wait_for_enter("Press Enter to continue...")
        return

    session.scan_result = result

    show_scan_results(result)
    wait_for_enter("Press Enter to continue...")