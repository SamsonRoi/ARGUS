"""Scan setup and execution screens."""

import ipaddress

from rich.console import Console
from rich.markup import escape

from argus.modules.discovery import (
    DISCOVERY_METHODS,
    DEFAULT_METHODS,
    discover_hosts,
)
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


CUSTOM_PORTS = "custom"
DISCOVERY = "discovery"


def scanning_menu_entries() -> list[tuple[str, str]]:
    """The scanning menu as (label, action) pairs, in display order.

    Menu numbers come from this list, so adding a TCP profile never shifts
    the meaning of another option.
    """
    entries = [("Host Discovery - Find which hosts respond (no port scan)", DISCOVERY)]

    for profile in TCP_PROFILES.values():
        entries.append((f"{profile.label} - {profile.description}", profile.key))

    entries.append(("Custom ports - Choose your own TCP ports", CUSTOM_PORTS))

    return entries


def ask_custom_ports() -> str:
    """Ask for a port list until it is valid."""
    while True:
        raw_ports = get_text_input(
            "Enter ports (for example 22,80,443 or 1-1024):"
        )

        try:
            return validate_port_spec(raw_ports)

        except InvalidScanRequestError as error:
            print(f"\n{error}")


def ask_scanning_choice() -> tuple[str, str | None] | None:
    """Ask which scanning operation to run.

    Returns ("discovery", None), (profile_key, None), ("standard", ports)
    for custom ports, or None for Back.
    """
    entries = scanning_menu_entries()

    print("\nSCANNING OPTIONS")
    print("-" * 35)

    for number, (label, _action) in enumerate(entries, start=1):
        print(f"{number}. {label}")

    print("0. Back")

    choice = get_menu_choice(
        "Your next move:",
        list(range(0, len(entries) + 1)),
    )

    if choice == 0:
        return None

    action = entries[choice - 1][1]

    if action == DISCOVERY:
        return DISCOVERY, None

    if action == CUSTOM_PORTS:
        # Custom ports override the profile's port list, so the profile
        # key only acts as a placeholder here.
        return "standard", ask_custom_ports()

    return action, None


def ask_scan_options(
    selection: tuple[str, str | None],
) -> ScanOptions:
    """Ask for optional extras after a TCP scan profile is selected."""

    profile_key, ports = selection

    privileged = is_privileged()
    admin_note = "" if privileged else " (needs Administrator)"

    print("\nOPTIONAL EXTRAS")

    service_detection = ask_yes_no(
        "Identify service versions on open ports?"
    )
    udp_scan = ask_yes_no(
        f"Scan common UDP ports?{admin_note}"
    )
    os_estimation = ask_yes_no(
        f"Estimate operating systems?{admin_note}"
    )

    discovery_methods = None

    if not ask_yes_no("Use the recommended host discovery methods?"):
        discovery_methods = choose_methods_manually()

        if discovery_methods is None:
            print("Using the recommended discovery methods instead.")

    return ScanOptions(
        profile_key=profile_key,
        ports=ports,
        service_detection=service_detection,
        udp_scan=udp_scan,
        os_estimation=os_estimation,
        discovery_methods=discovery_methods,
    )


def ask_discovery_methods() -> list[str] | None:
    """Let the user choose discovery methods."""

    print("\nHOST DISCOVERY METHODS")
    print("-" * 35)
    print("1. Recommended methods")
    print("2. Choose methods manually")
    print("0. Back")

    choice = get_menu_choice(
        "Your next move:",
        [0, 1, 2],
    )

    if choice == 0:
        return None

    if choice == 1:
        return list(DEFAULT_METHODS)

    return choose_methods_manually()


def choose_methods_manually() -> list[str] | None:
    """Let the user toggle discovery methods on and off.

    Returns the chosen method keys, or None if none were chosen.
    """
    selected = []
    method_keys = list(DISCOVERY_METHODS)

    while True:
        print("\nSELECT METHODS")
        print("-" * 35)

        for number, key in enumerate(method_keys, start=1):
            method = DISCOVERY_METHODS[key]
            marker = " [selected]" if key in selected else ""

            print(f"{number}. {method.label}{marker}")
            print(f"   {method.description}")

        print("0. Done")

        choice = get_menu_choice(
            "Your next move:",
            [0] + list(range(1, len(method_keys) + 1)),
        )

        if choice == 0:
            break

        key = method_keys[choice - 1]

        if key in selected:
            selected.remove(key)
        else:
            selected.append(key)

    if not selected:
        print("\nNo discovery methods selected.")
        return None

    return selected


def run_discovery_flow(session) -> None:
    """Run host discovery independently of TCP port scanning."""

    targets = list(session.target)

    show_scope_check(targets)

    methods = ask_discovery_methods()

    if methods is None:
        print("\nHost discovery cancelled.")
        return

    print("\nDISCOVERY PLAN")
    print("-" * 35)
    print(f"Targets: {', '.join(targets)}")
    print("Operation: Host discovery only")
    print("Port scanning: Disabled")
    print(
        "\nNote: a host that does not answer is not proven offline. "
        "Firewalls often block discovery probes."
    )

    if not ask_yes_no("Start host discovery now?"):
        print("\nHost discovery not started.")
        return

    console.print("\n[dim]Press Ctrl+C to cancel discovery.[/dim]")

    try:
        with console.status("Discovering hosts..."):
            result = discover_hosts(
                targets,
                methods=methods,
            )

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Host discovery was cancelled. "
            "No results were saved.[/yellow]"
        )
        wait_for_enter("Press Enter to continue...")
        return

    except ScannerError as error:
        console.print(
            f"\n[bold red]Host discovery could not run:[/bold red] "
            f"{escape(str(error))}"
        )
        wait_for_enter("Press Enter to continue...")
        return

    session.scan_result = result

    show_scan_results(result)
    wait_for_enter("Press Enter to continue...")


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
    """Choose and execute a scanning operation."""

    if not session.is_active:
        print("\nNo targets are stored. Choose a target first.")
        return

    selection = ask_scanning_choice()

    if selection is None:
        print("\nScanning setup cancelled.")
        return

    if selection[0] == "discovery":
        run_discovery_flow(session)
        return

    targets = list(session.target)

    show_scope_check(targets)

    options = ask_scan_options(selection)

    show_scan_plan(targets, options)

    if not ask_yes_no("Start the scan now?"):
        print("\nScan not started.")
        return

    try:
        result = run_with_progress(targets, options)

    except ScannerError as error:
        console.print(
            f"\n[bold red]The scan could not run:[/bold red] "
            f"{escape(str(error))}"
        )
        wait_for_enter("Press Enter to continue...")
        return

    session.scan_result = result

    show_scan_results(result)
    wait_for_enter("Press Enter to continue...")
