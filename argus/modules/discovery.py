"""Host discovery: find out which hosts respond.

Discovery only asks "is anything there?". It does not scan ports.
A host that does not answer is not listed, and silence does not prove a
host is offline: firewalls often block these probes.
"""

from dataclasses import dataclass

from argus.modules.models import ScanResult
from argus.modules.nmap_parser import get_scanner_version, hosts_from_scanner
from argus.modules.nmap_runner import (
    InvalidScanRequestError,
    is_privileged,
    run_scan,
    validate_targets,
)


@dataclass(frozen=True)
class DiscoveryMethod:
    """One way of checking whether a host is there."""

    key: str
    label: str
    argument: str
    needs_privileges: bool
    description: str


DISCOVERY_METHODS = {
    method.key: method
    for method in (
        DiscoveryMethod(
            "arp",
            "ARP ping",
            "-PR",
            True,
            "Asks 'who has this address?' on the local network. Very reliable, "
            "but only works on the same network segment.",
        ),
        DiscoveryMethod(
            "icmp",
            "ICMP echo ping",
            "-PE",
            True,
            "The classic ping. Many firewalls block it.",
        ),
        DiscoveryMethod(
            "tcp_syn",
            "TCP SYN ping",
            "-PS22,80,443",
            False,
            "Tries to start a TCP connection on common ports. Any reply, "
            "even a refusal, shows that a host is there.",
        ),
        DiscoveryMethod(
            "tcp_ack",
            "TCP ACK ping",
            "-PA80,443",
            True,
            "Sends an unexpected TCP packet. Can get through some simple "
            "firewalls that block pings.",
        ),
        DiscoveryMethod(
            "udp",
            "UDP ping",
            "-PU",
            True,
            "Sends a UDP packet to an unlikely port, hoping for an error reply.",
        ),
    )
}

# UDP ping is opt-in because it is slow and often silent.
DEFAULT_METHODS = ("arp", "icmp", "tcp_syn", "tcp_ack")


def select_methods(
    requested: list[str] | None,
    privileged: bool,
) -> tuple[list[DiscoveryMethod], list[str]]:
    """Choose the discovery methods to use, and explain any that were dropped.

    Without Administrator/root rights, methods that need raw packets cannot
    run properly, so they are skipped and the user is told.
    """
    keys = list(requested) if requested is not None else list(DEFAULT_METHODS)

    if not keys:
        raise InvalidScanRequestError("At least one discovery method is required.")

    unknown = [key for key in keys if key not in DISCOVERY_METHODS]

    if unknown:
        raise InvalidScanRequestError(
            f"Unknown discovery method: {', '.join(unknown)}"
        )

    # dict.fromkeys removes duplicates and keeps the original order.
    methods = [DISCOVERY_METHODS[key] for key in dict.fromkeys(keys)]
    warnings = []

    if not privileged:
        skipped = [method for method in methods if method.needs_privileges]
        methods = [method for method in methods if not method.needs_privileges]

        if skipped:
            names = ", ".join(method.label for method in skipped)
            warnings.append(
                f"ARGUS is not running as Administrator/root, so these methods "
                f"were skipped: {names}. Some hosts may be missed."
            )

        if not methods:
            methods = [DISCOVERY_METHODS["tcp_syn"]]
            warnings.append("TCP SYN ping was used instead.")

    return methods, warnings


def build_discovery_arguments(methods: list[DiscoveryMethod]) -> str:
    """Build the Nmap options for a discovery-only scan (-sn: no port scan)."""
    return " ".join(["-sn"] + [method.argument for method in methods])


def discover_hosts(
    targets: list[str],
    methods: list[str] | None = None,
    timeout: int = 600,
    privileged: bool | None = None,
) -> ScanResult:
    """Find which of the targets respond, and return them as a ScanResult."""
    clean_targets = validate_targets(targets)

    if privileged is None:
        privileged = is_privileged()

    chosen, warnings = select_methods(methods, privileged)

    result = ScanResult(
        targets=clean_targets,
        profile="discovery",
        warnings=warnings,
    )

    scanner = run_scan(
        clean_targets,
        build_discovery_arguments(chosen),
        timeout=timeout,
    )

    result.nmap_version = get_scanner_version(scanner)

    for host in hosts_from_scanner(scanner):
        result.add_host(host)

    result.finish()

    return result