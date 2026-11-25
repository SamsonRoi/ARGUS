"""Service and version detection.

Nmap connects to ports that are already known to be open and reads what the
service announces about itself. That information can be wrong, outdated or
hidden on purpose, so treat it as a clue, not a fact.
"""

from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo
from argus.modules.nmap_parser import hosts_from_scanner
from argus.modules.nmap_runner import InvalidScanRequestError, run_scan
from argus.modules.port_scan import choose_tcp_scan_flag


MIN_INTENSITY = 0
MAX_INTENSITY = 9
DEFAULT_INTENSITY = 7  # Nmap's own default
SERVICE_TIMEOUT = 900


def collect_open_tcp_ports(hosts: list[HostInfo]) -> list[int]:
    """Return every open TCP port across the hosts, without duplicates, sorted."""
    ports = set()

    for host in hosts:
        for port in host.open_ports:
            if port.protocol == "tcp":
                ports.add(port.port)

    return sorted(ports)


def build_service_arguments(
    ips: list[str],
    intensity: int,
    privileged: bool | None = None,
) -> str:
    """Build the Nmap options for version detection (-sV).

    Intensity runs from 0 (lightest, fewest probes) to 9 (try everything).
    """
    flag = choose_tcp_scan_flag(ips, privileged)

    return f"{flag} -Pn --open -sV --version-intensity {intensity}"


def detect_services(
    hosts: list[HostInfo],
    intensity: int = DEFAULT_INTENSITY,
    evidence: ScanEvidence | None = None,
) -> list[HostInfo]:
    """Identify the services on the open TCP ports of the given hosts."""
    if (
        not isinstance(intensity, int)
        or isinstance(intensity, bool)
        or not MIN_INTENSITY <= intensity <= MAX_INTENSITY
    ):
        raise InvalidScanRequestError(
            f"Intensity must be a whole number from {MIN_INTENSITY} to {MAX_INTENSITY}."
        )

    ips = [
        host.ip
        for host in hosts
        if any(port.protocol == "tcp" for port in host.open_ports)
    ]

    ports = collect_open_tcp_ports(hosts)

    if not ips or not ports:
        return []

    scanner = run_scan(
        ips,
        build_service_arguments(ips, intensity),
        ports=",".join(str(port) for port in ports),
        timeout=SERVICE_TIMEOUT,
    )

    if evidence is not None:
        evidence.record("service_detection", scanner, coverage=False)

    return hosts_from_scanner(scanner)