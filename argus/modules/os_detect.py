"""Operating system estimation.

Nmap compares how a host answers unusual network packets with a database of
known systems. The result is an ESTIMATE: the family (for example Linux or
Windows) is often right, but the exact version can be wrong, and sometimes
Nmap cannot guess at all.
"""

import ipaddress

from argus.modules.models import HostInfo
from argus.modules.evidence import ScanEvidence
from argus.modules.nmap_parser import hosts_from_scanner
from argus.modules.nmap_runner import run_scan, validate_targets


OS_TIMEOUT = 900


def is_loopback(target: str) -> bool:
    """Return True for 127.x.x.x addresses (the machine ARGUS runs on)."""
    return ipaddress.ip_network(target, strict=False).is_loopback


def build_os_arguments() -> str:
    """Build the Nmap options for OS estimation.

    -O turns on OS detection (needs Administrator/root).
    --osscan-limit skips hosts where Nmap does not have enough to work with.
    --top-ports 100 gives Nmap some open and closed ports to compare.
    """
    return "-O --osscan-limit --top-ports 100 -Pn -T3"


def estimate_os(
    ips: list[str],
    evidence: ScanEvidence | None = None,
) -> list[HostInfo]:
    """Estimate the operating system of each host.

    Loopback addresses are skipped, because the local machine cannot be
    fingerprinted this way. Hosts Nmap cannot estimate come back without
    an os_guess.
    """
    clean_ips = validate_targets(ips)
    scannable = [ip for ip in clean_ips if not is_loopback(ip)]

    if not scannable:
        return []

    scanner = run_scan(
        scannable,
        build_os_arguments(),
        timeout=OS_TIMEOUT,
    )

    if evidence is not None:
        evidence.record("os_estimation", scanner, coverage=False)

    return hosts_from_scanner(scanner)