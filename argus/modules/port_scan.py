"""TCP and UDP port scanning.

Open ports are reported as Nmap sees them. A port that is closed, or that
a firewall hides, is not reported as open, and UDP results marked
"open|filtered" mean "Nmap cannot tell", not "open".
"""

import ipaddress
import re
from dataclasses import dataclass

from argus.modules.models import HostInfo
from argus.modules.nmap_parser import hosts_from_scanner
from argus.modules.nmap_runner import (
    InvalidScanRequestError,
    is_privileged,
    run_scan,
    validate_targets,
)


@dataclass(frozen=True)
class ScanProfile:
    """A ready-made TCP scan, so users pick a number instead of typing flags."""

    key: str
    label: str
    description: str
    ports: str | None
    extra_arguments: str
    timeout: int


TCP_PROFILES = {
    profile.key: profile
    for profile in (
        ScanProfile(
            "quick",
            "Quick",
            "The 100 most common TCP ports.",
            None,
            "--top-ports 100",
            300,
        ),
        ScanProfile(
            "standard",
            "Standard",
            "The 1,000 most common TCP ports (Nmap's own default).",
            None,
            "--top-ports 1000",
            900,
        ),
        ScanProfile(
            "full",
            "Full TCP",
            "All 65,535 TCP ports. Thorough, but slow.",
            "1-65535",
            "",
            3600,
        ),
    )
}

# A short list of UDP services that are commonly exposed:
# DNS, DHCP, TFTP, NTP, NetBIOS, SNMP, IKE/IPsec, syslog, SSDP, mDNS.
UDP_PORTS = "53,67,69,123,137,161,500,514,1900,5353"
UDP_TIMEOUT = 900


def validate_port_spec(spec: str) -> str:
    """Check a port list such as '80', '22,80,443' or '1-1024'. Return it cleaned."""
    cleaned = spec.replace(" ", "")

    if not cleaned:
        raise InvalidScanRequestError("The port list cannot be empty.")

    for part in cleaned.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(-[0-9]{1,5})?", part):
            raise InvalidScanRequestError(
                f"Invalid port entry: {part or '(empty)'}"
            )

        numbers = [int(number) for number in part.split("-")]

        if any(not 1 <= number <= 65535 for number in numbers):
            raise InvalidScanRequestError(
                f"Ports must be between 1 and 65535: {part}"
            )

        if len(numbers) == 2 and numbers[0] > numbers[1]:
            raise InvalidScanRequestError(f"Port range is backwards: {part}")

    return cleaned


def choose_tcp_scan_flag(ips: list[str], privileged: bool | None = None) -> str:
    """Pick the TCP scan type.

    -sS (SYN scan) is faster and quieter but needs Administrator/root.
    -sT (connect scan) works for everyone. Windows cannot SYN-scan its own
    machine, so loopback targets always use -sT.
    """
    if privileged is None:
        privileged = is_privileged()

    if not privileged:
        return "-sT"

    for target in ips:
        if ipaddress.ip_network(target, strict=False).is_loopback:
            return "-sT"

    return "-sS"


def build_tcp_arguments(
    ips: list[str],
    extra_arguments: str,
    privileged: bool | None = None,
) -> str:
    """Build the Nmap options for a TCP port scan.

    -Pn skips discovery: the caller already chose exactly which hosts to scan.
    --open reports only ports that are open.
    """
    flag = choose_tcp_scan_flag(ips, privileged)
    parts = (flag, "-Pn", "--open", extra_arguments)

    return " ".join(part for part in parts if part)


def scan_tcp_ports(
    ips: list[str],
    profile_key: str = "standard",
    ports: str | None = None,
) -> list[HostInfo]:
    """Scan TCP ports on the given hosts. Custom ports override the profile.

    Only hosts with something to report come back. A host with no open ports
    is simply absent from the list. That does NOT mean the host is down.
    """
    profile = TCP_PROFILES.get(profile_key)

    if profile is None:
        raise InvalidScanRequestError(f"Unknown scan profile: {profile_key}")

    clean_ips = validate_targets(ips)

    if ports:
        port_spec = validate_port_spec(ports)
        extra_arguments = ""
    else:
        port_spec = profile.ports
        extra_arguments = profile.extra_arguments

    scanner = run_scan(
        clean_ips,
        build_tcp_arguments(clean_ips, extra_arguments),
        ports=port_spec,
        timeout=profile.timeout,
    )

    return hosts_from_scanner(scanner)


def build_udp_arguments() -> str:
    """Build the Nmap options for a UDP scan.

    UDP is slow because silence is normal. Two retries is a balance between
    speed and missing ports.
    """
    return "-sU -Pn --open -T3 --max-retries 2"


def scan_udp_ports(
    ips: list[str],
    ports: str | None = None,
) -> list[HostInfo]:
    """Scan a short list of important UDP ports. Needs Administrator/root."""
    clean_ips = validate_targets(ips)
    port_spec = validate_port_spec(ports) if ports else UDP_PORTS

    scanner = run_scan(
        clean_ips,
        build_udp_arguments(),
        ports=port_spec,
        timeout=UDP_TIMEOUT,
    )

    return hosts_from_scanner(scanner)