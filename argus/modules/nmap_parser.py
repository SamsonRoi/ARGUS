"""Turn python-nmap results into ARGUS models.

Every scanning module (discovery, port scan, service detection, OS
estimation) hands its python-nmap scanner to hosts_from_scanner(), so the
conversion logic lives in exactly one place.
"""

from argus.modules.models import HostInfo, OSGuess, PortInfo


PROTOCOLS = ("tcp", "udp")

# Nmap explains why it believes a host is up. These are plain-English versions.
# "user-set" is missing on purpose: it only means we skipped discovery.
REASON_TEXT = {
    "arp-response": "ARP reply",
    "echo-reply": "ICMP echo reply",
    "timestamp-reply": "ICMP timestamp reply",
    "netmask-reply": "ICMP netmask reply",
    "syn-ack": "TCP SYN/ACK reply",
    "reset": "TCP reset reply",
    "conn-refused": "TCP connection refused",
    "udp-response": "UDP reply",
    "port-unreach": "ICMP port unreachable",
    "localhost-response": "Local machine",
}


def describe_reason(reason: str | None) -> str | None:
    """Turn an Nmap 'reason' into readable text, or None if it says nothing."""
    cleaned = _clean(reason)

    if cleaned is None or cleaned == "user-set":
        return None

    return REASON_TEXT.get(cleaned, cleaned)


def _clean(value) -> str | None:
    """Strip text. Nmap uses empty strings for 'unknown', so return None for those."""
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _hostname(host_data) -> str | None:
    for entry in host_data.get("hostnames", []):
        name = _clean(entry.get("name"))

        if name:
            return name

    return None


def _ports(host_data) -> list[PortInfo]:
    ports = []

    for protocol in PROTOCOLS:
        for number, details in host_data.get(protocol, {}).items():
            try:
                ports.append(
                    PortInfo(
                        port=int(number),
                        protocol=protocol,
                        state=_clean(details.get("state")) or "unknown",
                        service=_clean(details.get("name")),
                        product=_clean(details.get("product")),
                        version=_clean(details.get("version")),
                        extra_info=_clean(details.get("extrainfo")),
                    )
                )

            except (TypeError, ValueError):
                # A malformed entry should not break the whole scan.
                continue

    return ports


def _best_os_guess(host_data) -> OSGuess | None:
    best = None

    for match in host_data.get("osmatch", []):
        name = _clean(match.get("name"))

        try:
            accuracy = int(match.get("accuracy", 0))
        except (TypeError, ValueError):
            continue

        if name is None:
            continue

        accuracy = max(0, min(100, accuracy))

        if best is None or accuracy > best.accuracy:
            best = OSGuess(name=name, accuracy=accuracy)

    return best


def hosts_from_scanner(scanner) -> list[HostInfo]:
    """Convert everything a python-nmap scanner found into HostInfo objects."""
    hosts = []

    for ip in scanner.all_hosts():
        data = scanner[ip]
        status = data.get("status", {})

        mac = _clean(data.get("addresses", {}).get("mac"))
        vendor = _clean(data.get("vendor", {}).get(mac)) if mac else None

        host = HostInfo(
            ip=ip,
            state=_clean(status.get("state")) or "unknown",
            hostname=_hostname(data),
            mac=mac,
            vendor=vendor,
            discovery_method=describe_reason(status.get("reason")),
            os_guess=_best_os_guess(data),
        )

        for port in _ports(data):
            host.add_port(port)

        hosts.append(host)

    return hosts


def get_scanner_version(scanner) -> str | None:
    """Return the Nmap version the scanner used, for example '7.993'."""
    try:
        major, minor = scanner.nmap_version()
        return f"{major}.{minor}"

    except (AttributeError, TypeError, ValueError):
        return None