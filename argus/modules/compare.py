"""Compare two scans and list what changed.

The comparison is careful about what each scan actually checked:

* A port is only reported as closed if the newer scan checked that port.
  If it did not, the port is listed as "not re-checked" instead.
* A port that is open now but was never checked before is "first checked",
  not "newly opened": it may have been open all along.
* A host is only reported as missing if the newer scan's targets included
  its address, and only reported as new if the older scan's did.

Hosts are matched by MAC address when both scans saw one, and by IP address
otherwise. A MAC match with a different IP is reported as an address change.
"""

import ipaddress
from dataclasses import dataclass, field

from argus.modules.models import HostInfo, PortInfo, ScanResult


HOST_NEW = "host_new"
HOST_MISSING = "host_missing"
HOST_IP_CHANGED = "host_ip_changed"
PORT_OPENED = "port_opened"
PORT_CLOSED = "port_closed"
PORT_FIRST_CHECKED = "port_first_checked"
PORT_NOT_RECHECKED = "port_not_rechecked"
SERVICE_CHANGED = "service_changed"
OS_CHANGED = "os_changed"

# Display order, and whether a kind is a confirmed change or only a hint.
EVENT_KINDS = {
    HOST_NEW: ("New host", True),
    HOST_MISSING: ("Host not seen", True),
    HOST_IP_CHANGED: ("Address changed", True),
    PORT_OPENED: ("Port opened", True),
    PORT_CLOSED: ("Port no longer open", True),
    SERVICE_CHANGED: ("Service changed", True),
    OS_CHANGED: ("OS estimate changed", True),
    PORT_FIRST_CHECKED: ("Open, not checked before", False),
    PORT_NOT_RECHECKED: ("Not re-checked", False),
}

MATCH_MAC = "mac"
MATCH_IP = "ip"

CANCELLED_MARKER = "stopped before it finished"


@dataclass
class ChangeEvent:
    """One difference between the older and the newer scan."""

    kind: str
    ip: str
    summary: str
    protocol: str | None = None
    port: int | None = None
    before: str | None = None
    after: str | None = None

    @property
    def label(self) -> str:
        return EVENT_KINDS[self.kind][0]

    @property
    def confirmed(self) -> bool:
        """True for real changes, False for "could not tell" hints."""
        return EVENT_KINDS[self.kind][1]


@dataclass
class HostMatch:
    older: HostInfo
    newer: HostInfo
    method: str


@dataclass
class ScanComparison:
    """Everything found when comparing two scans."""

    events: list[ChangeEvent] = field(default_factory=list)
    matches: list[HostMatch] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped_out_of_scope: int = 0

    def count(self, kind: str) -> int:
        return sum(1 for event in self.events if event.kind == kind)

    @property
    def confirmed_changes(self) -> list[ChangeEvent]:
        return [event for event in self.events if event.confirmed]

    @property
    def has_changes(self) -> bool:
        return bool(self.confirmed_changes)


# ---------- helpers ----------

def _networks(targets: list[str]) -> list:
    networks = []

    for target in targets:
        try:
            networks.append(ipaddress.ip_network(target, strict=False))
        except ValueError:
            continue

    return networks


def _in_scope(ip: str, networks: list) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return any(address in network for network in networks)


def _mac(host: HostInfo) -> str | None:
    return host.mac.strip().upper() if host.mac else None


def _ip_sort_key(ip: str):
    try:
        return (0, ipaddress.ip_address(ip))
    except ValueError:
        return (1, ip)


def _service_text(port: PortInfo) -> str | None:
    """What a port is running, as precisely as the scan knows it."""
    return port.version_text or port.service


def _has_version_details(port: PortInfo) -> bool:
    return bool(port.product or port.version)


def _open_ports(host: HostInfo) -> dict[tuple[str, int], PortInfo]:
    return {(port.protocol, port.port): port for port in host.open_ports}


def _is_cancelled(result: ScanResult) -> bool:
    return any(CANCELLED_MARKER in warning for warning in result.warnings)


# ---------- matching ----------

def match_hosts(
    older: list[HostInfo],
    newer: list[HostInfo],
) -> tuple[list[HostMatch], list[HostInfo], list[HostInfo]]:
    """Pair up hosts from two scans.

    Returns (matches, only_in_older, only_in_newer).
    """
    remaining_old = list(older)
    remaining_new = list(newer)
    matches = []

    # 1. Same MAC address: same device, even if its IP changed.
    new_by_mac = {}

    for host in remaining_new:
        mac = _mac(host)

        if mac and mac not in new_by_mac:
            new_by_mac[mac] = host

    for host in list(remaining_old):
        mac = _mac(host)
        partner = new_by_mac.pop(mac, None) if mac else None

        if partner is not None:
            matches.append(HostMatch(host, partner, MATCH_MAC))
            remaining_old.remove(host)
            remaining_new.remove(partner)

    # 2. Same IP address, unless both have MACs that disagree (a different
    #    device now uses that address).
    new_by_ip = {host.ip: host for host in remaining_new}

    for host in list(remaining_old):
        partner = new_by_ip.get(host.ip)

        if partner is None:
            continue

        old_mac, new_mac = _mac(host), _mac(partner)

        if old_mac and new_mac and old_mac != new_mac:
            continue

        matches.append(HostMatch(host, partner, MATCH_IP))
        remaining_old.remove(host)
        remaining_new.remove(partner)
        del new_by_ip[host.ip]

    return matches, remaining_old, remaining_new


# ---------- comparing ----------

def _compare_ports(
    match: HostMatch,
    older: ScanResult,
    newer: ScanResult,
    protocols: list[str],
) -> list[ChangeEvent]:
    events = []
    ip = match.newer.ip
    old_ports = _open_ports(match.older)
    new_ports = _open_ports(match.newer)

    for key in sorted(set(old_ports) | set(new_ports)):
        protocol, number = key

        if protocol not in protocols:
            continue

        name = f"{number}/{protocol}"
        before, after = old_ports.get(key), new_ports.get(key)

        if before and not after:
            if newer.evidence.covers(protocol, number):
                events.append(ChangeEvent(
                    PORT_CLOSED, ip, f"{name} is no longer open",
                    protocol, number, before=_service_text(before),
                ))
            else:
                events.append(ChangeEvent(
                    PORT_NOT_RECHECKED, ip,
                    f"{name} was open before but the newer scan did not check it",
                    protocol, number, before=_service_text(before),
                ))

        elif after and not before:
            if older.evidence.covers(protocol, number):
                events.append(ChangeEvent(
                    PORT_OPENED, ip, f"{name} is now open",
                    protocol, number, after=_service_text(after),
                ))
            else:
                events.append(ChangeEvent(
                    PORT_FIRST_CHECKED, ip,
                    f"{name} is open; the older scan did not check it",
                    protocol, number, after=_service_text(after),
                ))

        elif before and after:
            old_text, new_text = _service_text(before), _service_text(after)

            # Only compare like with like: version details against version
            # details, or plain service names when neither scan had more.
            comparable = (
                _has_version_details(before) and _has_version_details(after)
            ) or (
                not _has_version_details(before) and not _has_version_details(after)
            )

            if comparable and old_text and new_text and old_text != new_text:
                events.append(ChangeEvent(
                    SERVICE_CHANGED, ip,
                    f"{name} changed from {old_text} to {new_text}",
                    protocol, number, before=old_text, after=new_text,
                ))

    return events


def compare_scans(older: ScanResult, newer: ScanResult) -> ScanComparison:
    """List every change between two scans, without guessing."""
    comparison = ScanComparison()

    old_scope = _networks(older.targets)
    new_scope = _networks(newer.targets)

    old_hosts = [host for host in older.hosts if host.state == "up"]
    new_hosts = [host for host in newer.hosts if host.state == "up"]

    matches, only_old, only_new = match_hosts(old_hosts, new_hosts)
    comparison.matches = matches

    # ----- notes about what can and cannot be compared -----
    if sorted(older.targets) != sorted(newer.targets):
        comparison.notes.append(
            "The two scans had different targets. Only addresses that both "
            "scans covered are reported as new or missing."
        )

    if _is_cancelled(older) or _is_cancelled(newer):
        comparison.notes.append(
            "At least one scan was stopped before it finished, so some "
            "differences may only mean it did not get that far."
        )

    port_protocols = []

    for protocol in ("tcp", "udp"):
        old_cover = older.evidence.coverage.get(protocol, set())
        new_cover = newer.evidence.coverage.get(protocol, set())

        if old_cover and new_cover:
            port_protocols.append(protocol)

            if old_cover != new_cover:
                shared = len(old_cover & new_cover)
                comparison.notes.append(
                    f"{protocol.upper()}: the older scan checked {len(old_cover):,} "
                    f"ports and the newer one {len(new_cover):,}; {shared:,} were "
                    "checked by both. Only those can show as opened or closed."
                )

        elif old_cover or new_cover:
            comparison.notes.append(
                f"{protocol.upper()} ports were only checked by one of the scans, "
                "so they were not compared."
            )

    if not port_protocols and not any(
        "were only checked by one" in note for note in comparison.notes
    ):
        comparison.notes.append(
            "Neither scan has a port list on record, so only hosts were compared."
        )

    # ----- hosts -----
    for host in sorted(only_new, key=lambda item: _ip_sort_key(item.ip)):
        if _in_scope(host.ip, old_scope):
            comparison.events.append(ChangeEvent(
                HOST_NEW, host.ip,
                f"{host.ip} responded, and did not in the older scan",
                after=host.mac,
            ))
        else:
            comparison.skipped_out_of_scope += 1

    for host in sorted(only_old, key=lambda item: _ip_sort_key(item.ip)):
        if _in_scope(host.ip, new_scope):
            comparison.events.append(ChangeEvent(
                HOST_MISSING, host.ip,
                f"{host.ip} did not respond in the newer scan "
                "(it may be offline or blocking probes)",
                before=host.mac,
            ))
        else:
            comparison.skipped_out_of_scope += 1

    for match in sorted(matches, key=lambda item: _ip_sort_key(item.newer.ip)):
        if match.method == MATCH_MAC and match.older.ip != match.newer.ip:
            comparison.events.append(ChangeEvent(
                HOST_IP_CHANGED, match.newer.ip,
                f"Device {_mac(match.newer)} moved from {match.older.ip} "
                f"to {match.newer.ip}",
                before=match.older.ip, after=match.newer.ip,
            ))

        comparison.events.extend(_compare_ports(match, older, newer, port_protocols))

        old_os, new_os = match.older.os_guess, match.newer.os_guess

        if old_os and new_os and old_os.name != new_os.name:
            comparison.events.append(ChangeEvent(
                OS_CHANGED, match.newer.ip,
                f"OS estimate changed from {old_os.name} to {new_os.name}",
                before=old_os.name, after=new_os.name,
            ))

    order = list(EVENT_KINDS)
    comparison.events.sort(
        key=lambda event: (
            order.index(event.kind),
            _ip_sort_key(event.ip),
            event.protocol or "",
            event.port or 0,
        )
    )

    return comparison
