"""Build a map of the scanned network from a classified scan.

The map never presents a guess as a fact. Every link is one of:

* observed: a traceroute actually saw traffic pass this way;
* inferred: worked out from addresses alone (same subnet as a gateway).

Hosts are grouped into the subnets that were scanned. A host scanned on its
own (not inside a scanned range) is placed in an assumed /24 (IPv4) or /64
(IPv6), and the map says so.
"""

import ipaddress
from collections import Counter
from dataclasses import dataclass, field

from argus.modules.models import HostInfo, ScanResult


OBSERVED = "observed"
INFERRED = "inferred"

SCANNER_ID = "argus"
SCANNER_LABEL = "This computer (ARGUS)"

ROUTER_ROLE = "router"
TRUSTED_CONFIDENCE = ("high", "medium")


@dataclass
class MapNode:
    id: str
    kind: str                      # 'scanner', 'gateway', 'host' or 'hop'
    label: str
    ip: str | None = None
    subnet: str | None = None
    role: str | None = None
    role_label: str | None = None
    confidence: str | None = None
    criticality: str | None = None


@dataclass
class MapLink:
    source: str
    target: str
    kind: str                      # OBSERVED or INFERRED
    reason: str


@dataclass
class SubnetGroup:
    network: str
    assumed: bool                  # True when ARGUS guessed the subnet size
    host_ips: list[str] = field(default_factory=list)
    gateway_ip: str | None = None
    gateway_basis: str | None = None   # OBSERVED, INFERRED or None
    gateway_reason: str | None = None


@dataclass
class NetworkMap:
    nodes: dict[str, MapNode] = field(default_factory=dict)
    links: list[MapLink] = field(default_factory=list)
    subnets: list[SubnetGroup] = field(default_factory=list)
    paths: dict[str, list[str | None]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def observed_links(self) -> list[MapLink]:
        return [link for link in self.links if link.kind == OBSERVED]

    @property
    def inferred_links(self) -> list[MapLink]:
        return [link for link in self.links if link.kind == INFERRED]

    def subnet_of(self, ip: str) -> SubnetGroup | None:
        return next((group for group in self.subnets if ip in group.host_ips), None)


# ---------- helpers ----------

def _ip_key(ip: str):
    try:
        return (0, ipaddress.ip_address(ip))
    except ValueError:
        return (1, ip)


def _network_sort_key(text: str):
    network = ipaddress.ip_network(text, strict=False)
    return (network.version, network.network_address, network.prefixlen)


def _scanned_networks(targets: list[str]) -> list:
    networks = []

    for target in targets:
        if "/" not in target:
            continue

        try:
            networks.append(ipaddress.ip_network(target, strict=False))
        except ValueError:
            continue

    # Smallest range first, so a host lands in the most specific one.
    return sorted(networks, key=lambda network: -network.prefixlen)


def _place(ip: str, networks: list) -> tuple[str, bool]:
    """Return (subnet, assumed) for one address."""
    address = ipaddress.ip_address(ip)

    for network in networks:
        if address in network:
            return str(network), False

    if address.is_loopback:
        return str(ipaddress.ip_network(f"{ip}/{8 if address.version == 4 else 128}", strict=False)), False

    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)), True


def _is_router(host: HostInfo) -> bool:
    return any(
        match.role == ROUTER_ROLE and match.confidence in TRUSTED_CONFIDENCE
        for match in host.roles
    )


def _host_node(host: HostInfo, subnet: str, kind: str = "host") -> MapNode:
    role = host.primary_role
    label = host.ip if not host.hostname else f"{host.ip} ({host.hostname})"

    return MapNode(
        id=host.ip,
        kind=kind,
        label=label,
        ip=host.ip,
        subnet=subnet,
        role=role.role if role else None,
        role_label=role.label if role else None,
        confidence=role.confidence if role else None,
        criticality=host.criticality,
    )


def _add_link(network_map: NetworkMap, seen: set, link: MapLink) -> None:
    key = (link.source, link.target)

    if key in seen or (link.target, link.source) in seen or link.source == link.target:
        return

    seen.add(key)
    network_map.links.append(link)


# ---------- building ----------

def build_network_map(result: ScanResult) -> NetworkMap:
    """Turn a scan into nodes, links and subnet groups."""
    network_map = NetworkMap()
    seen_links: set = set()
    networks = _scanned_networks(result.targets)
    hosts = sorted(result.up_hosts, key=lambda host: _ip_key(host.ip))
    by_ip = {host.ip: host for host in hosts}

    # ----- subnets -----
    groups: dict[str, SubnetGroup] = {}

    for host in hosts:
        subnet, assumed = _place(host.ip, networks)
        group = groups.setdefault(subnet, SubnetGroup(network=subnet, assumed=assumed))
        group.host_ips.append(host.ip)

    # ----- traced paths -----
    first_hops: Counter = Counter()

    for host in hosts:
        answered = [hop for hop in host.trace if hop.ip]

        if not answered:
            continue

        path: list[str | None] = []
        expected_ttl = 1

        for hop in host.trace:
            while expected_ttl < hop.ttl:
                path.append(None)          # a hop that did not answer
                expected_ttl += 1

            path.append(hop.ip)
            expected_ttl = hop.ttl + 1

        network_map.paths[host.ip] = path

        if len(answered) >= 2 and answered[0].ttl == 1:
            first_hops[answered[0].ip] += 1

    # ----- gateways -----
    for group in groups.values():
        network = ipaddress.ip_network(group.network, strict=False)
        observed = [
            (count, ip) for ip, count in first_hops.items()
            if ipaddress.ip_address(ip) in network
        ]

        if observed:
            count, ip = max(observed, key=lambda item: (item[0], _ip_key(item[1])))
            group.gateway_ip = ip
            group.gateway_basis = OBSERVED
            group.gateway_reason = (
                f"first hop on {count} traced path{'s' if count != 1 else ''}"
            )
            continue

        routers = [by_ip[ip] for ip in group.host_ips if _is_router(by_ip[ip])]

        if routers:
            best = max(
                routers,
                key=lambda host: next(
                    match.score for match in host.roles if match.role == ROUTER_ROLE
                ),
            )
            group.gateway_ip = best.ip
            group.gateway_basis = INFERRED
            group.gateway_reason = "classified as a router or gateway"

    # ----- nodes -----
    gateway_ips = {group.gateway_ip for group in groups.values() if group.gateway_ip}

    if network_map.paths:
        network_map.nodes[SCANNER_ID] = MapNode(
            id=SCANNER_ID, kind="scanner", label=SCANNER_LABEL
        )

    for group in groups.values():
        for ip in group.host_ips:
            kind = "gateway" if ip in gateway_ips else "host"
            network_map.nodes[ip] = _host_node(by_ip[ip], group.network, kind)

    for path in network_map.paths.values():
        for ip in path:
            if ip and ip not in network_map.nodes:
                subnet = next(
                    (
                        group.network for group in groups.values()
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(group.network)
                    ),
                    None,
                )
                network_map.nodes[ip] = MapNode(
                    id=ip,
                    kind="gateway" if ip in first_hops else "hop",
                    label=ip,
                    ip=ip,
                    subnet=subnet,
                )

    # ----- observed links: exactly what traceroute saw -----
    for target, path in network_map.paths.items():
        previous = SCANNER_ID
        silent = 0

        for ip in path:
            if ip is None:
                silent += 1
                continue

            reason = "seen by traceroute"

            if silent:
                reason += f" ({silent} hop{'s' if silent != 1 else ''} in between did not answer)"

            _add_link(network_map, seen_links, MapLink(previous, ip, OBSERVED, reason))
            previous, silent = ip, 0

    # ----- inferred links: same subnet as the gateway -----
    traced_into = {link.target for link in network_map.observed_links}

    for group in groups.values():
        if not group.gateway_ip:
            continue

        for ip in group.host_ips:
            if ip == group.gateway_ip or ip in traced_into:
                continue

            _add_link(network_map, seen_links, MapLink(
                group.gateway_ip, ip, INFERRED, "same subnet as the gateway",
            ))

    network_map.subnets = sorted(
        groups.values(), key=lambda group: _network_sort_key(group.network)
    )

    # ----- notes -----
    if not network_map.paths:
        if "traceroute" in (result.profile or "").lower():
            network_map.notes.append(
                "Traceroute ran but returned no paths, so every link is "
                "inferred from addresses. Nmap cannot trace this computer "
                "itself, and hosts that ignore probes give no path."
            )
        else:
            network_map.notes.append(
                "No traceroute data, so every link is inferred from addresses. "
                "Run a scan with 'Trace network paths' for observed links."
            )

    assumed = [group.network for group in network_map.subnets if group.assumed]

    if assumed:
        network_map.notes.append(
            "These subnet sizes were assumed because the hosts were scanned "
            f"one address at a time: {', '.join(assumed)}."
        )

    missing = [
        group.network
        for group in network_map.subnets
        if not group.gateway_ip
        and not ipaddress.ip_network(group.network).is_loopback
    ]

    if missing and hosts:
        network_map.notes.append(
            f"No gateway was identified for: {', '.join(missing)}."
        )

    return network_map
