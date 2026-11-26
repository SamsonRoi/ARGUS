"""Trace the network path to each host with Nmap's --traceroute.

Traceroute shows which routers traffic passes through, so ARGUS can draw
observed links in the network map instead of guessing them. It needs
administrator rights and sends extra probes, so it is an optional extra.

python-nmap does not read traceroute results, so this module reads them
from Nmap's XML output directly.
"""

import xml.etree.ElementTree as ElementTree

from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo, TraceHop
from argus.modules.nmap_runner import ScanFailedError, run_scan, validate_targets


TRACE_ARGUMENTS = "-sn --traceroute"
TRACE_TIMEOUT = 600


def parse_traces(xml_text: str) -> dict[str, list[TraceHop]]:
    """Read every host's traceroute from Nmap XML: {host ip: [hops]}.

    Hops that did not answer are missing from Nmap's output; they are kept
    as gaps (consecutive ttl values are not guaranteed).
    """
    if not xml_text or not xml_text.strip():
        return {}

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as error:
        raise ScanFailedError("Nmap's traceroute output could not be read.") from error

    traces = {}

    for host in root.iter("host"):
        address = next(
            (
                item.get("addr")
                for item in host.findall("address")
                if item.get("addrtype") in ("ipv4", "ipv6")
            ),
            None,
        )
        trace = host.find("trace")

        if address is None or trace is None:
            continue

        hops = []

        for hop in trace.findall("hop"):
            try:
                ttl = int(hop.get("ttl", ""))
            except ValueError:
                continue

            try:
                rtt = float(hop.get("rtt")) if hop.get("rtt") not in (None, "", "--") else None
            except ValueError:
                rtt = None

            hops.append(TraceHop(
                ttl=ttl,
                ip=hop.get("ipaddr") or None,
                rtt_ms=rtt,
                hostname=hop.get("host") or None,
            ))

        if hops:
            hops.sort(key=lambda item: item.ttl)
            traces[address] = hops

    return traces


def trace_routes(
    ips: list[str],
    evidence: ScanEvidence | None = None,
) -> list[HostInfo]:
    """Trace the path to each address. Returns hosts carrying only their trace."""
    clean_ips = validate_targets(ips)

    scanner = run_scan(clean_ips, TRACE_ARGUMENTS, timeout=TRACE_TIMEOUT)

    if evidence is not None:
        evidence.record("traceroute", scanner, coverage=False)

    try:
        raw = scanner.get_nmap_last_output()
    except AttributeError:
        raw = ""

    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")

    return [
        HostInfo(ip=ip, trace=hops)
        for ip, hops in parse_traces(raw or "").items()
    ]
