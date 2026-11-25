"""Runs a complete ARGUS scan and merges the results into one ScanResult.

The stages are: host discovery, TCP port scan, then the optional extras
(UDP scan, service detection, OS estimation). A stage that fails does not
stop the scan: the failure is recorded as a warning and the next stage runs.
"""

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

from argus.modules.discovery import discover_hosts
from argus.modules.models import HostInfo, ScanResult
from argus.modules.nmap_runner import (
    InvalidScanRequestError,
    NmapNotFoundError,
    ScanInterruptedError,
    ScannerError,
    get_nmap_version,
    is_privileged,
    validate_targets,
)
from argus.modules.os_detect import estimate_os, is_loopback
from argus.modules.port_scan import (
    TCP_PROFILES,
    scan_tcp_ports,
    scan_udp_ports,
    validate_port_spec,
)
from argus.modules.service_detect import detect_services


CANCELLED_WARNING = (
    "The scan was stopped before it finished. These results are incomplete."
)

RANGE_WARNING = (
    "Port scans only covered hosts that answered discovery. A host that "
    "ignores discovery probes was not scanned, so this list may be incomplete."
)

PORT_SCAN_REASON = "Responded to port scan"

# Called as progress(step_number, total_steps, label) before each stage.
ProgressCallback = Callable[[int, int, str], None]


@dataclass
class ScanOptions:
    """What the user chose to run."""

    profile_key: str = "standard"
    ports: str | None = None
    service_detection: bool = False
    udp_scan: bool = False
    os_estimation: bool = False
    discovery_methods: list[str] | None = None

    def __post_init__(self):
        if self.profile_key not in TCP_PROFILES:
            raise InvalidScanRequestError(
                f"Unknown scan profile: {self.profile_key}"
            )

        self.ports = validate_port_spec(self.ports) if self.ports else None

    def tcp_description(self) -> str:
        """Describe the TCP part of the scan, for example 'Standard TCP'."""
        if self.ports:
            return f"Custom TCP ports ({self.ports})"

        return f"{TCP_PROFILES[self.profile_key].label} TCP"

    def describe(self) -> str:
        """A short description of the scan, for example 'Quick TCP + service detection'."""
        parts = [self.tcp_description()]

        if self.udp_scan:
            parts.append("UDP ports")

        if self.service_detection:
            parts.append("service detection")

        if self.os_estimation:
            parts.append("OS estimation")

        return " + ".join(parts)

    @property
    def stage_count(self) -> int:
        """Discovery and the TCP scan always run. Each extra adds one stage."""
        extras = (self.udp_scan, self.service_detection, self.os_estimation)
        return 2 + sum(extras)


def merge_host(
    result: ScanResult,
    new: HostInfo,
    *,
    add_if_missing: bool = True,
    include_ports: bool = True,
) -> None:
    """Fold what a later stage found into the host already in the result.

    Information is only ever added or refined, never thrown away.
    """
    host = result.get_host(new.ip)

    if host is None:
        if not add_if_missing:
            return

        host = HostInfo(
            ip=new.ip,
            state=new.state,
            hostname=new.hostname,
            mac=new.mac,
            vendor=new.vendor,
            discovery_method=new.discovery_method,
            os_guess=new.os_guess,
        )
        result.add_host(host)

    else:
        for name in ("hostname", "mac", "vendor", "discovery_method", "os_guess"):
            if getattr(host, name) is None and getattr(new, name) is not None:
                setattr(host, name, getattr(new, name))

        if host.state != "up" and new.state == "up":
            host.state = "up"

    if not include_ports:
        return

    for port in new.ports:
        existing = next(
            (
                item
                for item in host.ports
                if item.port == port.port and item.protocol == port.protocol
            ),
            None,
        )

        if existing is None:
            host.add_port(port)
            continue

        # Newer service details refine older ones.
        for name in ("service", "product", "version", "extra_info"):
            value = getattr(port, name)

            if value is not None:
                setattr(existing, name, value)

        if existing.state == "unknown":
            existing.state = port.state


def _run_stage(result: ScanResult, name: str, action):
    """Run one stage. A recoverable failure becomes a warning and the scan goes on."""
    try:
        return action()

    except (NmapNotFoundError, InvalidScanRequestError, ScanInterruptedError):
        # Without Nmap, with a bad request, or after a stop, no later stage
        # should run.
        raise

    except ScannerError as error:
        result.warnings.append(f"{name} failed: {error}")
        return None


def run_scan_pipeline(
    targets: list[str],
    options: ScanOptions,
    progress: ProgressCallback | None = None,
    privileged: bool | None = None,
) -> ScanResult:
    """Run every stage the user chose and return one merged ScanResult.

    Pressing Ctrl+C (or Nmap being stopped) ends the scan and returns what
    was found so far, with a warning that the results are incomplete.
    """
    clean_targets = validate_targets(targets)
    nmap_version = get_nmap_version()  # also proves Nmap is installed

    if privileged is None:
        privileged = is_privileged()

    result = ScanResult(
        targets=clean_targets,
        profile=options.describe(),
        nmap_version=nmap_version,
    )

    explicit_ips = [target for target in clean_targets if "/" not in target]

    if len(explicit_ips) != len(clean_targets):
        result.warnings.append(RANGE_WARNING)

    total = options.stage_count
    step = 0

    def announce(label: str) -> None:
        nonlocal step
        step += 1

        if progress is not None:
            progress(step, total, label)

    try:
        # ----- Stage 1: discovery -----
        announce("Discovering hosts")

        discovery = _run_stage(
            result,
            "Host discovery",
            lambda: discover_hosts(
                clean_targets,
                methods=options.discovery_methods,
                privileged=privileged,
            ),
        )

        if discovery is not None:
            result.warnings.extend(discovery.warnings)

            for host in discovery.hosts:
                merge_host(result, host)

        # Explicitly typed addresses are always scanned, because a host may
        # ignore discovery and still have open ports. Addresses inside a
        # range are only scanned if they answered discovery.
        scan_ips = list(
            dict.fromkeys(explicit_ips + [host.ip for host in result.up_hosts])
        )

        if scan_ips:
            # ----- Stage 2: TCP ports -----
            announce(f"Scanning TCP ports ({options.tcp_description()})")

            found = _run_stage(
                result,
                "TCP port scan",
                lambda: scan_tcp_ports(scan_ips, options.profile_key, options.ports),
            )

            for host in found or []:
                merge_host(result, host)

            # ----- Optional: UDP ports -----
            if options.udp_scan:
                announce("Scanning common UDP ports")

                found = _run_stage(
                    result,
                    "UDP port scan",
                    lambda: scan_udp_ports(scan_ips),
                )

                for host in found or []:
                    merge_host(result, host)

            # ----- Optional: service versions -----
            if options.service_detection:
                announce("Identifying services")

                found = _run_stage(
                    result,
                    "Service detection",
                    lambda: detect_services(result.hosts),
                )

                for host in found or []:
                    merge_host(result, host, add_if_missing=False)

            # ----- Optional: operating systems -----
            if options.os_estimation:
                announce("Estimating operating systems")

                skipped = [ip for ip in scan_ips if is_loopback(ip)]

                if skipped:
                    result.warnings.append(
                        "OS estimation was skipped for "
                        f"{', '.join(skipped)}: the local machine cannot be "
                        "fingerprinted this way."
                    )

                found = _run_stage(
                    result,
                    "OS estimation",
                    lambda: estimate_os(scan_ips),
                )

                # OS estimation never adds hosts or ports: it scans without
                # discovery, so it cannot prove that a host exists.
                for host in found or []:
                    merge_host(
                        result,
                        host,
                        add_if_missing=False,
                        include_ports=False,
                    )

    except (KeyboardInterrupt, ScanInterruptedError):
        result.warnings.append(CANCELLED_WARNING)

    for host in result.hosts:
        if host.discovery_method is None and host.open_ports:
            host.discovery_method = PORT_SCAN_REASON

    result.hosts.sort(key=lambda host: ipaddress.ip_address(host.ip))
    result.finish()

    return result