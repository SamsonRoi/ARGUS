"""Data models that hold scan results.

These classes only store data. They never run scans.
"""

from dataclasses import dataclass, field
from datetime import datetime


VALID_PROTOCOLS = ("tcp", "udp")


def _now() -> datetime:
    """Return the current time with the local time zone attached."""
    return datetime.now().astimezone()


@dataclass
class PortInfo:
    """One port on one host, as observed by a scan."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None

    def __post_init__(self):
        self.protocol = self.protocol.strip().lower()
        self.state = self.state.strip().lower()

        if self.protocol not in VALID_PROTOCOLS:
            raise ValueError(f"Invalid protocol: {self.protocol}")

        if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError(f"Invalid port number: {self.port}")

    @property
    def version_text(self) -> str | None:
        """Product and version joined together, for example 'OpenSSH 8.9'."""
        parts = [part for part in (self.product, self.version) if part]
        return " ".join(parts) or None


@dataclass
class OSGuess:
    """An operating system estimate. It is a guess, not a confirmed fact."""

    name: str
    accuracy: int

    def __post_init__(self):
        if not 0 <= self.accuracy <= 100:
            raise ValueError(f"Accuracy must be 0-100, got {self.accuracy}")


@dataclass
class HostInfo:
    """One host that responded during a scan."""

    ip: str
    state: str = "up"
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    discovery_method: str | None = None
    ports: list[PortInfo] = field(default_factory=list)
    os_guess: OSGuess | None = None

    def add_port(self, port_info: PortInfo) -> None:
        """Add a port. A port with the same number and protocol is replaced."""
        for index, existing in enumerate(self.ports):
            if (
                existing.port == port_info.port
                and existing.protocol == port_info.protocol
            ):
                self.ports[index] = port_info
                return

        self.ports.append(port_info)

    @property
    def open_ports(self) -> list[PortInfo]:
        """Ports whose state is exactly 'open', sorted by protocol and number."""
        return sorted(
            (port for port in self.ports if port.state == "open"),
            key=lambda port: (port.protocol, port.port),
        )


@dataclass
class ScanResult:
    """Everything found by one scan."""

    targets: list[str]
    profile: str
    started_at: datetime = field(default_factory=_now)
    finished_at: datetime | None = None
    nmap_version: str | None = None
    hosts: list[HostInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_host(self, host: HostInfo) -> None:
        """Add a host. A host with the same IP address is replaced."""
        for index, existing in enumerate(self.hosts):
            if existing.ip == host.ip:
                self.hosts[index] = host
                return

        self.hosts.append(host)

    def get_host(self, ip: str) -> HostInfo | None:
        """Find a host by IP address, or return None."""
        for host in self.hosts:
            if host.ip == ip:
                return host
        return None

    def finish(self) -> None:
        """Record the time the scan ended."""
        self.finished_at = _now()

    @property
    def duration_seconds(self) -> float | None:
        """How long the scan took, or None if it has not finished."""
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def up_hosts(self) -> list[HostInfo]:
        """Hosts that responded."""
        return [host for host in self.hosts if host.state == "up"]

    @property
    def total_open_ports(self) -> int:
        """Number of open ports across all hosts."""
        return sum(len(host.open_ports) for host in self.hosts)