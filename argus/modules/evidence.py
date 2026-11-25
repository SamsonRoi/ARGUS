"""Evidence collected while a scan runs.

Two things are recorded for every Nmap run:

* coverage: exactly which ports Nmap checked, per protocol. Without it, a
  comparison could not tell "this port closed" from "this port was not
  checked this time".
* raw XML: Nmap's own output, kept so every result can be traced back to
  what Nmap actually reported, and re-read if the parser improves later.
"""

from dataclasses import dataclass, field


PORT_PROTOCOLS = ("tcp", "udp")


def parse_port_list(text: str | None) -> set[int]:
    """Turn Nmap's port list, for example '1,3-5,80', into a set of numbers.

    Bad pieces are skipped rather than failing the whole scan.
    """
    ports: set[int] = set()

    if not text:
        return ports

    for part in str(text).replace(" ", "").split(","):
        if not part:
            continue

        try:
            if "-" in part:
                start, end = (int(value) for value in part.split("-", 1))
            else:
                start = end = int(part)

        except ValueError:
            continue

        start, end = max(1, start), min(65535, end)

        if start <= end:
            ports.update(range(start, end + 1))

    return ports


def format_port_list(ports: set[int] | list[int]) -> str:
    """Turn a set of port numbers into a compact list such as '1,3-5,80'."""
    ordered = sorted(set(ports))
    pieces = []
    index = 0

    while index < len(ordered):
        start = end = ordered[index]

        while index + 1 < len(ordered) and ordered[index + 1] == end + 1:
            index += 1
            end = ordered[index]

        pieces.append(str(start) if start == end else f"{start}-{end}")
        index += 1

    return ",".join(pieces)


@dataclass
class ScanEvidence:
    """Coverage and raw output gathered from every Nmap run in one scan."""

    coverage: dict[str, set[int]] = field(default_factory=dict)
    raw_outputs: list[tuple[str, str]] = field(default_factory=list)

    def record(self, stage: str, scanner, *, coverage: bool = True) -> None:
        """Store what one Nmap run checked and what it printed.

        Pass coverage=False for runs whose port results are not kept (service
        detection re-checks known ports; OS estimation's ports are discarded),
        so they never widen what the scan claims to have checked.

        Works with python-nmap's PortScanner, and quietly does nothing for
        test doubles that lack these methods.
        """
        info = {}

        if coverage:
            try:
                info = scanner.scaninfo() or {}
            except (AttributeError, TypeError, KeyError):
                info = {}

        for protocol in PORT_PROTOCOLS:
            details = info.get(protocol)

            if isinstance(details, dict):
                ports = parse_port_list(details.get("services"))

                if ports:
                    self.coverage.setdefault(protocol, set()).update(ports)

        try:
            raw = scanner.get_nmap_last_output()
        except (AttributeError, TypeError):
            raw = None

        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        if raw:
            self.raw_outputs.append((stage, raw))

    def covers(self, protocol: str, port: int) -> bool:
        """Return True if this scan checked the given port."""
        return port in self.coverage.get(protocol, set())
