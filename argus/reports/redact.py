"""Redact a report so it can be shared without revealing the network.

Every IP address, subnet, MAC address and hostname is replaced with a
consistent label: the same device is always "host-3", the same range always
"net-1". This keeps the report readable and comparable.

Replacement happens in every text field, including free-text evidence,
because addresses appear inside sentences too. Finding ids are re-made with
a random salt, since a short hash of a private IP address could otherwise be
reversed by trying every address.

People's names in the engagement (who authorized the work) are removed too.
"""

import copy
import hashlib
import ipaddress
import re
import secrets


IPV4 = r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
CIDR4 = IPV4[:-len(r"(?![\d.])")] + r"/\d{1,2}(?![\d.])"
MAC = r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])"
IPV6 = r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"

REDACTED = "[redacted]"


class Redactor:
    """Hands out stable labels and rewrites text with them."""

    def __init__(self):
        self.labels: dict[str, str] = {}
        self.counters = {"host": 0, "net": 0, "mac": 0, "name": 0}
        self.salt = secrets.token_hex(16)

    def _label(self, kind: str, value: str) -> str:
        key = f"{kind}:{value.lower()}"

        if key not in self.labels:
            self.counters[kind] += 1
            self.labels[key] = f"{kind}-{self.counters[kind]}"

        return self.labels[key]

    def ip(self, value: str) -> str:
        return self._label("host", value)

    def network(self, value: str) -> str:
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass

        return self._label("net", value)

    def mac(self, value: str) -> str:
        return self._label("mac", value)

    def hostname(self, value: str) -> str:
        return self._label("name", value)

    def fingerprint(self, value: str) -> str:
        return hashlib.sha256(f"{self.salt}|{value}".encode()).hexdigest()[:12]

    # ----- rewriting text -----

    def text(self, value: str, hostnames: list[str]) -> str:
        value = re.sub(CIDR4, lambda match: self.network(match.group(0)), value)
        value = re.sub(MAC, lambda match: self.mac(match.group(0)), value)
        value = re.sub(IPV4, lambda match: self.ip(match.group(0)), value)
        value = re.sub(IPV6, lambda match: self._ipv6(match.group(0)), value)

        for name in hostnames:
            value = re.sub(
                r"(?<![A-Za-z0-9.-])" + re.escape(name) + r"(?![A-Za-z0-9-])",
                self.hostname(name),
                value,
                flags=re.IGNORECASE,
            )

        return value

    def _ipv6(self, value: str) -> str:
        # Only replace real IPv6 addresses, not times like 10:30:00.
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            return value

        return self.ip(value)


def _walk(value, change):
    if isinstance(value, str):
        return change(value)

    if isinstance(value, list):
        return [_walk(item, change) for item in value]

    if isinstance(value, dict):
        return {key: _walk(item, change) for key, item in value.items()}

    return value


def _collect_hostnames(data: dict) -> list[str]:
    names = set()

    for host in data.get("hosts", []):
        if host.get("hostname"):
            names.add(host["hostname"])

        for hop in host.get("trace", []):
            if hop.get("hostname"):
                names.add(hop["hostname"])

    # Longest first, so 'web01.office.lan' is replaced before 'web01'.
    return sorted(names, key=len, reverse=True)


def redact_report(data: dict) -> dict:
    """Return a redacted copy of a report model. The original is unchanged."""
    redactor = Redactor()
    output = copy.deepcopy(data)
    hostnames = _collect_hostnames(output)

    # Give hosts their labels in report order, so host-1 is the first host listed.
    for host in output.get("hosts", []):
        redactor.ip(host["ip"])

    for group in output.get("network", {}).get("subnets", []):
        redactor.network(group["network"])

    # Ids are hashes of addresses: re-make them so they reveal nothing.
    for section in ("findings", "accepted_risks"):
        for finding in output.get(section, []):
            finding["id"] = redactor.fingerprint(finding["id"])

    for section in ("new", "resolved", "not_rechecked"):
        for finding in (output.get("changes") or {}).get(section, []):
            finding["id"] = redactor.fingerprint(finding["id"])

    engagement = output.get("engagement")

    if engagement:
        if engagement.get("authorized_by"):
            engagement["authorized_by"] = REDACTED
        if engagement.get("notes"):
            engagement["notes"] = REDACTED

    for section in ("findings", "accepted_risks"):
        for finding in output.get(section, []):
            acceptance = finding.get("acceptance")
            if acceptance and acceptance.get("accepted_by"):
                acceptance["accepted_by"] = REDACTED

    # The traced-paths table is keyed by IP address.
    network = output.get("network", {})

    if network.get("traced_paths"):
        network["traced_paths"] = {
            redactor.text(key, hostnames): value
            for key, value in network["traced_paths"].items()
        }

    output = _walk(output, lambda text: redactor.text(text, hostnames))
    output["redacted"] = True

    return output
