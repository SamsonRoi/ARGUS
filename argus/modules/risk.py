"""The ARGUS risk engine.

It turns what a scan saw into findings that a person can act on:

1. Host findings come from argus/data/risk_rules.toml. Each one points at
   concrete evidence (an open port, a software banner, an OS estimate).
2. Network findings come from how the hosts relate to each other: critical
   assets sharing a subnet with weak devices, management interfaces on the
   general network, unidentified devices.
3. Every finding gets a 0-10 score worked out in the open:
   severity x asset criticality x exposure x confidence (+ persistence),
   with each factor listed, so no number is a black box.
4. Attack paths show where a weak device could be used to reach a critical
   one, and a fix-first plan ranks the fixes by how much risk they remove.

Nothing here sends a packet. It only reasons about what was already found,
and it never claims more than that evidence shows.
"""

import hashlib
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from functools import lru_cache
from importlib import resources

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from argus.modules.classify import find_word
from argus.modules.models import HostInfo, ScanResult
from argus.modules.topology import build_network_map
from argus.modules.versions import version_below, version_matches


SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
CATEGORIES = (
    "cleartext", "remote_access", "data_exposure", "no_auth",
    "management", "outdated", "device_hygiene", "segmentation", "inventory",
)
CATEGORY_LABELS = {
    "cleartext": "Cleartext logins and data",
    "remote_access": "Remote access",
    "data_exposure": "Data exposure",
    "no_auth": "No login by default",
    "management": "Management interfaces",
    "outdated": "Outdated software",
    "device_hygiene": "Device hygiene",
    "segmentation": "Network segmentation",
    "inventory": "Asset inventory",
}

# ----- scoring: every number here is shown to the user next to the score -----

SEVERITY_POINTS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
CRITICALITY_FACTOR = {"high": 1.25, "medium": 1.0, "low": 0.8}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.85, "low": 0.7}
PUBLIC_FACTOR = 1.3
PERSISTENCE_BONUS = 0.5          # added when a finding survived several scans
PERSISTENCE_SCANS = 3
MAX_SCORE = 10.0

TRUSTED_CONFIDENCE = ("high", "medium")

# Roles the segmentation checks care about.
CRITICAL_ROLES = (
    "domain_controller", "database_server", "nas", "hypervisor",
    "management_controller", "industrial_device", "router",
)
WEAK_DEVICE_ROLES = ("camera", "iot_device", "media_device", "mobile_device", "printer", "voip_device")
GENERAL_ROLES = ("workstation", "mobile_device", "iot_device", "media_device", "camera", "printer")
MANAGEMENT_ROLES = ("management_controller", "hypervisor")

REMOTE_ACCESS_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM (HTTPS)"}
REMOTE_ACCESS_LIMIT = 3

MAX_ATTACK_PATHS = 15


class RiskRulesError(Exception):
    """The risk rules file is invalid."""


# ======================================================================
# Rules
# ======================================================================

WHEN_KEYS = {
    "tcp_any", "udp_any", "service_any", "product_any", "version_below",
    "version_is", "os_any", "role_any", "role_none",
}
EVIDENCE_KEYS = {"tcp_any", "udp_any", "product_any", "version_below", "version_is", "os_any"}
RAISE_CONDITIONS = {"role_any", "criticality", "public"}
RULE_KEYS = {
    "key", "title", "category", "severity", "confidence", "why", "fix",
    "references", "when", "raise",
}


@dataclass(frozen=True)
class Raise:
    condition: str
    value: object
    to: str
    note: str


@dataclass(frozen=True)
class RiskRule:
    key: str
    title: str
    category: str
    severity: str
    confidence: str
    why: str
    fix: str
    references: tuple[str, ...]
    when: dict
    raises: tuple[Raise, ...]


@dataclass(frozen=True)
class RiskRuleSet:
    version: str
    rules: tuple[RiskRule, ...]


def _words(where: str, name: str, value) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise RiskRulesError(f"{where}: '{name}' must be a non-empty list of words")
    return tuple(value)


def _ports(where: str, name: str, value) -> tuple[int, ...]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, int) and 1 <= item <= 65535 for item in value
    ):
        raise RiskRulesError(f"{where}: '{name}' must list port numbers 1-65535")
    return tuple(value)


def _parse_when(where: str, raw) -> dict:
    if not isinstance(raw, dict) or not raw:
        raise RiskRulesError(f"{where}: needs a [rule.when] section")

    unknown = set(raw) - WHEN_KEYS

    if unknown:
        raise RiskRulesError(f"{where}: unknown condition(s) {', '.join(sorted(unknown))}")

    if not set(raw) & EVIDENCE_KEYS:
        raise RiskRulesError(
            f"{where}: needs at least one of {', '.join(sorted(EVIDENCE_KEYS))}"
        )

    when = {}

    for name, value in raw.items():
        if name in ("tcp_any", "udp_any"):
            when[name] = _ports(where, name, value)

        elif name in ("service_any", "product_any", "os_any", "role_any", "role_none"):
            when[name] = _words(where, name, value)

        elif name in ("version_below", "version_is"):
            needed = {"product", "below"} if name == "version_below" else {"product", "versions"}

            if not isinstance(value, dict) or not needed <= set(value) or set(value) - needed - {"unless"}:
                raise RiskRulesError(
                    f"{where}: {name} needs {' and '.join(sorted(needed))} (and optionally 'unless')"
                )

            wanted = (
                str(value["below"]) if name == "version_below"
                else _words(where, "versions", value["versions"])
            )
            unless = _words(where, "unless", value["unless"]) if "unless" in value else ()
            when[name] = (str(value["product"]), wanted, unless)

    return when


def _parse_raise(where: str, raw) -> Raise:
    if not isinstance(raw, dict):
        raise RiskRulesError(f"{where}: each [[rule.raise]] must be a table")

    conditions = set(raw) & RAISE_CONDITIONS
    unknown = set(raw) - RAISE_CONDITIONS - {"to", "note"}

    if unknown:
        raise RiskRulesError(f"{where}: unknown raise setting(s) {', '.join(sorted(unknown))}")

    if len(conditions) != 1:
        raise RiskRulesError(f"{where}: each raise needs exactly one condition")

    condition = conditions.pop()
    value = raw[condition]

    if condition == "role_any":
        value = _words(where, "role_any", value)
    elif condition == "criticality" and value not in ("high", "medium", "low"):
        raise RiskRulesError(f"{where}: raise criticality must be high, medium or low")
    elif condition == "public" and value is not True:
        raise RiskRulesError(f"{where}: raise 'public' must be true")

    if raw.get("to") not in SEVERITIES:
        raise RiskRulesError(f"{where}: raise 'to' must be one of {', '.join(SEVERITIES)}")

    if not isinstance(raw.get("note"), str) or not raw["note"].strip():
        raise RiskRulesError(f"{where}: each raise needs a 'note'")

    return Raise(condition=condition, value=value, to=raw["to"], note=raw["note"])


def parse_risk_rules(data: dict) -> RiskRuleSet:
    """Check and convert loaded TOML into a RiskRuleSet."""
    version = data.get("version")

    if not isinstance(version, int):
        raise RiskRulesError("The risk rules file needs a whole-number 'version'.")

    raw_rules = data.get("rule")

    if not isinstance(raw_rules, list) or not raw_rules:
        raise RiskRulesError("The risk rules file has no [[rule]] entries.")

    rules, seen = [], set()

    for raw in raw_rules:
        key = raw.get("key")

        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            raise RiskRulesError(f"Invalid rule key: {key!r}")

        if key in seen:
            raise RiskRulesError(f"Rule '{key}' is defined twice.")

        seen.add(key)
        where = f"rule '{key}'"

        unknown = set(raw) - RULE_KEYS

        if unknown:
            raise RiskRulesError(f"{where}: unknown setting(s) {', '.join(sorted(unknown))}")

        for name in ("title", "why", "fix"):
            if not isinstance(raw.get(name), str) or not raw[name].strip():
                raise RiskRulesError(f"{where}: needs '{name}'")

        if raw.get("category") not in CATEGORIES:
            raise RiskRulesError(f"{where}: category must be one of {', '.join(CATEGORIES)}")

        if raw.get("severity") not in SEVERITIES:
            raise RiskRulesError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")

        if raw.get("confidence") not in CONFIDENCES:
            raise RiskRulesError(f"{where}: confidence must be one of {', '.join(CONFIDENCES)}")

        references = raw.get("references", [])

        if not isinstance(references, list) or not all(isinstance(item, str) for item in references):
            raise RiskRulesError(f"{where}: references must be a list of text")

        raises = tuple(_parse_raise(where, item) for item in raw.get("raise", []))

        rules.append(RiskRule(
            key=key,
            title=raw["title"],
            category=raw["category"],
            severity=raw["severity"],
            confidence=raw["confidence"],
            why=raw["why"],
            fix=raw["fix"],
            references=tuple(references),
            when=_parse_when(where, raw.get("when")),
            raises=raises,
        ))

    return RiskRuleSet(version=str(version), rules=tuple(rules))


@lru_cache(maxsize=1)
def default_risk_rules() -> RiskRuleSet:
    """The risk rules shipped with ARGUS."""
    text = resources.files("argus.data").joinpath("risk_rules.toml").read_bytes()

    try:
        return parse_risk_rules(tomllib.loads(text.decode("utf-8")))
    except tomllib.TOMLDecodeError as error:
        raise RiskRulesError(f"The risk rules file is not valid TOML: {error}") from error


# ======================================================================
# Findings
# ======================================================================

@dataclass
class Acceptance:
    """A finding someone decided to live with, for a reason, until a date."""

    id: int | None
    fingerprint: str
    reason: str
    accepted_by: str | None = None
    expires_on: date | None = None
    created_on: date | None = None

    def active(self, today: date | None = None) -> bool:
        today = today or date.today()
        return self.expires_on is None or self.expires_on >= today


@dataclass
class Finding:
    """One risk, with everything needed to judge and fix it."""

    rule: str
    title: str
    category: str
    severity: str
    base_severity: str
    confidence: str
    why: str
    fix: str
    scope: str                                  # 'host' or 'network'
    host_ip: str | None = None
    host_label: str | None = None
    subnet: str | None = None
    ports: list[tuple[str, int]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    escalations: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    related_hosts: list[str] = field(default_factory=list)
    criticality: str | None = None
    public: bool = False
    score: float = 0.0
    score_factors: list[str] = field(default_factory=list)
    fingerprint: str = ""
    identity: str = ""                          # MAC/IP of the host, or the subnet
    # Filled in from scan history (risk_history.py):
    first_seen_scan: int | None = None
    first_seen_at: object = None
    seen_in_scans: int | None = None
    streak: int | None = None
    new_since_baseline: bool | None = None
    acceptance: Acceptance | None = None

    @property
    def where(self) -> str:
        if self.scope == "network":
            return self.subnet or "network"

        if not self.ports:
            return self.host_ip or "-"

        listed = ", ".join(f"{port}/{protocol}" for protocol, port in self.ports)
        return f"{self.host_ip} ({listed})"

    @property
    def band(self) -> str:
        return score_band(self.score)


def score_band(score: float) -> str:
    """The priority band a score falls in."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "info"


def host_identity(host: HostInfo) -> str:
    """How a host is recognised across scans: its MAC if known, else its IP."""
    return f"mac:{host.mac.upper()}" if host.mac else f"ip:{host.ip}"


def make_fingerprint(rule: str, identity: str) -> str:
    """A short id that stays the same for the same problem on the same host."""
    digest = hashlib.sha256(f"{rule}|{identity}".encode()).hexdigest()
    return digest[:12]


def is_public(ip: str | None) -> bool:
    if not ip:
        return False

    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _host_label(host: HostInfo) -> str:
    role = host.primary_role
    name = f"{host.ip} ({host.hostname})" if host.hostname else host.ip

    if role and role.confidence in TRUSTED_CONFIDENCE:
        return f"{name}, {role.label}"

    return name


def _believable_roles(host: HostInfo) -> set[str]:
    return {match.role for match in host.roles if match.confidence in TRUSTED_CONFIDENCE}


def _raise_severity(current: str, target: str) -> str:
    """Return the more severe of two severities."""
    return target if SEVERITIES.index(target) < SEVERITIES.index(current) else current


# ----- checking one rule against one host -----

def _open(host: HostInfo, protocol: str) -> dict[int, object]:
    return {port.port: port for port in host.open_ports if port.protocol == protocol}


def _evaluate_rule(rule: RiskRule, host: HostInfo) -> Finding | None:
    when = rule.when
    ports: list[tuple[str, int]] = []
    evidence: list[str] = []
    roles = _believable_roles(host)

    for protocol in ("tcp", "udp"):
        name = f"{protocol}_any"

        if name not in when:
            continue

        found = sorted(set(_open(host, protocol)) & set(when[name]))

        if not found:
            return None

        for number in found:
            ports.append((protocol, number))
            port = _open(host, protocol)[number]
            detail = port.version_text or port.service
            evidence.append(
                f"port {number}/{protocol} open" + (f" ({detail})" if detail else "")
            )

    if "service_any" in when:
        hits = [
            port for port in host.open_ports
            if find_word(when["service_any"], [port.service or ""])
        ]

        if not hits:
            return None

        for port in hits:
            evidence.append(f"service '{port.service}' on {port.port}/{port.protocol}")
            ports.append((port.protocol, port.port))

    if "product_any" in when:
        hits = [
            port for port in host.open_ports
            if find_word(when["product_any"], [port.version_text or "", port.extra_info or ""])
        ]

        if not hits:
            return None

        for port in hits:
            evidence.append(f"software '{port.version_text}' on {port.port}/{port.protocol}")
            ports.append((port.protocol, port.port))

    for condition in ("version_below", "version_is"):
        if condition not in when:
            continue

        product, wanted, unless = when[condition]
        hits = []

        for port in host.open_ports:
            if not find_word((product,), [port.product or ""]):
                continue

            # e.g. MariaDB reports itself as 'MySQL 5.5.5-10.6.12-MariaDB'.
            if unless and find_word(unless, [port.version_text or "", port.extra_info or ""]):
                continue

            if condition == "version_below":
                matched = version_below(port.version, wanted)
            else:
                matched = any(version_matches(port.version, item) for item in wanted)

            if matched:
                hits.append(port)

        if not hits:
            return None

        for port in hits:
            evidence.append(
                f"banner reports {port.version_text} on {port.port}/{port.protocol} "
                "(version from the service banner)"
            )
            ports.append((port.protocol, port.port))

    if "os_any" in when:
        name = host.os_guess.name if host.os_guess else ""

        if not find_word(when["os_any"], [name]):
            return None

        evidence.append(f"OS estimate '{name}' ({host.os_guess.accuracy}% match)")

    if "role_any" in when:
        matched = roles & set(when["role_any"])

        if not matched:
            return None

        labels = [match.label for match in host.roles if match.role in matched]
        evidence.append(f"device classified as {', '.join(labels)}")

    if "role_none" in when and roles & set(when["role_none"]):
        return None

    severity = rule.severity
    escalations = []
    public = is_public(host.ip)

    for step in rule.raises:
        applies = (
            (step.condition == "role_any" and roles & set(step.value))
            or (step.condition == "criticality" and host.criticality == step.value)
            or (step.condition == "public" and public)
        )

        if applies:
            raised = _raise_severity(severity, step.to)

            if raised != severity:
                escalations.append(f"{severity} -> {raised}: {step.note}")
                severity = raised

    # De-duplicate ports while keeping their order.
    ports = list(dict.fromkeys(ports))

    return Finding(
        rule=rule.key,
        title=rule.title,
        category=rule.category,
        severity=severity,
        base_severity=rule.severity,
        confidence=rule.confidence,
        why=rule.why,
        fix=rule.fix,
        scope="host",
        host_ip=host.ip,
        host_label=_host_label(host),
        ports=ports,
        evidence=evidence,
        escalations=escalations,
        references=list(rule.references),
        criticality=host.criticality,
        public=public,
        fingerprint=make_fingerprint(rule.key, host_identity(host)),
        identity=host_identity(host),
    )


# ----- findings that need the whole network -----

def _remote_access_finding(host: HostInfo) -> Finding | None:
    tcp = _open(host, "tcp")
    services = [(number, name) for number, name in REMOTE_ACCESS_PORTS.items() if number in tcp]

    if len(services) < REMOTE_ACCESS_LIMIT:
        return None

    return Finding(
        rule="many_remote_access",
        title="Many ways to log in remotely",
        category="remote_access",
        severity="medium",
        base_severity="medium",
        confidence="high",
        why=(
            "Every remote login service is another door to guard. This host "
            f"offers {len(services)}, so a weak password or an unpatched flaw "
            "in any one of them is enough."
        ),
        fix="Keep one well-secured remote access method (usually SSH or RDP through a VPN) and turn off the rest.",
        scope="host",
        host_ip=host.ip,
        host_label=_host_label(host),
        ports=[("tcp", number) for number, _ in services],
        evidence=[f"{name} on {number}/tcp" for number, name in services],
        criticality=host.criticality,
        public=is_public(host.ip),
        fingerprint=make_fingerprint("many_remote_access", host_identity(host)),
        identity=host_identity(host),
    )


def _unidentified_finding(host: HostInfo) -> Finding | None:
    if host.primary_role is not None or not host.open_ports:
        return None

    listed = ", ".join(f"{port.port}/{port.protocol}" for port in host.open_ports[:8])

    return Finding(
        rule="unidentified_device",
        title="Unidentified device with open services",
        category="inventory",
        severity="low",
        base_severity="low",
        confidence="high",
        why=(
            "ARGUS could not tell what this device is. Devices nobody recognises "
            "are often forgotten, unpatched, or not supposed to be there."
        ),
        fix="Find out who owns this device and what it does, then record it, secure it, or remove it.",
        scope="host",
        host_ip=host.ip,
        host_label=_host_label(host),
        ports=[(port.protocol, port.port) for port in host.open_ports],
        evidence=[f"open ports {listed} but no role matched"],
        criticality=host.criticality,
        public=is_public(host.ip),
        fingerprint=make_fingerprint("unidentified_device", host_identity(host)),
        identity=host_identity(host),
    )


def _weak_hosts(result: ScanResult, findings: list[Finding]) -> dict[str, list[Finding]]:
    """Likely starting points for an attacker.

    These are hosts that are not themselves critical, but have high or critical
    exposures, or are a device type that is often poorly secured. Critical
    hosts are targets, so they are never counted here.
    """
    by_host: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        if finding.scope == "host" and finding.severity in ("critical", "high"):
            by_host[finding.host_ip].append(finding)

    weak = {}

    for host in result.up_hosts:
        if host.criticality == "high":
            continue

        serious = by_host.get(host.ip, [])
        roles = _believable_roles(host)

        if serious or (roles & set(WEAK_DEVICE_ROLES) and host.open_ports):
            weak[host.ip] = serious

    return weak


def _segmentation_findings(result: ScanResult, findings: list[Finding], network_map) -> list[Finding]:
    """Critical assets reachable from weak devices on the same subnet."""
    hosts = {host.ip: host for host in result.up_hosts}
    weak = _weak_hosts(result, findings)
    out = []

    for group in network_map.subnets:
        members = [hosts[ip] for ip in group.host_ips if ip in hosts]

        critical = [
            host for host in members
            if host.criticality == "high" and _believable_roles(host) & set(CRITICAL_ROLES)
            and "router" not in _believable_roles(host)
        ]
        weak_here = [host for host in members if host.ip in weak]

        if critical and weak_here:
            out.append(Finding(
                rule="flat_network",
                title="Critical assets share a network with weakly protected devices",
                category="segmentation",
                severity="high",
                base_severity="high",
                confidence="medium",
                why=(
                    "If one of the weak devices is taken over, nothing ARGUS can see "
                    "stands between it and the critical systems on the same subnet. "
                    "Attackers routinely start with a camera, printer or IoT gadget "
                    "and move on from there. (A host firewall may still block this; "
                    "ARGUS cannot see one.)"
                ),
                fix=(
                    "Separate critical systems from everyday and IoT devices with VLANs "
                    "or a firewall, and allow only the traffic each system needs."
                ),
                scope="network",
                subnet=group.network,
                evidence=[
                    "critical: " + ", ".join(_host_label(host) for host in critical),
                    "weak: " + ", ".join(_host_label(host) for host in weak_here),
                ],
                related_hosts=[host.ip for host in critical + weak_here],
                criticality="high",
                fingerprint=make_fingerprint("flat_network", f"net:{group.network}"),
                identity=f"net:{group.network}",
            ))

        management = [host for host in members if _believable_roles(host) & set(MANAGEMENT_ROLES)]
        general = [
            host for host in members
            if _believable_roles(host) & set(GENERAL_ROLES) and host not in management
        ]

        if management and general:
            out.append(Finding(
                rule="management_not_separated",
                title="Management interfaces are on the general network",
                category="segmentation",
                severity="medium",
                base_severity="medium",
                confidence="medium",
                why=(
                    "Server management controllers and hypervisors control other "
                    "systems. Here they share a subnet with everyday devices, so "
                    "anyone on those devices can reach them."
                ),
                fix="Move management interfaces to a dedicated management network that only administrators can reach.",
                scope="network",
                subnet=group.network,
                evidence=[
                    "management: " + ", ".join(_host_label(host) for host in management),
                    "general devices: " + ", ".join(_host_label(host) for host in general[:6])
                    + (f" and {len(general) - 6} more" if len(general) > 6 else ""),
                ],
                related_hosts=[host.ip for host in management + general],
                criticality="high",
                fingerprint=make_fingerprint("management_not_separated", f"net:{group.network}"),
                identity=f"net:{group.network}",
            ))

    return out


# ======================================================================
# Scoring
# ======================================================================

def score_finding(finding: Finding) -> None:
    """Work out a 0-10 score and record every factor that went into it."""
    base = SEVERITY_POINTS[finding.severity]
    factors = [f"{finding.severity} severity: {base:g}"]
    score = base

    criticality = finding.criticality or "medium"
    factor = CRITICALITY_FACTOR[criticality]

    if factor != 1.0:
        score *= factor
        factors.append(f"x {factor:g} asset criticality {criticality}")

    if finding.public:
        score *= PUBLIC_FACTOR
        factors.append(f"x {PUBLIC_FACTOR:g} public address")

    factor = CONFIDENCE_FACTOR[finding.confidence]

    if factor != 1.0:
        score *= factor
        factors.append(f"x {factor:g} {finding.confidence} confidence")

    if finding.streak and finding.streak >= PERSISTENCE_SCANS:
        score += PERSISTENCE_BONUS
        factors.append(f"+ {PERSISTENCE_BONUS:g} still open after {finding.streak} scans")

    if score > MAX_SCORE:
        factors.append(f"-> capped at {MAX_SCORE:g}")

    finding.score = round(min(MAX_SCORE, score), 1)
    finding.score_factors = factors


def host_risk(findings: list[Finding]) -> float:
    """A host's score: its worst finding, plus a little for each additional one."""
    scores = sorted((finding.score for finding in findings), reverse=True)

    if not scores:
        return 0.0

    return round(min(MAX_SCORE, scores[0] + 0.15 * sum(scores[1:])), 1)


# ======================================================================
# Attack paths and the fix-first plan
# ======================================================================

@dataclass
class AttackPath:
    entry_ip: str
    entry_label: str
    entry_reasons: list[str]
    target_ip: str
    target_label: str
    subnet: str
    basis: str              # how ARGUS knows the two can reach each other


@dataclass
class FixAction:
    rule: str
    title: str
    fix: str
    findings: int
    hosts: list[str]
    risk_removed: float
    worst: str


def find_attack_paths(result: ScanResult, findings: list[Finding], network_map) -> list[AttackPath]:
    """Weak devices that sit next to critical assets.

    These are possible paths, not proven ones: ARGUS cannot see firewalls
    between hosts on the same subnet.
    """
    hosts = {host.ip: host for host in result.up_hosts}
    weak = _weak_hosts(result, findings)
    paths = []

    observed = {
        (link.source, link.target) for link in network_map.observed_links
    }

    for group in network_map.subnets:
        targets = [
            hosts[ip] for ip in group.host_ips
            if ip in hosts and hosts[ip].criticality == "high"
            and _believable_roles(hosts[ip]) & set(CRITICAL_ROLES)
        ]

        for entry_ip, serious in weak.items():
            if entry_ip not in group.host_ips:
                continue

            entry = hosts[entry_ip]

            if serious:
                reasons = [f"{finding.title} ({finding.severity})" for finding in serious[:3]]
            else:
                role = entry.primary_role
                reasons = [f"{role.label}: a device type that is often poorly secured"]

            for target in targets:
                if target.ip == entry_ip:
                    continue

                linked = (entry_ip, target.ip) in observed or (target.ip, entry_ip) in observed
                paths.append(AttackPath(
                    entry_ip=entry_ip,
                    entry_label=_host_label(entry),
                    entry_reasons=reasons,
                    target_ip=target.ip,
                    target_label=_host_label(target),
                    subnet=group.network,
                    basis="observed link" if linked else "same subnet (inferred)",
                ))

    # Most dangerous first: entry points with serious findings, then targets.
    paths.sort(key=lambda path: (
        -len(weak.get(path.entry_ip, [])),
        path.target_ip,
        path.entry_ip,
    ))

    return paths[:MAX_ATTACK_PATHS]


def build_fix_plan(findings: list[Finding]) -> list[FixAction]:
    """Group findings by fix and rank the fixes by how much risk they remove."""
    groups: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        groups[finding.rule].append(finding)

    plan = []

    for rule, items in groups.items():
        worst = min(items, key=lambda item: SEVERITIES.index(item.severity)).severity
        plan.append(FixAction(
            rule=rule,
            title=items[0].title,
            fix=items[0].fix,
            findings=len(items),
            hosts=sorted({item.host_ip or item.subnet for item in items}),
            risk_removed=round(sum(item.score for item in items), 1),
            worst=worst,
        ))

    plan.sort(key=lambda action: (-action.risk_removed, SEVERITIES.index(action.worst)))
    return plan


# ======================================================================
# The report
# ======================================================================

@dataclass
class RiskReport:
    findings: list[Finding] = field(default_factory=list)        # active, worst first
    accepted: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    plan: list[FixAction] = field(default_factory=list)
    host_scores: dict[str, float] = field(default_factory=dict)
    grade: str = "A"
    grade_reason: str = ""
    notes: list[str] = field(default_factory=list)
    rules_version: str = ""
    # Filled in from scan history (risk_history.py):
    resolved: list[Finding] = field(default_factory=list)
    not_rechecked: list[Finding] = field(default_factory=list)
    compared_with: int | None = None
    history_scans: int = 0

    def count(self, band: str) -> int:
        return sum(1 for finding in self.findings if finding.band == band)

    @property
    def total_risk(self) -> float:
        return round(sum(finding.score for finding in self.findings), 1)


def grade_report(report: RiskReport) -> None:
    """A letter grade for the whole network, with the reason spelled out."""
    critical = report.count("critical")
    high = report.count("high")
    medium = report.count("medium")

    if critical >= 2:
        grade, reason = "F", f"{critical} critical-priority findings"
    elif critical == 1:
        grade, reason = "D", "1 critical-priority finding"
    elif high >= 3:
        grade, reason = "D", f"{high} high-priority findings"
    elif high:
        grade, reason = "C", f"{high} high-priority finding{'s' if high != 1 else ''}"
    elif medium:
        grade, reason = "B", f"no high or critical findings; {medium} medium"
    else:
        grade, reason = "A", "no medium, high or critical findings"

    report.grade, report.grade_reason = grade, reason


def _sort_findings(findings: list[Finding]) -> None:
    findings.sort(key=lambda finding: (
        -finding.score,
        SEVERITIES.index(finding.severity),
        finding.rule,
        finding.host_ip or finding.subnet or "",
    ))


def finalize(report: RiskReport, acceptances: dict[str, Acceptance] | None = None,
             today: date | None = None) -> RiskReport:
    """(Re)score everything, apply accepted risks, and rebuild the summaries.

    Called once by analyze(), and again after history adds persistence.
    """
    acceptances = acceptances or {}
    everything = report.findings + report.accepted
    report.findings, report.accepted = [], []

    for finding in everything:
        score_finding(finding)
        acceptance = acceptances.get(finding.fingerprint)

        if acceptance is not None:
            finding.acceptance = acceptance

        if finding.acceptance is not None and finding.acceptance.active(today):
            report.accepted.append(finding)
        else:
            report.findings.append(finding)

    _sort_findings(report.findings)
    _sort_findings(report.accepted)

    per_host: dict[str, list[Finding]] = defaultdict(list)

    for finding in report.findings:
        if finding.scope == "host":
            per_host[finding.host_ip].append(finding)

    report.host_scores = dict(sorted(
        ((ip, host_risk(items)) for ip, items in per_host.items()),
        key=lambda item: -item[1],
    ))
    report.plan = build_fix_plan(report.findings)
    grade_report(report)

    expired = [
        finding for finding in report.findings
        if finding.acceptance is not None and not finding.acceptance.active(today)
    ]

    report.notes = [note for note in report.notes if not note.startswith("Accepted risk expired")]

    for finding in expired:
        report.notes.append(
            f"Accepted risk expired on {finding.acceptance.expires_on.isoformat()}: "
            f"{finding.title} on {finding.where}. It counts again until re-accepted."
        )

    return report


def analyze(
    result: ScanResult,
    rules: RiskRuleSet | None = None,
    acceptances: dict[str, Acceptance] | None = None,
    today: date | None = None,
) -> RiskReport:
    """Find, score and prioritise every risk this scan shows evidence of."""
    rules = rules or default_risk_rules()
    report = RiskReport(rules_version=rules.version)
    findings: list[Finding] = []

    for host in result.up_hosts:
        for rule in rules.rules:
            finding = _evaluate_rule(rule, host)

            if finding is not None:
                findings.append(finding)

        for extra in (_remote_access_finding(host), _unidentified_finding(host)):
            if extra is not None:
                findings.append(extra)

    network_map = build_network_map(result)
    findings.extend(_segmentation_findings(result, findings, network_map))

    report.findings = findings
    report.attack_paths = find_attack_paths(result, findings, network_map)

    # ----- what this analysis could not see -----
    if result.profile == "discovery" or not result.evidence.coverage.get("tcp"):
        report.notes.append(
            "This scan did not check TCP ports, so port-based risks could not be assessed."
        )

    if not any(port.version for host in result.up_hosts for port in host.open_ports):
        report.notes.append(
            "No software versions were collected, so outdated-software checks had "
            "nothing to examine. Run a scan with service detection to include them."
        )

    if not result.evidence.coverage.get("udp"):
        report.notes.append(
            "UDP ports were not scanned, so services such as SNMP, TFTP and IPMI were not checked."
        )

    if any("stopped before it finished" in warning for warning in result.warnings):
        report.notes.append(
            "The scan was stopped early, so this analysis covers only part of the network."
        )

    return finalize(report, acceptances, today)
