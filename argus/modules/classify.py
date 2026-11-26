"""Work out what each host is, from the evidence a scan collected.

The rules live in argus/data/asset_rules.toml. Each role adds up the
weights of the clues that match a host. The result is a list of roles,
strongest first, each with a confidence level and the exact evidence that
produced it. Nothing here runs Nmap: it only reads what was already found.

Classifications are estimates. They are always shown with their evidence
so a person can check them.
"""

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from argus.modules.models import (
    CRITICALITY_LEVELS,
    HostInfo,
    RoleMatch,
    ScanResult,
)


HIGH_SCORE = 70
MEDIUM_SCORE = 40
LOW_SCORE = 20

UNKNOWN_CRITICALITY = "medium"
UNKNOWN_CRITICALITY_REASON = (
    "No role could be identified, so this host is treated as medium "
    "until more is known."
)

LIST_TESTS = (
    "tcp_any", "tcp_all", "udp_any", "service_any", "product_any",
    "vendor_any", "os_any", "hostname_any", "ip_last_octet",
)
FLAG_TESTS = ("gateway", "no_open_ports")
SIGNAL_KEYS = set(LIST_TESTS) | set(FLAG_TESTS) | {"weight", "note"}
ROLE_KEYS = {"key", "label", "criticality", "signal"}
PORT_TESTS = ("tcp_any", "tcp_all", "udp_any")


class RulesError(Exception):
    """The classification rules file is invalid."""


# ---------- rules ----------

@dataclass(frozen=True)
class Signal:
    test: str
    values: tuple
    weight: int
    note: str | None = None


@dataclass(frozen=True)
class Role:
    key: str
    label: str
    criticality: str
    signals: tuple[Signal, ...]


@dataclass(frozen=True)
class RuleSet:
    version: str
    roles: tuple[Role, ...]


def _parse_signal(role_key: str, index: int, raw: dict) -> Signal:
    where = f"role '{role_key}', clue {index + 1}"
    unknown = set(raw) - SIGNAL_KEYS

    if unknown:
        raise RulesError(f"{where}: unknown setting(s) {', '.join(sorted(unknown))}")

    tests = [name for name in (*LIST_TESTS, *FLAG_TESTS) if name in raw]

    if len(tests) != 1:
        raise RulesError(f"{where}: needs exactly one test, found {len(tests)}")

    test = tests[0]
    value = raw[test]

    if test in FLAG_TESTS:
        if value is not True:
            raise RulesError(f"{where}: '{test}' must be true")
        values: tuple = ()

    else:
        if not isinstance(value, list) or not value:
            raise RulesError(f"{where}: '{test}' must be a non-empty list")

        if test in PORT_TESTS or test == "ip_last_octet":
            limit = 255 if test == "ip_last_octet" else 65535

            if not all(isinstance(item, int) and 0 <= item <= limit for item in value):
                raise RulesError(f"{where}: '{test}' must list numbers 0-{limit}")

        elif not all(isinstance(item, str) and item.strip() for item in value):
            raise RulesError(f"{where}: '{test}' must list words")

        values = tuple(value)

    weight = raw.get("weight")

    if not isinstance(weight, int) or not -100 <= weight <= 100 or weight == 0:
        raise RulesError(f"{where}: 'weight' must be a whole number from -100 to 100, not 0")

    note = raw.get("note")

    if note is not None and not isinstance(note, str):
        raise RulesError(f"{where}: 'note' must be text")

    return Signal(test=test, values=values, weight=weight, note=note)


def parse_rules(data: dict) -> RuleSet:
    """Check and convert loaded TOML into a RuleSet. Mistakes are reported clearly."""
    version = data.get("version")

    if not isinstance(version, int):
        raise RulesError("The rules file needs a whole-number 'version'.")

    raw_roles = data.get("role")

    if not isinstance(raw_roles, list) or not raw_roles:
        raise RulesError("The rules file has no [[role]] entries.")

    roles, seen = [], set()

    for raw in raw_roles:
        key = raw.get("key")

        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            raise RulesError(f"Invalid role key: {key!r}")

        if key in seen:
            raise RulesError(f"Role '{key}' is defined twice.")

        seen.add(key)

        unknown = set(raw) - ROLE_KEYS

        if unknown:
            raise RulesError(f"role '{key}': unknown setting(s) {', '.join(sorted(unknown))}")

        label = raw.get("label")
        criticality = raw.get("criticality")

        if not isinstance(label, str) or not label.strip():
            raise RulesError(f"role '{key}': needs a label")

        if criticality not in CRITICALITY_LEVELS:
            raise RulesError(
                f"role '{key}': criticality must be one of {', '.join(CRITICALITY_LEVELS)}"
            )

        raw_signals = raw.get("signal")

        if not isinstance(raw_signals, list) or not raw_signals:
            raise RulesError(f"role '{key}': needs at least one [[role.signal]]")

        signals = tuple(
            _parse_signal(key, index, item) for index, item in enumerate(raw_signals)
        )

        if not any(signal.weight > 0 for signal in signals):
            raise RulesError(f"role '{key}': needs at least one positive clue")

        roles.append(Role(key=key, label=label, criticality=criticality, signals=signals))

    return RuleSet(version=str(version), roles=tuple(roles))


@lru_cache(maxsize=1)
def default_rules() -> RuleSet:
    """The rules shipped with ARGUS."""
    text = resources.files("argus.data").joinpath("asset_rules.toml").read_bytes()

    try:
        return parse_rules(tomllib.loads(text.decode("utf-8")))
    except tomllib.TOMLDecodeError as error:
        raise RulesError(f"The rules file is not valid TOML: {error}") from error


# ---------- matching ----------

@lru_cache(maxsize=2048)
def _word_pattern(word: str) -> re.Pattern:
    """Match a word or phrase on its own, ignoring case.

    'iOS' matches 'Apple iOS 17' but not 'BIOS', and 'Wiz' does not match
    'Wizard'.
    """
    word = word.strip()

    # Only insist on a boundary where the word itself starts or ends with a
    # letter or digit, so patterns like '-pc' still match 'john-pc'.
    before = r"(?<![A-Za-z0-9])" if word[0].isalnum() else ""
    after = r"(?![A-Za-z0-9])" if word[-1].isalnum() else ""

    return re.compile(before + re.escape(word) + after, re.IGNORECASE)


def _find_word(words: tuple, texts: list[str]) -> tuple[str, str] | None:
    """Return (word, text) for the first word found in any text."""
    for word in words:
        pattern = _word_pattern(word)

        for text in texts:
            if text and pattern.search(text):
                return word, text

    return None


def find_word(words, texts: list[str]) -> tuple[str, str] | None:
    """Public form of the whole-word matcher, shared with the risk engine."""
    return _find_word(tuple(words), texts)


def _ports(host: HostInfo, protocol: str) -> set[int]:
    return {port.port for port in host.open_ports if port.protocol == protocol}


def _port_list(numbers, protocol: str) -> str:
    items = [f"{number}/{protocol}" for number in sorted(numbers)]
    word = "port" if len(items) == 1 else "ports"
    return f"{word} {', '.join(items)} open"


def _last_octet(ip: str) -> int | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None

    return int(str(address).rsplit(".", 1)[1]) if address.version == 4 else None


def _check(signal: Signal, host: HostInfo, gateways: set[str]) -> str | None:
    """Return a description of the evidence if the clue matches, else None."""
    test, values = signal.test, signal.values

    if test in ("tcp_any", "udp_any"):
        protocol = test[:3]
        found = _ports(host, protocol) & set(values)
        return _port_list(found, protocol) if found else None

    if test == "tcp_all":
        open_tcp = _ports(host, "tcp")
        return _port_list(values, "tcp") if set(values) <= open_tcp else None

    if test == "service_any":
        hit = _find_word(values, [port.service or "" for port in host.open_ports])
        return f"service '{hit[1]}'" if hit else None

    if test == "product_any":
        texts = [
            " ".join(part for part in (port.version_text, port.extra_info) if part)
            for port in host.open_ports
        ]
        hit = _find_word(values, texts)
        return f"software '{hit[1]}'" if hit else None

    if test == "vendor_any":
        hit = _find_word(values, [host.vendor or ""])
        return f"vendor '{host.vendor}'" if hit else None

    if test == "os_any":
        name = host.os_guess.name if host.os_guess else ""
        hit = _find_word(values, [name])
        return (
            f"OS estimate '{name}' ({host.os_guess.accuracy}%)" if hit else None
        )

    if test == "hostname_any":
        hit = _find_word(values, [host.hostname or ""])
        return f"hostname '{host.hostname}'" if hit else None

    if test == "ip_last_octet":
        octet = _last_octet(host.ip)
        return f"address ends in .{octet}" if octet in values else None

    if test == "gateway":
        return "first hop in a traceroute" if host.ip in gateways else None

    if test == "no_open_ports":
        return "no open ports found" if not host.open_ports else None

    return None


def _confidence(score: int) -> str | None:
    if score >= HIGH_SCORE:
        return "high"
    if score >= MEDIUM_SCORE:
        return "medium"
    if score >= LOW_SCORE:
        return "low"
    return None


def classify_host(
    host: HostInfo,
    rules: RuleSet | None = None,
    gateways: set[str] | None = None,
) -> list[RoleMatch]:
    """Score every role for one host. Returns matching roles, strongest first."""
    rules = rules or default_rules()
    gateways = gateways or set()
    matches = []

    for order, role in enumerate(rules.roles):
        score = 0
        reasons = []
        has_positive = False

        for signal in role.signals:
            evidence = _check(signal, host, gateways)

            if evidence is None:
                continue

            if signal.note:
                evidence = f"{evidence} ({signal.note})"

            score += signal.weight

            if signal.weight > 0:
                has_positive = True
                reasons.append(evidence)
            else:
                reasons.append(f"against: {evidence}")

        score = max(0, min(100, score))
        confidence = _confidence(score)

        if has_positive and confidence is not None:
            matches.append((score, -order, RoleMatch(
                role=role.key,
                label=role.label,
                confidence=confidence,
                score=score,
                reasons=reasons,
            )))

    matches.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [match for _score, _order, match in matches]


def assign_criticality(host: HostInfo, rules: RuleSet | None = None) -> None:
    """Set how important a host is, from its medium- or high-confidence roles.

    A host is as critical as its most critical believable role. Low-confidence
    roles are not trusted enough to raise or lower it.
    """
    rules = rules or default_rules()
    levels = {role.key: role.criticality for role in rules.roles}
    rank = {level: index for index, level in enumerate(CRITICALITY_LEVELS)}

    believable = [
        match for match in host.roles if match.confidence in ("high", "medium")
    ]

    if not believable:
        host.criticality = UNKNOWN_CRITICALITY
        host.criticality_reason = UNKNOWN_CRITICALITY_REASON
        return

    deciding = min(believable, key=lambda match: rank[levels.get(match.role, "medium")])
    host.criticality = levels.get(deciding.role, "medium")
    host.criticality_reason = (
        f"{deciding.label} ({deciding.confidence} confidence)"
    )


def observed_gateways(result: ScanResult) -> set[str]:
    """Addresses seen as the first hop of a multi-hop traceroute."""
    gateways = set()

    for host in result.hosts:
        answered = [hop for hop in host.trace if hop.ip]

        if len(answered) >= 2 and answered[0].ttl == 1:
            gateways.add(answered[0].ip)

    return gateways


def classify_result(result: ScanResult, rules: RuleSet | None = None) -> ScanResult:
    """Classify every host in a scan, in place, and return the same scan."""
    rules = rules or default_rules()
    gateways = observed_gateways(result)

    for host in result.hosts:
        host.roles = classify_host(host, rules, gateways)
        assign_criticality(host, rules)

    result.classifier_version = rules.version
    return result
