import pytest

from argus.modules.classify import (
    MEDIUM_SCORE,
    RulesError,
    UNKNOWN_CRITICALITY,
    assign_criticality,
    classify_host,
    classify_result,
    default_rules,
    observed_gateways,
    parse_rules,
)
from argus.modules.models import HostInfo, OSGuess, PortInfo, RoleMatch, ScanResult, TraceHop


def device(ip="192.168.1.50", tcp=(), udp=(), **details):
    host = HostInfo(ip=ip, **details)

    for number in tcp:
        host.add_port(number if isinstance(number, PortInfo) else PortInfo(number, "tcp"))

    for number in udp:
        host.add_port(PortInfo(number, "udp"))

    return host


def roles_of(host, **kwargs):
    return [match.role for match in classify_host(host, **kwargs)]


def top(host, **kwargs):
    matches = classify_host(host, **kwargs)
    return matches[0] if matches else None


# ---------- the packaged rules ----------

def test_packaged_rules_load():
    rules = default_rules()

    assert rules.version == "1"
    assert len(rules.roles) >= 15
    assert len({role.key for role in rules.roles}) == len(rules.roles)


def test_every_role_can_reach_medium_confidence():
    """A role whose clues can never add up to 'medium' would be dead weight."""
    for role in default_rules().roles:
        best = sum(signal.weight for signal in role.signals if signal.weight > 0)
        assert best >= MEDIUM_SCORE, role.key


# ---------- recognising devices ----------

def test_printer():
    match = top(device(tcp=[9100, 631, 80]))

    assert match.role == "printer"
    assert match.confidence == "high"
    assert "port 9100/tcp open (raw printing)" in match.reasons


def test_domain_controller():
    match = top(device(tcp=[53, 88, 135, 139, 389, 445, 464, 3268]))

    assert match.role == "domain_controller"
    assert match.confidence == "high"


def test_router_from_vendor_and_os():
    match = top(device(
        ip="192.168.1.1",
        tcp=[22, 80],
        vendor="Cisco Systems",
        os_guess=OSGuess("Cisco IOS 15.X", 95),
    ))

    assert match.role == "router"
    assert match.confidence == "high"


def test_cisco_ios_is_not_an_iphone():
    host = device(os_guess=OSGuess("Cisco IOS 15.X", 95))

    assert "mobile_device" not in roles_of(host)


def test_apple_ios_is_a_phone():
    match = top(device(os_guess=OSGuess("Apple iOS 17", 92), tcp=[62078]))

    assert match.role == "mobile_device"


def test_database_server_from_software():
    match = top(device(tcp=[PortInfo(5432, "tcp", "open", "postgresql", "PostgreSQL DB", "15.2")]))

    assert match.role == "database_server"
    assert match.confidence == "high"
    assert any("PostgreSQL" in reason for reason in match.reasons)


def test_camera_from_vendor():
    match = top(device(vendor="Hangzhou Hikvision Digital Technology", tcp=[554, 80]))

    assert match.role == "camera"
    assert match.confidence == "high"


def test_windows_server_is_not_a_workstation():
    host = device(tcp=[135, 139, 445, 3389], os_guess=OSGuess("Microsoft Windows Server 2019", 96))

    assert "workstation" not in roles_of(host)
    assert top(host).role == "server"


def test_windows_desktop_is_a_workstation():
    host = device(tcp=[135, 139, 445], os_guess=OSGuess("Microsoft Windows 11", 95))

    assert top(host).role == "workstation"


def test_counter_evidence_is_shown():
    host = device(tcp=[139, 445, 21], os_guess=OSGuess("Microsoft Windows 10", 90))
    file_server = next(m for m in classify_host(host) if m.role == "file_server")

    assert any(reason.startswith("against:") for reason in file_server.reasons)


def test_a_lone_ssh_port_is_not_enough():
    host = device(tcp=[22])

    assert classify_host(host) == []


def test_nothing_open_and_nothing_known_is_unknown():
    host = device()

    assert classify_host(host) == []


def test_unidentified_hosts_get_medium_with_an_explanation():
    host = device()
    host.roles = []
    assign_criticality(host)

    assert host.criticality == UNKNOWN_CRITICALITY
    assert "No role could be identified" in host.criticality_reason


def test_low_confidence_roles_do_not_set_criticality():
    host = device()
    host.roles = [RoleMatch("database_server", "Database server", "low", 25)]
    assign_criticality(host)

    assert host.criticality == UNKNOWN_CRITICALITY


def test_most_critical_believable_role_wins():
    host = device()
    host.roles = [
        RoleMatch("web_server", "Web server", "high", 80),
        RoleMatch("database_server", "Database server", "medium", 55),
    ]
    assign_criticality(host)

    assert host.criticality == "high"
    assert host.criticality_reason == "Database server (medium confidence)"


def test_whole_word_matching():
    # 'Wiz' is an IoT vendor; 'Wizard Labs' must not match it.
    assert "iot_device" not in roles_of(device(vendor="Wizard Labs"))
    # '-pc' in hostnames still matches 'office-pc'.
    workstation = next(
        m for m in classify_host(device(hostname="office-pc", tcp=[3389]))
        if m.role == "workstation"
    )
    assert any("office-pc" in reason for reason in workstation.reasons)


def test_udp_open_filtered_does_not_count():
    host = HostInfo(ip="192.168.1.9")
    host.add_port(PortInfo(623, "udp", "open|filtered"))

    assert "management_controller" not in roles_of(host)


# ---------- gateways from traceroute ----------

def test_first_hop_of_a_multi_hop_trace_is_a_gateway():
    result = ScanResult(targets=["10.0.0.0/24"], profile="x")
    result.add_host(HostInfo("10.0.0.5", trace=[TraceHop(1, "10.0.0.1"), TraceHop(2, "10.0.0.5")]))
    result.add_host(HostInfo("10.0.0.6", trace=[TraceHop(1, "10.0.0.6")]))

    assert observed_gateways(result) == {"10.0.0.1"}


def test_gateway_clue_raises_router_score():
    plain = device(ip="10.0.0.1", udp=[161])
    assert "router" not in [m.role for m in classify_host(plain) if m.confidence != "low"]

    traced = top(device(ip="10.0.0.1", udp=[161]), gateways={"10.0.0.1"})
    assert traced.role == "router"
    assert any("traceroute" in reason for reason in traced.reasons)


def test_classify_result_labels_every_host():
    result = ScanResult(targets=["10.0.0.0/24"], profile="x")
    result.add_host(device(ip="10.0.0.5", tcp=[3306]))
    result.add_host(device(ip="10.0.0.6"))

    classify_result(result)

    assert result.classifier_version == default_rules().version
    assert result.get_host("10.0.0.5").primary_role.role == "database_server"
    assert result.get_host("10.0.0.5").criticality == "high"
    assert result.get_host("10.0.0.6").primary_role is None
    assert result.get_host("10.0.0.6").criticality == UNKNOWN_CRITICALITY


# ---------- checking a rules file ----------

def rules_with(**role_overrides):
    role = {
        "key": "thing",
        "label": "Thing",
        "criticality": "low",
        "signal": [{"tcp_any": [1], "weight": 50}],
    }
    role.update(role_overrides)
    return {"version": 1, "role": [role]}


@pytest.mark.parametrize(
    "data, message",
    [
        ({"role": []}, "version"),
        ({"version": 1}, "no \\[\\[role\\]\\]"),
        (rules_with(key="Bad Key"), "Invalid role key"),
        (rules_with(criticality="extreme"), "criticality"),
        (rules_with(label=""), "needs a label"),
        (rules_with(colour="red"), "unknown setting"),
        (rules_with(signal=[]), "at least one"),
        (rules_with(signal=[{"tcp_any": [1], "udp_any": [2], "weight": 5}]), "exactly one test"),
        (rules_with(signal=[{"weight": 5}]), "exactly one test"),
        (rules_with(signal=[{"tcp_any": [70000], "weight": 5}]), "numbers"),
        (rules_with(signal=[{"vendor_any": [""], "weight": 5}]), "words"),
        (rules_with(signal=[{"tcp_any": [1], "weight": 0}]), "weight"),
        (rules_with(signal=[{"tcp_any": [1], "weight": -5}]), "positive clue"),
        (rules_with(signal=[{"gateway": False, "weight": 5}]), "must be true"),
        (rules_with(signal=[{"tcp_any": [1], "weight": 5, "typo": 1}]), "unknown setting"),
    ],
)
def test_rule_mistakes_are_reported(data, message):
    with pytest.raises(RulesError, match=message):
        parse_rules(data)


def test_duplicate_roles_are_refused():
    data = rules_with()
    data["role"].append(dict(data["role"][0]))

    with pytest.raises(RulesError, match="defined twice"):
        parse_rules(data)
