from argus.modules.compare import (
    HOST_IP_CHANGED,
    HOST_MISSING,
    HOST_NEW,
    MATCH_IP,
    MATCH_MAC,
    OS_CHANGED,
    PORT_CLOSED,
    PORT_FIRST_CHECKED,
    PORT_NOT_RECHECKED,
    PORT_OPENED,
    SERVICE_CHANGED,
    compare_scans,
    match_hosts,
)
from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo, OSGuess, PortInfo, ScanResult


TOP_PORTS = set(range(1, 1025))


def host(ip, *ports, mac=None, os_name=None):
    item = HostInfo(ip=ip, mac=mac, os_guess=OSGuess(os_name, 90) if os_name else None)

    for port in ports:
        item.add_port(port if isinstance(port, PortInfo) else PortInfo(port, "tcp"))

    return item


def scan(*hosts, targets=("10.0.0.0/24",), tcp=TOP_PORTS, udp=None, warnings=()):
    coverage = {}

    if tcp:
        coverage["tcp"] = set(tcp)

    if udp:
        coverage["udp"] = set(udp)

    return ScanResult(
        targets=list(targets),
        profile="Standard TCP",
        hosts=list(hosts),
        warnings=list(warnings),
        evidence=ScanEvidence(coverage=coverage),
    )


def kinds(comparison):
    return [(event.kind, event.ip, event.port) for event in comparison.events]


def test_identical_scans_have_no_changes():
    older = scan(host("10.0.0.5", 22, 80))
    newer = scan(host("10.0.0.5", 22, 80))

    comparison = compare_scans(older, newer)

    assert comparison.events == []
    assert not comparison.has_changes
    assert len(comparison.matches) == 1


def test_opened_and_closed_ports_inside_shared_coverage():
    comparison = compare_scans(
        scan(host("10.0.0.5", 22, 80)),
        scan(host("10.0.0.5", 22, 443)),
    )

    assert kinds(comparison) == [
        (PORT_OPENED, "10.0.0.5", 443),
        (PORT_CLOSED, "10.0.0.5", 80),
    ]


def test_port_outside_newer_coverage_is_not_called_closed():
    """A full scan followed by a quick scan must not 'close' port 8443."""
    comparison = compare_scans(
        scan(host("10.0.0.5", 22, 8443), tcp=range(1, 65536)),
        scan(host("10.0.0.5", 22), tcp=TOP_PORTS),
    )

    assert kinds(comparison) == [(PORT_NOT_RECHECKED, "10.0.0.5", 8443)]
    assert not comparison.has_changes
    assert any("checked by both" in note for note in comparison.notes)


def test_port_outside_older_coverage_is_not_called_new():
    comparison = compare_scans(
        scan(host("10.0.0.5", 22), tcp=TOP_PORTS),
        scan(host("10.0.0.5", 22, 8443), tcp=range(1, 65536)),
    )

    assert kinds(comparison) == [(PORT_FIRST_CHECKED, "10.0.0.5", 8443)]
    assert not comparison.has_changes


def test_new_and_missing_hosts():
    comparison = compare_scans(
        scan(host("10.0.0.5", 22), host("10.0.0.7")),
        scan(host("10.0.0.5", 22), host("10.0.0.8", 80)),
    )

    assert kinds(comparison) == [
        (HOST_NEW, "10.0.0.8", None),
        (HOST_MISSING, "10.0.0.7", None),
    ]


def test_hosts_outside_the_other_scans_targets_are_not_compared():
    comparison = compare_scans(
        scan(host("10.0.0.5"), host("10.0.0.7"), targets=["10.0.0.0/24"]),
        scan(host("10.0.0.5"), host("10.0.1.9"), targets=["10.0.0.5", "10.0.1.0/24"]),
    )

    assert comparison.events == []
    assert comparison.skipped_out_of_scope == 2
    assert any("different targets" in note for note in comparison.notes)


def test_same_mac_new_ip_is_one_device_that_moved():
    mac = "AA:BB:CC:00:11:22"
    comparison = compare_scans(
        scan(host("10.0.0.5", 22, mac=mac)),
        scan(host("10.0.0.40", 22, mac=mac.lower())),
    )

    assert kinds(comparison) == [(HOST_IP_CHANGED, "10.0.0.40", None)]
    assert comparison.matches[0].method == MATCH_MAC


def test_same_ip_different_mac_is_a_different_device():
    comparison = compare_scans(
        scan(host("10.0.0.5", 22, mac="AA:AA:AA:AA:AA:AA")),
        scan(host("10.0.0.5", 80, mac="BB:BB:BB:BB:BB:BB")),
    )

    assert kinds(comparison) == [
        (HOST_NEW, "10.0.0.5", None),
        (HOST_MISSING, "10.0.0.5", None),
    ]
    assert comparison.matches == []


def test_ip_match_when_only_one_side_has_a_mac():
    matches, only_old, only_new = match_hosts(
        [host("10.0.0.5")],
        [host("10.0.0.5", mac="AA:AA:AA:AA:AA:AA")],
    )

    assert [item.method for item in matches] == [MATCH_IP]
    assert only_old == only_new == []


def test_service_version_change():
    comparison = compare_scans(
        scan(host("10.0.0.5", PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "8.9p1"))),
        scan(host("10.0.0.5", PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "9.6p1"))),
    )

    assert kinds(comparison) == [(SERVICE_CHANGED, "10.0.0.5", 22)]
    assert comparison.events[0].before == "OpenSSH 8.9p1"
    assert comparison.events[0].after == "OpenSSH 9.6p1"


def test_missing_version_details_are_not_a_change():
    """Running service detection once and not the next time is not a change."""
    comparison = compare_scans(
        scan(host("10.0.0.5", PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "8.9p1"))),
        scan(host("10.0.0.5", PortInfo(22, "tcp", "open", "ssh"))),
    )

    assert comparison.events == []


def test_os_estimate_change():
    comparison = compare_scans(
        scan(host("10.0.0.5", os_name="Linux 5.x")),
        scan(host("10.0.0.5", os_name="Windows 11")),
    )

    assert kinds(comparison) == [(OS_CHANGED, "10.0.0.5", None)]


def test_udp_only_compared_when_both_scans_checked_udp():
    older = scan(host("10.0.0.5", 22, PortInfo(161, "udp")), udp={53, 161})
    newer = scan(host("10.0.0.5", 22))

    comparison = compare_scans(older, newer)

    assert comparison.events == []
    assert any("UDP ports were only checked by one" in note for note in comparison.notes)


def test_discovery_scans_compare_hosts_only():
    older = scan(host("10.0.0.5"), tcp=None)
    newer = scan(host("10.0.0.5"), host("10.0.0.6"), tcp=None)

    comparison = compare_scans(older, newer)

    assert kinds(comparison) == [(HOST_NEW, "10.0.0.6", None)]
    assert any("only hosts were compared" in note for note in comparison.notes)


def test_cancelled_scan_is_noted():
    comparison = compare_scans(
        scan(host("10.0.0.5")),
        scan(warnings=["The scan was stopped before it finished. These results are incomplete."]),
    )

    assert any("stopped before it finished" in note for note in comparison.notes)


def test_hosts_that_are_not_up_are_ignored():
    down = HostInfo(ip="10.0.0.7", state="down")

    comparison = compare_scans(scan(down), scan())

    assert comparison.events == []


def test_role_change_is_reported_for_believable_roles():
    from argus.modules.compare import ROLE_CHANGED
    from argus.modules.models import RoleMatch

    old = host("10.0.0.5", 80)
    new = host("10.0.0.5", 80)
    old.roles = [RoleMatch("web_server", "Web server", "medium", 45)]
    new.roles = [RoleMatch("camera", "Camera or video recorder", "high", 75)]

    comparison = compare_scans(scan(old), scan(new))

    assert kinds(comparison) == [(ROLE_CHANGED, "10.0.0.5", None)]
    assert "Web server to Camera or video recorder" in comparison.events[0].summary


def test_low_confidence_role_flips_are_ignored():
    from argus.modules.models import RoleMatch

    old = host("10.0.0.5", 80)
    new = host("10.0.0.5", 80)
    old.roles = [RoleMatch("web_server", "Web server", "low", 30)]
    new.roles = [RoleMatch("iot_device", "IoT device", "high", 75)]

    assert compare_scans(scan(old), scan(new)).events == []
