from datetime import date, datetime, timedelta

from argus.modules.classify import classify_result
from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo, PortInfo, ScanResult
from argus.modules.risk import analyze
from argus.modules.risk_history import (
    ScanFindings,
    analyze_with_history,
    apply_history,
    check_status,
    risk_changes,
)
from argus.storage.database import connect
from argus.storage.repository import accept_risk, save_scan, set_baseline


START = datetime(2026, 11, 1, 10, 0).astimezone()
TOP_1000 = set(range(1, 1001))


def scan(*hosts, tcp=TOP_1000, day=0, targets=("192.168.1.0/24",)):
    result = ScanResult(
        targets=list(targets),
        profile="Standard TCP",
        evidence=ScanEvidence(coverage={"tcp": set(tcp)} if tcp else {}),
    )
    result.started_at = START + timedelta(days=day)

    for item in hosts:
        result.add_host(item)

    return classify_result(result)


def camera(*ports, ip="192.168.1.30", **details):
    item = HostInfo(ip=ip, vendor="Hikvision", **details)

    for port in ports:
        item.add_port(port if isinstance(port, PortInfo) else PortInfo(port))

    return item


def findings(result):
    return {finding.rule for finding in analyze(result).findings}


def titled(items):
    return sorted(finding.rule for finding in items)


def history_of(*results, start_id=1):
    return [
        ScanFindings(
            scan_id=start_id + index,
            result=item,
            report=(report := analyze(item)),
            by_fingerprint={finding.fingerprint: finding for finding in report.findings},
        )
        for index, item in enumerate(results)
    ]


# ---------- resolved only when really re-checked ----------

def test_closed_port_that_was_checked_is_resolved():
    older = scan(camera(23, 554))
    newer = scan(camera(554))

    changes = risk_changes(older, newer)

    assert titled(changes.resolved) == ["telnet_open"]
    assert changes.not_rechecked == []


def test_port_outside_newer_coverage_is_not_rechecked():
    older = scan(camera(2375, 554), tcp=range(1, 65536))
    newer = scan(camera(554), tcp=TOP_1000)

    changes = risk_changes(older, newer)

    assert titled(changes.not_rechecked) == ["docker_api_open"]
    assert changes.resolved == []


def test_host_that_did_not_answer_is_not_rechecked():
    older = scan(camera(23))
    newer = scan()

    changes = risk_changes(older, newer)

    assert "telnet_open" in titled(changes.not_rechecked)
    assert changes.resolved == []


def test_version_finding_needs_versions_to_be_resolved():
    old_ssh = camera(PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "6.6.1p1"))
    no_versions = camera(PortInfo(22, "tcp", "open", "ssh"))
    upgraded = camera(PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "9.6p1"))

    assert "ssh_outdated" in titled(risk_changes(scan(old_ssh), scan(no_versions)).not_rechecked)
    assert "ssh_outdated" in titled(risk_changes(scan(old_ssh), scan(upgraded)).resolved)


def test_new_only_when_the_older_scan_could_have_seen_it():
    older = scan(camera(554), tcp=TOP_1000)
    newer = scan(camera(554, 23, 2375), tcp=range(1, 65536))

    changes = risk_changes(older, newer)

    # 23 was inside the older scan's coverage: really new.
    # 2375 was not: it may have been open all along, so it is not called new.
    assert "telnet_open" in titled(changes.new)
    assert "docker_api_open" not in titled(changes.new)


def test_check_status_present():
    result = scan(camera(23))
    report = analyze(result)
    telnet = next(item for item in report.findings if item.rule == "telnet_open")

    assert check_status(telnet, result, report) == "present"


def test_network_findings_resolve_when_the_subnet_is_scanned_again():
    dc = HostInfo("192.168.1.5")
    for number in (53, 88, 389, 445, 3268):
        dc.add_port(PortInfo(number))

    older = scan(camera(23), dc)
    newer = scan(camera(554), dc)   # camera no longer weak... but still a camera

    changes = risk_changes(older, newer)

    assert "telnet_open" in titled(changes.resolved)


# ---------- streaks and first seen ----------

def test_streak_counts_consecutive_scans_and_adds_persistence():
    old = history_of(scan(camera(23), day=0), scan(camera(23), day=1))
    current = scan(camera(23), day=2)

    report = apply_history(analyze(current), current, old)
    telnet = next(item for item in report.findings if item.rule == "telnet_open")

    assert telnet.streak == 3
    assert telnet.seen_in_scans == 3
    assert telnet.first_seen_scan == 1
    assert "+ 0.5 still open after 3 scans" in telnet.score_factors


def test_scans_that_could_not_check_neither_extend_nor_break_a_streak():
    old = history_of(
        scan(camera(2375), tcp=range(1, 65536), day=0),
        scan(camera(554), tcp=TOP_1000, day=1),        # did not check 2375
    )
    current = scan(camera(2375), tcp=range(1, 65536), day=2)

    report = apply_history(analyze(current), current, old)
    docker = next(item for item in report.findings if item.rule == "docker_api_open")

    assert docker.streak == 2


def test_a_scan_that_checked_and_did_not_see_it_breaks_the_streak():
    old = history_of(scan(camera(23), day=0), scan(camera(554), day=1))
    current = scan(camera(23), day=2)

    report = apply_history(analyze(current), current, old)
    telnet = next(item for item in report.findings if item.rule == "telnet_open")

    assert telnet.streak == 1
    assert telnet.seen_in_scans == 2
    assert telnet.first_seen_scan == 1


def test_new_since_baseline():
    old = history_of(scan(camera(554), day=0))
    current = scan(camera(554, 23), day=1)

    report = apply_history(analyze(current), current, old, baseline=old[0])
    telnet = next(item for item in report.findings if item.rule == "telnet_open")
    rtsp = next(item for item in report.findings if item.rule == "rtsp_camera_stream")

    assert telnet.new_since_baseline is True
    assert rtsp.new_since_baseline is False


def test_scans_of_other_networks_are_ignored():
    old = history_of(scan(camera(23, ip="10.9.9.9"), targets=["10.9.9.0/24"]))
    current = scan(camera(23), day=1)

    report = apply_history(analyze(current), current, old)

    assert report.history_scans == 0
    assert report.compared_with is None


# ---------- with the real database ----------

def test_analyze_with_history_end_to_end():
    connection = connect()

    first = save_scan(connection, scan(camera(23, 554), day=0))
    set_baseline(connection, first)
    second = save_scan(connection, scan(camera(23, 554), day=1))
    third_result = scan(camera(554, 110, 1883), day=2)
    third = save_scan(connection, third_result)

    report = analyze_with_history(connection, third_result, scan_id=third)

    assert report.history_scans == 2
    assert report.compared_with == second
    assert "telnet_open" in titled(report.resolved)

    mail = next(item for item in report.findings if item.rule == "mail_cleartext")
    assert mail.new_since_baseline is True

    # 1883 was outside the baseline's coverage (1-1000): ARGUS cannot say
    # whether it is new, so it says "unknown" rather than guessing.
    mqtt = next(item for item in report.findings if item.rule == "mqtt_cleartext")
    assert mqtt.new_since_baseline is None

    rtsp = next(item for item in report.findings if item.rule == "rtsp_camera_stream")
    assert rtsp.streak == 3
    assert rtsp.first_seen_scan == first


def test_accepted_risks_come_from_the_database():
    connection = connect()
    result = scan(camera(23))
    telnet = next(item for item in analyze(result).findings if item.rule == "telnet_open")

    accept_risk(connection, telnet, "lab camera, unplugged from the main network",
                expires_on=date.today() + timedelta(days=7))

    report = analyze_with_history(connection, result)

    assert "telnet_open" in [item.rule for item in report.accepted]
    assert "telnet_open" not in [item.rule for item in report.findings]
