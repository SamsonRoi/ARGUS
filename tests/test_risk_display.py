from datetime import date, timedelta

from rich.console import Console

from argus.modules.classify import classify_result
from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo, OSGuess, PortInfo, ScanResult
from argus.modules.risk import Acceptance, analyze
from argus.modules.risk_history import risk_changes
from argus.results_display import show_risk_changes, show_risk_report


def render(function, *args, **kwargs):
    console = Console(record=True, width=220)
    function(*args, output=console, **kwargs)
    return console.export_text()


def office(*camera_ports):
    result = ScanResult(
        targets=["192.168.1.0/24"],
        profile="Full TCP",
        evidence=ScanEvidence(coverage={"tcp": set(range(1, 65536))}),
    )
    router = HostInfo("192.168.1.1", vendor="MikroTik", os_guess=OSGuess("MikroTik RouterOS 7", 95))
    router.add_port(PortInfo(80))
    dc = HostInfo("192.168.1.5", hostname="[bold]dc01[/bold]")
    for number in (53, 88, 389, 445, 3268):
        dc.add_port(PortInfo(number))
    camera = HostInfo("192.168.1.30", vendor="Hikvision")
    for number in camera_ports or (23, 554):
        camera.add_port(PortInfo(number))

    for item in (router, dc, camera):
        result.add_host(item)

    return classify_result(result)


def test_report_shows_grade_plan_findings_paths_and_footer():
    text = render(show_risk_report, analyze(office()))

    assert "RISK ANALYSIS" in text
    assert "Risk grade" in text
    assert "Fix these first" in text
    assert "Findings (highest priority first)" in text
    assert "Telnet is open" in text
    assert "Raised because" in text
    assert "Score" in text and "critical severity: 9.5" in text
    assert "Possible attack paths" in text
    assert "Possible, not proven" in text
    assert "Highest-risk hosts" in text
    assert "did not try to exploit anything" in text


def test_detail_limit_hides_and_then_shows_everything():
    report = analyze(office())

    limited = render(show_risk_report, report, detail_limit=1)
    everything = render(show_risk_report, report, detail_limit=None)

    assert "more finding(s) are hidden" in limited
    assert "hidden" not in everything
    assert everything.count("How to fix") == len(report.findings)


def test_untrusted_text_is_shown_literally():
    text = render(show_risk_report, analyze(office()))

    assert "[bold]dc01[/bold]" in text


def test_clean_report():
    result = ScanResult(targets=["10.0.0.0/24"], profile="Full TCP",
                        evidence=ScanEvidence(coverage={"tcp": {443}}))
    text = render(show_risk_report, analyze(classify_result(result)))

    assert "No open risk findings" in text
    assert " A " in text


def test_accepted_risks_are_listed_separately():
    result = office()
    telnet = next(item for item in analyze(result).findings if item.rule == "telnet_open")
    report = analyze(result, acceptances={telnet.fingerprint: Acceptance(
        1, telnet.fingerprint, "isolated lab", expires_on=date.today() + timedelta(days=5)
    )})

    text = render(show_risk_report, report)

    assert "Accepted risks (not counted in the grade)" in text
    assert "isolated lab" in text


def test_history_columns_and_change_tables():
    report = analyze(office())
    telnet = next(item for item in report.findings if item.rule == "telnet_open")
    telnet.streak, telnet.first_seen_scan, telnet.new_since_baseline = 4, 2, True
    report.compared_with = 7
    report.resolved = [next(item for item in report.findings if item.rule == "rtsp_camera_stream")]

    text = render(show_risk_report, report)

    assert "NEW since baseline" in text
    assert "open for 4 scans" in text
    assert "first seen in #2" in text
    assert "vs scan #7" in text
    assert "Resolved since scan #7" in text


def test_risk_changes_screen():
    changes = risk_changes(office(23, 554), office(554, 1883))
    text = render(show_risk_changes, changes)

    assert "New" in text and "MQTT" in text
    assert "Resolved" in text and "Telnet is open" in text

    nothing = render(show_risk_changes, risk_changes(office(), office()))
    assert "No change in risk findings" in nothing
