from datetime import date, timedelta

from argus import history_menu, menus, risk_menu
from argus.modules.classify import classify_result
from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo, PortInfo, ScanResult
from argus.storage.database import StorageError, connect
from argus.storage.repository import list_acceptances, save_scan
from argus.utils.session import Session


def feed(monkeypatch, module, name, answers):
    remaining = iter(answers)
    monkeypatch.setattr(module, name, lambda *a, **k: next(remaining))


def quiet(monkeypatch, module=risk_menu):
    monkeypatch.setattr(module, "wait_for_enter", lambda *a, **k: None)


def camera_scan():
    result = ScanResult(
        targets=["192.168.1.30"],
        profile="Standard TCP",
        evidence=ScanEvidence(coverage={"tcp": set(range(1, 1001))}),
    )
    camera = HostInfo("192.168.1.30", vendor="Hikvision")
    camera.add_port(PortInfo(23))
    camera.add_port(PortInfo(554))
    result.add_host(camera)
    return classify_result(result)


def test_risk_flow_shows_report_and_details(monkeypatch):
    shown = []
    monkeypatch.setattr(risk_menu, "show_risk_report", lambda report, **k: shown.append(k))
    feed(monkeypatch, risk_menu, "get_menu_choice", [1, 0])

    risk_menu.risk_analysis_flow(camera_scan())

    assert shown == [{}, {"detail_limit": None}]


def test_accepting_a_finding_from_the_flow(monkeypatch):
    monkeypatch.setattr(risk_menu, "show_risk_report", lambda report, **k: None)
    until = (date.today() + timedelta(days=30)).isoformat()
    # menu: accept -> finding #1 -> back
    feed(monkeypatch, risk_menu, "get_menu_choice", [2, 1, 0])
    feed(monkeypatch, risk_menu, "get_text_input", ["camera is on an isolated VLAN"])
    feed(monkeypatch, risk_menu, "get_optional_text", ["Samson", until])

    risk_menu.risk_analysis_flow(camera_scan())

    [record] = list_acceptances(connect())
    assert record.reason == "camera is on an isolated VLAN"
    assert record.accepted_by == "Samson"
    assert record.expires_on.isoformat() == until


def test_no_expiry_needs_confirmation(monkeypatch):
    monkeypatch.setattr(risk_menu, "show_risk_report", lambda report, **k: None)
    later = (date.today() + timedelta(days=3)).isoformat()
    feed(monkeypatch, risk_menu, "get_menu_choice", [2, 1, 0])
    feed(monkeypatch, risk_menu, "get_text_input", ["lab"])
    feed(monkeypatch, risk_menu, "get_optional_text", [None, None, later])
    feed(monkeypatch, risk_menu, "ask_yes_no", [False])

    risk_menu.risk_analysis_flow(camera_scan())

    assert list_acceptances(connect())[0].expires_on.isoformat() == later


def test_expiry_date_is_validated(monkeypatch, capsys):
    past = (date.today() - timedelta(days=1)).isoformat()
    later = (date.today() + timedelta(days=1)).isoformat()
    feed(monkeypatch, risk_menu, "get_optional_text", ["soon", past, later])

    assert risk_menu._ask_expiry().isoformat() == later
    out = capsys.readouterr().out
    assert "YYYY-MM-DD" in out and "in the past" in out


def test_without_history_the_analysis_still_runs(monkeypatch, capsys):
    def broken():
        raise StorageError("locked")

    monkeypatch.setattr(risk_menu, "connect", broken)
    shown = []
    monkeypatch.setattr(risk_menu, "show_risk_report", lambda report, **k: shown.append(report))
    feed(monkeypatch, risk_menu, "get_menu_choice", [2, 0])

    risk_menu.risk_analysis_flow(camera_scan())

    out = capsys.readouterr().out
    assert shown and shown[0].findings
    assert "runs without history" in out
    assert "needs the scan history database" in out


def test_revoke_from_accepted_risks(monkeypatch):
    from argus.modules.risk import analyze
    from argus.storage.repository import accept_risk

    connection = connect()
    finding = analyze(camera_scan()).findings[0]
    record_id = accept_risk(connection, finding, "temporary")
    quiet(monkeypatch)
    feed(monkeypatch, risk_menu, "get_menu_choice", [record_id, 0])
    feed(monkeypatch, risk_menu, "ask_yes_no", [True])

    risk_menu.accepted_risks_menu(connection)

    assert list_acceptances(connection) == []


def test_session_menu_opens_risk_analysis(monkeypatch):
    session = Session()
    session.set_target("Single IP", ["192.168.1.30"])
    session.scan_result = camera_scan()
    session.scan_id = 5
    monkeypatch.setattr(menus, "current_session", session)
    calls = []
    monkeypatch.setattr(menus, "risk_analysis_flow", lambda result, **k: calls.append((result, k)))
    feed(monkeypatch, menus, "get_menu_choice", [5, 0])
    monkeypatch.setattr(menus, "wait_for_enter", lambda *a, **k: None)

    menus.current_session_menu()

    assert calls == [(session.scan_result, {"scan_id": 5, "engagement_id": None})]


def test_history_menu_risk_and_accepted_risks(monkeypatch):
    connection = connect()
    scan_id = save_scan(connection, camera_scan())
    connection.close()
    calls = []
    monkeypatch.setattr(history_menu, "risk_analysis_flow", lambda result, **k: calls.append(k))
    monkeypatch.setattr(history_menu, "accepted_risks_menu", lambda conn: calls.append("accepted"))
    quiet(monkeypatch, history_menu)
    feed(monkeypatch, history_menu, "get_menu_choice", [3, scan_id, 10, 0])

    session = Session()
    history_menu.scan_history_menu(session)

    assert calls == [{"scan_id": scan_id, "engagement_id": None}, "accepted"]


def test_comparison_screen_includes_risk_changes(monkeypatch, capsys):
    connection = connect()
    older = camera_scan()
    newer = camera_scan()
    newer.started_at = older.started_at + timedelta(hours=1)
    newer.get_host("192.168.1.30").ports = [PortInfo(554)]
    first, second = save_scan(connection, older), save_scan(connection, newer)
    connection.close()
    quiet(monkeypatch, history_menu)
    feed(monkeypatch, history_menu, "get_menu_choice", [5, first, second, 0])

    history_menu.scan_history_menu(Session())

    out = capsys.readouterr().out
    assert "RISK CHANGES" in out
    assert "Telnet is open" in out
