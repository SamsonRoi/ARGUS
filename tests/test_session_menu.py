from argus import menus
from argus.modules.classify import classify_result
from argus.modules.models import HostInfo, PortInfo, ScanResult
from argus.utils.session import Session


def feed(monkeypatch, answers):
    remaining = iter(answers)
    monkeypatch.setattr(menus, "get_menu_choice", lambda *a, **k: next(remaining))
    monkeypatch.setattr(menus, "wait_for_enter", lambda *a, **k: None)


def active_session(with_scan=True):
    session = Session()
    session.set_target("Single IP", ["10.0.0.5"])

    if with_scan:
        result = ScanResult(targets=["10.0.0.5"], profile="Quick TCP")
        item = HostInfo("10.0.0.5")
        item.add_port(PortInfo(3306))
        result.add_host(item)
        session.scan_result = classify_result(result)

    return session


def test_assets_and_map_open_for_the_last_scan(monkeypatch):
    session = active_session()
    monkeypatch.setattr(menus, "current_session", session)
    shown = []
    monkeypatch.setattr(menus, "show_assets", lambda result: shown.append(("assets", result)))
    monkeypatch.setattr(menus, "show_network_map", lambda network_map: shown.append(("map", network_map)))
    feed(monkeypatch, [3, 4, 0])

    menus.current_session_menu()

    assert [kind for kind, _ in shown] == ["assets", "map"]
    assert shown[0][1] is session.scan_result
    assert shown[1][1].subnets[0].host_ips == ["10.0.0.5"]


def test_assets_without_a_scan_explain_why(monkeypatch, capsys):
    monkeypatch.setattr(menus, "current_session", active_session(with_scan=False))
    feed(monkeypatch, [3, 4, 5, 0])

    menus.current_session_menu()

    assert capsys.readouterr().out.count("No scan has been run in this session yet.") == 3


def test_clear_session_is_option_six(monkeypatch):
    session = active_session()
    monkeypatch.setattr(menus, "current_session", session)
    feed(monkeypatch, [6, 0])

    menus.current_session_menu()

    assert session.scan_result is None
