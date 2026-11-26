from datetime import datetime, timedelta

import pytest
from rich.console import Console

from argus import history_menu, scan_menu
from argus.modules.compare import compare_scans
from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo, PortInfo, ScanResult
from argus.results_display import show_comparison
from argus.storage.database import StorageError, connect
from argus.storage.repository import (
    create_engagement,
    get_baseline_id,
    list_scans,
    load_scan,
    save_scan,
)
from argus.utils.session import Session


def feed(monkeypatch, name, answers):
    remaining = iter(answers)
    monkeypatch.setattr(history_menu, name, lambda *a, **k: next(remaining))


def quiet(monkeypatch):
    monkeypatch.setattr(history_menu, "wait_for_enter", lambda *a, **k: None)


def result_with(ports, started=None, targets=("10.0.0.5",)):
    result = ScanResult(
        targets=list(targets),
        profile="Quick TCP",
        evidence=ScanEvidence(coverage={"tcp": set(range(1, 1025))}),
    )

    if started:
        result.started_at = started

    item = HostInfo(ip="10.0.0.5")

    for port in ports:
        item.add_port(PortInfo(port, "tcp"))

    result.add_host(item)
    result.finish()
    return result


def make_session():
    session = Session()
    session.set_target("Single IP", ["10.0.0.5"])
    return session


# ---------- saving ----------

def test_save_to_history_stores_the_scan_and_its_id(capsys):
    session = make_session()

    scan_id = history_menu.save_to_history(session, result_with([22]))

    assert session.scan_id == scan_id
    assert f"scan #{scan_id}" in capsys.readouterr().out

    connection = connect()
    assert load_scan(connection, scan_id).get_host("10.0.0.5").open_ports[0].port == 22


def test_save_files_the_scan_under_the_current_engagement():
    connection = connect()
    office = create_engagement(connection, "Office LAN", scope=["10.0.0.5"])
    session = make_session()
    session.engagement_id = office.id

    history_menu.save_to_history(session, result_with([22]))

    assert list_scans(connection)[0].engagement_name == "Office LAN"


def test_a_failed_save_is_reported_and_never_crashes(monkeypatch, capsys):
    def broken():
        raise StorageError("disk is full")

    monkeypatch.setattr(history_menu, "connect", broken)
    session = make_session()

    assert history_menu.save_to_history(session, result_with([22])) is None
    assert session.scan_id is None
    assert "disk is full" in capsys.readouterr().out


def test_scan_flow_saves_every_scan(monkeypatch):
    monkeypatch.setattr(scan_menu, "ask_scanning_choice", lambda: ("quick", None))
    monkeypatch.setattr(
        scan_menu, "ask_scan_options", lambda *a, **k: scan_menu.ScanOptions()
    )
    monkeypatch.setattr(scan_menu, "ask_yes_no", lambda prompt: True)
    monkeypatch.setattr(scan_menu, "wait_for_enter", lambda *a, **k: None)
    monkeypatch.setattr(scan_menu, "show_scan_results", lambda *a, **k: None)
    monkeypatch.setattr(
        scan_menu, "run_with_progress", lambda targets, options: result_with([80])
    )
    session = make_session()

    scan_menu.run_scan_flow(session)

    assert session.scan_id is not None
    assert list_scans(connect())[0].id == session.scan_id


def test_discovery_flow_saves_too(monkeypatch):
    monkeypatch.setattr(scan_menu, "ask_discovery_methods", lambda: ["tcp_syn"])
    monkeypatch.setattr(scan_menu, "ask_yes_no", lambda prompt: True)
    monkeypatch.setattr(scan_menu, "wait_for_enter", lambda *a, **k: None)
    monkeypatch.setattr(scan_menu, "show_scan_results", lambda *a, **k: None)
    monkeypatch.setattr(
        scan_menu,
        "discover_hosts",
        lambda targets, methods: ScanResult(targets=targets, profile="discovery"),
    )
    session = make_session()

    scan_menu.run_discovery_flow(session)

    assert list_scans(connect())[0].kind == "discovery"


# ---------- the history screen ----------

@pytest.fixture
def two_scans():
    connection = connect()
    now = datetime.now().astimezone()
    older = save_scan(connection, result_with([22, 80], started=now - timedelta(hours=2)))
    newer = save_scan(connection, result_with([22, 443], started=now))
    connection.close()
    return older, newer


def test_empty_history_explains_itself(monkeypatch, capsys):
    quiet(monkeypatch)
    feed(monkeypatch, "get_menu_choice", [1, 0])

    history_menu.scan_history_menu(make_session())

    text = capsys.readouterr().out
    assert "No scans have been saved yet" in text
    assert "There are no saved scans yet" in text


def test_compare_two_scans_from_the_menu(monkeypatch, capsys, two_scans):
    older, newer = two_scans
    quiet(monkeypatch)
    # menu: compare -> pick newer first, then older -> back out
    feed(monkeypatch, "get_menu_choice", [4, newer, older, 0])

    history_menu.scan_history_menu(make_session())

    text = capsys.readouterr().out
    assert "SCAN COMPARISON" in text
    assert "443/tcp is now open" in text
    assert "80/tcp is no longer open" in text
    # Always shown oldest -> newest, whatever order they were picked in.
    assert text.index(f"#{older} -") < text.index(f"#{newer} -")


def test_baseline_then_compare_latest(monkeypatch, capsys, two_scans):
    older, newer = two_scans
    quiet(monkeypatch)
    feed(monkeypatch, "get_menu_choice", [6, older, 5, 0])

    history_menu.scan_history_menu(make_session())

    text = capsys.readouterr().out
    assert get_baseline_id(connect(), None) == older
    assert f"Scan #{older} is now the baseline" in text
    assert "443/tcp is now open" in text


def test_compare_latest_without_baseline(monkeypatch, capsys, two_scans):
    quiet(monkeypatch)
    feed(monkeypatch, "get_menu_choice", [5, 0])

    history_menu.scan_history_menu(make_session())

    assert "No baseline is set" in capsys.readouterr().out


def test_delete_asks_first(monkeypatch, capsys, two_scans):
    older, newer = two_scans
    quiet(monkeypatch)
    feed(monkeypatch, "get_menu_choice", [7, older, 7, older, 0])
    feed(monkeypatch, "ask_yes_no", [False, True])

    history_menu.scan_history_menu(make_session())

    text = capsys.readouterr().out
    assert "Nothing was deleted" in text
    assert f"Scan #{older} was deleted" in text
    assert [s.id for s in list_scans(connect())] == [newer]


def test_view_a_saved_scan(monkeypatch, two_scans):
    older, _newer = two_scans
    quiet(monkeypatch)
    shown = []
    monkeypatch.setattr(history_menu, "show_scan_results", lambda result, **k: shown.append(result))
    monkeypatch.setattr(history_menu, "show_assets", lambda result, **k: None)
    feed(monkeypatch, "get_menu_choice", [1, older, 0])

    history_menu.scan_history_menu(make_session())

    assert [p.port for p in shown[0].get_host("10.0.0.5").open_ports] == [22, 80]


def test_create_and_choose_an_engagement(monkeypatch, capsys):
    quiet(monkeypatch)
    session = make_session()
    feed(monkeypatch, "get_menu_choice", [8, 1, 0, 0])
    feed(monkeypatch, "get_text_input", ["Office LAN"])
    # authorized by, scope (Enter = session targets), start, end, notes
    feed(monkeypatch, "get_optional_text", ["R. Kumar", None, "2026-12-01", None, None])
    feed(monkeypatch, "ask_yes_no", [True])

    history_menu.scan_history_menu(session)

    assert session.engagement_name == "Office LAN"
    engagement = history_menu.list_engagements(connect())[0]
    assert engagement.scope == ["10.0.0.5"]
    assert engagement.authorized_by == "R. Kumar"
    assert engagement.starts_on.isoformat() == "2026-12-01"


def test_scope_input_is_validated(monkeypatch, capsys):
    feed(monkeypatch, "get_optional_text", ["10.0.0.0/24, nonsense", "10.0.0.0/24, 10.0.0.0/24"])

    scope = history_menu._ask_scope(Session())

    assert scope == ["10.0.0.0/24"]
    assert "nonsense" in capsys.readouterr().out


# ---------- display ----------

def test_comparison_display_escapes_untrusted_text():
    older = result_with([22])
    newer = result_with([22])
    newer.hosts[0].ports[0] = PortInfo(22, "tcp", "open", "ssh", "[bold]Evil[/bold]", "1")
    older.hosts[0].ports[0] = PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "8.9")

    console = Console(record=True, width=200)
    show_comparison(compare_scans(older, newer), "#1", "#2", output=console)

    assert "[bold]Evil[/bold] 1" in console.export_text()


def test_network_map_of_a_saved_scan(monkeypatch, two_scans):
    older, _newer = two_scans
    quiet(monkeypatch)
    maps = []
    monkeypatch.setattr(history_menu, "show_network_map", lambda network_map: maps.append(network_map))
    feed(monkeypatch, "get_menu_choice", [2, older, 0])

    history_menu.scan_history_menu(make_session())

    assert maps[0].subnets[0].host_ips == ["10.0.0.5"]
