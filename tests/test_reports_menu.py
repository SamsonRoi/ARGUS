import pytest

from argus import menus, report_menu
from argus.storage.database import connect
from argus.storage.repository import save_scan
from argus.utils.session import Session
from sample_network import office_scan


@pytest.fixture(autouse=True)
def reports_dir(tmp_path, monkeypatch):
    folder = tmp_path / "reports"
    monkeypatch.setenv("ARGUS_REPORTS_DIR", str(folder))
    monkeypatch.setattr(menus, "wait_for_enter", lambda *a, **k: None)
    monkeypatch.setattr(report_menu, "wait_for_enter", lambda *a, **k: None)
    return folder


def answers(monkeypatch, menu_choices, yes_no=()):
    choices = iter(menu_choices)
    replies = iter(yes_no)
    monkeypatch.setattr(menus, "get_menu_choice", lambda *a, **k: next(choices))
    monkeypatch.setattr(report_menu, "get_menu_choice", lambda *a, **k: next(choices))
    monkeypatch.setattr(report_menu, "ask_yes_no", lambda prompt: next(replies))
    import argus.history_menu as history_menu
    monkeypatch.setattr(history_menu, "get_menu_choice", lambda *a, **k: next(choices))


def test_main_menu_reports_is_no_longer_a_placeholder(monkeypatch, capsys):
    monkeypatch.setattr(menus, "current_session", Session())
    answers(monkeypatch, [0])

    menus.show_reports()

    out = capsys.readouterr().out
    assert "not built yet" not in out
    assert "REPORTS" in out and "Report for a saved scan" in out


def test_current_scan_report_needs_a_scan(monkeypatch, capsys):
    monkeypatch.setattr(menus, "current_session", Session())
    answers(monkeypatch, [1, 0])

    menus.show_reports()

    assert "No scan has been run in this session yet" in capsys.readouterr().out


def test_report_for_the_current_scan(monkeypatch, reports_dir):
    session = Session()
    session.set_target("CIDR Range", ["192.168.1.0/24"])
    session.scan_result = office_scan()
    monkeypatch.setattr(menus, "current_session", session)
    # Reports -> current scan -> HTML only -> back;  redact? no, open now? no
    answers(monkeypatch, [1, 2, 0], yes_no=[False, False])

    menus.show_reports()

    folder = next(reports_dir.iterdir())
    assert (folder / "argus-report.html").is_file()


def test_report_for_a_saved_scan(monkeypatch, reports_dir):
    connection = connect()
    scan_id = save_scan(connection, office_scan())
    connection.close()
    monkeypatch.setattr(menus, "current_session", Session())
    # Reports -> saved scan -> pick it -> JSON and CSV -> back
    answers(monkeypatch, [2, scan_id, 4, 0], yes_no=[False])

    menus.show_reports()

    folder = next(reports_dir.iterdir())
    assert folder.name.startswith(f"scan-{scan_id}-")
    assert (folder / "argus-report.json").is_file()


def test_saved_scan_report_with_empty_history(monkeypatch, capsys):
    monkeypatch.setattr(menus, "current_session", Session())
    answers(monkeypatch, [2, 0])

    menus.show_reports()

    assert "No scans have been saved yet" in capsys.readouterr().out


def test_verify_and_open_folder_are_routed(monkeypatch, reports_dir):
    calls = []
    monkeypatch.setattr(menus, "current_session", Session())
    monkeypatch.setattr(menus, "verify_report_flow", lambda: calls.append("verify"))
    monkeypatch.setattr(report_menu, "open_path", lambda path: calls.append(("open", path)) or True)
    answers(monkeypatch, [3, 4, 0])

    menus.show_reports()

    assert calls == ["verify", ("open", reports_dir)]
    assert reports_dir.is_dir()


def test_offer_to_open_the_report_after_making_it(monkeypatch):
    opened = []
    monkeypatch.setattr(report_menu, "open_path", lambda path: opened.append(path) or True)
    answers(monkeypatch, [3], yes_no=[False, True])   # HTML and PDF; no redaction; open now

    report_menu.generate_report_flow(office_scan())

    assert opened and opened[0].name == "argus-report.html"


def test_about_describes_what_argus_does(monkeypatch, capsys):
    menus.about_menu()

    out = capsys.readouterr().out
    assert "under development" not in out
    assert "Writes HTML, PDF, JSON and CSV reports" in out
