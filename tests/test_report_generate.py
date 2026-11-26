import hashlib
from datetime import datetime, timedelta

import pytest

from argus import main as cli
from argus import menus, report_menu
from argus.reports import generate
from argus.reports.generate import ReportError, write_reports
from argus.reports.verify import MODIFIED, UNKNOWN, VERIFIED, verify_report
from argus.storage.database import connect
from argus.storage.repository import create_engagement, save_scan, set_baseline
from argus.utils.session import Session
from sample_network import office_report, office_scan


@pytest.fixture(autouse=True)
def reports_dir(tmp_path, monkeypatch):
    folder = tmp_path / "reports"
    monkeypatch.setenv("ARGUS_REPORTS_DIR", str(folder))
    return folder


def test_every_format_with_fingerprints(reports_dir):
    connection = connect()
    output = write_reports(office_report(), connection=connection)

    assert output.folder.parent == reports_dir
    assert sorted({item.format for item in output.files}) == ["csv", "html", "json", "pdf"]

    sums = (output.folder / "SHA256SUMS").read_text().splitlines()
    assert len(sums) == len(output.files)

    for item in output.files:
        assert item.sha256 == hashlib.sha256(item.path.read_bytes()).hexdigest()
        assert f"{item.sha256}  {item.path.name}" in sums

    assert connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == len(output.files)


def test_folder_names(reports_dir):
    when = datetime(2026, 12, 1, 9, 30, 5)
    data = office_report()
    data["engagement"] = {"name": "Office LAN / Dec", "hosts_outside_scope": [], "scope": []}

    first = write_reports(data, ("json",), when=when)
    second = write_reports(data, ("json",), when=when)
    redacted = write_reports(data, ("json",), when=when, redact=True)

    assert first.folder.name == "office-lan-dec-scan-12-20261201-093005"
    assert second.folder != first.folder
    assert redacted.folder.name.endswith("-redacted")


def test_bad_format_choices():
    with pytest.raises(ReportError, match="Unknown"):
        write_reports(office_report(), ("docx",))

    with pytest.raises(ReportError, match="at least one"):
        write_reports(office_report(), ())


def test_pdf_is_skipped_with_a_warning_when_nothing_can_make_it(monkeypatch):
    monkeypatch.setattr(generate, "pdf_engine", lambda: None)

    output = write_reports(office_report(), ("html", "pdf"))

    assert [item.format for item in output.files] == ["html"]
    assert "Chrome or Microsoft Edge" in output.warnings[0]


def test_basic_pdf_is_used_without_a_browser(monkeypatch):
    monkeypatch.setattr(generate, "pdf_engine", lambda: "reportlab")

    output = write_reports(office_report(), ("pdf",))

    assert [item.format for item in output.files] == ["pdf"]
    assert "basic layout" in output.warnings[0]


def test_browser_failure_falls_back_to_the_basic_pdf(monkeypatch):
    from argus.reports.pdf_report import PDFRenderError

    def broken(data, path):
        raise PDFRenderError("The browser did not produce a PDF (crashed).")

    monkeypatch.setattr(generate, "pdf_engine", lambda: "browser")
    monkeypatch.setattr(generate, "write_pdf", broken)

    output = write_reports(office_report(), ("pdf",))

    assert [item.format for item in output.files] == ["pdf"]
    assert "basic layout instead" in output.warnings[0]


def test_generate_from_history_includes_engagement_and_changes():
    connection = connect()
    office = create_engagement(connection, "Office LAN", authorized_by="R. Kumar", scope=["192.168.1.0/24"])

    older = office_scan()
    first = save_scan(connection, older, engagement_id=office.id)
    set_baseline(connection, first)

    newer = office_scan()
    newer.started_at = older.started_at + timedelta(hours=2)
    newer.get_host("192.168.1.30").ports = [p for p in newer.get_host("192.168.1.30").ports if p.port != 23]
    second = save_scan(connection, newer, engagement_id=office.id)

    data = generate.prepare_report_data(newer, connection=connection, scan_id=second, engagement_id=office.id)

    assert data["engagement"]["name"] == "Office LAN"
    assert data["engagement"]["hosts_outside_scope"] == []
    assert data["changes"]["compared_with"] == first
    assert "telnet_open" in [item["rule"] for item in data["changes"]["resolved"]]
    rtsp = next(item for item in data["findings"] if item["rule"] == "rtsp_camera_stream")
    assert rtsp["history"]["streak"] == 2


# ---------- verification ----------

def test_verify_unchanged_modified_copied_and_unknown(tmp_path):
    connection = connect()
    output = write_reports(office_report(), ("html", "json"), connection=connection)
    html = next(item.path for item in output.files if item.format == "html")

    check = verify_report(html, connection)
    assert check.status == VERIFIED
    # Scan #12 is not in this database, so the record keeps no scan link.
    assert any("Matches a HTML report ARGUS generated" in line for line in check.details)

    copy = tmp_path / "elsewhere.html"
    copy.write_bytes(html.read_bytes())
    assert verify_report(copy, connection).status == VERIFIED

    html.write_text(html.read_text().replace("Risk grade", "Risk grade!"))
    changed = verify_report(html, connection)
    assert changed.status == MODIFIED
    assert any("Does NOT match the SHA256SUMS" in line for line in changed.details)

    stranger = tmp_path / "stranger.html"
    stranger.write_text("<p>hi</p>")
    assert verify_report(stranger, connection).status == UNKNOWN


def test_verify_without_database_uses_sums_file():
    output = write_reports(office_report(), ("json",))
    path = output.files[0].path

    assert verify_report(path).status == VERIFIED

    path.write_text(path.read_text() + " ")
    assert verify_report(path).status == MODIFIED


def test_verify_missing_file():
    with pytest.raises(FileNotFoundError):
        verify_report("does-not-exist.html")


# ---------- command line ----------

def saved_scan():
    connection = connect()
    scan_id = save_scan(connection, office_scan())
    connection.close()
    return scan_id


def test_cli_report_and_verify(reports_dir, capsys):
    scan_id = saved_scan()

    assert cli.main(["report", str(scan_id), "-f", "html,json"]) == cli.EXIT_OK
    folder = next(reports_dir.iterdir())
    assert sorted(path.name for path in folder.iterdir()) == ["SHA256SUMS", "argus-report.html", "argus-report.json"]

    assert cli.main(["verify", str(folder / "argus-report.html")]) == cli.EXIT_OK
    (folder / "argus-report.json").write_text("{}")
    assert cli.main(["verify", str(folder / "argus-report.json")]) == cli.EXIT_MODIFIED
    assert cli.main(["verify", "nope.html"]) == cli.EXIT_ERROR


def test_cli_latest_redacted(reports_dir):
    saved_scan()

    assert cli.main(["report", "--latest", "-f", "json", "--redact"]) == cli.EXIT_OK
    folder = next(reports_dir.iterdir())
    assert folder.name.endswith("-redacted")
    assert "192.168." not in (folder / "argus-report.json").read_text()


def test_cli_errors(capsys):
    assert cli.main(["report", "999"]) == cli.EXIT_ERROR
    assert cli.main(["report", "--latest"]) == cli.EXIT_ERROR

    with pytest.raises(SystemExit):
        cli.main(["report", "1", "-f", "docx"])


def test_cli_scans(capsys):
    saved_scan()

    assert cli.main(["scans"]) == cli.EXIT_OK
    assert "Saved scans" in capsys.readouterr().out


def test_no_command_starts_the_menus(monkeypatch):
    monkeypatch.setattr(cli, "interactive", lambda: "menus")

    assert cli.main([]) == "menus"


# ---------- menus ----------

def test_report_flow_from_the_session_menu(monkeypatch, reports_dir):
    session = Session()
    session.set_target("CIDR Range", ["192.168.1.0/24"])
    session.scan_result = office_scan()
    monkeypatch.setattr(menus, "current_session", session)
    monkeypatch.setattr(menus, "wait_for_enter", lambda *a, **k: None)
    monkeypatch.setattr(report_menu, "wait_for_enter", lambda *a, **k: None)
    answers = iter([6, 3, 0])   # Generate Report -> HTML and PDF -> back
    monkeypatch.setattr(menus, "get_menu_choice", lambda *a, **k: next(answers))
    monkeypatch.setattr(report_menu, "get_menu_choice", lambda *a, **k: next(answers))
    monkeypatch.setattr(report_menu, "ask_yes_no", lambda prompt: False)

    menus.current_session_menu()

    folder = next(reports_dir.iterdir())
    assert sorted(path.suffix for path in folder.iterdir() if path.suffix) == [".html", ".pdf"]


def test_verify_flow_accepts_quoted_windows_paths(monkeypatch, capsys):
    output = write_reports(office_report(), ("json",), connection=connect())
    replies = iter(["p", f'"{output.files[0].path}"'])
    monkeypatch.setattr(report_menu, "get_text_input", lambda prompt: next(replies))
    monkeypatch.setattr(report_menu, "wait_for_enter", lambda *a, **k: None)

    report_menu.verify_report_flow()

    assert "VERIFIED" in capsys.readouterr().out
