from datetime import datetime

import pytest

from argus import report_menu
from argus.reports.generate import write_reports
from argus.storage.database import connect
from argus.storage.repository import list_reports
from sample_network import office_report


@pytest.fixture(autouse=True)
def quiet(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(report_menu, "wait_for_enter", lambda *a, **k: None)


def replies(monkeypatch, *answers):
    remaining = iter(answers)
    monkeypatch.setattr(report_menu, "get_text_input", lambda prompt: next(remaining))


def make_reports():
    connection = connect()
    first = write_reports(office_report(), ("html", "json"), connection=connection,
                          when=datetime(2026, 11, 1, 9, 0, 0))
    second = write_reports(office_report(), ("html", "pdf", "csv"), connection=connection,
                           when=datetime(2026, 11, 2, 9, 0, 0), redact=True)
    connection.close()
    return first, second


def test_reports_are_grouped_newest_first():
    first, second = make_reports()

    sets = report_menu.group_reports(list_reports(connect()))

    assert [item.folder for item in sets] == [second.folder, first.folder]
    assert sets[0].formats == "HTML, PDF, CSV"
    assert sets[0].redacted
    assert len(sets[0].files) == len(second.files)
    assert sets[1].formats == "HTML, JSON"


def test_pick_a_report_and_verify_all_its_files(monkeypatch, capsys):
    make_reports()
    replies(monkeypatch, "2")          # the older report

    report_menu.verify_report_flow()

    out = capsys.readouterr().out
    assert "Your reports (newest first)" in out
    assert out.count("VERIFIED") == 2
    assert "All 2 file(s) are exactly as ARGUS wrote them." in out


def test_changed_and_missing_files_are_reported(monkeypatch, capsys):
    first, _second = make_reports()
    html = next(item.path for item in first.files if item.format == "html")
    json_file = next(item.path for item in first.files if item.format == "json")
    html.write_text(html.read_text().replace("Risk grade", "Risk grade!"))
    json_file.unlink()
    replies(monkeypatch, "2")

    report_menu.verify_report_flow()

    out = capsys.readouterr().out
    assert "MODIFIED" in out and "MISSING" in out
    assert "1 file(s) were changed after ARGUS wrote them" in out
    assert "1 file(s) were moved or deleted" in out


def test_bad_choices_are_asked_again_and_zero_goes_back(monkeypatch, capsys):
    make_reports()
    replies(monkeypatch, "9", "abc", "0")

    report_menu.verify_report_flow()

    out = capsys.readouterr().out
    assert out.count("Enter a number from 0 to 2, or P.") == 2
    assert "Checking" not in out


def test_a_path_can_still_be_typed(monkeypatch, capsys, tmp_path):
    make_reports()
    stranger = tmp_path / "from-a-colleague.html"
    stranger.write_text("<p>not from ARGUS</p>")
    replies(monkeypatch, "P", str(stranger))

    report_menu.verify_report_flow()

    assert "UNKNOWN" in capsys.readouterr().out


def test_no_reports_yet_offers_a_path(monkeypatch, capsys, tmp_path):
    file = tmp_path / "x.html"
    file.write_text("hi")
    monkeypatch.setattr(report_menu, "ask_yes_no", lambda prompt: True)
    replies(monkeypatch, str(file))

    report_menu.verify_report_flow()

    out = capsys.readouterr().out
    assert "has not made any reports on this computer yet" in out
    assert "UNKNOWN" in out


def test_deleted_report_folders_are_marked(monkeypatch, capsys):
    import shutil

    first, _second = make_reports()
    shutil.rmtree(first.folder)
    replies(monkeypatch, "0")

    report_menu.verify_report_flow()

    assert "(folder deleted)" in capsys.readouterr().out
