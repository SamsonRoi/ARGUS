import csv
import json
import re
import subprocess

import pytest

from argus.reports.csv_report import safe_cell, write_csv
from argus.reports.html_report import render_html
from argus.reports.json_report import to_json
from argus.reports.layout import build_diagram
from argus.reports.redact import redact_report
from sample_network import FORMULA_BANNER, HOSTILE_BANNER, office_report


# ---------- JSON ----------

def test_json_is_the_model():
    data = office_report()

    assert json.loads(to_json(data)) == json.loads(json.dumps(data))


# ---------- CSV ----------

@pytest.mark.parametrize("value, expected", [
    ("=SUM(A1)", "'=SUM(A1)"),
    ("+1", "'+1"),
    ("-cmd", "'-cmd"),
    ("@x", "'@x"),
    ("plain", "plain"),
    (-5, "-5"),
    (None, ""),
    (True, "yes"),
    (["a", "b"], "a; b"),
])
def test_csv_cells_are_safe(value, expected):
    assert safe_cell(value) == expected


def test_csv_files(tmp_path):
    paths = write_csv(office_report(), tmp_path, "report")

    assert [path.name for path in paths] == [
        "report-hosts.csv", "report-ports.csv", "report-findings.csv", "report-fix-plan.csv",
    ]

    with paths[1].open(encoding="utf-8-sig") as handle:
        ports = list(csv.DictReader(handle))

    banner = next(row for row in ports if row["port"] == "8443")
    assert banner["product"] == "'" + FORMULA_BANNER   # cannot run as a formula

    with paths[2].open(encoding="utf-8-sig") as handle:
        findings = list(csv.DictReader(handle))

    assert findings[0]["number"] == "1"
    assert findings[0]["status"] == "open"
    assert findings[0]["title"] == "Telnet is open"


# ---------- HTML ----------

def test_html_escapes_untrusted_text():
    html = render_html(office_report())

    assert HOSTILE_BANNER not in html
    assert "&lt;script&gt;alert(" in html


def test_html_is_self_contained_and_locked_down():
    html = render_html(office_report())

    assert "Content-Security-Policy" in html
    assert "default-src 'none'" in html
    # Nothing is loaded from elsewhere: no external scripts, styles or images.
    assert not re.search(r'<(script|link|img)[^>]+(src|href)=["\']https?:', html)
    assert "<link" not in html


def test_html_sections():
    html = render_html(office_report())

    for text in ("Summary", "Authorization and scope", "Fix these first", "Findings",
                 "Possible attack paths", "Network map", "Assets", "Method and limitations",
                 "No engagement was recorded", "network-svg", "argus verify"):
        assert text in html, text


def test_redacted_html_says_so():
    html = render_html(redact_report(office_report()))

    assert "REDACTED" in html
    assert "192.168." not in html


# ---------- diagram ----------

def test_diagram_places_every_node_inside_the_canvas():
    diagram = build_diagram(office_report())

    assert {node.id for node in diagram.nodes} >= {"argus", "192.168.1.1", "192.168.1.5"}
    assert all(0 <= node.x <= diagram.width and 0 <= node.y <= diagram.height for node in diagram.nodes)
    assert any(link.kind == "observed" for link in diagram.links)
    gateway = next(node for node in diagram.nodes if node.id == "192.168.1.1")
    assert gateway.kind == "gateway"
    assert gateway.findings == 2


def test_diagram_without_traceroute_has_no_scanner():
    diagram = build_diagram(office_report(traced=False))

    assert "argus" not in {node.id for node in diagram.nodes}
    assert all(link.kind == "inferred" for link in diagram.links)


def test_big_subnets_are_capped():
    data = office_report()
    group = data["network"]["subnets"][0]
    extra = [f"192.168.1.{n}" for n in range(100, 180)]
    group["hosts"] = group["hosts"] + extra

    diagram = build_diagram(data)

    assert "more hosts not drawn" in diagram.boxes[0].note


# ---------- PDF ----------

def pdf_text(path):
    try:
        return subprocess.run(["pdftotext", str(path), "-"], capture_output=True, text=True, check=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("pdftotext is not installed")


def hostile_report():
    data = office_report()
    data["findings"][0]["evidence"].append("a & b <b>not bold</b>")
    return data


def test_browser_pdf_looks_like_the_html(tmp_path):
    from argus.reports import pdf_report

    if pdf_report.find_browser() is None:
        pytest.skip("no Chrome or Edge on this machine")

    path = pdf_report.write_pdf(hostile_report(), tmp_path / "report.pdf")
    text = pdf_text(path)

    assert path.read_bytes().startswith(b"%PDF")
    assert "Network security report" in text
    assert "a & b <b>not bold</b>" in text      # shown as text, never as markup
    assert "Page 1 of" in text                  # the report's own page footer


def test_basic_pdf_escapes_markup(tmp_path):
    from argus.reports.pdf_report import write_basic_pdf

    path = write_basic_pdf(hostile_report(), tmp_path / "basic.pdf")
    text = pdf_text(path)

    assert "a & b <b>not bold</b>" in text
    assert "Telnet is open" in text


def test_engine_choice(monkeypatch):
    from argus.reports import pdf_report

    monkeypatch.delenv("ARGUS_PDF_ENGINE", raising=False)
    monkeypatch.setattr(pdf_report, "find_browser", lambda: "/usr/bin/chrome")
    assert pdf_report.pdf_engine() == "browser"

    monkeypatch.setenv("ARGUS_PDF_ENGINE", "reportlab")
    assert pdf_report.pdf_engine() == "reportlab"

    monkeypatch.delenv("ARGUS_PDF_ENGINE")
    monkeypatch.setattr(pdf_report, "find_browser", lambda: None)
    assert pdf_report.pdf_engine() == "reportlab"

    monkeypatch.setattr(pdf_report, "reportlab_available", lambda: False)
    assert pdf_report.pdf_engine() is None
    assert not pdf_report.pdf_available()


def test_no_pdf_engine_explains_what_to_install(monkeypatch, tmp_path):
    from argus.reports import pdf_report

    monkeypatch.setattr(pdf_report, "pdf_engine", lambda: None)

    with pytest.raises(pdf_report.PDFUnavailableError, match="Chrome or Microsoft Edge"):
        pdf_report.write_pdf(office_report(), tmp_path / "x.pdf")


def test_browser_can_be_chosen(monkeypatch, tmp_path):
    from argus.reports import pdf_report

    fake = tmp_path / "my-chrome"
    fake.write_text("")
    monkeypatch.setenv("ARGUS_BROWSER", str(fake))
    assert pdf_report.find_browser() == str(fake)

    monkeypatch.setenv("ARGUS_BROWSER", str(tmp_path / "missing"))
    assert pdf_report.find_browser() is None


def test_browser_that_fails_is_reported(tmp_path, monkeypatch):
    from argus.reports import pdf_report

    monkeypatch.setattr(pdf_report, "PDF_WAIT_SECONDS", 1)

    with pytest.raises(pdf_report.PDFRenderError):
        pdf_report.print_html_to_pdf(office_report(), tmp_path / "x.pdf", "/bin/false")


def test_print_version_opens_every_section():
    screen = render_html(office_report())
    printed = render_html(office_report(), for_print=True)

    assert '<details class="finding" open' not in screen
    assert printed.count('<details class="finding" open') == len(office_report()["findings"])
    assert "@page" in printed and "counter(pages)" in printed


def test_css_text_cannot_break_out_of_the_style_block():
    from argus.reports.html_report import css_text

    escaped = str(css_text('Lab "A" </style><script>x</script> & more'))

    for bad in ('"', "<", ">", "&"):
        assert bad not in escaped
    assert escaped.startswith("Lab \\22 A\\22  \\3c /style\\3e ")


# ---------- how the browser is driven (fake browsers copy Windows behaviour) ----------

FAKE_BROWSER = """#!{python}
import subprocess, sys, time
args = sys.argv[1:]
target = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--print-to-pdf="))
mode = "{mode}"
if mode == "old-only" and "--headless" not in args:
    sys.exit(0)                    # the new mode silently does nothing
if mode == "late":
    # Return at once and finish writing a moment later, as Edge can on Windows.
    subprocess.Popen([sys.executable, "-c",
        "import time,sys; time.sleep(1.0); open(sys.argv[1],'wb').write(b'%PDF-1.7 late')", target])
    sys.exit(0)
if mode == "never":
    sys.stderr.write("GPU process exited unexpectedly\\n")
    sys.exit(21)
open(target, "wb").write(b"%PDF-1.7 fake")
"""


def fake_browser(tmp_path, mode):
    import os
    import sys

    if os.name == "nt":
        pytest.skip("fake browser scripts need a POSIX shell")

    script = tmp_path / f"fake-browser-{mode}"
    script.write_text(FAKE_BROWSER.format(python=sys.executable, mode=mode))
    script.chmod(0o755)
    return str(script)


def test_older_headless_mode_is_tried_when_the_new_one_prints_nothing(tmp_path, monkeypatch):
    from argus.reports import pdf_report
    from argus.reports.pdf_report import print_html_to_pdf

    monkeypatch.setattr(pdf_report, "PDF_WAIT_SECONDS", 1)
    path = print_html_to_pdf(office_report(), tmp_path / "r.pdf", fake_browser(tmp_path, "old-only"))

    assert path.read_bytes() == b"%PDF-1.7 fake"


def test_a_pdf_written_after_the_browser_returns_is_waited_for(tmp_path):
    from argus.reports.pdf_report import print_html_to_pdf

    path = print_html_to_pdf(office_report(), tmp_path / "r.pdf", fake_browser(tmp_path, "late"))

    assert path.read_bytes() == b"%PDF-1.7 late"


def test_failure_explains_every_attempt(tmp_path, monkeypatch):
    from argus.reports import pdf_report

    monkeypatch.setattr(pdf_report, "PDF_WAIT_SECONDS", 1)

    with pytest.raises(pdf_report.PDFRenderError) as error:
        pdf_report.print_html_to_pdf(office_report(), tmp_path / "r.pdf", fake_browser(tmp_path, "never"))

    message = str(error.value)
    assert "--headless=new: exit code 21, GPU process exited unexpectedly" in message
    assert "--headless: exit code 21" in message
