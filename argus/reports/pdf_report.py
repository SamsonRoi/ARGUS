"""The PDF report.

The PDF is the HTML report, printed by Chrome or Microsoft Edge in headless
mode, so it has exactly the same fonts, colours, cards and network map.
Every Windows PC has Edge, so this works out of the box there; on macOS and
Linux, Chrome, Chromium or Edge is used if installed.

Only if no such browser is found does ARGUS fall back to a basic layout
drawn with reportlab (pip install reportlab).

Settings (optional):
  ARGUS_BROWSER     full path of the browser to use
  ARGUS_PDF_ENGINE  'browser' or 'reportlab' to force one engine
"""

import importlib.util
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape


PRIORITY_COLOURS = {
    "critical": "#b3121f", "high": "#e0542e", "medium": "#d89a00", "low": "#2a7fb8", "info": "#8794a3",
}
CRITICALITY_COLOURS = {"high": "#b3121f", "medium": "#d89a00", "low": "#1f8a4c"}
GRADE_COLOURS = {"A": "#1f8a4c", "B": "#1f8a4c", "C": "#d89a00", "D": "#e0542e", "F": "#b3121f"}
BRAND = "#0f3d5e"

BROWSER_TIMEOUT = 120

BROWSER_COMMANDS = (
    "google-chrome", "google-chrome-stable", "chrome", "chromium", "chromium-browser",
    "microsoft-edge", "microsoft-edge-stable", "msedge",
)


class PDFUnavailableError(Exception):
    """Neither a suitable browser nor reportlab is available."""


class PDFRenderError(Exception):
    """The browser could not turn the report into a PDF."""


# ---------- finding a browser ----------

def _known_browser_paths() -> list[Path]:
    paths = []

    if os.name == "nt":
        for variable in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA"):
            base = os.environ.get(variable)

            if base:
                paths += [
                    Path(base) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
                    Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe",
                ]
    else:
        paths += [
            Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        ]

    return paths


def find_browser() -> str | None:
    """A Chrome, Chromium or Edge that can print PDFs, or None."""
    override = os.environ.get("ARGUS_BROWSER")

    if override:
        return override if Path(override).is_file() or shutil.which(override) else None

    for path in _known_browser_paths():
        if path.is_file():
            return str(path)

    for command in BROWSER_COMMANDS:
        found = shutil.which(command)

        if found:
            return found

    return None


def reportlab_available() -> bool:
    return importlib.util.find_spec("reportlab") is not None


def pdf_engine() -> str | None:
    """'browser', 'reportlab', or None if PDFs cannot be made here."""
    forced = os.environ.get("ARGUS_PDF_ENGINE", "").strip().lower()

    if forced == "reportlab":
        return "reportlab" if reportlab_available() else None

    if find_browser():
        return "browser"

    if forced != "browser" and reportlab_available():
        return "reportlab"

    return None


def pdf_available() -> bool:
    return pdf_engine() is not None


# ---------- the main entry point ----------

def write_pdf(report: dict, path: Path) -> Path:
    """Write the PDF, using the browser when possible."""
    engine = pdf_engine()

    if engine == "browser":
        return print_html_to_pdf(report, Path(path), find_browser())

    if engine == "reportlab":
        return write_basic_pdf(report, Path(path))

    raise PDFUnavailableError(
        "PDF reports need Chrome or Microsoft Edge (recommended), or the reportlab "
        "package (pip install reportlab)."
    )


HEADLESS_MODES = ("--headless=new", "--headless")
PDF_WAIT_SECONDS = 15


def _wait_for_pdf(path: Path, seconds: float) -> bool:
    """Wait until the browser has finished writing a PDF.

    On Windows, Edge and Chrome can finish writing shortly after the command
    returns, so the file is checked until it exists, starts with '%PDF-' and
    has stopped growing.
    """
    deadline = time.monotonic() + seconds
    last_size = -1

    while time.monotonic() < deadline:
        try:
            if path.is_file():
                size = path.stat().st_size

                if size > 0 and size == last_size:
                    with path.open("rb") as handle:
                        return handle.read(5) == b"%PDF-"

                last_size = size
        except OSError:
            pass   # still being written

        time.sleep(0.3)

    return False


def _browser_command(browser: str, mode: str, profile: Path, page: Path, path: Path) -> list[str]:
    command = [
        browser,
        mode,
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        "--no-pdf-header-footer",          # current Chrome and Edge
        "--print-to-pdf-no-header",         # older versions
        f"--user-data-dir={profile}",       # never touches your own browser profile
        f"--print-to-pdf={path}",
        page.as_uri(),
    ]

    # Chrome refuses to run as root (e.g. under sudo) without this.
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
        command.insert(1, "--no-sandbox")

    return command


def print_html_to_pdf(report: dict, path: Path, browser: str) -> Path:
    """Print the HTML report to PDF with a headless browser.

    The newer headless mode is tried first, then the older one, because some
    Edge and Chrome versions only print PDFs in one of them.
    """
    from argus.reports.html_report import render_html

    path = path.resolve()
    attempts = []

    # ignore_cleanup_errors: the browser may still hold profile files open on Windows.
    with tempfile.TemporaryDirectory(prefix="argus-pdf-", ignore_cleanup_errors=True) as work:
        page = Path(work) / "report.html"
        page.write_text(render_html(report, for_print=True), encoding="utf-8")

        for index, mode in enumerate(HEADLESS_MODES):
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass

            command = _browser_command(browser, mode, Path(work) / f"profile-{index}", page, path)

            try:
                finished = subprocess.run(
                    command, capture_output=True, text=True, timeout=BROWSER_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                attempts.append(f"{mode}: no answer after {BROWSER_TIMEOUT} seconds")
                continue
            except OSError as error:
                raise PDFRenderError(f"The browser could not be started: {error}") from error

            # A browser that reports success may still be writing, so give it
            # time; one that reports an error gets only a short grace period.
            wait = PDF_WAIT_SECONDS if finished.returncode == 0 else min(2, PDF_WAIT_SECONDS)

            if _wait_for_pdf(path, wait):
                return path

            last_line = ((finished.stderr or "") + (finished.stdout or "")).strip().splitlines()[-1:]
            attempts.append(
                f"{mode}: exit code {finished.returncode}, "
                f"{last_line[0][:160] if last_line else 'no message'}"
            )

    raise PDFRenderError(
        f"The browser at {browser} did not produce a PDF. Tried: " + "; ".join(attempts) + "."
    )


def _text(value) -> str:
    """Escape any value for a reportlab Paragraph."""
    if value is None or value == "" or value == []:
        return "-"
    return escape(str(value))


def write_basic_pdf(report: dict, path: Path) -> Path:
    """The fallback PDF, drawn with reportlab when no browser is available."""
    if not reportlab_available():
        raise PDFUnavailableError(
            "PDF reports need Chrome or Microsoft Edge (recommended), or the reportlab "
            "package (pip install reportlab)."
        )

    from reportlab.graphics.shapes import Circle, Drawing, Group, Line, Polygon, Rect, String
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        CondPageBreak,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    from argus.reports.layout import build_diagram

    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10, textColor=colors.HexColor("#5d6b7c"))
    cell = ParagraphStyle("cell", parent=body, fontSize=8, leading=10)
    mono = ParagraphStyle("mono", parent=cell, fontName="Courier", fontSize=7.5)
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=22, leading=26, textColor=colors.HexColor(BRAND), alignment=0)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14, leading=18, textColor=colors.HexColor(BRAND),
                        spaceBefore=12, spaceAfter=6)
    h3 = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=11, leading=14, spaceBefore=8, spaceAfter=4)
    headline = ParagraphStyle("headline", parent=body, fontSize=10, leading=14, backColor=colors.HexColor("#f5f7fa"),
                              borderPadding=8, borderColor=colors.HexColor(BRAND), borderWidth=0, spaceBefore=6, spaceAfter=10)
    centered = ParagraphStyle("centered", parent=body, alignment=TA_CENTER)

    page_width, _ = A4
    frame_width = page_width - 36 * mm
    story = []

    def p(text, style=cell):
        return Paragraph(text, style)

    def table(rows, widths, header=True, zebra=False):
        result = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        commands = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#dfe4ea")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]
        if header:
            commands.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f5f7fa")))
        result.setStyle(TableStyle(commands))
        return result

    def priority(band, label=None):
        colour = PRIORITY_COLOURS.get(band, "#8794a3")
        return f'<font color="{colour}"><b>{_text((label or band).upper())}</b></font>'

    def bullets(lines):
        return "<br/>".join(f"&bull; {_text(line)}" for line in lines) if lines else "-"

    scan = report["scan"]
    summary = report["summary"]
    engagement = report["engagement"]

    # ----- title -----
    title = "Network security report"
    if report["redacted"]:
        title += ' <font color="#a07800" size="12">[REDACTED]</font>'
    story.append(Paragraph(title, h1))
    subtitle = []
    if engagement:
        subtitle.append(_text(engagement["name"]))
    subtitle.append(f"Scan{' #' + str(scan['id']) if scan['id'] else ''} of {_text(', '.join(scan['targets']))}")
    subtitle.append(_text((scan["started_at"] or "")[:16].replace("T", " ")))
    story.append(Paragraph(" &middot; ".join(subtitle), small))
    story.append(Spacer(1, 8))

    # ----- summary tiles -----
    grade_colour = GRADE_COLOURS.get(summary["grade"], BRAND)
    bands = " ".join(
        priority(band, f"{count} {band}")
        for band, count in summary["findings_by_priority"].items() if count
    ) or "none"
    tiles = Table([[
        p(f'<font size="26" color="{grade_colour}"><b>{_text(summary["grade"])}</b></font><br/>'
          f'<font size="7">{_text(summary["grade_reason"])}</font>', centered),
        p(f'<font size="18"><b>{summary["findings"]}</b></font><br/>open findings<br/>{bands}', centered),
        p(f'<font size="18"><b>{summary["total_risk"]}</b></font><br/>total risk points', centered),
        p(f'<font size="18"><b>{summary["hosts_up"]}</b></font><br/>hosts responded', centered),
        p(f'<font size="18"><b>{summary["open_ports"]}</b></font><br/>open ports', centered),
    ]], colWidths=[frame_width / 5] * 5)
    tiles.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dfe4ea")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dfe4ea")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f7fa")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story += [tiles, Spacer(1, 8), Paragraph(_text(summary["headline"]), headline)]

    if scan["incomplete"]:
        story.append(p('<font color="#8a5a00"><b>This scan was stopped before it finished.</b> '
                       'The results cover only part of the network.</font>', body))

    # ----- authorization -----
    story.append(Paragraph("Authorization and scope", h2))
    if engagement:
        rows = [
            [p("<b>Engagement</b>"), p(_text(engagement["name"]))],
            [p("<b>Authorized by</b>"), p(_text(engagement["authorized_by"]))],
            [p("<b>Authorized scope</b>"), p(_text(", ".join(engagement["scope"])), mono)],
            [p("<b>Dates</b>"), p(f"{_text(engagement['starts_on'])} to {_text(engagement['ends_on'])}")],
            [p("<b>Scanned targets</b>"), p(_text(", ".join(scan["targets"])), mono)],
        ]
        story.append(table(rows, [40 * mm, frame_width - 40 * mm], header=False))
        if engagement["hosts_outside_scope"]:
            story.append(p(
                f'<font color="#b3121f"><b>{len(engagement["hosts_outside_scope"])} responding host(s) are outside the '
                f'authorized scope:</b></font> {_text(", ".join(engagement["hosts_outside_scope"]))}', body))
        else:
            story.append(p('<font color="#1f8a4c">Every responding host is inside the authorized scope.</font>', body))
        if engagement["scan_within_dates"] is False:
            story.append(p('<font color="#b3121f"><b>The scan date is outside the engagement\'s dates.</b></font>', body))
    else:
        story.append(p('<font color="#8a5a00"><b>No engagement was recorded for this scan.</b></font> This report '
                       'does not show who authorized the work or what was in scope. Only scan networks you own '
                       'or have written permission to assess.', body))

    # ----- fix plan -----
    story.append(Paragraph("Fix these first", h2))
    if report["fix_plan"]:
        rows = [[p("<b>#</b>"), p("<b>Fix</b>"), p("<b>What to do</b>"), p("<b>Where</b>"), p("<b>Risk removed</b>")]]
        for action in report["fix_plan"]:
            rows.append([
                p(str(action["rank"])),
                p(f'{priority(action["worst_severity"])}<br/>{_text(action["title"])}'),
                p(_text(action["fix"])),
                p(_text(", ".join(action["where"])), mono),
                p(f'<b>{action["risk_removed"]}</b>'),
            ])
        story.append(table(rows, [8 * mm, 45 * mm, frame_width - 113 * mm, 40 * mm, 20 * mm]))
    else:
        story.append(p("Nothing to fix in what this scan could see.", body))

    # ----- findings -----
    story += [PageBreak(), Paragraph("Findings", h2)]
    if not report["findings"]:
        story.append(p("No open risk findings in what this scan could see.", body))

    for finding in report["findings"]:
        history = finding["history"]
        chips = []
        if history["new_since_baseline"]:
            chips.append('<font color="#6a1b9a"><b>NEW since baseline</b></font>')
        if history["streak"] and history["streak"] > 1:
            chips.append(f'<font color="#8a5a00">open for {history["streak"]} scans</font>')
        if history["first_seen_scan"]:
            chips.append(f"first seen in #{history['first_seen_scan']}")

        score_label = f"{finding['score']} {finding['priority']}"
        header = p(
            f'<b>#{finding["number"]}</b>&nbsp;&nbsp;{priority(finding["priority"], score_label)}'
            f'&nbsp;&nbsp;<b>{_text(finding["title"])}</b>'
            f'<br/><font size="7.5" color="#5d6b7c">{_text(finding["category_label"])}'
            f'{" &middot; " + " &middot; ".join(chips) if chips else ""}</font>', body)
        rows = [
            [p("<b>Where</b>"), p(_text(finding["host_label"] or finding["where"]))],
            [p("<b>Evidence</b>"), p(bullets(finding["evidence"]))],
            [p("<b>Why it matters</b>"), p(_text(finding["why"]))],
        ]
        if finding["raised_because"]:
            rows.append([p("<b>Raised because</b>"), p(bullets(finding["raised_because"]))])
        rows += [
            [p("<b>Score</b>"), p(_text(f"{finding['score']} = " + " ".join(finding["score_factors"])), mono)],
            [p("<b>Confidence</b>"), p(_text(finding["confidence"]))],
            [p("<b>How to fix</b>"), p(f"<b>{_text(finding['fix'])}</b>")],
        ]
        if finding["references"]:
            rows.append([p("<b>References</b>"), p(_text("; ".join(finding["references"])))])
        details = Table(rows, colWidths=[30 * mm, frame_width - 34 * mm])
        details.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 1.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ]))
        block = Table([[header], [details]], colWidths=[frame_width])
        block.setStyle(TableStyle([
            ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(PRIORITY_COLOURS[finding["priority"]])),
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dfe4ea")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f9fafb")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story += [KeepTogether([block]), Spacer(1, 6)]

    if report["accepted_risks"]:
        story.append(Paragraph("Accepted risks (not counted in the grade)", h3))
        rows = [[p("<b>Finding</b>"), p("<b>Where</b>"), p("<b>Reason</b>"), p("<b>Until</b>")]]
        for finding in report["accepted_risks"]:
            acceptance = finding.get("acceptance") or {}
            rows.append([p(_text(finding["title"])), p(_text(finding["where"]), mono),
                         p(_text(acceptance.get("reason"))), p(_text(acceptance.get("expires_on") or "no expiry"))])
        story.append(table(rows, [50 * mm, 40 * mm, frame_width - 115 * mm, 25 * mm]))

    # ----- attack paths -----
    if report["attack_paths"]:
        story += [CondPageBreak(60 * mm), Paragraph("Possible attack paths", h2),
                  p("A weakly protected device that shares a network with a critical one. Possible, not proven: "
                    "ARGUS cannot see firewalls between hosts on the same subnet.", small), Spacer(1, 4)]
        rows = [[p("<b>Starting point (weak)</b>"), p("<b>Why it is weak</b>"), p("<b>Could reach (critical)</b>"), p("<b>Basis</b>")]]
        for attack in report["attack_paths"]:
            rows.append([p(_text(attack["from_label"])), p(bullets(attack["why_weak"])),
                         p(f"<b>{_text(attack['to_label'])}</b>"), p(_text(attack["basis"]), small)])
        story.append(table(rows, [45 * mm, frame_width - 120 * mm, 45 * mm, 30 * mm]))

    # ----- network map -----
    story += [PageBreak(), Paragraph("Network map", h2)]
    diagram = build_diagram(report)

    if diagram.nodes:
        scale = min(frame_width / diagram.width, (170 * mm) / max(diagram.height, 1))
        drawing = Drawing(diagram.width * scale, diagram.height * scale)
        group = Group()
        group.transform = (scale, 0, 0, scale, 0, 0)
        height = diagram.height

        def y(value):
            return height - value

        for box in diagram.boxes:
            group.add(Rect(box.x, y(box.y + box.height), box.width, box.height, rx=10, ry=10,
                           fillColor=colors.white, strokeColor=colors.HexColor("#c9d2dc")))
            group.add(String(box.x + 14, y(box.y + 24), box.label, fontName="Helvetica-Bold", fontSize=14,
                             fillColor=colors.HexColor(BRAND)))
            if box.note:
                group.add(String(box.x + 14, y(box.y + 42), box.note, fontName="Helvetica", fontSize=11,
                                 fillColor=colors.HexColor("#8a5a00")))

        for link in diagram.links:
            observed = link.kind == "observed"
            group.add(Line(link.x1, y(link.y1), link.x2, y(link.y2),
                           strokeColor=colors.HexColor("#1f8a4c" if observed else "#9aa6b2"),
                           strokeWidth=2.2 if observed else 1.2,
                           strokeDashArray=None if observed else [5, 4]))

        for node in diagram.nodes:
            fill = colors.HexColor(CRITICALITY_COLOURS.get(node.criticality, "#5d6b7c"))
            cx, cy = node.x, y(node.y)
            if node.kind == "gateway":
                group.add(Polygon([cx, cy + 17, cx + 17, cy, cx, cy - 17, cx - 17, cy],
                                  fillColor=fill, strokeColor=colors.white, strokeWidth=2))
            elif node.kind == "scanner":
                group.add(Rect(cx - 18, cy - 12, 36, 24, rx=4, ry=4, fillColor=colors.HexColor(BRAND), strokeColor=None))
            elif node.kind == "hop":
                group.add(Rect(cx - 8, cy - 8, 16, 16, fillColor=colors.HexColor("#8794a3"), strokeColor=None))
            else:
                group.add(Circle(cx, cy, 13, fillColor=fill, strokeColor=colors.white, strokeWidth=2))
            if node.findings:
                group.add(Circle(cx + 13, cy + 12, 8, fillColor=colors.white,
                                 strokeColor=colors.HexColor("#b3121f"), strokeWidth=1.5))
                group.add(String(cx + 13, cy + 8.5, str(node.findings), fontName="Helvetica-Bold", fontSize=10,
                                 fillColor=colors.HexColor("#b3121f"), textAnchor="middle"))
            group.add(String(cx, cy - 30, node.label, fontName="Helvetica", fontSize=12, textAnchor="middle"))
            if node.sublabel:
                group.add(String(cx, cy - 44, node.sublabel, fontName="Helvetica", fontSize=10.5,
                                 textAnchor="middle", fillColor=colors.HexColor("#5d6b7c")))

        drawing.add(group)
        story += [drawing, Spacer(1, 4), p(
            '<font color="#1f8a4c">solid green: observed (seen by traceroute)</font> &middot; '
            '<font color="#7a8794">dashed grey: inferred (from addresses only)</font> &middot; '
            'colour: asset criticality (red high, amber medium, green low) &middot; badge: open findings', small)]
    else:
        story.append(p("No hosts responded, so there is nothing to map.", body))

    for note in report["network"]["notes"]:
        story.append(p(f"&bull; {_text(note)}", small))

    rows = [[p("<b>Subnet</b>"), p("<b>Hosts</b>"), p("<b>Gateway</b>"), p("<b>How the gateway was found</b>")]]
    for subnet in report["network"]["subnets"]:
        rows.append([
            p(_text(subnet["network"]) + (" (size assumed)" if subnet["size_assumed"] else ""), mono),
            p(str(len(subnet["hosts"]))),
            p(_text(subnet["gateway"]), mono),
            p(_text(f"{subnet['gateway_basis']}: {subnet['gateway_reason']}" if subnet["gateway"] else "not identified")),
        ])
    story += [Spacer(1, 6), table(rows, [40 * mm, 15 * mm, 35 * mm, frame_width - 90 * mm])]

    # ----- assets -----
    story += [CondPageBreak(60 * mm), Paragraph("Assets", h2)]
    rows = [[p("<b>Host</b>"), p("<b>Likely role</b>"), p("<b>Evidence</b>"), p("<b>Criticality</b>"), p("<b>Risk</b>"), p("<b>Open</b>")]]
    for host in report["hosts"]:
        role = host["roles"][0] if host["roles"] else None
        role_text = f"{_text(role['label'])} ({_text(role['confidence'])})" if role else "Unknown"
        for extra in host["roles"][1:3]:
            role_text += f'<br/><font size="7" color="#5d6b7c">also: {_text(extra["label"])} ({_text(extra["confidence"])})</font>'
        colour = CRITICALITY_COLOURS.get(host["criticality"], "#5d6b7c")
        rows.append([
            p(_text(host["ip"]) + (f'<br/><font size="7" color="#5d6b7c">{_text(host["hostname"])}</font>' if host["hostname"] else ""), mono),
            p(role_text),
            p(bullets(role["evidence"]) if role else "-", small),
            p(f'<font color="{colour}"><b>{_text((host["criticality"] or "-").title())}</b></font>'),
            p(_text(host["risk_score"])),
            p(str(sum(1 for port in host["ports"] if port["state"] == "open"))),
        ])
    story.append(table(rows, [32 * mm, 38 * mm, frame_width - 116 * mm, 20 * mm, 13 * mm, 13 * mm]))

    # ----- changes -----
    changes = report["changes"]
    if changes:
        story += [CondPageBreak(50 * mm), Paragraph(f"Changes since scan #{changes['compared_with']}", h2),
                  p('"Resolved" means this scan checked again and the problem was gone; "not re-checked" means '
                    "this scan did not look, so the result is unknown.", small), Spacer(1, 4)]
        rows = [[p("<b>Change</b>"), p("<b>Finding</b>"), p("<b>Where</b>")]]
        for label, colour, items in (("New", "#6a1b9a", changes["new"]), ("Resolved", "#1f8a4c", changes["resolved"]),
                                     ("Not re-checked", "#5d6b7c", changes["not_rechecked"])):
            for item in items:
                rows.append([p(f'<font color="{colour}"><b>{label}</b></font>'), p(_text(item["title"])), p(_text(item["where"]), mono)])
        if len(rows) > 1:
            story.append(table(rows, [28 * mm, 80 * mm, frame_width - 108 * mm]))
        else:
            story.append(p("No change in risk findings.", body))
        if changes["scan_changes"]:
            story.append(Paragraph("Network changes", h3))
            rows = [[p("<b>Change</b>"), p("<b>Host</b>"), p("<b>What happened</b>")]]
            for event in changes["scan_changes"]:
                rows.append([p(_text(event["label"])), p(_text(event["host"]), mono), p(_text(event["summary"]))])
            story.append(table(rows, [35 * mm, 30 * mm, frame_width - 65 * mm]))

    # ----- method and limitations -----
    story += [CondPageBreak(60 * mm), Paragraph("Method and limitations", h2)]
    coverage = ", ".join(f"{count:,} {protocol.upper()}" for protocol, count in scan["coverage"].items()) or "none recorded"
    rows = [
        [p("<b>Scan type</b>"), p(_text(scan["profile"]))],
        [p("<b>Targets</b>"), p(_text(", ".join(scan["targets"])), mono)],
        [p("<b>Started / finished</b>"), p(f"{_text((scan['started_at'] or '')[:16].replace('T', ' '))} / "
                                            f"{_text((scan['finished_at'] or '')[:16].replace('T', ' '))}")],
        [p("<b>Ports checked</b>"), p(_text(coverage))],
        [p("<b>Nmap version</b>"), p(_text(scan["nmap_version"]))],
        [p("<b>Rules</b>"), p(f"asset rules v{_text(report['rules']['asset_rules_version'])}, "
                               f"risk rules v{_text(report['rules']['risk_rules_version'])}")],
    ]
    story.append(table(rows, [40 * mm, frame_width - 40 * mm], header=False))
    for heading, items in (("Scan warnings", scan["warnings"]),
                           ("What this analysis could not see", report["analysis_notes"]),
                           ("Limitations", report["limitations"])):
        if items:
            story.append(Paragraph(heading, h3))
            story += [p(f"&bull; {_text(item)}", body) for item in items]

    story += [Spacer(1, 10), p(
        f"Generated by ARGUS {_text(report['argus_version'])} on {_text(report['generated_at'][:16].replace('T', ' '))}, "
        f"report format {_text(report['schema'])}. To check this file has not been changed, run "
        "<font name='Courier'>argus verify &lt;file&gt;</font>; its SHA-256 is listed in the SHA256SUMS file saved next to it.",
        small)]

    # ----- page header and footer -----
    running = "ARGUS network security report"
    if engagement:
        running += f" - {engagement['name']}"
    if report["redacted"]:
        running += "  [REDACTED]"

    def decorate(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#5d6b7c"))
        canvas.drawString(18 * mm, 10 * mm, running[:110])
        canvas.drawRightString(page_width - 18 * mm, 10 * mm, f"Page {document.page}")
        canvas.setStrokeColor(colors.HexColor(BRAND))
        canvas.setLineWidth(1.2)
        canvas.line(18 * mm, A4[1] - 12 * mm, page_width - 18 * mm, A4[1] - 12 * mm)
        canvas.restoreState()

    document = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=running, author="ARGUS", subject="Network security report", creator=f"ARGUS {report['argus_version']}",
    )
    document.build(story, onFirstPage=decorate, onLaterPages=decorate)

    return path
