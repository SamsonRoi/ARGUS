"""The HTML report: one self-contained file that opens in any browser.

* No internet needed and nothing loaded from elsewhere. A Content Security
  Policy blocks any outside request, so the report cannot leak or phone home.
* All text from the network is escaped by Jinja2's autoescaping, so a
  hostile banner or hostname cannot inject script into the report.
* The network diagram is SVG drawn from layout.py, with a little inline
  script for clicking, highlighting, filtering and sorting. The report reads
  fine with scripts off and prints cleanly.
"""

from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup

from argus.reports.layout import build_diagram


PRIORITY_ORDER = ("critical", "high", "medium", "low", "info")


def css_text(value) -> Markup:
    """Escape text for use inside a quoted CSS string.

    Inside <style>, HTML escaping is wrong (it would print '&amp;'), so every
    character that could end the string or the style block is written as a
    CSS escape instead: quotes, backslashes, '<', '>', '&' and line breaks.
    """
    out = []

    for char in str(value or ""):
        if char.isalnum() or char in " .,:;-_()/'@#+=!?[]{}|~":
            out.append(char)
        else:
            out.append(f"\\{ord(char):x} ")

    return Markup("".join(out))


def _environment() -> Environment:
    environment = Environment(
        loader=PackageLoader("argus.reports", "templates"),
        autoescape=select_autoescape(["html", "j2"], default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["dash"] = lambda value: "-" if value in (None, "", []) else value
    environment.filters["css_text"] = css_text
    environment.filters["when"] = lambda value: (value or "-").replace("T", " ")[:16]
    return environment


def render_html(report: dict, for_print: bool = False) -> str:
    """Render the report model as one HTML document.

    for_print=True opens every finding and appendix section, which is the
    version turned into the PDF.
    """
    template = _environment().get_template("report.html.j2")

    return template.render(
        report=report,
        diagram=build_diagram(report),
        priorities=PRIORITY_ORDER,
        for_print=for_print,
    )


def write_html(report: dict, path: Path) -> Path:
    path.write_text(render_html(report), encoding="utf-8")
    return path
