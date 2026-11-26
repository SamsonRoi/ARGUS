"""Generate reports: build the model once, then write each format.

Every file gets a SHA-256 fingerprint. The fingerprints are written to a
SHA256SUMS file in the report folder (the standard format that tools such
as `sha256sum -c` understand) and recorded in the ARGUS database, so
`argus verify` can later tell whether a report was changed.
"""

import hashlib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from argus.modules.compare import compare_scans
from argus.modules.risk import analyze
from argus.modules.risk_history import analyze_with_history, risk_changes
from argus.modules.topology import build_network_map
from argus.reports.csv_report import write_csv
from argus.reports.html_report import write_html
from argus.reports.json_report import write_json
from argus.reports.model import build_report_data
from argus.reports.pdf_report import (
    PDFRenderError,
    PDFUnavailableError,
    pdf_engine,
    reportlab_available,
    write_basic_pdf,
    write_pdf,
)
from argus.reports.redact import redact_report


FORMATS = ("json", "csv", "html", "pdf")
REPORTS_ENV_VAR = "ARGUS_REPORTS_DIR"
REPORTS_DIR_NAME = "ARGUS-reports"
SUMS_FILE = "SHA256SUMS"


class ReportError(Exception):
    """A report could not be produced."""


@dataclass
class ReportFile:
    format: str
    path: Path
    sha256: str
    size: int


@dataclass
class GeneratedReport:
    folder: Path
    files: list[ReportFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    redacted: bool = False


# ---------- where reports go ----------

def default_reports_dir() -> Path:
    """$ARGUS_REPORTS_DIR if set, otherwise ARGUS-reports in the user's home.

    Under sudo, the real user's home is used, like the history database.
    """
    override = os.environ.get(REPORTS_ENV_VAR)

    if override:
        return Path(override).expanduser()

    from argus.storage.database import _sudo_owner

    owner = _sudo_owner()
    home = owner[2] if owner else Path.home()
    return home / REPORTS_DIR_NAME


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "report"


def report_folder_name(data: dict, when: datetime) -> str:
    parts = []

    if data.get("engagement"):
        parts.append(_slug(data["engagement"]["name"]))

    scan_id = data["scan"]["id"]
    parts.append(f"scan-{scan_id}" if scan_id else "scan-unsaved")
    parts.append(when.strftime("%Y%m%d-%H%M%S"))

    if data.get("redacted"):
        parts.append("redacted")

    return "-".join(parts)


def _give_back_to_sudo_user(paths) -> None:
    from argus.storage.database import _sudo_owner

    owner = _sudo_owner()

    if owner is None:
        return

    uid, gid, _home = owner

    for item in paths:
        try:
            os.chown(item, uid, gid)
        except OSError:
            pass


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


# ---------- building the model ----------

def prepare_report_data(
    result,
    *,
    connection=None,
    scan_id: int | None = None,
    engagement_id: int | None = None,
) -> dict:
    """Build the report model for one scan.

    With a database connection, the report includes finding history,
    accepted risks, the engagement, and changes since the previous scan.
    """
    engagement = None
    previous = previous_id = changes = comparison = None

    if connection is None:
        risk = analyze(result)
    else:
        from argus.storage.repository import get_engagement, load_scan

        risk = analyze_with_history(connection, result, scan_id, engagement_id)

        if engagement_id is not None:
            engagement = get_engagement(connection, engagement_id)

        if risk.compared_with:
            previous_id = risk.compared_with
            previous = load_scan(connection, previous_id)

            if previous is not None:
                changes = risk_changes(previous, result, newer_report=risk)
                comparison = compare_scans(previous, result)

    return build_report_data(
        result,
        risk,
        build_network_map(result),
        scan_id=scan_id,
        engagement=engagement,
        previous=previous,
        previous_id=previous_id,
        risk_changes=changes,
        scan_comparison=comparison,
    )


# ---------- writing ----------

def _write_pdf_with_fallback(data: dict, path: Path, warnings: list[str]) -> list[tuple[str, Path]]:
    """Print the PDF with the browser; fall back to the basic layout if that fails."""
    engine = pdf_engine()

    if engine is None:
        warnings.append(
            "PDF was skipped: it needs Chrome or Microsoft Edge (recommended), "
            "or reportlab (pip install reportlab)."
        )
        return []

    if engine == "reportlab":
        warnings.append(
            "No Chrome or Edge was found, so the PDF uses the basic layout. "
            "Install Chrome or Edge for a PDF that looks like the HTML report."
        )
        return [("pdf", write_basic_pdf(data, path))]

    try:
        return [("pdf", write_pdf(data, path))]
    except PDFRenderError as error:
        if not reportlab_available():
            warnings.append(f"PDF was skipped: {error}")
            return []

        warnings.append(f"{error} The PDF uses the basic layout instead.")
        return [("pdf", write_basic_pdf(data, path))]


def write_reports(
    data: dict,
    formats=FORMATS,
    *,
    out_dir: Path | None = None,
    redact: bool = False,
    connection=None,
    when: datetime | None = None,
) -> GeneratedReport:
    """Write the chosen formats into a new folder. Returns what was written."""
    unknown = set(formats) - set(FORMATS)

    if unknown:
        raise ReportError(f"Unknown report format(s): {', '.join(sorted(unknown))}")

    if not formats:
        raise ReportError("Choose at least one report format.")

    if redact:
        data = redact_report(data)

    when = when or datetime.now().astimezone()
    base = Path(out_dir) if out_dir else default_reports_dir()
    folder = base / report_folder_name(data, when)

    try:
        folder.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        folder = base / (folder.name + "-" + when.strftime("%f"))
        folder.mkdir(parents=True)
    except OSError as error:
        raise ReportError(f"The report folder could not be created: {error}") from error

    output = GeneratedReport(folder=folder, redacted=redact)
    stem = "argus-report"
    written: list[tuple[str, Path]] = []

    try:
        for name in FORMATS:
            if name not in formats:
                continue

            if name == "json":
                written.append(("json", write_json(data, folder / f"{stem}.json")))
            elif name == "csv":
                written += [("csv", path) for path in write_csv(data, folder, stem)]
            elif name == "html":
                written.append(("html", write_html(data, folder / f"{stem}.html")))
            elif name == "pdf":
                written += _write_pdf_with_fallback(data, folder / f"{stem}.pdf", output.warnings)

    except PDFUnavailableError as error:
        output.warnings.append(str(error))
    except OSError as error:
        raise ReportError(f"A report file could not be written: {error}") from error

    for name, path in written:
        output.files.append(ReportFile(
            format=name, path=path, sha256=sha256_of(path), size=path.stat().st_size,
        ))

    sums = folder / SUMS_FILE
    sums.write_text(
        "".join(f"{item.sha256}  {item.path.name}\n" for item in output.files),
        encoding="utf-8",
    )

    if connection is not None:
        from argus.storage.repository import record_report

        for item in output.files:
            record_report(
                connection,
                scan_id=data["scan"]["id"],
                format=item.format,
                path=str(item.path.resolve()),
                sha256=item.sha256,
                size=item.size,
                redacted=redact,
            )

    _give_back_to_sudo_user([base, folder, sums] + [item.path for item in output.files])

    return output


def generate_reports(
    result,
    formats=FORMATS,
    *,
    connection=None,
    scan_id: int | None = None,
    engagement_id: int | None = None,
    out_dir: Path | None = None,
    redact: bool = False,
) -> GeneratedReport:
    """Build the report model for a scan and write the chosen formats."""
    data = prepare_report_data(
        result, connection=connection, scan_id=scan_id, engagement_id=engagement_id,
    )
    return write_reports(data, formats, out_dir=out_dir, redact=redact, connection=connection)
