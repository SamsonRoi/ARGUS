"""Check whether a report file is exactly as ARGUS wrote it.

Two independent records are checked:

* the SHA256SUMS file saved in the report's folder, and
* the ARGUS database, which recorded every report's SHA-256 when it was made.

The SHA256SUMS file travels with the report, so someone who edits the report
could edit it too. The database stays on the computer that made the report,
which is why a match there is the stronger proof.
"""

from dataclasses import dataclass, field
from pathlib import Path

from argus.reports.generate import SUMS_FILE, sha256_of


VERIFIED = "verified"
MODIFIED = "modified"
UNKNOWN = "unknown"


@dataclass
class Verification:
    path: Path
    sha256: str
    status: str
    details: list[str] = field(default_factory=list)
    scan_id: int | None = None


def _sums_entry(path: Path) -> str | None:
    sums = path.parent / SUMS_FILE

    if not sums.is_file():
        return None

    for line in sums.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split(None, 1)

        if len(parts) == 2 and parts[1].lstrip("*") == path.name:
            return parts[0].lower()

    return None


def verify_report(path, connection=None) -> Verification:
    """Compare a file's SHA-256 with what ARGUS recorded for it."""
    path = Path(path)

    if not path.is_file():
        raise FileNotFoundError(f"No such file: {path}")

    digest = sha256_of(path)
    check = Verification(path=path, sha256=digest, status=UNKNOWN)
    matched = changed = False

    # ----- the database: the stronger record -----
    if connection is not None:
        from argus.storage.repository import find_reports_by_hash, find_reports_by_path

        records = find_reports_by_hash(connection, digest)

        if records:
            first = records[0]
            matched = True
            check.scan_id = first.scan_id
            check.details.append(
                f"Matches a {first.format.upper()} report ARGUS generated on "
                f"{first.created_at:%d %b %Y %H:%M}"
                + (f" for scan #{first.scan_id}" if first.scan_id else "")
                + (" (redacted)" if first.redacted else "")
                + "."
            )
        else:
            earlier = find_reports_by_path(connection, str(path.resolve()))

            if earlier:
                changed = True
                check.details.append(
                    f"ARGUS wrote a different file at this path on "
                    f"{earlier[0].created_at:%d %b %Y %H:%M}: this file has been changed since."
                )

    # ----- the SHA256SUMS file next to it -----
    expected = _sums_entry(path)

    if expected is None:
        check.details.append(f"No {SUMS_FILE} entry was found next to this file.")
    elif expected == digest:
        matched = True
        check.details.append(f"Matches the {SUMS_FILE} file in its folder.")
    else:
        changed = True
        check.details.append(f"Does NOT match the {SUMS_FILE} file in its folder.")

    if changed:
        check.status = MODIFIED
    elif matched:
        check.status = VERIFIED

    return check
