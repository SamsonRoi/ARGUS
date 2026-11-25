"""Save scans to the database and read them back.

Every function takes an open connection (from database.connect), so the
caller decides where the data lives and tests can use ":memory:".
"""

import gzip
import json
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime

from argus.modules.evidence import ScanEvidence, format_port_list, parse_port_list
from argus.modules.models import HostInfo, OSGuess, PortInfo, ScanResult
from argus.storage.database import StorageError


DISCOVERY_PROFILE = "discovery"
CANCELLED_MARKER = "stopped before it finished"


# ---------- engagements ----------

@dataclass
class Engagement:
    """An authorized piece of work: who approved it, and what is in scope.

    ARGUS records this now; enforcing the scope comes in a later version.
    """

    id: int | None
    name: str
    authorized_by: str | None = None
    scope: list[str] | None = None
    starts_on: date | None = None
    ends_on: date | None = None
    notes: str | None = None
    created_at: datetime | None = None


def _now_text() -> str:
    return datetime.now().astimezone().isoformat()


def create_engagement(
    connection: sqlite3.Connection,
    name: str,
    *,
    authorized_by: str | None = None,
    scope: list[str] | None = None,
    starts_on: date | None = None,
    ends_on: date | None = None,
    notes: str | None = None,
) -> Engagement:
    """Record a new engagement and return it with its id."""
    name = name.strip()

    if not name:
        raise StorageError("An engagement needs a name.")

    if starts_on and ends_on and ends_on < starts_on:
        raise StorageError("The end date is before the start date.")

    created = _now_text()

    try:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO engagements
                    (name, authorized_by, scope, starts_on, ends_on, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    authorized_by,
                    json.dumps(list(scope or [])),
                    starts_on.isoformat() if starts_on else None,
                    ends_on.isoformat() if ends_on else None,
                    notes,
                    created,
                ),
            )
    except sqlite3.IntegrityError as error:
        raise StorageError(f"An engagement called '{name}' already exists.") from error

    return Engagement(
        id=cursor.lastrowid,
        name=name,
        authorized_by=authorized_by,
        scope=list(scope or []),
        starts_on=starts_on,
        ends_on=ends_on,
        notes=notes,
        created_at=datetime.fromisoformat(created),
    )


def _engagement_from_row(row: sqlite3.Row) -> Engagement:
    return Engagement(
        id=row["id"],
        name=row["name"],
        authorized_by=row["authorized_by"],
        scope=json.loads(row["scope"] or "[]"),
        starts_on=date.fromisoformat(row["starts_on"]) if row["starts_on"] else None,
        ends_on=date.fromisoformat(row["ends_on"]) if row["ends_on"] else None,
        notes=row["notes"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def list_engagements(connection: sqlite3.Connection) -> list[Engagement]:
    rows = connection.execute("SELECT * FROM engagements ORDER BY id").fetchall()
    return [_engagement_from_row(row) for row in rows]


def get_engagement(connection: sqlite3.Connection, engagement_id: int) -> Engagement | None:
    row = connection.execute(
        "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
    ).fetchone()
    return _engagement_from_row(row) if row else None


# ---------- saving scans ----------

def scan_kind(result: ScanResult) -> str:
    return "discovery" if result.profile == DISCOVERY_PROFILE else "port_scan"


def save_scan(
    connection: sqlite3.Connection,
    result: ScanResult,
    engagement_id: int | None = None,
) -> int:
    """Save a finished (or cancelled) scan, with its evidence. Returns its id."""
    incomplete = any(CANCELLED_MARKER in warning for warning in result.warnings)

    try:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO scans
                    (engagement_id, kind, profile, targets, started_at,
                     finished_at, nmap_version, incomplete)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    scan_kind(result),
                    result.profile,
                    json.dumps(result.targets),
                    result.started_at.isoformat(),
                    result.finished_at.isoformat() if result.finished_at else None,
                    result.nmap_version,
                    int(incomplete),
                ),
            )
            scan_id = cursor.lastrowid

            for host in result.hosts:
                host_id = connection.execute(
                    """
                    INSERT INTO hosts
                        (scan_id, ip, state, hostname, mac, vendor,
                         discovery_method, os_name, os_accuracy)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        host.ip,
                        host.state,
                        host.hostname,
                        host.mac.upper() if host.mac else None,
                        host.vendor,
                        host.discovery_method,
                        host.os_guess.name if host.os_guess else None,
                        host.os_guess.accuracy if host.os_guess else None,
                    ),
                ).lastrowid

                connection.executemany(
                    """
                    INSERT INTO ports
                        (host_id, port, protocol, state, service, product,
                         version, extra_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            host_id,
                            port.port,
                            port.protocol,
                            port.state,
                            port.service,
                            port.product,
                            port.version,
                            port.extra_info,
                        )
                        for port in host.ports
                    ],
                )

            connection.executemany(
                "INSERT INTO scan_warnings (scan_id, position, message) VALUES (?, ?, ?)",
                [(scan_id, index, text) for index, text in enumerate(result.warnings)],
            )

            connection.executemany(
                "INSERT INTO scan_coverage (scan_id, protocol, ports) VALUES (?, ?, ?)",
                [
                    (scan_id, protocol, format_port_list(ports))
                    for protocol, ports in sorted(result.evidence.coverage.items())
                    if ports
                ],
            )

            connection.executemany(
                "INSERT INTO raw_outputs (scan_id, stage, xml_gz) VALUES (?, ?, ?)",
                [
                    (scan_id, stage, gzip.compress(xml.encode("utf-8")))
                    for stage, xml in result.evidence.raw_outputs
                ],
            )

    except sqlite3.Error as error:
        raise StorageError(f"The scan could not be saved: {error}") from error

    return scan_id


# ---------- reading scans back ----------

@dataclass
class ScanSummary:
    """One line of the scan history."""

    id: int
    kind: str
    profile: str
    targets: list[str]
    started_at: datetime
    finished_at: datetime | None
    is_baseline: bool
    incomplete: bool
    engagement_id: int | None
    engagement_name: str | None
    hosts_up: int
    open_ports: int


def list_scans(
    connection: sqlite3.Connection,
    limit: int | None = 50,
    engagement_id: int | None = None,
) -> list[ScanSummary]:
    """The most recent scans first, with host and open-port counts."""
    query = """
        SELECT s.*,
               e.name AS engagement_name,
               (SELECT COUNT(*) FROM hosts h
                 WHERE h.scan_id = s.id AND h.state = 'up') AS hosts_up,
               (SELECT COUNT(*) FROM ports p JOIN hosts h ON p.host_id = h.id
                 WHERE h.scan_id = s.id AND p.state = 'open') AS open_ports
          FROM scans s
          LEFT JOIN engagements e ON e.id = s.engagement_id
    """
    params: list = []

    if engagement_id is not None:
        query += " WHERE s.engagement_id = ?"
        params.append(engagement_id)

    query += " ORDER BY s.started_at DESC, s.id DESC"

    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)

    return [
        ScanSummary(
            id=row["id"],
            kind=row["kind"],
            profile=row["profile"],
            targets=json.loads(row["targets"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=(
                datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None
            ),
            is_baseline=bool(row["is_baseline"]),
            incomplete=bool(row["incomplete"]),
            engagement_id=row["engagement_id"],
            engagement_name=row["engagement_name"],
            hosts_up=row["hosts_up"],
            open_ports=row["open_ports"],
        )
        for row in connection.execute(query, params).fetchall()
    ]


def load_scan(
    connection: sqlite3.Connection,
    scan_id: int,
    include_raw: bool = False,
) -> ScanResult | None:
    """Rebuild a saved scan as a ScanResult, or return None if it does not exist."""
    row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

    if row is None:
        return None

    result = ScanResult(
        targets=json.loads(row["targets"]),
        profile=row["profile"],
        started_at=datetime.fromisoformat(row["started_at"]),
        finished_at=(
            datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None
        ),
        nmap_version=row["nmap_version"],
    )

    host_rows = connection.execute(
        "SELECT * FROM hosts WHERE scan_id = ? ORDER BY id", (scan_id,)
    ).fetchall()

    for host_row in host_rows:
        os_guess = None

        if host_row["os_name"] is not None:
            os_guess = OSGuess(
                name=host_row["os_name"],
                accuracy=host_row["os_accuracy"] or 0,
            )

        host = HostInfo(
            ip=host_row["ip"],
            state=host_row["state"],
            hostname=host_row["hostname"],
            mac=host_row["mac"],
            vendor=host_row["vendor"],
            discovery_method=host_row["discovery_method"],
            os_guess=os_guess,
        )

        for port_row in connection.execute(
            "SELECT * FROM ports WHERE host_id = ? ORDER BY protocol, port",
            (host_row["id"],),
        ):
            host.add_port(
                PortInfo(
                    port=port_row["port"],
                    protocol=port_row["protocol"],
                    state=port_row["state"],
                    service=port_row["service"],
                    product=port_row["product"],
                    version=port_row["version"],
                    extra_info=port_row["extra_info"],
                )
            )

        result.hosts.append(host)

    result.warnings = [
        warning_row["message"]
        for warning_row in connection.execute(
            "SELECT message FROM scan_warnings WHERE scan_id = ? ORDER BY position",
            (scan_id,),
        )
    ]

    evidence = ScanEvidence()

    for coverage_row in connection.execute(
        "SELECT protocol, ports FROM scan_coverage WHERE scan_id = ?", (scan_id,)
    ):
        evidence.coverage[coverage_row["protocol"]] = parse_port_list(coverage_row["ports"])

    if include_raw:
        for raw_row in connection.execute(
            "SELECT stage, xml_gz FROM raw_outputs WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ):
            evidence.raw_outputs.append(
                (raw_row["stage"], gzip.decompress(raw_row["xml_gz"]).decode("utf-8"))
            )

    result.evidence = evidence

    return result


def scan_engagement_id(connection: sqlite3.Connection, scan_id: int) -> int | None:
    row = connection.execute(
        "SELECT engagement_id FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    return row["engagement_id"] if row else None


# ---------- baselines and deletion ----------

def set_baseline(connection: sqlite3.Connection, scan_id: int) -> None:
    """Mark a scan as the baseline that later scans are compared against.

    There is one baseline per engagement (and one for scans with no
    engagement), so marking a new one clears the old one.
    """
    row = connection.execute(
        "SELECT engagement_id FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()

    if row is None:
        raise StorageError(f"There is no scan #{scan_id}.")

    with connection:
        connection.execute(
            "UPDATE scans SET is_baseline = 0 WHERE engagement_id IS ?",
            (row["engagement_id"],),
        )
        connection.execute("UPDATE scans SET is_baseline = 1 WHERE id = ?", (scan_id,))


def get_baseline_id(
    connection: sqlite3.Connection,
    engagement_id: int | None = None,
) -> int | None:
    row = connection.execute(
        "SELECT id FROM scans WHERE is_baseline = 1 AND engagement_id IS ?",
        (engagement_id,),
    ).fetchone()
    return row["id"] if row else None


def delete_scan(connection: sqlite3.Connection, scan_id: int) -> bool:
    """Delete a scan and everything recorded with it. Returns False if missing."""
    with connection:
        cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cursor.rowcount > 0
