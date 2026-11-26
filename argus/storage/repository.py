"""Save scans to the database and read them back.

Every function takes an open connection (from database.connect), so the
caller decides where the data lives and tests can use ":memory:".
"""

import gzip
import json
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime

from argus.modules.classify import RulesError, classify_result
from argus.modules.evidence import ScanEvidence, format_port_list, parse_port_list
from argus.modules.models import (
    HostInfo,
    OSGuess,
    PortInfo,
    RoleMatch,
    ScanResult,
    TraceHop,
)
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
                     finished_at, nmap_version, incomplete, classifier_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    result.classifier_version,
                ),
            )
            scan_id = cursor.lastrowid

            for host in result.hosts:
                host_id = connection.execute(
                    """
                    INSERT INTO hosts
                        (scan_id, ip, state, hostname, mac, vendor,
                         discovery_method, os_name, os_accuracy,
                         criticality, criticality_reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        host.criticality,
                        host.criticality_reason,
                    ),
                ).lastrowid

                connection.executemany(
                    """
                    INSERT INTO host_roles
                        (host_id, position, role, label, confidence, score, reasons)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            host_id,
                            position,
                            match.role,
                            match.label,
                            match.confidence,
                            match.score,
                            json.dumps(match.reasons),
                        )
                        for position, match in enumerate(host.roles)
                    ],
                )

                connection.executemany(
                    """
                    INSERT INTO trace_hops (host_id, ttl, ip, rtt_ms, hostname)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (host_id, hop.ttl, hop.ip, hop.rtt_ms, hop.hostname)
                        for hop in host.trace
                    ],
                )

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
        classifier_version=row["classifier_version"],
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
            criticality=host_row["criticality"],
            criticality_reason=host_row["criticality_reason"],
        )

        host.roles = [
            RoleMatch(
                role=role_row["role"],
                label=role_row["label"],
                confidence=role_row["confidence"],
                score=role_row["score"],
                reasons=json.loads(role_row["reasons"] or "[]"),
            )
            for role_row in connection.execute(
                "SELECT * FROM host_roles WHERE host_id = ? ORDER BY position",
                (host_row["id"],),
            )
        ]

        host.trace = [
            TraceHop(
                ttl=hop_row["ttl"],
                ip=hop_row["ip"],
                rtt_ms=hop_row["rtt_ms"],
                hostname=hop_row["hostname"],
            )
            for hop_row in connection.execute(
                "SELECT * FROM trace_hops WHERE host_id = ? ORDER BY ttl",
                (host_row["id"],),
            )
        ]

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

    # Scans saved before classification existed are classified when opened.
    # This is not written back, so the stored record stays as it was.
    if result.classifier_version is None:
        try:
            classify_result(result)
        except RulesError:
            pass

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


# ---------- accepted risks ----------

@dataclass
class AcceptanceRecord:
    id: int
    fingerprint: str
    rule: str
    title: str
    location: str
    reason: str
    accepted_by: str | None
    expires_on: date | None
    created_at: datetime
    engagement_id: int | None

    def active(self, today: date | None = None) -> bool:
        today = today or date.today()
        return self.expires_on is None or self.expires_on >= today


def accept_risk(
    connection: sqlite3.Connection,
    finding,
    reason: str,
    *,
    accepted_by: str | None = None,
    expires_on: date | None = None,
    engagement_id: int | None = None,
) -> int:
    """Record that a finding is a known, accepted risk. Returns the record id.

    Accepting the same finding again replaces the earlier record.
    """
    reason = (reason or "").strip()

    if not reason:
        raise StorageError("Accepting a risk needs a reason.")

    if expires_on is not None and expires_on < date.today():
        raise StorageError("The expiry date is already in the past.")

    with connection:
        connection.execute(
            "DELETE FROM risk_acceptances WHERE fingerprint = ?", (finding.fingerprint,)
        )
        cursor = connection.execute(
            """
            INSERT INTO risk_acceptances
                (fingerprint, rule, title, location, reason, accepted_by,
                 expires_on, created_at, engagement_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.fingerprint,
                finding.rule,
                finding.title,
                finding.where,
                reason,
                accepted_by,
                expires_on.isoformat() if expires_on else None,
                _now_text(),
                engagement_id,
            ),
        )

    return cursor.lastrowid


def list_acceptances(connection: sqlite3.Connection) -> list[AcceptanceRecord]:
    rows = connection.execute(
        "SELECT * FROM risk_acceptances ORDER BY created_at DESC, id DESC"
    ).fetchall()

    return [
        AcceptanceRecord(
            id=row["id"],
            fingerprint=row["fingerprint"],
            rule=row["rule"],
            title=row["title"],
            location=row["location"],
            reason=row["reason"],
            accepted_by=row["accepted_by"],
            expires_on=date.fromisoformat(row["expires_on"]) if row["expires_on"] else None,
            created_at=datetime.fromisoformat(row["created_at"]),
            engagement_id=row["engagement_id"],
        )
        for row in rows
    ]


def revoke_acceptance(connection: sqlite3.Connection, acceptance_id: int) -> bool:
    """Stop accepting a risk, so it counts again. Returns False if missing."""
    with connection:
        cursor = connection.execute(
            "DELETE FROM risk_acceptances WHERE id = ?", (acceptance_id,)
        )
    return cursor.rowcount > 0


def acceptances_by_fingerprint(connection: sqlite3.Connection) -> dict:
    """Accepted risks keyed by finding fingerprint, for the risk engine."""
    from argus.modules.risk import Acceptance

    return {
        record.fingerprint: Acceptance(
            id=record.id,
            fingerprint=record.fingerprint,
            reason=record.reason,
            accepted_by=record.accepted_by,
            expires_on=record.expires_on,
            created_on=record.created_at.date(),
        )
        for record in reversed(list_acceptances(connection))
    }


# ---------- generated reports ----------

@dataclass
class ReportRecord:
    id: int
    scan_id: int | None
    format: str
    path: str
    sha256: str
    size: int
    redacted: bool
    created_at: datetime


def _report_from_row(row) -> ReportRecord:
    return ReportRecord(
        id=row["id"],
        scan_id=row["scan_id"],
        format=row["format"],
        path=row["path"],
        sha256=row["sha256"],
        size=row["size"],
        redacted=bool(row["redacted"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def record_report(
    connection: sqlite3.Connection,
    *,
    scan_id: int | None,
    format: str,
    path: str,
    sha256: str,
    size: int,
    redacted: bool,
) -> int:
    """Remember a generated report file and its SHA-256, for verifying later.

    The fingerprint is always kept, even if the scan has since been deleted.
    """
    if scan_id is not None and connection.execute(
        "SELECT 1 FROM scans WHERE id = ?", (scan_id,)
    ).fetchone() is None:
        scan_id = None

    with connection:
        cursor = connection.execute(
            """
            INSERT INTO reports (scan_id, format, path, sha256, size, redacted, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, format, path, sha256, size, int(redacted), _now_text()),
        )
    return cursor.lastrowid


def find_reports_by_hash(connection: sqlite3.Connection, sha256: str) -> list[ReportRecord]:
    rows = connection.execute(
        "SELECT * FROM reports WHERE sha256 = ? ORDER BY id", (sha256.lower(),)
    ).fetchall()
    return [_report_from_row(row) for row in rows]


def find_reports_by_path(connection: sqlite3.Connection, path: str) -> list[ReportRecord]:
    rows = connection.execute(
        "SELECT * FROM reports WHERE path = ? ORDER BY id DESC", (path,)
    ).fetchall()
    return [_report_from_row(row) for row in rows]


def list_reports(connection: sqlite3.Connection, limit: int | None = None) -> list[ReportRecord]:
    """Every report file ARGUS has made, newest first."""
    query = "SELECT * FROM reports ORDER BY id DESC"
    params: tuple = ()

    if limit is not None:
        query += " LIMIT ?"
        params = (limit,)

    return [_report_from_row(row) for row in connection.execute(query, params).fetchall()]
