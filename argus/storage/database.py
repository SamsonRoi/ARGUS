"""The ARGUS database: where it lives, how to open it, and its schema.

ARGUS keeps every scan in one SQLite file. The schema is versioned with
SQLite's own `PRAGMA user_version`, and each later version is one more
entry in MIGRATIONS, applied in order. Never edit a migration that has
already been released; add a new one instead.
"""

import os
import sqlite3
from pathlib import Path


DB_ENV_VAR = "ARGUS_DB"
DB_DIR_NAME = ".argus"
DB_FILE_NAME = "argus.db"


class StorageError(Exception):
    """The ARGUS database could not be opened, read or written."""


MIGRATIONS: list[str] = [
    # ----- Version 1: scans, hosts, ports, evidence, engagements -----
    """
    CREATE TABLE engagements (
        id            INTEGER PRIMARY KEY,
        name          TEXT NOT NULL UNIQUE,
        authorized_by TEXT,
        scope         TEXT NOT NULL DEFAULT '[]',  -- JSON list of IPs/CIDRs
        starts_on     TEXT,                         -- ISO date
        ends_on       TEXT,                         -- ISO date
        notes         TEXT,
        created_at    TEXT NOT NULL
    );

    CREATE TABLE scans (
        id            INTEGER PRIMARY KEY,
        engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
        kind          TEXT NOT NULL,                -- 'discovery' or 'port_scan'
        profile       TEXT NOT NULL,
        targets       TEXT NOT NULL,                -- JSON list
        started_at    TEXT NOT NULL,
        finished_at   TEXT,
        nmap_version  TEXT,
        is_baseline   INTEGER NOT NULL DEFAULT 0,
        incomplete    INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE hosts (
        id               INTEGER PRIMARY KEY,
        scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        ip               TEXT NOT NULL,
        state            TEXT NOT NULL,
        hostname         TEXT,
        mac              TEXT,
        vendor           TEXT,
        discovery_method TEXT,
        os_name          TEXT,
        os_accuracy      INTEGER,
        UNIQUE (scan_id, ip)
    );

    CREATE TABLE ports (
        id         INTEGER PRIMARY KEY,
        host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
        port       INTEGER NOT NULL,
        protocol   TEXT NOT NULL,
        state      TEXT NOT NULL,
        service    TEXT,
        product    TEXT,
        version    TEXT,
        extra_info TEXT,
        UNIQUE (host_id, port, protocol)
    );

    CREATE TABLE scan_warnings (
        id       INTEGER PRIMARY KEY,
        scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        position INTEGER NOT NULL,
        message  TEXT NOT NULL
    );

    -- Which ports each scan actually checked, as a compact list ('1-1024,8080').
    CREATE TABLE scan_coverage (
        scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        protocol TEXT NOT NULL,
        ports    TEXT NOT NULL,
        PRIMARY KEY (scan_id, protocol)
    );

    -- Nmap's own XML output for every run, gzip-compressed.
    CREATE TABLE raw_outputs (
        id      INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        stage   TEXT NOT NULL,
        xml_gz  BLOB NOT NULL
    );

    CREATE INDEX idx_scans_started   ON scans(started_at);
    CREATE INDEX idx_hosts_scan      ON hosts(scan_id);
    CREATE INDEX idx_hosts_mac       ON hosts(mac);
    CREATE INDEX idx_ports_host      ON ports(host_id);
    CREATE INDEX idx_raw_scan        ON raw_outputs(scan_id);
    """,
    # ----- Version 2: asset roles, criticality, traceroute hops -----
    """
    ALTER TABLE scans ADD COLUMN classifier_version TEXT;
    ALTER TABLE hosts ADD COLUMN criticality TEXT;
    ALTER TABLE hosts ADD COLUMN criticality_reason TEXT;

    -- Every role a host matched, strongest first, with its evidence.
    CREATE TABLE host_roles (
        host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
        position   INTEGER NOT NULL,
        role       TEXT NOT NULL,
        label      TEXT NOT NULL,
        confidence TEXT NOT NULL,
        score      INTEGER NOT NULL,
        reasons    TEXT NOT NULL DEFAULT '[]',   -- JSON list of evidence
        PRIMARY KEY (host_id, role)
    );

    -- The traceroute path to a host (ip is NULL for hops that did not answer).
    CREATE TABLE trace_hops (
        host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
        ttl      INTEGER NOT NULL,
        ip       TEXT,
        rtt_ms   REAL,
        hostname TEXT,
        PRIMARY KEY (host_id, ttl)
    );

    CREATE INDEX idx_roles_role ON host_roles(role);
    """,
    # ----- Version 3: accepted risks -----
    """
    -- A finding someone decided to live with, for a reason, until a date.
    CREATE TABLE risk_acceptances (
        id            INTEGER PRIMARY KEY,
        fingerprint   TEXT NOT NULL,     -- same problem on the same host/subnet
        rule          TEXT NOT NULL,
        title         TEXT NOT NULL,
        location      TEXT NOT NULL,     -- host and ports, or subnet
        reason        TEXT NOT NULL,
        accepted_by   TEXT,
        expires_on    TEXT,              -- ISO date; NULL = no expiry
        created_at    TEXT NOT NULL,
        engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL
    );

    CREATE INDEX idx_acceptances_fingerprint ON risk_acceptances(fingerprint);
    """,
    # ----- Version 4: generated reports, for verifying them later -----
    """
    CREATE TABLE reports (
        id         INTEGER PRIMARY KEY,
        scan_id    INTEGER REFERENCES scans(id) ON DELETE SET NULL,
        format     TEXT NOT NULL,       -- json, csv, html, pdf
        path       TEXT NOT NULL,
        sha256     TEXT NOT NULL,
        size       INTEGER NOT NULL,
        redacted   INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE INDEX idx_reports_sha256 ON reports(sha256);
    """,
]

SCHEMA_VERSION = len(MIGRATIONS)


def _sudo_owner() -> tuple[int, int, Path] | None:
    """When ARGUS runs under sudo, return the real user's (uid, gid, home).

    Scans that need root are run with sudo, and without this the history
    would be split between root's home folder and the user's own.
    """
    if os.name == "nt":
        return None

    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")

    if not uid or not gid or os.geteuid() != 0:
        return None

    try:
        import pwd

        home = Path(pwd.getpwuid(int(uid)).pw_dir)
        return int(uid), int(gid), home

    except (ImportError, KeyError, ValueError):
        return None


def default_db_path() -> Path:
    """Where the database lives: $ARGUS_DB if set, otherwise ~/.argus/argus.db."""
    override = os.environ.get(DB_ENV_VAR)

    if override:
        return Path(override).expanduser()

    owner = _sudo_owner()
    home = owner[2] if owner else Path.home()

    return home / DB_DIR_NAME / DB_FILE_NAME


def _give_back_to_sudo_user(path: Path) -> None:
    """Keep the folder and file owned by the real user when running under sudo."""
    owner = _sudo_owner()

    if owner is None:
        return

    uid, gid, _home = owner

    for item in (path.parent, path):
        try:
            if item.exists():
                os.chown(item, uid, gid)
        except OSError:
            pass


def migrate(connection: sqlite3.Connection) -> int:
    """Bring the schema up to date. Returns the schema version afterwards."""
    current = connection.execute("PRAGMA user_version").fetchone()[0]

    if current > SCHEMA_VERSION:
        raise StorageError(
            f"This database was created by a newer ARGUS (schema {current}; "
            f"this version understands up to {SCHEMA_VERSION}). "
            "Update ARGUS to use it."
        )

    for version in range(current, SCHEMA_VERSION):
        # One transaction per migration: it applies completely or not at all.
        try:
            connection.executescript(
                "BEGIN;\n"
                + MIGRATIONS[version]
                + f"\nPRAGMA user_version = {version + 1};\nCOMMIT;"
            )
        except sqlite3.Error as error:
            if connection.in_transaction:
                connection.rollback()

            raise StorageError(
                f"Could not upgrade the database to schema {version + 1}: {error}"
            ) from error

    return SCHEMA_VERSION


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open (and create or upgrade, if needed) the ARGUS database.

    Pass ":memory:" for a throwaway database, which tests use.
    """
    in_memory = str(path) == ":memory:"
    db_path = Path(path) if path is not None and not in_memory else None

    if db_path is None and not in_memory:
        db_path = default_db_path()

    try:
        if db_path is not None:
            db_path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(":memory:" if in_memory else str(db_path))

    except (OSError, sqlite3.Error) as error:
        raise StorageError(f"Could not open the ARGUS database: {error}") from error

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        migrate(connection)
    except StorageError:
        connection.close()
        raise

    if db_path is not None:
        _give_back_to_sudo_user(db_path)

    return connection
