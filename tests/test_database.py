import sqlite3

import pytest

from argus.storage import database
from argus.storage.database import (
    SCHEMA_VERSION,
    StorageError,
    connect,
    default_db_path,
    migrate,
)


def test_new_database_gets_the_latest_schema(tmp_path):
    connection = connect(tmp_path / "new.db")

    version = connection.execute("PRAGMA user_version").fetchone()[0]
    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }

    assert version == SCHEMA_VERSION
    assert {
        "engagements", "scans", "hosts", "ports",
        "scan_warnings", "scan_coverage", "raw_outputs",
    } <= tables


def test_opening_twice_does_not_migrate_again(tmp_path):
    path = tmp_path / "twice.db"
    connect(path).close()

    connection = connect(path)

    assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_folder_is_created(tmp_path):
    path = tmp_path / "deep" / "folder" / "argus.db"
    connect(path).close()

    assert path.exists()


def test_foreign_keys_are_enforced():
    connection = connect(":memory:")

    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO hosts (scan_id, ip, state) VALUES (999, '10.0.0.1', 'up')"
        )


def test_newer_schema_is_refused(tmp_path):
    path = tmp_path / "future.db"
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 5}")
    raw.close()

    with pytest.raises(StorageError, match="newer ARGUS"):
        connect(path)


def test_failed_migration_changes_nothing(monkeypatch):
    connection = sqlite3.connect(":memory:")
    monkeypatch.setattr(
        database,
        "MIGRATIONS",
        ["CREATE TABLE ok_table (id INTEGER); CREATE TABLE broken ("],
    )
    monkeypatch.setattr(database, "SCHEMA_VERSION", 1)

    with pytest.raises(StorageError):
        migrate(connection)

    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    assert connection.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE name = 'ok_table'"
    ).fetchone()[0] == 0


def test_env_var_overrides_the_location(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGUS_DB", str(tmp_path / "custom.db"))

    assert default_db_path() == tmp_path / "custom.db"


def test_default_location_is_in_the_home_folder(monkeypatch, tmp_path):
    monkeypatch.delenv("ARGUS_DB", raising=False)
    monkeypatch.setattr(database, "_sudo_owner", lambda: None)
    monkeypatch.setattr(database.Path, "home", lambda: tmp_path)

    assert default_db_path() == tmp_path / ".argus" / "argus.db"


def test_under_sudo_the_real_users_home_is_used(monkeypatch, tmp_path):
    monkeypatch.delenv("ARGUS_DB", raising=False)
    monkeypatch.setattr(database, "_sudo_owner", lambda: (1000, 1000, tmp_path / "samson"))

    assert default_db_path() == tmp_path / "samson" / ".argus" / "argus.db"
