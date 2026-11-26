from datetime import date, datetime, timedelta

import pytest

from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo, OSGuess, PortInfo, ScanResult
from argus.storage.database import StorageError, connect
from argus.storage.repository import (
    create_engagement,
    delete_scan,
    get_baseline_id,
    get_engagement,
    list_engagements,
    list_scans,
    load_scan,
    save_scan,
    set_baseline,
)


@pytest.fixture
def db():
    connection = connect(":memory:")
    yield connection
    connection.close()


def make_result(profile="Quick TCP", started=None, warnings=()):
    result = ScanResult(
        targets=["10.0.0.0/24", "10.0.1.5"],
        profile=profile,
        nmap_version="7.94",
        warnings=list(warnings),
        evidence=ScanEvidence(
            coverage={"tcp": {22, 80, 443}, "udp": {53}},
            raw_outputs=[("tcp_scan", "<nmaprun>tcp</nmaprun>")],
        ),
    )

    if started is not None:
        result.started_at = started

    host = HostInfo(
        ip="10.0.0.5",
        hostname="web01",
        mac="aa:bb:cc:dd:ee:ff",
        vendor="Dell",
        discovery_method="ARP reply",
        os_guess=OSGuess("Linux 5.x", 96),
    )
    host.add_port(PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "8.9p1", "Ubuntu"))
    host.add_port(PortInfo(53, "udp", "open", "domain"))
    result.add_host(host)
    result.add_host(HostInfo(ip="10.0.0.9", discovery_method="ICMP echo reply"))
    result.finish()

    return result


def test_saved_scan_comes_back_the_same(db):
    original = make_result(warnings=["UDP scan failed: needs root"])

    scan_id = save_scan(db, original)
    loaded = load_scan(db, scan_id)

    assert loaded.targets == original.targets
    assert loaded.profile == original.profile
    assert loaded.nmap_version == "7.94"
    assert loaded.started_at == original.started_at
    assert loaded.finished_at == original.finished_at
    assert loaded.warnings == ["UDP scan failed: needs root"]
    assert loaded.evidence.coverage == {"tcp": {22, 80, 443}, "udp": {53}}

    web = loaded.get_host("10.0.0.5")
    assert web.hostname == "web01"
    assert web.mac == "AA:BB:CC:DD:EE:FF"   # stored in one consistent form
    assert web.vendor == "Dell"
    assert web.os_guess == OSGuess("Linux 5.x", 96)
    assert [(p.port, p.protocol) for p in web.open_ports] == [(22, "tcp"), (53, "udp")]
    assert web.open_ports[0].version_text == "OpenSSH 8.9p1"
    assert web.open_ports[0].extra_info == "Ubuntu"

    assert loaded.get_host("10.0.0.9").os_guess is None


def test_raw_xml_is_compressed_and_only_loaded_on_request(db):
    scan_id = save_scan(db, make_result())

    assert load_scan(db, scan_id).evidence.raw_outputs == []
    assert load_scan(db, scan_id, include_raw=True).evidence.raw_outputs == [
        ("tcp_scan", "<nmaprun>tcp</nmaprun>")
    ]


def test_missing_scan_returns_none(db):
    assert load_scan(db, 42) is None


def test_list_shows_newest_first_with_counts(db):
    now = datetime.now().astimezone()
    older = save_scan(db, make_result(started=now - timedelta(days=1)))
    newer = save_scan(db, make_result("discovery", started=now))

    summaries = list_scans(db)

    assert [item.id for item in summaries] == [newer, older]
    assert summaries[0].kind == "discovery"
    assert summaries[1].kind == "port_scan"
    assert summaries[1].hosts_up == 2
    assert summaries[1].open_ports == 2
    assert list_scans(db, limit=1)[0].id == newer


def test_cancelled_scans_are_flagged_incomplete(db):
    scan_id = save_scan(
        db,
        make_result(warnings=["The scan was stopped before it finished. These results are incomplete."]),
    )

    assert list_scans(db)[0].id == scan_id
    assert list_scans(db)[0].incomplete


def test_one_baseline_per_engagement(db):
    office = create_engagement(db, "Office LAN", scope=["10.0.0.0/24"])
    first = save_scan(db, make_result(), engagement_id=office.id)
    second = save_scan(db, make_result(), engagement_id=office.id)
    loose = save_scan(db, make_result())

    set_baseline(db, first)
    set_baseline(db, loose)
    set_baseline(db, second)

    assert get_baseline_id(db, office.id) == second
    assert get_baseline_id(db, None) == loose
    assert [s.id for s in list_scans(db) if s.is_baseline] == sorted(
        [second, loose], reverse=True
    )


def test_baseline_for_missing_scan_is_refused(db):
    with pytest.raises(StorageError):
        set_baseline(db, 7)


def test_delete_removes_everything_for_that_scan(db):
    scan_id = save_scan(db, make_result())

    assert delete_scan(db, scan_id)
    assert not delete_scan(db, scan_id)

    for table in ("hosts", "ports", "scan_warnings", "scan_coverage", "raw_outputs"):
        assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_engagements_are_stored_and_read_back(db):
    created = create_engagement(
        db,
        "  Office LAN  ",
        authorized_by="R. Kumar, IT Manager",
        scope=["10.0.0.0/24"],
        starts_on=date(2026, 12, 1),
        ends_on=date(2026, 12, 5),
        notes="Weekends only",
    )

    loaded = get_engagement(db, created.id)

    assert loaded.name == "Office LAN"
    assert loaded.authorized_by == "R. Kumar, IT Manager"
    assert loaded.scope == ["10.0.0.0/24"]
    assert loaded.starts_on == date(2026, 12, 1)
    assert loaded.ends_on == date(2026, 12, 5)
    assert [item.name for item in list_engagements(db)] == ["Office LAN"]


def test_engagement_rules(db):
    create_engagement(db, "Office LAN")

    with pytest.raises(StorageError, match="already exists"):
        create_engagement(db, "Office LAN")

    with pytest.raises(StorageError, match="needs a name"):
        create_engagement(db, "   ")

    with pytest.raises(StorageError, match="before the start"):
        create_engagement(db, "Backwards", starts_on=date(2026, 12, 5), ends_on=date(2026, 12, 1))


def test_scans_keep_their_engagement(db):
    office = create_engagement(db, "Office LAN")
    save_scan(db, make_result(), engagement_id=office.id)
    save_scan(db, make_result())

    assert [s.engagement_name for s in list_scans(db, engagement_id=office.id)] == ["Office LAN"]


# ---------- Step 6: roles, criticality, traces ----------

def test_roles_criticality_and_trace_round_trip(db):
    from argus.modules.classify import classify_result
    from argus.modules.models import TraceHop

    original = make_result()
    original.get_host("10.0.0.5").trace = [
        TraceHop(1, "10.0.0.1", 0.5, "gw.lan"),
        TraceHop(2, None),
        TraceHop(3, "10.0.0.5", 1.25),
    ]
    original.get_host("10.0.0.5").add_port(PortInfo(5432, "tcp", "open", "postgresql"))
    classify_result(original)

    loaded = load_scan(db, save_scan(db, original))
    before, after = original.get_host("10.0.0.5"), loaded.get_host("10.0.0.5")

    assert loaded.classifier_version == original.classifier_version
    assert after.roles == before.roles
    assert after.primary_role.role == "database_server"
    assert after.criticality == "high"
    assert after.criticality_reason == before.criticality_reason
    assert after.trace == before.trace


def test_step5_database_is_upgraded_and_old_scans_are_classified(tmp_path):
    """A history file made before Step 6 keeps working."""
    import sqlite3

    from argus.storage import database

    path = tmp_path / "step5.db"
    raw = sqlite3.connect(path)
    raw.executescript(database.MIGRATIONS[0] + "\nPRAGMA user_version = 1;")
    raw.execute(
        "INSERT INTO scans (id, kind, profile, targets, started_at) "
        "VALUES (1, 'port_scan', 'Quick TCP', '[\"10.0.0.5\"]', '2026-11-25T10:00:00+05:30')"
    )
    raw.execute("INSERT INTO hosts (id, scan_id, ip, state) VALUES (1, 1, '10.0.0.5', 'up')")
    raw.execute(
        "INSERT INTO ports (host_id, port, protocol, state) VALUES (1, 9100, 'tcp', 'open')"
    )
    raw.commit()
    raw.close()

    connection = connect(path)
    loaded = load_scan(connection, 1)

    assert connection.execute("PRAGMA user_version").fetchone()[0] == database.SCHEMA_VERSION
    assert loaded.get_host("10.0.0.5").primary_role.role == "printer"
    # Classifying on load does not rewrite the stored record.
    assert connection.execute("SELECT COUNT(*) FROM host_roles").fetchone()[0] == 0
