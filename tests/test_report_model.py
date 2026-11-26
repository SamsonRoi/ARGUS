import json
from datetime import timedelta
from pathlib import Path

import jsonschema
import pytest

from argus.modules.compare import compare_scans
from argus.modules.risk import analyze
from argus.modules.risk_history import risk_changes
from argus.modules.topology import build_network_map
from argus.reports.model import SCHEMA_ID, build_report_data
from argus.reports.redact import redact_report
from argus.storage.repository import Engagement
from sample_network import office_report, office_scan


SCHEMA = json.loads(
    (Path(__file__).parent.parent / "argus" / "data" / "report.schema.json").read_text()
)


def roundtrip(data):
    return json.loads(json.dumps(data))


def test_report_matches_its_published_schema():
    data = office_report()

    jsonschema.validate(roundtrip(data), SCHEMA)
    assert data["schema"] == SCHEMA_ID


def test_redacted_report_matches_the_schema_too():
    jsonschema.validate(roundtrip(redact_report(office_report())), SCHEMA)


def test_summary_and_sections():
    data = office_report()

    assert data["summary"]["hosts_up"] == 6
    assert data["summary"]["grade"] == "F"
    assert data["summary"]["findings"] == len(data["findings"])
    assert "risk grade is F" in data["summary"]["headline"]
    assert "Telnet is open" in data["summary"]["headline"]
    assert [item["rank"] for item in data["fix_plan"]] == list(range(1, len(data["fix_plan"]) + 1))
    assert data["findings"][0]["number"] == 1
    assert data["findings"][0]["score_factors"]
    assert data["attack_paths"]
    assert data["network"]["traced_paths"]
    assert data["limitations"]
    assert data["engagement"] is None
    assert data["changes"] is None


def test_engagement_scope_and_dates_are_checked():
    result = office_scan()
    today = result.started_at.date()
    engagement = Engagement(
        id=1, name="Office LAN", authorized_by="R. Kumar, IT Manager",
        scope=["192.168.1.0/28", "192.168.1.30"],
        starts_on=today + timedelta(days=1), ends_on=today + timedelta(days=5),
    )

    data = build_report_data(result, analyze(result), build_network_map(result), engagement=engagement)

    assert data["engagement"]["hosts_outside_scope"] == ["192.168.1.20", "192.168.1.40", "192.168.1.77"]
    assert data["engagement"]["scan_within_dates"] is False


def test_changes_since_previous_scan():
    older = office_scan()
    newer = office_scan()
    newer.get_host("192.168.1.30").ports = [port for port in newer.get_host("192.168.1.30").ports if port.port != 23]
    risk = analyze(newer)

    data = build_report_data(
        newer, risk, build_network_map(newer),
        previous=older, previous_id=11,
        risk_changes=risk_changes(older, newer, newer_report=risk),
        scan_comparison=compare_scans(older, newer),
    )

    changes = data["changes"]
    assert changes["compared_with"] == 11
    assert [item["rule"] for item in changes["resolved"]] == ["telnet_open"]
    assert any(event["kind"] == "port_closed" for event in changes["scan_changes"])
    assert "1 finding was resolved" in data["summary"]["headline"]


def test_clean_network_headline():
    result = office_scan()
    result.hosts = []
    data = build_report_data(result, analyze(result), build_network_map(result))

    assert "no open risk findings" in data["summary"]["headline"]
    assert data["summary"]["grade"] == "A"


# ---------- redaction ----------

SENSITIVE = ["192.168.", "dc01", "office.lan", "router.lan", "db01", "aa:bb:cc", "R. Kumar"]


def test_redaction_removes_every_address_name_and_person():
    result = office_scan()
    engagement = Engagement(id=1, name="Office LAN", authorized_by="R. Kumar", scope=["192.168.1.0/24"],
                            notes="call R. Kumar on 192.168.1.5 issues")
    data = build_report_data(result, analyze(result), build_network_map(result), engagement=engagement)

    text = json.dumps(redact_report(data)).lower()

    for secret in SENSITIVE:
        assert secret.lower() not in text, secret


def test_redaction_is_consistent_and_readable():
    redacted = redact_report(office_report())

    assert [host["ip"] for host in redacted["hosts"]] == [f"host-{n}" for n in range(1, 7)]
    first = redacted["findings"][0]
    assert first["where"] == "host-1 (23/tcp)"
    assert first["host_label"].startswith("host-1 (name-")
    assert redacted["network"]["subnets"][0]["network"] == "net-1"
    assert "net-1" in redacted["summary"]["headline"]
    assert redacted["redacted"] is True


def test_redaction_rehashes_finding_ids():
    original = office_report()
    first = redact_report(original)
    second = redact_report(original)

    assert first["findings"][0]["id"] != original["findings"][0]["id"]
    # A fresh random salt each time, so ids cannot be linked across reports.
    assert first["findings"][0]["id"] != second["findings"][0]["id"]


def test_redaction_keeps_times_and_versions():
    original = office_report()
    redacted = redact_report(original)

    assert redacted["generated_at"] == original["generated_at"]
    assert redacted["scan"]["started_at"] == original["scan"]["started_at"]
    mysql = next(port for host in redacted["hosts"] for port in host["ports"] if port["port"] == 3306)
    assert mysql["version"] == "5.7.44"


def test_redaction_does_not_change_the_original():
    original = office_report()
    before = json.dumps(original)
    redact_report(original)

    assert json.dumps(original) == before


@pytest.mark.parametrize("text, expected", [
    ("10.0.0.5 and 10.0.0.5/32", "host-1 and net-1"),
    ("fe80::1 at 10:30:00", "host-1 at 10:30:00"),
    ("version 1.2.3", "version 1.2.3"),
])
def test_redactor_text_rules(text, expected):
    from argus.reports.redact import Redactor

    assert Redactor().text(text, []) == expected
