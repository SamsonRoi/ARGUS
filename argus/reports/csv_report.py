"""CSV reports: hosts, ports, findings and the fix plan, one file each.

CSV files are usually opened in a spreadsheet. Text that came from the
network (banners, hostnames) could start with '=', '+', '-' or '@' and be run
as a formula, so such cells are prefixed with an apostrophe, the standard
defence against CSV formula injection.
"""

import csv
from pathlib import Path


FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value) -> str:
    """Make one value safe to open in a spreadsheet."""
    if value is None:
        return ""

    if isinstance(value, bool):
        return "yes" if value else "no"

    if isinstance(value, (list, tuple)):
        value = "; ".join(str(item) for item in value)

    text = str(value)

    # Numbers stay numbers, including negative ones.
    if isinstance(value, (int, float)):
        return text

    if text.startswith(FORMULA_STARTS):
        return "'" + text

    return text


def _write(path: Path, header: list[str], rows) -> Path:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)

        for row in rows:
            writer.writerow([safe_cell(value) for value in row])

    return path


def write_csv(report: dict, folder: Path, stem: str) -> list[Path]:
    """Write the CSV files into `folder`. Returns their paths."""
    hosts = _write(
        folder / f"{stem}-hosts.csv",
        ["ip", "hostname", "mac", "vendor", "os_estimate", "os_accuracy",
         "likely_role", "role_confidence", "other_roles", "criticality",
         "risk_score", "open_ports", "responded_via"],
        (
            [
                host["ip"], host["hostname"], host["mac"], host["vendor"],
                host["os"]["name"] if host["os"] else None,
                host["os"]["accuracy"] if host["os"] else None,
                host["roles"][0]["label"] if host["roles"] else "Unknown",
                host["roles"][0]["confidence"] if host["roles"] else None,
                [f"{role['label']} ({role['confidence']})" for role in host["roles"][1:]],
                host["criticality"],
                host["risk_score"],
                sum(1 for port in host["ports"] if port["state"] == "open"),
                host["responded_via"],
            ]
            for host in report["hosts"]
        ),
    )

    ports = _write(
        folder / f"{stem}-ports.csv",
        ["ip", "port", "protocol", "state", "service", "product", "version", "extra_info"],
        (
            [host["ip"], port["port"], port["protocol"], port["state"], port["service"],
             port["product"], port["version"], port["extra_info"]]
            for host in report["hosts"]
            for port in host["ports"]
        ),
    )

    def finding_rows(items, status):
        for finding in items:
            acceptance = finding.get("acceptance") or {}
            yield [
                finding["number"], status, finding["priority"], finding["score"],
                finding["severity"], finding["confidence"], finding["title"],
                finding["category_label"], finding["where"], finding["evidence"],
                finding["raised_because"], finding["why"], finding["fix"],
                finding["references"], finding["history"]["first_seen_scan"],
                finding["history"]["streak"], finding["history"]["new_since_baseline"],
                acceptance.get("reason"), acceptance.get("expires_on"), finding["id"],
            ]

    findings = _write(
        folder / f"{stem}-findings.csv",
        ["number", "status", "priority", "score", "severity", "confidence", "title",
         "category", "where", "evidence", "raised_because", "why_it_matters", "fix",
         "references", "first_seen_scan", "streak", "new_since_baseline",
         "accepted_reason", "accepted_until", "id"],
        list(finding_rows(report["findings"], "open"))
        + list(finding_rows(report["accepted_risks"], "accepted")),
    )

    plan = _write(
        folder / f"{stem}-fix-plan.csv",
        ["rank", "fix", "how", "findings", "where", "risk_removed", "worst_severity"],
        (
            [action["rank"], action["title"], action["fix"], action["findings"],
             action["where"], action["risk_removed"], action["worst_severity"]]
            for action in report["fix_plan"]
        ),
    )

    return [hosts, ports, findings, plan]
