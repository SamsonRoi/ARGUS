"""Risk over time: how long each finding has been open, and what really got fixed.

This applies ARGUS's main rule to risk: never claim more than the evidence
shows.

* A finding only counts as "resolved" when the newer scan actually checked
  it again. That means the host answered, the finding's ports were inside
  the scan's coverage, and, for version-based findings, versions were
  collected.
* Otherwise it is "not re-checked", which means unknown, not fixed.
* A finding's streak counts the scans in a row it was seen in. Scans that
  could not check it neither extend nor break the streak.

All scans are analysed with the current rules, so old and new results are
always compared like with like.
"""

import ipaddress
from dataclasses import dataclass, field

from argus.modules.risk import (
    Finding,
    RiskReport,
    analyze,
    finalize,
    host_identity,
)
from argus.modules.topology import build_network_map


HISTORY_LIMIT = 20
VERSION_CATEGORIES = ("outdated",)


@dataclass
class ScanFindings:
    """One saved scan, analysed with the current rules."""

    scan_id: int
    result: object
    report: RiskReport
    by_fingerprint: dict[str, Finding] = field(default_factory=dict)


@dataclass
class RiskChanges:
    """How the risk picture moved between two scans."""

    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    not_rechecked: list[Finding] = field(default_factory=list)


# ---------- can a scan check a finding? ----------

def _hosts_by_identity(result) -> dict[str, object]:
    hosts = {}

    for host in result.up_hosts:
        hosts[host_identity(host)] = host
        hosts.setdefault(f"ip:{host.ip}", host)

    return hosts


def _networks(result) -> list:
    networks = []

    for target in result.targets:
        try:
            networks.append(ipaddress.ip_network(target, strict=False))
        except ValueError:
            continue

    return networks


def _in_targets(ip: str | None, result) -> bool:
    if not ip:
        return False

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return any(address in network for network in _networks(result))


def check_status(finding: Finding, result, report: RiskReport | None = None) -> str:
    """Could `result` confirm whether `finding` is still there?

    Returns 'present', 'resolved' or 'not_rechecked'.
    """
    fingerprints = {item.fingerprint for item in (report.findings + report.accepted)} if report else set()

    if finding.fingerprint in fingerprints:
        return "present"

    if finding.scope == "network":
        subnets = {group.network for group in build_network_map(result).subnets}
        return "resolved" if finding.subnet in subnets else "not_rechecked"

    host = _hosts_by_identity(result).get(finding.identity) or _hosts_by_identity(result).get(
        f"ip:{finding.host_ip}"
    )

    if host is None:
        # The host did not answer. That is not proof the problem is fixed.
        return "not_rechecked"

    for protocol, port in finding.ports:
        if not result.evidence.covers(protocol, port):
            return "not_rechecked"

    if finding.category in VERSION_CATEGORIES or any(
        "banner reports" in line for line in finding.evidence
    ):
        still_open = {
            (port.protocol, port.port): port for port in host.open_ports
        }

        for key in finding.ports:
            port = still_open.get(key)

            # The port is still open but no version was collected this time,
            # so the version-based problem could not be re-checked.
            if port is not None and not port.version:
                return "not_rechecked"

    if any(line.startswith("OS estimate") for line in finding.evidence) and host.os_guess is None:
        return "not_rechecked"

    return "resolved"


def could_check(finding: Finding, result) -> bool:
    """True if `result` was able to look for this finding at all."""
    return check_status(finding, result) != "not_rechecked"


# ---------- comparing two scans ----------

def risk_changes(older, newer, older_report=None, newer_report=None) -> RiskChanges:
    """New, resolved and not re-checked findings between two scans."""
    older_report = older_report or analyze(older)
    newer_report = newer_report or analyze(newer)
    changes = RiskChanges()

    old_prints = {item.fingerprint for item in older_report.findings + older_report.accepted}

    for finding in newer_report.findings + newer_report.accepted:
        if finding.fingerprint in old_prints:
            continue

        # Only call it new if the older scan could have seen it.
        if could_check(finding, older):
            changes.new.append(finding)

    for finding in older_report.findings + older_report.accepted:
        status = check_status(finding, newer, newer_report)

        if status == "resolved":
            changes.resolved.append(finding)
        elif status == "not_rechecked":
            changes.not_rechecked.append(finding)

    return changes


# ---------- the full history of every finding ----------

def _overlaps(first, second) -> bool:
    return any(
        a.version == b.version and a.overlaps(b)
        for a in _networks(first) for b in _networks(second)
    )


def apply_history(
    report: RiskReport,
    result,
    previous: list[ScanFindings],
    baseline: ScanFindings | None = None,
    acceptances=None,
) -> RiskReport:
    """Add first-seen, streak, new-since-baseline and resolved findings.

    `previous` holds earlier scans, oldest first, already analysed.
    """
    previous = [item for item in previous if _overlaps(item.result, result)]
    report.history_scans = len(previous)

    for finding in report.findings + report.accepted:
        seen = [item for item in previous if finding.fingerprint in item.by_fingerprint]

        if seen:
            finding.first_seen_scan = seen[0].scan_id
            finding.first_seen_at = seen[0].result.started_at
        else:
            finding.first_seen_scan = None
            finding.first_seen_at = result.started_at

        finding.seen_in_scans = len(seen) + 1

        streak = 1

        for item in reversed(previous):
            if finding.fingerprint in item.by_fingerprint:
                streak += 1
            elif could_check(finding, item.result):
                break
            # A scan that could not check this finding is skipped.

        finding.streak = streak

        if baseline is not None and baseline.scan_id in {item.scan_id for item in previous}:
            if finding.fingerprint in baseline.by_fingerprint:
                finding.new_since_baseline = False
            elif could_check(finding, baseline.result):
                finding.new_since_baseline = True
            else:
                finding.new_since_baseline = None

    if previous:
        last = previous[-1]
        report.compared_with = last.scan_id
        changes = risk_changes(last.result, result, last.report, report)
        report.resolved = changes.resolved
        report.not_rechecked = changes.not_rechecked

    return finalize(report, acceptances)


# ---------- reading history from the database ----------

def analyze_with_history(
    connection,
    result,
    scan_id: int | None = None,
    engagement_id: int | None = None,
    limit: int = HISTORY_LIMIT,
) -> RiskReport:
    """Analyse a scan, using saved history and accepted risks when available.

    `scan_id` is this scan's id in the history (if saved), so it is not
    compared with itself; only scans that started earlier are used.
    """
    from argus.storage.repository import (
        acceptances_by_fingerprint,
        get_baseline_id,
        list_scans,
        load_scan,
    )

    acceptances = acceptances_by_fingerprint(connection)
    report = analyze(result, acceptances=acceptances)

    summaries = [
        summary for summary in list_scans(connection, limit=None, engagement_id=engagement_id)
        if summary.engagement_id == engagement_id
        and summary.id != scan_id
        and summary.started_at < result.started_at
        and summary.kind == "port_scan"
    ][:limit]

    previous = []

    for summary in reversed(summaries):          # oldest first
        loaded = load_scan(connection, summary.id)

        if loaded is None:
            continue

        analysed = analyze(loaded)
        previous.append(ScanFindings(
            scan_id=summary.id,
            result=loaded,
            report=analysed,
            by_fingerprint={
                item.fingerprint: item for item in analysed.findings + analysed.accepted
            },
        ))

    baseline_id = get_baseline_id(connection, engagement_id)
    baseline = next((item for item in previous if item.scan_id == baseline_id), None)

    return apply_history(report, result, previous, baseline, acceptances)
