"""The report model: everything a report says, built once, as plain data.

Every output format (JSON, CSV, HTML, PDF) is written from this one model,
so they can never disagree. The model is plain dictionaries and lists, so
it is also exactly what the JSON report contains.

Nothing in here runs a scan. It gathers what the scan, the classifier, the
network map and the risk engine already found, and adds the context a
reader needs: who authorized the work, what was in scope, what was and was
not checked, and what changed since last time.
"""

import ipaddress
from datetime import date, datetime

from argus import __version__
from argus.modules.risk import CATEGORY_LABELS, SEVERITIES


SCHEMA_ID = "argus-report/1"

LIMITATIONS = [
    "ARGUS reports what responded during this scan. A host or port that is "
    "missing may be offline, filtered or out of range, so absence is not proof.",
    "Findings describe exposure seen from the scanning computer. They are not "
    "confirmed vulnerabilities, and ARGUS did not try to exploit anything.",
    "Software versions come from service banners, which can be wrong, hidden, "
    "or patched by the vendor without a version change.",
    "Device roles and operating systems are estimates worked out from evidence.",
    "Attack paths are possible, not proven: ARGUS cannot see firewalls between "
    "hosts on the same subnet.",
    "Network links not seen by traceroute are inferred from addresses and may "
    "not match the real wiring.",
]


def _iso(value) -> str | None:
    if value is None:
        return None

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    return str(value)


# ---------- pieces ----------

def _host_data(host, risk_score: float | None) -> dict:
    return {
        "ip": host.ip,
        "hostname": host.hostname,
        "mac": host.mac,
        "vendor": host.vendor,
        "state": host.state,
        "responded_via": host.discovery_method,
        "os": (
            {"name": host.os_guess.name, "accuracy": host.os_guess.accuracy}
            if host.os_guess else None
        ),
        "roles": [
            {
                "role": match.role,
                "label": match.label,
                "confidence": match.confidence,
                "score": match.score,
                "evidence": list(match.reasons),
            }
            for match in host.roles
        ],
        "criticality": host.criticality,
        "criticality_reason": host.criticality_reason,
        "risk_score": risk_score,
        "ports": [
            {
                "port": port.port,
                "protocol": port.protocol,
                "state": port.state,
                "service": port.service,
                "product": port.product,
                "version": port.version,
                "extra_info": port.extra_info,
            }
            for port in sorted(host.ports, key=lambda item: (item.protocol, item.port))
        ],
        "trace": [
            {"ttl": hop.ttl, "ip": hop.ip, "rtt_ms": hop.rtt_ms, "hostname": hop.hostname}
            for hop in host.trace
        ],
    }


def _finding_data(finding, number: int | None = None) -> dict:
    data = {
        "number": number,
        "id": finding.fingerprint,
        "rule": finding.rule,
        "title": finding.title,
        "category": finding.category,
        "category_label": CATEGORY_LABELS.get(finding.category, finding.category),
        "severity": finding.severity,
        "base_severity": finding.base_severity,
        "priority": finding.band,
        "score": finding.score,
        "score_factors": list(finding.score_factors),
        "confidence": finding.confidence,
        "scope": finding.scope,
        "host": finding.host_ip,
        "host_label": finding.host_label,
        "subnet": finding.subnet,
        "where": finding.where,
        "ports": [{"port": port, "protocol": protocol} for protocol, port in finding.ports],
        "evidence": list(finding.evidence),
        "raised_because": list(finding.escalations),
        "why": finding.why,
        "fix": finding.fix,
        "references": list(finding.references),
        "related_hosts": list(finding.related_hosts),
        "history": {
            "first_seen_scan": finding.first_seen_scan,
            "first_seen_at": _iso(finding.first_seen_at),
            "seen_in_scans": finding.seen_in_scans,
            "streak": finding.streak,
            "new_since_baseline": finding.new_since_baseline,
        },
    }

    if finding.acceptance is not None:
        data["acceptance"] = {
            "reason": finding.acceptance.reason,
            "accepted_by": finding.acceptance.accepted_by,
            "expires_on": _iso(finding.acceptance.expires_on),
            "active": finding.acceptance.active(),
        }

    return data


def _network_data(network_map) -> dict:
    return {
        "subnets": [
            {
                "network": group.network,
                "size_assumed": group.assumed,
                "hosts": list(group.host_ips),
                "gateway": group.gateway_ip,
                "gateway_basis": group.gateway_basis,
                "gateway_reason": group.gateway_reason,
            }
            for group in network_map.subnets
        ],
        "nodes": [
            {
                "id": node.id,
                "kind": node.kind,
                "label": node.label,
                "ip": node.ip,
                "subnet": node.subnet,
                "role": node.role,
                "role_label": node.role_label,
                "confidence": node.confidence,
                "criticality": node.criticality,
            }
            for node in network_map.nodes.values()
        ],
        "links": [
            {"source": link.source, "target": link.target, "kind": link.kind, "reason": link.reason}
            for link in network_map.links
        ],
        "traced_paths": {ip: list(path) for ip, path in network_map.paths.items()},
        "notes": list(network_map.notes),
    }


def _engagement_data(engagement, result) -> dict | None:
    if engagement is None:
        return None

    networks = []

    for item in engagement.scope or []:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue

    outside = sorted(
        (
            host.ip for host in result.up_hosts
            if networks and not any(ipaddress.ip_address(host.ip) in network for network in networks)
        ),
        key=ipaddress.ip_address,
    )

    scan_day = result.started_at.date()
    within_dates = None

    if engagement.starts_on or engagement.ends_on:
        within_dates = (
            (engagement.starts_on is None or scan_day >= engagement.starts_on)
            and (engagement.ends_on is None or scan_day <= engagement.ends_on)
        )

    return {
        "name": engagement.name,
        "authorized_by": engagement.authorized_by,
        "scope": list(engagement.scope or []),
        "starts_on": _iso(engagement.starts_on),
        "ends_on": _iso(engagement.ends_on),
        "notes": engagement.notes,
        "hosts_outside_scope": outside,
        "scan_within_dates": within_dates,
    }


def _headline(result, risk, changes) -> str:
    """A short executive summary in plain words."""
    hosts = len(result.up_hosts)
    ports = result.total_open_ports
    parts = [
        f"ARGUS checked {', '.join(result.targets)} on "
        f"{result.started_at.strftime('%d %B %Y')} and found {hosts} responding "
        f"host{'s' if hosts != 1 else ''} with {ports} open port{'s' if ports != 1 else ''}."
    ]

    if risk.findings:
        parts.append(f"The network's risk grade is {risk.grade} ({risk.grade_reason}).")
        first = risk.plan[0]
        where = ", ".join(first.hosts[:3]) + (f" and {len(first.hosts) - 3} more" if len(first.hosts) > 3 else "")
        action = first.fix.split(". ")[0].rstrip(".")
        parts.append(
            f"The most urgent issue is \"{first.title}\" ({where}); "
            f"fixing it removes the most risk: {action[0].lower() + action[1:]}."
        )
    else:
        parts.append("There are no open risk findings in what this scan could see.")

    if changes is not None:
        parts.append(
            f"Since scan #{changes['compared_with']}, {len(changes['resolved'])} "
            f"finding{'s were' if len(changes['resolved']) != 1 else ' was'} resolved and "
            f"{len(changes['new'])} {'are' if len(changes['new']) != 1 else 'is'} new."
        )

    if risk.accepted:
        parts.append(
            f"{len(risk.accepted)} known risk{'s are' if len(risk.accepted) != 1 else ' is'} "
            "accepted and left out of the grade."
        )

    return " ".join(parts)


# ---------- the whole report ----------

def build_report_data(
    result,
    risk,
    network_map,
    *,
    scan_id: int | None = None,
    engagement=None,
    previous=None,
    previous_id: int | None = None,
    risk_changes=None,
    scan_comparison=None,
    generated_at: datetime | None = None,
) -> dict:
    """Assemble the full report as plain data.

    `previous`/`scan_comparison`/`risk_changes` describe the scan this one is
    compared with (the previous scan of the same engagement), when there is one.
    """
    generated_at = generated_at or datetime.now().astimezone()
    incomplete = any("stopped before it finished" in warning for warning in result.warnings)

    changes = None

    if previous is not None and risk_changes is not None:
        changes = {
            "compared_with": previous_id,
            "compared_with_started_at": _iso(previous.started_at),
            "new": [_finding_data(item) for item in risk_changes.new],
            "resolved": [_finding_data(item) for item in risk_changes.resolved],
            "not_rechecked": [_finding_data(item) for item in risk_changes.not_rechecked],
            "scan_changes": [
                {
                    "kind": event.kind,
                    "label": event.label,
                    "host": event.ip,
                    "summary": event.summary,
                    "confirmed": event.confirmed,
                }
                for event in (scan_comparison.events if scan_comparison else [])
            ],
            "comparison_notes": list(scan_comparison.notes) if scan_comparison else [],
        }

    bands = {band: risk.count(band) for band in SEVERITIES}

    return {
        "schema": SCHEMA_ID,
        "generated_at": _iso(generated_at),
        "argus_version": __version__,
        "redacted": False,
        "rules": {
            "asset_rules_version": result.classifier_version,
            "risk_rules_version": risk.rules_version,
        },
        "scan": {
            "id": scan_id,
            "profile": result.profile,
            "targets": list(result.targets),
            "started_at": _iso(result.started_at),
            "finished_at": _iso(result.finished_at),
            "duration_seconds": result.duration_seconds,
            "nmap_version": result.nmap_version,
            "incomplete": incomplete,
            "coverage": {
                protocol: len(ports)
                for protocol, ports in sorted(result.evidence.coverage.items())
            },
            "warnings": list(result.warnings),
        },
        "engagement": _engagement_data(engagement, result),
        "summary": {
            "headline": _headline(result, risk, changes),
            "grade": risk.grade,
            "grade_reason": risk.grade_reason,
            "hosts_up": len(result.up_hosts),
            "open_ports": result.total_open_ports,
            "findings": len(risk.findings),
            "findings_by_priority": bands,
            "total_risk": risk.total_risk,
            "accepted_risks": len(risk.accepted),
            "hosts_with_findings": len(risk.host_scores),
        },
        "fix_plan": [
            {
                "rank": rank,
                "rule": action.rule,
                "title": action.title,
                "fix": action.fix,
                "findings": action.findings,
                "where": list(action.hosts),
                "risk_removed": action.risk_removed,
                "worst_severity": action.worst,
            }
            for rank, action in enumerate(risk.plan, start=1)
        ],
        "findings": [
            _finding_data(finding, number)
            for number, finding in enumerate(risk.findings, start=1)
        ],
        "accepted_risks": [_finding_data(finding) for finding in risk.accepted],
        "attack_paths": [
            {
                "from": path.entry_ip,
                "from_label": path.entry_label,
                "why_weak": list(path.entry_reasons),
                "to": path.target_ip,
                "to_label": path.target_label,
                "subnet": path.subnet,
                "basis": path.basis,
            }
            for path in risk.attack_paths
        ],
        "hosts": [
            _host_data(host, risk.host_scores.get(host.ip))
            for host in result.up_hosts
        ],
        "network": _network_data(network_map),
        "changes": changes,
        "analysis_notes": list(risk.notes),
        "limitations": list(LIMITATIONS),
    }
