from datetime import date, timedelta

import pytest

from argus.modules.classify import classify_result
from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo, OSGuess, PortInfo, RoleMatch, ScanResult
from argus.modules.risk import (
    Acceptance,
    RiskRulesError,
    analyze,
    default_risk_rules,
    host_risk,
    make_fingerprint,
    parse_risk_rules,
    score_band,
    score_finding,
)


ALL_TCP = set(range(1, 65536))


def network(*hosts, targets=("192.168.1.0/24",), tcp=ALL_TCP, udp=None, profile="Full TCP"):
    coverage = {"tcp": set(tcp)} if tcp else {}

    if udp:
        coverage["udp"] = set(udp)

    result = ScanResult(
        targets=list(targets),
        profile=profile,
        evidence=ScanEvidence(coverage=coverage),
    )

    for item in hosts:
        result.add_host(item)

    return classify_result(result)


def host(ip, *ports, **details):
    item = HostInfo(ip=ip, **details)

    for port in ports:
        item.add_port(port if isinstance(port, PortInfo) else PortInfo(port))

    return item


def rules_of(report):
    return [(finding.rule, finding.host_ip or finding.subnet) for finding in report.findings]


def find(report, rule, ip=None):
    return next(
        finding for finding in report.findings + report.accepted
        if finding.rule == rule and (ip is None or finding.host_ip == ip)
    )


# ---------- the packaged rules ----------

def test_packaged_rules_load_and_reference_real_roles():
    from argus.modules.classify import default_rules

    rules = default_risk_rules()
    roles = {role.key for role in default_rules().roles}

    assert len(rules.rules) >= 30

    for rule in rules.rules:
        for name in ("role_any", "role_none"):
            assert set(rule.when.get(name, ())) <= roles, (rule.key, name)

        for step in rule.raises:
            if step.condition == "role_any":
                assert set(step.value) <= roles, rule.key


# ---------- host findings ----------

def test_telnet_on_a_camera_is_raised_to_critical():
    report = analyze(network(host("192.168.1.30", 23, 554, vendor="Hikvision")))
    telnet = find(report, "telnet_open")

    assert telnet.base_severity == "high"
    assert telnet.severity == "critical"
    assert telnet.escalations == ["high -> critical: this kind of device is a frequent botnet and takeover target"]
    assert telnet.evidence == ["port 23/tcp open"]
    assert telnet.ports == [("tcp", 23)]


def test_role_conditions_use_believable_roles_only():
    # An unknown host with port 80 is not a "device management page".
    report = analyze(network(host("192.168.1.50", 80)))

    assert "management_over_http" not in [rule for rule, _ in rules_of(report)]


def test_public_address_raises_and_scores_higher():
    public = analyze(network(host("8.8.4.4", 3389), targets=["8.8.4.4"]))
    private = analyze(network(host("192.168.1.9", 3389)))

    rdp_public, rdp_private = find(public, "rdp_open"), find(private, "rdp_open")

    assert rdp_public.severity == "critical"
    assert rdp_public.public
    assert "x 1.3 public address" in rdp_public.score_factors
    assert rdp_public.score > rdp_private.score


def test_version_rules_use_banners_and_say_so():
    report = analyze(network(host(
        "192.168.1.40",
        PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "6.6.1p1"),
        PortInfo(21, "tcp", "open", "ftp", "vsftpd", "2.3.4"),
    )))

    ssh = find(report, "ssh_outdated")
    backdoor = find(report, "vsftpd_backdoor")

    assert ssh.confidence == "low"
    assert "banner reports OpenSSH 6.6.1p1 on 22/tcp" in ssh.evidence[0]
    assert backdoor.severity == "critical"


def test_current_versions_are_not_flagged():
    report = analyze(network(host("192.168.1.40", PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "9.6p1"))))

    assert "ssh_outdated" not in [rule for rule, _ in rules_of(report)]


def test_mariadb_is_not_mistaken_for_old_mysql():
    report = analyze(network(host(
        "192.168.1.41", PortInfo(3306, "tcp", "open", "mysql", "MySQL", "5.5.5-10.6.12-MariaDB"),
    )))

    assert "mysql_eol" not in [rule for rule, _ in rules_of(report)]
    assert "database_exposed" in [rule for rule, _ in rules_of(report)]


def test_os_estimate_rules():
    report = analyze(network(host("192.168.1.60", 445, os_guess=OSGuess("Microsoft Windows 7 SP1", 94))))

    eol = find(report, "windows_eol")
    assert eol.evidence == ["OS estimate 'Microsoft Windows 7 SP1' (94% match)"]


def test_udp_rules_need_udp_coverage_to_matter():
    item = host("192.168.1.1", vendor="Cisco Systems")
    item.add_port(PortInfo(161, "udp"))
    report = analyze(network(item, udp={161}))

    snmp = find(report, "snmp_open")
    assert snmp.severity == "high"   # raised: router


def test_many_remote_access_and_unidentified_devices():
    report = analyze(network(
        host("192.168.1.70", 22, 23, 3389, 5900),
        host("192.168.1.71", 7777, 31337),
    ))

    many = find(report, "many_remote_access")
    assert many.evidence == ["SSH on 22/tcp", "Telnet on 23/tcp", "RDP on 3389/tcp", "VNC on 5900/tcp"]
    assert find(report, "unidentified_device", "192.168.1.71").severity == "low"


def test_quiet_hosts_have_no_findings():
    report = analyze(network(host("192.168.1.80"), host("192.168.1.81", 443)))

    assert report.findings == []
    assert report.grade == "A"


# ---------- network findings and attack paths ----------

def office():
    return network(
        host("192.168.1.1", 80, vendor="MikroTik", os_guess=OSGuess("MikroTik RouterOS 7", 95)),
        host("192.168.1.5", 53, 88, 389, 445, 3268),           # domain controller
        host("192.168.1.30", 23, 554, vendor="Hikvision"),      # camera with Telnet
        host("192.168.1.40", 5432),                             # database server
    )


def test_flat_network_is_found():
    report = analyze(office())
    flat = find(report, "flat_network")

    assert flat.scope == "network"
    assert flat.subnet == "192.168.1.0/24"
    assert "192.168.1.5" in flat.evidence[0] and "192.168.1.40" in flat.evidence[0]
    assert "192.168.1.30" in flat.evidence[1]
    assert "192.168.1.1" not in flat.evidence[1]   # critical hosts are never "weak"


def test_attack_paths_start_from_weak_devices():
    report = analyze(office())

    starts = {path.entry_ip for path in report.attack_paths}
    targets = {path.target_ip for path in report.attack_paths}

    assert starts == {"192.168.1.30"}
    assert {"192.168.1.5", "192.168.1.40"} <= targets
    assert all(path.basis == "same subnet (inferred)" for path in report.attack_paths)
    assert report.attack_paths[0].entry_reasons[0].startswith("Telnet is open")


def test_separate_subnets_are_not_flat():
    report = analyze(network(
        host("10.0.1.5", 88, 389),
        host("10.0.2.30", 23, vendor="Hikvision"),
        targets=["10.0.1.0/24", "10.0.2.0/24"],
    ))

    assert "flat_network" not in [rule for rule, _ in rules_of(report)]
    assert report.attack_paths == []


def test_management_on_general_network():
    bmc = host("192.168.1.90", 443, 623)
    bmc.roles = []
    result = network(bmc, host("192.168.1.20", 3389, 445, os_guess=OSGuess("Microsoft Windows 11", 95)))
    result.get_host("192.168.1.90").roles = [
        RoleMatch("management_controller", "Server management controller", "high", 80)
    ]
    result.get_host("192.168.1.90").criticality = "high"

    report = analyze(result)

    assert "management_not_separated" in [rule for rule, _ in rules_of(report)]


# ---------- scoring, grade, plan ----------

def test_score_is_explained_factor_by_factor():
    report = analyze(network(host("192.168.1.40", 5432)))
    db = find(report, "database_exposed")

    # medium 5 x 1.25 (database server is high criticality) x 0.85 (medium confidence)
    assert db.score == 5.3
    assert db.score_factors == [
        "medium severity: 5",
        "x 1.25 asset criticality high",
        "x 0.85 medium confidence",
    ]


def test_persistence_adds_to_the_score():
    report = analyze(network(host("192.168.1.30", 23)))
    telnet = find(report, "telnet_open")
    before = telnet.score

    telnet.streak = 3
    score_finding(telnet)

    assert telnet.score == round(before + 0.5, 1)
    assert telnet.score_factors[-1] == "+ 0.5 still open after 3 scans"


def test_scores_are_capped_at_ten():
    report = analyze(network(host("8.8.4.4", 2375), targets=["8.8.4.4"]))
    docker = find(report, "docker_api_open")

    assert docker.score == 10.0
    assert docker.score_factors[-1] == "-> capped at 10"


@pytest.mark.parametrize("score, band", [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (1.0, "low"), (0.5, "info")])
def test_score_bands(score, band):
    assert score_band(score) == band


def test_host_risk_combines_findings():
    assert host_risk([]) == 0.0

    class F:
        def __init__(self, score):
            self.score = score

    assert host_risk([F(8.0), F(4.0), F(2.0)]) == 8.9


def test_grade_and_fix_plan():
    report = analyze(office())

    assert report.grade == "D"
    assert report.plan[0].rule == "telnet_open"
    assert report.plan[0].risk_removed == find(report, "telnet_open").score
    assert report.total_risk == round(sum(item.score for item in report.findings), 1)
    assert list(report.host_scores)[0] == "192.168.1.30"


def test_findings_are_sorted_worst_first():
    report = analyze(office())
    scores = [finding.score for finding in report.findings]

    assert scores == sorted(scores, reverse=True)


# ---------- accepted risks ----------

def test_accepted_risks_leave_the_grade_but_stay_listed():
    result = network(host("192.168.1.30", 23, vendor="Hikvision"))
    fingerprint = find(analyze(result), "telnet_open").fingerprint

    report = analyze(result, acceptances={
        fingerprint: Acceptance(1, fingerprint, "isolated lab device", expires_on=date.today() + timedelta(days=30)),
    })

    assert "telnet_open" not in [finding.rule for finding in report.findings]
    assert [finding.rule for finding in report.accepted] == ["telnet_open"]
    assert report.accepted[0].acceptance.reason == "isolated lab device"


def test_expired_acceptance_counts_again_with_a_note():
    result = network(host("192.168.1.30", 23, vendor="Hikvision"))
    fingerprint = find(analyze(result), "telnet_open").fingerprint

    report = analyze(result, acceptances={
        fingerprint: Acceptance(1, fingerprint, "temporary", expires_on=date.today() - timedelta(days=1)),
    })

    assert "telnet_open" in [finding.rule for finding in report.findings]
    assert report.accepted == []
    assert any(note.startswith("Accepted risk expired") for note in report.notes)


def test_fingerprints_follow_the_device_not_the_address():
    with_mac = host("192.168.1.30", 23, mac="aa:bb:cc:dd:ee:ff")
    moved = host("192.168.1.99", 23, mac="AA:BB:CC:DD:EE:FF")

    first = analyze(network(with_mac)).findings[0].fingerprint
    second = analyze(network(moved)).findings[0].fingerprint

    assert first == second == make_fingerprint("telnet_open", "mac:AA:BB:CC:DD:EE:FF")


# ---------- honesty about what was not checked ----------

def test_notes_say_what_could_not_be_checked():
    report = analyze(network(host("192.168.1.30", 23), tcp=None, profile="discovery"))

    assert any("did not check TCP ports" in note for note in report.notes)
    assert any("No software versions" in note for note in report.notes)
    assert any("UDP ports were not scanned" in note for note in report.notes)


# ---------- checking a rules file ----------

def rule_with(**changes):
    rule = {
        "key": "thing", "title": "Thing", "category": "cleartext", "severity": "high",
        "confidence": "high", "why": "Because.", "fix": "Fix it.",
        "when": {"tcp_any": [23]},
    }
    rule.update(changes)
    return {"version": 1, "rule": [rule]}


@pytest.mark.parametrize("data, message", [
    ({"rule": []}, "version"),
    ({"version": 1}, "no \\[\\[rule\\]\\]"),
    (rule_with(key="Bad"), "Invalid rule key"),
    (rule_with(category="weird"), "category"),
    (rule_with(severity="extreme"), "severity"),
    (rule_with(confidence="sure"), "confidence"),
    (rule_with(why=""), "needs 'why'"),
    (rule_with(colour=1), "unknown setting"),
    (rule_with(when={}), "needs a \\[rule.when\\]"),
    (rule_with(when={"role_any": ["camera"]}), "at least one of"),
    (rule_with(when={"tcp_any": [0]}), "port numbers"),
    (rule_with(when={"tcp_any": [23], "typo": 1}), "unknown condition"),
    (rule_with(when={"version_below": {"product": "OpenSSH"}}), "version_below needs"),
    (rule_with(**{"raise": [{"to": "critical", "note": "x"}]}), "exactly one condition"),
    (rule_with(**{"raise": [{"public": True, "to": "worse", "note": "x"}]}), "raise 'to'"),
    (rule_with(**{"raise": [{"public": True, "to": "critical"}]}), "needs a 'note'"),
    (rule_with(**{"raise": [{"criticality": "huge", "to": "critical", "note": "x"}]}), "criticality"),
])
def test_rule_mistakes_are_reported(data, message):
    with pytest.raises(RiskRulesError, match=message):
        parse_risk_rules(data)
