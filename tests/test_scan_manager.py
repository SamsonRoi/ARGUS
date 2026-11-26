import pytest

from argus.modules import scan_manager
from argus.modules.models import HostInfo, OSGuess, PortInfo, ScanResult
from argus.modules.nmap_runner import (
    InvalidScanRequestError,
    NmapNotFoundError,
    ScanFailedError,
    ScanInterruptedError,
    find_nmap,
)
from argus.modules.scan_manager import (
    CANCELLED_WARNING,
    PORT_SCAN_REASON,
    RANGE_WARNING,
    ScanOptions,
    merge_host,
    run_scan_pipeline,
)


# ---------- helpers ----------

def host(ip, *ports, **details):
    item = HostInfo(ip=ip, **details)

    for port in ports:
        item.add_port(port)

    return item


def patch_stages(
    monkeypatch,
    *,
    discovery=(),
    discovery_warnings=(),
    tcp=(),
    udp=(),
    services=(),
    os_hosts=(),
    traces=(),
):
    """Replace every scanning stage with a fake. Returns a dict of what was called."""
    calls = {}

    def stage(name, outcome):
        def run(*args, **kwargs):
            calls[name] = args

            if isinstance(outcome, BaseException):
                raise outcome

            return list(outcome)

        return run

    def fake_discover(
        targets, methods=None, timeout=600, privileged=None, evidence=None
    ):
        calls["discovery"] = (targets,)

        if isinstance(discovery, BaseException):
            raise discovery

        result = ScanResult(
            targets=list(targets),
            profile="discovery",
            warnings=list(discovery_warnings),
        )

        for item in discovery:
            result.add_host(item)

        return result

    monkeypatch.setattr(scan_manager, "get_nmap_version", lambda: "7.99")
    monkeypatch.setattr(scan_manager, "discover_hosts", fake_discover)
    monkeypatch.setattr(scan_manager, "scan_tcp_ports", stage("tcp", tcp))
    monkeypatch.setattr(scan_manager, "scan_udp_ports", stage("udp", udp))
    monkeypatch.setattr(scan_manager, "detect_services", stage("services", services))
    monkeypatch.setattr(scan_manager, "estimate_os", stage("os", os_hosts))
    monkeypatch.setattr(scan_manager, "trace_routes", stage("trace", traces))

    return calls


def run(targets, options=None, **kwargs):
    return run_scan_pipeline(targets, options or ScanOptions(), privileged=True, **kwargs)


# ---------- ScanOptions ----------

def test_default_options():
    options = ScanOptions()

    assert options.profile_key == "standard"
    assert options.ports is None
    assert options.stage_count == 2
    assert options.describe() == "Standard TCP"


def test_options_with_everything_on():
    options = ScanOptions(
        profile_key="quick",
        service_detection=True,
        udp_scan=True,
        os_estimation=True,
    )

    assert options.stage_count == 5
    assert options.describe() == "Quick TCP + UDP ports + service detection + OS estimation"


def test_custom_ports_are_cleaned_and_described():
    options = ScanOptions(ports="80, 443")

    assert options.ports == "80,443"
    assert options.describe() == "Custom TCP ports (80,443)"


def test_bad_options_are_rejected():
    with pytest.raises(InvalidScanRequestError):
        ScanOptions(profile_key="reckless")

    with pytest.raises(InvalidScanRequestError):
        ScanOptions(ports="80;ls")


# ---------- merge_host ----------

def test_merge_fills_gaps_without_erasing():
    result = ScanResult(targets=["10.0.0.1"], profile="x")
    result.add_host(host("10.0.0.1", hostname="router", discovery_method="ARP reply"))

    merge_host(result, host("10.0.0.1", hostname="other", mac="AA:BB", vendor="Acme"))

    merged = result.get_host("10.0.0.1")

    assert merged.hostname == "router"
    assert merged.mac == "AA:BB"
    assert merged.vendor == "Acme"
    assert merged.discovery_method == "ARP reply"


def test_merge_refines_port_details():
    result = ScanResult(targets=["10.0.0.1"], profile="x")
    result.add_host(host("10.0.0.1", PortInfo(port=22, service="ssh")))

    merge_host(
        result,
        host("10.0.0.1", PortInfo(port=22, service="ssh", product="OpenSSH", version="8.9")),
    )

    port = result.get_host("10.0.0.1").ports[0]

    assert len(result.get_host("10.0.0.1").ports) == 1
    assert port.version_text == "OpenSSH 8.9"
    assert port.state == "open"


def test_merge_keeps_tcp_and_udp_ports_separate():
    result = ScanResult(targets=["10.0.0.1"], profile="x")
    result.add_host(host("10.0.0.1", PortInfo(port=53, protocol="tcp")))

    merge_host(result, host("10.0.0.1", PortInfo(port=53, protocol="udp", state="open|filtered")))

    assert len(result.get_host("10.0.0.1").ports) == 2


def test_merge_can_refuse_to_add_unknown_hosts():
    result = ScanResult(targets=["10.0.0.1"], profile="x")

    merge_host(result, host("10.0.0.9"), add_if_missing=False)

    assert result.hosts == []


def test_merge_can_ignore_ports():
    result = ScanResult(targets=["10.0.0.1"], profile="x")
    result.add_host(host("10.0.0.1"))

    merge_host(
        result,
        host("10.0.0.1", PortInfo(port=80), os_guess=OSGuess(name="Linux", accuracy=90)),
        include_ports=False,
    )

    merged = result.get_host("10.0.0.1")

    assert merged.ports == []
    assert merged.os_guess.name == "Linux"


def test_merge_marks_host_up():
    result = ScanResult(targets=["10.0.0.1"], profile="x")
    result.add_host(host("10.0.0.1", state="unknown"))

    merge_host(result, host("10.0.0.1", state="up"))

    assert result.get_host("10.0.0.1").state == "up"


# ---------- the pipeline ----------

def test_pipeline_merges_every_stage(monkeypatch):
    patch_stages(
        monkeypatch,
        discovery=[host("192.168.1.10", hostname="nas.lan", discovery_method="ARP reply")],
        tcp=[host("192.168.1.10", PortInfo(port=22, service="ssh"), PortInfo(port=80, service="http"))],
        udp=[host("192.168.1.10", PortInfo(port=161, protocol="udp", state="open|filtered"))],
        services=[host("192.168.1.10", PortInfo(port=22, service="ssh", product="OpenSSH", version="8.9"))],
        os_hosts=[host("192.168.1.10", os_guess=OSGuess(name="Linux 5.4", accuracy=96))],
    )
    options = ScanOptions(service_detection=True, udp_scan=True, os_estimation=True)

    result = run(["192.168.1.0/24"], options)

    merged = result.get_host("192.168.1.10")

    assert result.profile == "Standard TCP + UDP ports + service detection + OS estimation"
    assert result.nmap_version == "7.99"
    assert result.finished_at is not None
    assert merged.hostname == "nas.lan"
    assert [port.port for port in merged.open_ports] == [22, 80]
    assert any(port.protocol == "udp" and port.state == "open|filtered" for port in merged.ports)
    assert merged.open_ports[0].version_text == "OpenSSH 8.9"
    assert merged.os_guess.name == "Linux 5.4"
    assert result.total_open_ports == 2


def test_typed_ip_is_scanned_even_if_it_ignores_discovery(monkeypatch):
    calls = patch_stages(
        monkeypatch,
        discovery=[],
        tcp=[host("10.0.0.5", PortInfo(port=443))],
    )

    result = run(["10.0.0.5"])

    assert calls["tcp"][0] == ["10.0.0.5"]
    assert result.get_host("10.0.0.5").discovery_method == PORT_SCAN_REASON
    assert RANGE_WARNING not in result.warnings


def test_range_only_scans_hosts_that_answered(monkeypatch):
    calls = patch_stages(
        monkeypatch,
        discovery=[host("10.0.0.2"), host("10.0.0.7")],
        tcp=[host("10.0.0.7", PortInfo(port=80))],
    )

    result = run(["10.0.0.0/24"])

    assert calls["tcp"][0] == ["10.0.0.2", "10.0.0.7"]
    assert RANGE_WARNING in result.warnings


def test_range_with_no_answers_stops_early(monkeypatch):
    calls = patch_stages(monkeypatch, discovery=[])

    result = run(["10.0.0.0/24"])

    assert "tcp" not in calls
    assert result.hosts == []
    assert result.finished_at is not None


def test_typed_ip_inside_range_is_scanned_once(monkeypatch):
    calls = patch_stages(monkeypatch, discovery=[host("10.0.0.5")])

    run(["10.0.0.0/24", "10.0.0.5"])

    assert calls["tcp"][0] == ["10.0.0.5"]


def test_failed_stage_becomes_a_warning_and_scan_continues(monkeypatch):
    calls = patch_stages(
        monkeypatch,
        discovery=[host("10.0.0.5")],
        tcp=[host("10.0.0.5", PortInfo(port=80))],
        udp=ScanFailedError("This scan needs higher privileges."),
        services=[host("10.0.0.5", PortInfo(port=80, product="nginx"))],
    )

    result = run(["10.0.0.5"], ScanOptions(udp_scan=True, service_detection=True))

    assert any("UDP port scan failed" in warning for warning in result.warnings)
    assert "services" in calls
    assert result.get_host("10.0.0.5").open_ports[0].product == "nginx"


def test_missing_nmap_is_fatal(monkeypatch):
    patch_stages(monkeypatch)

    def no_nmap():
        raise NmapNotFoundError("Nmap was not found.")

    monkeypatch.setattr(scan_manager, "get_nmap_version", no_nmap)

    with pytest.raises(NmapNotFoundError):
        run(["10.0.0.5"])


def test_bad_targets_are_rejected_before_anything_runs(monkeypatch):
    calls = patch_stages(monkeypatch)

    with pytest.raises(InvalidScanRequestError):
        run(["--version"])

    assert calls == {}


def test_ctrl_c_returns_partial_results(monkeypatch):
    calls = patch_stages(
        monkeypatch,
        discovery=[host("10.0.0.5", hostname="box")],
        tcp=KeyboardInterrupt(),
    )

    result = run(["10.0.0.5"], ScanOptions(udp_scan=True))

    assert CANCELLED_WARNING in result.warnings
    assert result.get_host("10.0.0.5").hostname == "box"
    assert result.finished_at is not None
    assert "udp" not in calls


def test_interrupted_nmap_stops_the_scan_too(monkeypatch):
    calls = patch_stages(
        monkeypatch,
        discovery=[host("10.0.0.5")],
        tcp=ScanInterruptedError("Nmap stopped."),
    )

    result = run(["10.0.0.5"], ScanOptions(udp_scan=True))

    assert CANCELLED_WARNING in result.warnings
    assert "udp" not in calls


def test_os_stage_never_adds_hosts_or_ports(monkeypatch):
    patch_stages(
        monkeypatch,
        discovery=[host("10.0.0.5")],
        os_hosts=[
            host("10.0.0.5", PortInfo(port=1, state="closed"), os_guess=OSGuess(name="Linux", accuracy=90)),
            host("10.0.0.99", os_guess=OSGuess(name="Windows", accuracy=80)),
        ],
    )

    result = run(["10.0.0.5"], ScanOptions(os_estimation=True))

    assert [item.ip for item in result.hosts] == ["10.0.0.5"]
    assert result.get_host("10.0.0.5").ports == []
    assert result.get_host("10.0.0.5").os_guess.name == "Linux"


def test_os_stage_warns_about_the_local_machine(monkeypatch):
    patch_stages(monkeypatch, discovery=[host("127.0.0.1")])

    result = run(["127.0.0.1"], ScanOptions(os_estimation=True))

    assert any("OS estimation was skipped for 127.0.0.1" in w for w in result.warnings)


def test_hosts_are_sorted_by_address(monkeypatch):
    patch_stages(
        monkeypatch,
        discovery=[host("10.0.0.10"), host("10.0.0.2"), host("10.0.0.1")],
    )

    result = run(["10.0.0.0/24"])

    assert [item.ip for item in result.hosts] == ["10.0.0.1", "10.0.0.2", "10.0.0.10"]


def test_progress_is_reported_for_each_stage(monkeypatch):
    patch_stages(monkeypatch, discovery=[host("10.0.0.5")])
    steps = []

    run(
        ["10.0.0.5"],
        ScanOptions(udp_scan=True, service_detection=True),
        progress=lambda step, total, label: steps.append((step, total, label)),
    )

    assert [(step, total) for step, total, _ in steps] == [(1, 4), (2, 4), (3, 4), (4, 4)]
    assert steps[0][2] == "Discovering hosts"
    assert "Standard TCP" in steps[1][2]


def test_privilege_warnings_from_discovery_are_kept(monkeypatch):
    patch_stages(
        monkeypatch,
        discovery=[host("10.0.0.5")],
        discovery_warnings=["ARP was skipped."],
    )

    result = run(["10.0.0.5"])

    assert "ARP was skipped." in result.warnings


# ---------- one real scan of your own machine ----------

@pytest.mark.skipif(find_nmap() is None, reason="Nmap is not installed")
def test_real_pipeline_on_localhost(ssh_banner_port):
    options = ScanOptions(ports=str(ssh_banner_port), service_detection=True)

    result = run_scan_pipeline(["127.0.0.1"], options)

    local = result.get_host("127.0.0.1")
    port = local.open_ports[0]

    assert port.port == ssh_banner_port
    assert port.service == "ssh"
    assert port.product == "OpenSSH"
    assert result.finished_at is not None
    assert result.nmap_version

# ---------- traceroute and classification ----------

def test_traceroute_option_adds_a_stage():
    options = ScanOptions(profile_key="quick", traceroute=True)

    assert options.stage_count == 3
    assert options.describe() == "Quick TCP + traceroute"


def test_traceroute_attaches_paths_to_known_hosts_only(monkeypatch):
    from argus.modules.models import TraceHop

    path = [TraceHop(1, "10.0.0.1"), TraceHop(2, "10.0.0.5")]
    calls = patch_stages(
        monkeypatch,
        tcp=[host("10.0.0.5", PortInfo(22))],
        traces=[HostInfo("10.0.0.5", trace=path), HostInfo("10.9.9.9", trace=path)],
    )

    result = run(["10.0.0.5"], ScanOptions(traceroute=True))

    assert "trace" in calls
    assert result.get_host("10.0.0.5").trace == path
    assert result.get_host("10.9.9.9") is None


def test_traceroute_is_skipped_without_privileges(monkeypatch):
    calls = patch_stages(monkeypatch, tcp=[host("10.0.0.5", PortInfo(22))])

    result = run_scan_pipeline(
        ["10.0.0.5"], ScanOptions(traceroute=True), privileged=False
    )

    assert "trace" not in calls
    assert scan_manager.TRACEROUTE_SKIPPED in result.warnings


def test_traceroute_failure_is_a_warning(monkeypatch):
    patch_stages(
        monkeypatch,
        tcp=[host("10.0.0.5", PortInfo(22))],
        traces=ScanFailedError("no route"),
    )

    result = run(["10.0.0.5"], ScanOptions(traceroute=True))

    assert any(warning.startswith("Traceroute failed") for warning in result.warnings)
    assert result.get_host("10.0.0.5").open_ports


def test_every_scan_is_classified(monkeypatch):
    patch_stages(monkeypatch, tcp=[host("10.0.0.5", PortInfo(9100), PortInfo(515))])

    result = run(["10.0.0.5"])

    printer = result.get_host("10.0.0.5")
    assert result.classifier_version is not None
    assert printer.primary_role.role == "printer"
    assert printer.criticality == "medium"


def test_cancelled_scans_are_still_classified(monkeypatch):
    patch_stages(
        monkeypatch,
        tcp=[host("10.0.0.5", PortInfo(3306))],
        udp=KeyboardInterrupt(),
    )

    result = run(["10.0.0.5"], ScanOptions(udp_scan=True))

    assert CANCELLED_WARNING in result.warnings
    assert result.get_host("10.0.0.5").primary_role.role == "database_server"


def test_broken_rules_become_a_warning(monkeypatch):
    from argus.modules.classify import RulesError

    def broken(result):
        raise RulesError("bad rules")

    monkeypatch.setattr(scan_manager, "classify_result", broken)
    patch_stages(monkeypatch, tcp=[host("10.0.0.5", PortInfo(22))])

    result = run(["10.0.0.5"])

    assert "Asset classification failed: bad rules" in result.warnings
