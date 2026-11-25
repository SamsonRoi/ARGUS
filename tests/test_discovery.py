import pytest

from argus.modules import discovery
from argus.modules.discovery import (
    DISCOVERY_METHODS,
    build_discovery_arguments,
    discover_hosts,
    select_methods,
)
from argus.modules.nmap_runner import InvalidScanRequestError, find_nmap


def keys(methods):
    return [method.key for method in methods]


# ---------- choosing methods ----------

def test_default_methods_when_privileged():
    methods, warnings = select_methods(None, privileged=True)

    assert keys(methods) == ["arp", "icmp", "tcp_syn", "tcp_ack"]
    assert warnings == []


def test_unprivileged_drops_raw_packet_methods_and_warns():
    methods, warnings = select_methods(None, privileged=False)

    assert keys(methods) == ["tcp_syn"]
    assert len(warnings) == 1
    assert "ARP ping" in warnings[0]


def test_unprivileged_with_only_raw_methods_falls_back():
    methods, warnings = select_methods(["icmp", "udp"], privileged=False)

    assert keys(methods) == ["tcp_syn"]
    assert len(warnings) == 2


def test_duplicate_methods_are_removed():
    methods, _ = select_methods(["icmp", "icmp", "arp"], privileged=True)

    assert keys(methods) == ["icmp", "arp"]


def test_unknown_method_is_rejected():
    with pytest.raises(InvalidScanRequestError):
        select_methods(["telepathy"], privileged=True)


def test_empty_method_list_is_rejected():
    with pytest.raises(InvalidScanRequestError):
        select_methods([], privileged=True)


def test_build_discovery_arguments():
    methods = [DISCOVERY_METHODS["arp"], DISCOVERY_METHODS["tcp_syn"]]

    assert build_discovery_arguments(methods) == "-sn -PR -PS22,80,443"


# ---------- discover_hosts with a fake scan ----------

def test_discover_hosts_builds_a_scan_result(monkeypatch, fake_scanner):
    fake = fake_scanner(
        hosts={
            "192.168.1.1": {
                "hostnames": [{"name": "router.lan", "type": "PTR"}],
                "addresses": {"ipv4": "192.168.1.1"},
                "vendor": {},
                "status": {"state": "up", "reason": "echo-reply"},
            }
        },
        version=(7, 993),
    )

    captured = {}

    def fake_run_scan(targets, arguments, ports=None, timeout=300):
        captured["targets"] = targets
        captured["arguments"] = arguments
        return fake

    monkeypatch.setattr(discovery, "run_scan", fake_run_scan)

    result = discover_hosts(["192.168.1.0/24"], methods=["icmp"], privileged=True)

    assert captured["targets"] == ["192.168.1.0/24"]
    assert captured["arguments"] == "-sn -PE"
    assert result.profile == "discovery"
    assert result.nmap_version == "7.993"
    assert result.finished_at is not None
    assert len(result.up_hosts) == 1
    assert result.hosts[0].discovery_method == "ICMP echo reply"


def test_discover_hosts_keeps_privilege_warnings(monkeypatch, fake_scanner):
    monkeypatch.setattr(discovery, "run_scan", lambda *a, **k: fake_scanner())

    result = discover_hosts(["10.0.0.0/30"], privileged=False)

    assert result.hosts == []
    assert len(result.warnings) == 1


def test_discover_hosts_rejects_bad_target_before_scanning(monkeypatch):
    def must_not_run(*args, **kwargs):
        raise AssertionError("Nmap should not have been started")

    monkeypatch.setattr(discovery, "run_scan", must_not_run)

    with pytest.raises(InvalidScanRequestError):
        discover_hosts(["--version"])


# ---------- one real discovery of your own machine ----------

@pytest.mark.skipif(find_nmap() is None, reason="Nmap is not installed")
def test_real_discovery_of_localhost():
    result = discover_hosts(["127.0.0.1"], methods=["tcp_syn"])

    assert [host.ip for host in result.up_hosts] == ["127.0.0.1"]