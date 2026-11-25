import pytest

from argus.modules import port_scan
from argus.modules.nmap_runner import InvalidScanRequestError, find_nmap
from argus.modules.port_scan import (
    TCP_PROFILES,
    UDP_PORTS,
    build_tcp_arguments,
    build_udp_arguments,
    choose_tcp_scan_flag,
    scan_tcp_ports,
    scan_udp_ports,
    validate_port_spec,
)


# ---------- port list checking ----------

@pytest.mark.parametrize(
    "spec, expected",
    [
        ("80", "80"),
        ("22, 80 ,443", "22,80,443"),
        ("1-1024", "1-1024"),
        ("22,80-90,443", "22,80-90,443"),
        ("65535", "65535"),
    ],
)
def test_valid_port_specs(spec, expected):
    assert validate_port_spec(spec) == expected


@pytest.mark.parametrize(
    "spec",
    ["", " ", "0", "65536", "80,", ",80", "90-80", "abc", "80;ls", "-p 80", "1-2-3", "８０"],
)
def test_invalid_port_specs(spec):
    with pytest.raises(InvalidScanRequestError):
        validate_port_spec(spec)


# ---------- scan type choice ----------

def test_unprivileged_uses_connect_scan():
    assert choose_tcp_scan_flag(["192.168.1.10"], privileged=False) == "-sT"


def test_privileged_uses_syn_scan():
    assert choose_tcp_scan_flag(["192.168.1.10"], privileged=True) == "-sS"


def test_loopback_always_uses_connect_scan():
    assert choose_tcp_scan_flag(["127.0.0.1"], privileged=True) == "-sT"
    assert choose_tcp_scan_flag(["10.0.0.5", "127.0.0.0/8"], privileged=True) == "-sT"


def test_build_tcp_arguments():
    arguments = build_tcp_arguments(["10.0.0.5"], "--top-ports 100", privileged=True)

    assert arguments == "-sS -Pn --open --top-ports 100"


def test_build_tcp_arguments_without_extras():
    assert build_tcp_arguments(["10.0.0.5"], "", privileged=False) == "-sT -Pn --open"


# ---------- profiles ----------

def test_profiles_exist_and_differ():
    assert set(TCP_PROFILES) == {"quick", "standard", "full"}
    assert "--top-ports 100" in TCP_PROFILES["quick"].extra_arguments
    assert "--top-ports 1000" in TCP_PROFILES["standard"].extra_arguments
    assert TCP_PROFILES["full"].ports == "1-65535"


def test_unknown_profile_is_rejected():
    with pytest.raises(InvalidScanRequestError):
        scan_tcp_ports(["10.0.0.5"], profile_key="reckless")


# ---------- what gets passed to Nmap (fake runner) ----------

def capture_run_scan(monkeypatch, fake_scanner):
    captured = {}

    def fake_run_scan(targets, arguments, ports=None, timeout=300):
        captured.update(
            targets=targets, arguments=arguments, ports=ports, timeout=timeout
        )
        return fake_scanner()

    monkeypatch.setattr(port_scan, "run_scan", fake_run_scan)
    return captured


def test_profile_ports_and_arguments_are_used(monkeypatch, fake_scanner):
    captured = capture_run_scan(monkeypatch, fake_scanner)

    scan_tcp_ports(["10.0.0.5"], profile_key="quick")

    assert "--top-ports 100" in captured["arguments"]
    assert captured["ports"] is None
    assert captured["timeout"] == TCP_PROFILES["quick"].timeout


def test_custom_ports_replace_the_profile(monkeypatch, fake_scanner):
    captured = capture_run_scan(monkeypatch, fake_scanner)

    scan_tcp_ports(["10.0.0.5"], profile_key="quick", ports="80, 443")

    assert captured["ports"] == "80,443"
    assert "--top-ports" not in captured["arguments"]


def test_bad_custom_ports_never_reach_nmap(monkeypatch, fake_scanner):
    captured = capture_run_scan(monkeypatch, fake_scanner)

    with pytest.raises(InvalidScanRequestError):
        scan_tcp_ports(["10.0.0.5"], ports="80;rm")

    assert captured == {}


def test_udp_defaults(monkeypatch, fake_scanner):
    captured = capture_run_scan(monkeypatch, fake_scanner)

    scan_udp_ports(["10.0.0.5"])

    assert captured["ports"] == UDP_PORTS
    assert "-sU" in captured["arguments"]


def test_udp_custom_ports(monkeypatch, fake_scanner):
    captured = capture_run_scan(monkeypatch, fake_scanner)

    scan_udp_ports(["10.0.0.5"], ports="53")

    assert captured["ports"] == "53"


def test_udp_arguments():
    assert build_udp_arguments() == "-sU -Pn --open -T3 --max-retries 2"


def test_udp_port_list_is_valid():
    assert validate_port_spec(UDP_PORTS) == UDP_PORTS


# ---------- real scans of your own machine ----------

@pytest.mark.skipif(find_nmap() is None, reason="Nmap is not installed")
def test_real_tcp_scan_finds_an_open_port(listening_port):
    hosts = scan_tcp_ports(["127.0.0.1"], ports=str(listening_port))

    assert len(hosts) == 1
    assert [port.port for port in hosts[0].open_ports] == [listening_port]


@pytest.mark.skipif(find_nmap() is None, reason="Nmap is not installed")
def test_real_tcp_scan_with_nothing_open_returns_no_hosts():
    # Port 1 is almost never in use. The host is up, but has nothing to report.
    assert scan_tcp_ports(["127.0.0.1"], ports="1") == []