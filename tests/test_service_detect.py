import pytest

from argus.modules import service_detect
from argus.modules.models import HostInfo, PortInfo
from argus.modules.nmap_runner import InvalidScanRequestError, find_nmap
from argus.modules.service_detect import (
    build_service_arguments,
    collect_open_tcp_ports,
    detect_services,
)


def make_host(ip, *ports):
    host = HostInfo(ip=ip)

    for port in ports:
        host.add_port(port)

    return host


def test_collect_open_tcp_ports():
    first = make_host(
        "10.0.0.1",
        PortInfo(port=443),
        PortInfo(port=22),
        PortInfo(port=23, state="closed"),
        PortInfo(port=161, protocol="udp"),
    )
    second = make_host("10.0.0.2", PortInfo(port=22), PortInfo(port=80))

    assert collect_open_tcp_ports([first, second]) == [22, 80, 443]


def test_collect_ports_with_nothing_open():
    assert collect_open_tcp_ports([make_host("10.0.0.1")]) == []


def test_service_arguments():
    arguments = build_service_arguments(["10.0.0.1"], 5, privileged=True)

    assert arguments == "-sS -Pn --open -sV --version-intensity 5"


@pytest.mark.parametrize("bad_intensity", [-1, 10, 2.5, "7", True, None])
def test_bad_intensity_is_rejected(bad_intensity):
    host = make_host("10.0.0.1", PortInfo(port=22))

    with pytest.raises(InvalidScanRequestError):
        detect_services([host], intensity=bad_intensity)


def test_nothing_to_detect_does_not_start_nmap(monkeypatch):
    def must_not_run(*args, **kwargs):
        raise AssertionError("Nmap should not have been started")

    monkeypatch.setattr(service_detect, "run_scan", must_not_run)

    assert detect_services([make_host("10.0.0.1")]) == []
    assert detect_services([]) == []


def test_only_hosts_with_open_tcp_ports_are_scanned(monkeypatch, fake_scanner):
    captured = {}

    def fake_run_scan(targets, arguments, ports=None, timeout=300):
        captured.update(targets=targets, ports=ports)
        return fake_scanner()

    monkeypatch.setattr(service_detect, "run_scan", fake_run_scan)

    with_port = make_host("10.0.0.1", PortInfo(port=22), PortInfo(port=80))
    without_port = make_host("10.0.0.2", PortInfo(port=22, state="closed"))

    detect_services([with_port, without_port])

    assert captured["targets"] == ["10.0.0.1"]
    assert captured["ports"] == "22,80"


@pytest.mark.skipif(find_nmap() is None, reason="Nmap is not installed")
def test_real_service_detection(ssh_banner_port):
    host = make_host("127.0.0.1", PortInfo(port=ssh_banner_port))

    found = detect_services([host], intensity=7)

    port = found[0].open_ports[0]

    assert port.port == ssh_banner_port
    assert port.service == "ssh"
    assert port.product == "OpenSSH"