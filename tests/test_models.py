import pytest

from argus.modules.models import HostInfo, OSGuess, PortInfo, ScanResult


# ---------- PortInfo ----------

def test_port_defaults():
    port = PortInfo(port=80)

    assert port.protocol == "tcp"
    assert port.state == "open"
    assert port.service is None


def test_port_normalizes_text():
    port = PortInfo(port=53, protocol=" UDP ", state=" Open|Filtered ")

    assert port.protocol == "udp"
    assert port.state == "open|filtered"


@pytest.mark.parametrize("bad_port", [0, -1, 65536, 99999])
def test_port_number_out_of_range(bad_port):
    with pytest.raises(ValueError):
        PortInfo(port=bad_port)


def test_port_rejects_non_integer():
    with pytest.raises(ValueError):
        PortInfo(port="80")


def test_port_rejects_unknown_protocol():
    with pytest.raises(ValueError):
        PortInfo(port=80, protocol="icmp")


def test_version_text():
    assert PortInfo(port=22, product="OpenSSH", version="8.9").version_text == "OpenSSH 8.9"
    assert PortInfo(port=22, product="OpenSSH").version_text == "OpenSSH"
    assert PortInfo(port=22).version_text is None


# ---------- OSGuess ----------

def test_os_guess_accuracy_limits():
    assert OSGuess(name="Linux 5.x", accuracy=95).accuracy == 95

    with pytest.raises(ValueError):
        OSGuess(name="Linux", accuracy=101)


# ---------- HostInfo ----------

def test_open_ports_are_filtered_and_sorted():
    host = HostInfo(ip="192.168.1.10")
    host.add_port(PortInfo(port=443))
    host.add_port(PortInfo(port=22))
    host.add_port(PortInfo(port=23, state="closed"))
    host.add_port(PortInfo(port=161, protocol="udp", state="open|filtered"))

    assert [port.port for port in host.open_ports] == [22, 443]


def test_add_port_replaces_same_port_and_protocol():
    host = HostInfo(ip="192.168.1.10")
    host.add_port(PortInfo(port=80, state="filtered"))
    host.add_port(PortInfo(port=80, state="open"))

    assert len(host.ports) == 1
    assert host.ports[0].state == "open"


def test_same_port_number_different_protocol_is_kept():
    host = HostInfo(ip="192.168.1.10")
    host.add_port(PortInfo(port=53, protocol="tcp"))
    host.add_port(PortInfo(port=53, protocol="udp"))

    assert len(host.ports) == 2


def test_hosts_do_not_share_port_lists():
    first = HostInfo(ip="10.0.0.1")
    second = HostInfo(ip="10.0.0.2")

    first.add_port(PortInfo(port=80))

    assert second.ports == []


# ---------- ScanResult ----------

def test_scan_result_starts_unfinished():
    result = ScanResult(targets=["10.0.0.0/24"], profile="quick")

    assert result.started_at is not None
    assert result.finished_at is None
    assert result.duration_seconds is None


def test_finish_sets_duration():
    result = ScanResult(targets=["10.0.0.1"], profile="quick")

    result.finish()

    assert result.finished_at is not None
    assert result.duration_seconds >= 0


def test_add_host_replaces_same_ip():
    result = ScanResult(targets=["10.0.0.1"], profile="quick")
    result.add_host(HostInfo(ip="10.0.0.1", hostname="old"))
    result.add_host(HostInfo(ip="10.0.0.1", hostname="new"))

    assert len(result.hosts) == 1
    assert result.get_host("10.0.0.1").hostname == "new"


def test_get_host_missing_returns_none():
    result = ScanResult(targets=["10.0.0.1"], profile="quick")

    assert result.get_host("10.0.0.99") is None


def test_summary_counts():
    result = ScanResult(targets=["10.0.0.0/30"], profile="quick")

    first = HostInfo(ip="10.0.0.1")
    first.add_port(PortInfo(port=22))
    first.add_port(PortInfo(port=80))

    second = HostInfo(ip="10.0.0.2")
    second.add_port(PortInfo(port=443))

    down = HostInfo(ip="10.0.0.3", state="down")

    for host in (first, second, down):
        result.add_host(host)

    assert len(result.up_hosts) == 2
    assert result.total_open_ports == 3