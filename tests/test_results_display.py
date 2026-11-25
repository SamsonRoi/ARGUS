import io

from rich.console import Console

from argus.modules.models import HostInfo, OSGuess, PortInfo, ScanResult
from argus.results_display import FOOTER, safe_text, show_scan_results


def render(result, **kwargs):
    """Draw a result into plain text so tests can read it."""
    console = Console(record=True, width=130, file=io.StringIO())
    show_scan_results(result, output=console, **kwargs)
    return console.export_text()


def make_result(*hosts, warnings=()):
    result = ScanResult(targets=["192.168.1.0/24"], profile="Standard TCP", nmap_version="7.99")

    for item in hosts:
        result.add_host(item)

    result.warnings.extend(warnings)
    result.finish()

    return result


def make_host(ip, *ports, **details):
    item = HostInfo(ip=ip, **details)

    for port in ports:
        item.add_port(port)

    return item


# ---------- safe_text ----------

def test_empty_values_show_a_dash():
    assert safe_text(None).plain == "-"
    assert safe_text("").plain == "-"
    assert safe_text("   ").plain == "-"


def test_control_characters_are_removed():
    cleaned = safe_text("a\x1b[31mred\x07\x00b\r\nc").plain

    assert "\x1b" not in cleaned
    assert "\x07" not in cleaned
    assert "\x00" not in cleaned
    assert "\n" not in cleaned
    assert cleaned.startswith("a")


# ---------- the results screen ----------

def test_shows_hosts_ports_and_details():
    result = make_result(
        make_host(
            "192.168.1.10",
            PortInfo(port=22, service="ssh", product="OpenSSH", version="8.9", extra_info="protocol 2.0"),
            hostname="nas.lan",
            mac="AA:BB:CC:DD:EE:FF",
            vendor="Acme",
            discovery_method="ARP reply",
            os_guess=OSGuess(name="Linux 5.4", accuracy=96),
        )
    )

    text = render(result)

    for expected in (
        "SCAN RESULTS",
        "192.168.1.0/24",
        "7.99",
        "192.168.1.10",
        "nas.lan",
        "Acme (AA:BB:CC:DD:EE:FF)",
        "ARP reply",
        "OS (estimate)",
        "Linux 5.4 (96% match)",
        "22/tcp",
        "ssh",
        "OpenSSH 8.9 | protocol 2.0",
    ):
        assert expected in text


def test_unconfirmed_udp_port_keeps_its_state():
    result = make_result(
        make_host("10.0.0.1", PortInfo(port=161, protocol="udp", state="open|filtered", service="snmp"))
    )

    text = render(result)

    assert "161/udp" in text
    assert "open|filtered" in text


def test_empty_result_says_nothing_responded():
    text = render(make_result())

    assert "No hosts responded" in text


def test_warnings_are_shown():
    text = render(make_result(make_host("10.0.0.1"), warnings=["UDP port scan failed: needs Administrator."]))

    assert "Warnings" in text
    assert "UDP port scan failed" in text


def test_footer_reminds_that_absence_is_not_proof():
    text = " ".join(render(make_result()).split())

    assert " ".join(FOOTER.split()) in text


def test_detail_limit_hides_extra_hosts():
    result = make_result(
        make_host("10.0.0.1", PortInfo(port=80)),
        make_host("10.0.0.2", PortInfo(port=81)),
        make_host("10.0.0.3", PortInfo(port=82)),
    )

    limited = render(result, detail_limit=1)
    everything = render(result, detail_limit=None)

    assert "Ports on 10.0.0.1" in limited
    assert "Ports on 10.0.0.2" not in limited
    assert "2 more host(s)" in limited

    assert "Ports on 10.0.0.3" in everything
    assert "more host(s)" not in everything


def test_text_from_the_network_is_never_treated_as_formatting():
    result = make_result(
        make_host(
            "10.0.0.1",
            PortInfo(port=80, service="http", product="[bold red]Evil[/bold red]"),
            hostname="host\x1b[2Jname",
        )
    )

    text = render(result)

    assert "[bold red]Evil[/bold red]" in text
    assert "\x1b" not in text
    assert "host[2Jname" in text