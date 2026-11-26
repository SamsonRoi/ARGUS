from rich.console import Console

from argus.modules.classify import classify_result
from argus.modules.models import HostInfo, PortInfo, ScanResult, TraceHop
from argus.modules.topology import build_network_map
from argus.results_display import show_assets, show_network_map, show_scan_results


def render(function, *args):
    console = Console(record=True, width=220)
    function(*args, output=console)
    return console.export_text()


def sample(traced=False):
    result = ScanResult(targets=["192.168.1.0/24"], profile="Quick TCP")

    router = HostInfo("192.168.1.1", vendor="MikroTik")
    router.add_port(PortInfo(80))
    printer = HostInfo("192.168.1.20", hostname="[red]evil[/red]")
    printer.add_port(PortInfo(9100))
    printer.add_port(PortInfo(631))
    unknown = HostInfo("192.168.1.40")

    if traced:
        printer.trace = [TraceHop(1, "192.168.1.1"), TraceHop(2, "192.168.1.20")]

    for host in (router, printer, unknown):
        result.add_host(host)

    return classify_result(result)


def test_results_table_shows_likely_role():
    text = render(show_scan_results, sample())

    assert "Likely role" in text
    assert "Printer (high)" in text
    assert "Unknown" in text


def test_assets_show_evidence_criticality_and_alternatives():
    text = render(show_assets, sample())

    assert "Assets by criticality" in text
    assert "port 9100/tcp open (raw printing)" in text
    assert "Not enough evidence to tell" in text
    assert "No role could be identified" in text
    assert "Roles are estimates" in text


def test_untrusted_hostnames_are_shown_literally():
    text = render(show_assets, sample())

    assert "[red]evil[/red]" in text


def test_network_map_tree_without_traceroute():
    text = render(show_network_map, build_network_map(sample()))

    assert "192.168.1.0/24" in text
    assert "gateway, inferred" in text
    assert "Printer (high)" in text
    assert "Observed links  0" in text
    assert "No traceroute data" in text


def test_network_map_with_traced_paths():
    text = render(show_network_map, build_network_map(sample(traced=True)))

    assert "gateway, observed" in text
    assert "Traced paths" in text
    assert "192.168.1.1 -> 192.168.1.20" in text


def test_empty_map_says_so():
    empty = ScanResult(targets=["10.0.0.0/24"], profile="x")

    assert "nothing to map" in render(show_network_map, build_network_map(empty))


def test_empty_assets_says_so():
    empty = ScanResult(targets=["10.0.0.0/24"], profile="x")

    assert "No hosts responded" in render(show_assets, empty)
