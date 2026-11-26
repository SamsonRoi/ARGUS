from argus.modules.classify import classify_result
from argus.modules.models import HostInfo, OSGuess, PortInfo, ScanResult, TraceHop
from argus.modules.topology import (
    INFERRED,
    OBSERVED,
    SCANNER_ID,
    build_network_map,
)


def host(ip, *tcp, **details):
    item = HostInfo(ip=ip, **details)

    for number in tcp:
        item.add_port(PortInfo(number))

    return item


def office(traced=False):
    result = ScanResult(targets=["192.168.1.0/24"], profile="Quick TCP")
    router = host("192.168.1.1", 22, 80, vendor="MikroTik", os_guess=OSGuess("MikroTik RouterOS 7", 95))
    printer = host("192.168.1.20", 9100, 631)
    db = host("192.168.1.30", 5432)

    if traced:
        printer.trace = [TraceHop(1, "192.168.1.1"), TraceHop(2, "192.168.1.20")]

    for item in (router, printer, db):
        result.add_host(item)

    return classify_result(result)


def links(network_map, kind=None):
    return {
        (link.source, link.target)
        for link in network_map.links
        if kind is None or link.kind == kind
    }


def test_hosts_are_grouped_into_scanned_subnets():
    network_map = build_network_map(office())

    assert [group.network for group in network_map.subnets] == ["192.168.1.0/24"]
    assert network_map.subnets[0].host_ips == ["192.168.1.1", "192.168.1.20", "192.168.1.30"]
    assert not network_map.subnets[0].assumed


def test_without_traceroute_every_link_is_inferred():
    network_map = build_network_map(office())
    group = network_map.subnets[0]

    assert group.gateway_ip == "192.168.1.1"
    assert group.gateway_basis == INFERRED
    assert network_map.observed_links == []
    assert links(network_map, INFERRED) == {
        ("192.168.1.1", "192.168.1.20"),
        ("192.168.1.1", "192.168.1.30"),
    }
    assert SCANNER_ID not in network_map.nodes
    assert any("No traceroute data" in note for note in network_map.notes)


def test_traceroute_makes_observed_links_and_gateways():
    network_map = build_network_map(office(traced=True))
    group = network_map.subnets[0]

    assert group.gateway_basis == OBSERVED
    assert group.gateway_reason == "first hop on 1 traced path"
    assert links(network_map, OBSERVED) == {
        (SCANNER_ID, "192.168.1.1"),
        ("192.168.1.1", "192.168.1.20"),
    }
    # The printer is already linked by traceroute; only the database is inferred.
    assert links(network_map, INFERRED) == {("192.168.1.1", "192.168.1.30")}
    assert network_map.nodes["192.168.1.1"].kind == "gateway"
    assert network_map.paths["192.168.1.20"] == ["192.168.1.1", "192.168.1.20"]


def test_silent_hops_are_kept_as_gaps():
    result = ScanResult(targets=["10.0.0.0/24"], profile="x")
    result.add_host(HostInfo("10.0.0.9", trace=[TraceHop(1, "10.0.0.1"), TraceHop(3, "10.0.0.9")]))

    network_map = build_network_map(classify_result(result))

    assert network_map.paths["10.0.0.9"] == ["10.0.0.1", None, "10.0.0.9"]
    hop_link = next(link for link in network_map.links if link.target == "10.0.0.9")
    assert "1 hop in between did not answer" in hop_link.reason
    # The gateway itself was not in the results, but it is still on the map.
    assert network_map.nodes["10.0.0.1"].kind == "gateway"


def test_single_addresses_get_an_assumed_subnet():
    result = ScanResult(targets=["10.0.0.5", "172.16.4.9"], profile="x")
    result.add_host(host("10.0.0.5", 22))
    result.add_host(host("172.16.4.9", 22))

    network_map = build_network_map(classify_result(result))

    assert [group.network for group in network_map.subnets] == ["10.0.0.0/24", "172.16.4.0/24"]
    assert all(group.assumed for group in network_map.subnets)
    assert any("assumed" in note for note in network_map.notes)
    assert any("No gateway was identified" in note for note in network_map.notes)


def test_most_specific_scanned_range_wins():
    result = ScanResult(targets=["10.0.0.0/16", "10.0.5.0/24"], profile="x")
    result.add_host(host("10.0.5.7"))
    result.add_host(host("10.0.9.7"))

    network_map = build_network_map(result)

    assert network_map.subnet_of("10.0.5.7").network == "10.0.5.0/24"
    assert network_map.subnet_of("10.0.9.7").network == "10.0.0.0/16"


def test_low_confidence_routers_are_not_gateways():
    result = ScanResult(targets=["10.0.0.0/24"], profile="x")
    result.add_host(host("10.0.0.1"))   # only "ends in .1": not enough

    network_map = build_network_map(classify_result(result))

    assert network_map.subnets[0].gateway_ip is None


def test_loopback_has_its_own_subnet():
    result = ScanResult(targets=["127.0.0.1"], profile="x")
    result.add_host(host("127.0.0.1", 22))

    network_map = build_network_map(result)

    assert network_map.subnets[0].network == "127.0.0.0/8"
    assert not network_map.subnets[0].assumed
    assert not any("No gateway" in note for note in network_map.notes)


def test_note_when_traceroute_ran_but_found_nothing():
    result = ScanResult(targets=["127.0.0.1"], profile="Quick TCP + traceroute")
    result.add_host(host("127.0.0.1", 22))

    network_map = build_network_map(result)

    assert any("Traceroute ran but returned no paths" in note for note in network_map.notes)


def test_empty_scan_gives_empty_map():
    network_map = build_network_map(ScanResult(targets=["10.0.0.0/24"], profile="x"))

    assert network_map.subnets == []
    assert network_map.links == []
