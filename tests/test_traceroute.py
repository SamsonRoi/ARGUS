import pytest

from argus.modules import traceroute
from argus.modules.evidence import ScanEvidence
from argus.modules.models import TraceHop
from argus.modules.nmap_runner import ScanFailedError
from argus.modules.traceroute import TRACE_ARGUMENTS, parse_traces, trace_routes


SAMPLE = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn --traceroute">
<host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
<trace proto="icmp">
<hop ttl="1" ipaddr="10.0.0.1" rtt="0.84" host="router.lan"/>
<hop ttl="3" ipaddr="10.0.0.5" rtt="2.10"/>
</trace>
</host>
<host><status state="up"/>
<address addr="10.0.0.6" addrtype="ipv4"/>
</host>
<host><status state="up"/>
<address addr="10.0.0.7" addrtype="ipv4"/>
<trace><hop ttl="1" ipaddr="10.0.0.7" rtt="--"/></trace>
</host>
</nmaprun>"""


def test_hops_are_read_with_gaps_kept():
    traces = parse_traces(SAMPLE)

    assert traces["10.0.0.5"] == [
        TraceHop(1, "10.0.0.1", 0.84, "router.lan"),
        TraceHop(3, "10.0.0.5", 2.10, None),
    ]
    assert traces["10.0.0.7"] == [TraceHop(1, "10.0.0.7", None, None)]
    assert "10.0.0.6" not in traces


def test_empty_output_has_no_traces():
    assert parse_traces("") == {}


def test_broken_xml_is_a_scan_failure():
    with pytest.raises(ScanFailedError):
        parse_traces("<nmaprun><host>")


class TraceScanner:
    def scaninfo(self):
        return {"tcp": {"services": "1-1000"}}

    def get_nmap_last_output(self):
        return SAMPLE.encode()


def test_trace_routes_runs_nmap_and_keeps_evidence(monkeypatch):
    calls = []

    def fake_run_scan(targets, arguments, ports=None, timeout=300):
        calls.append((targets, arguments))
        return TraceScanner()

    monkeypatch.setattr(traceroute, "run_scan", fake_run_scan)
    evidence = ScanEvidence()

    hosts = trace_routes(["10.0.0.5", "10.0.0.7"], evidence=evidence)

    assert calls == [(["10.0.0.5", "10.0.0.7"], TRACE_ARGUMENTS)]
    assert {host.ip for host in hosts} == {"10.0.0.5", "10.0.0.7"}
    assert all(not host.ports for host in hosts)
    # The trace run's ports must never widen the scan's coverage.
    assert evidence.coverage == {}
    assert evidence.raw_outputs[0][0] == "traceroute"
