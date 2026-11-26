"""A small, realistic network used by the report tests."""

from argus.modules.classify import classify_result
from argus.modules.evidence import ScanEvidence
from argus.modules.models import HostInfo, PortInfo, ScanResult, TraceHop
from argus.modules.risk import analyze
from argus.modules.topology import build_network_map
from argus.reports.model import build_report_data


HOSTILE_BANNER = '<script>alert("x")</script>'
FORMULA_BANNER = '=HYPERLINK("http://evil.example","click")'


def office_scan(traced: bool = True) -> ScanResult:
    result = ScanResult(
        targets=["192.168.1.0/24"],
        profile="Standard TCP + service detection + traceroute",
        nmap_version="7.94",
        evidence=ScanEvidence(coverage={"tcp": set(range(1, 1001))}),
    )

    def add(ip, *ports, **details):
        host = HostInfo(ip, **details)

        for port in ports:
            host.add_port(port if isinstance(port, PortInfo) else PortInfo(port))

        if traced and ip != "192.168.1.1":
            host.trace = [TraceHop(1, "192.168.1.1", 0.6, "router.lan"), TraceHop(2, ip, 1.2)]

        result.add_host(host)

    add("192.168.1.1", 23, 80, vendor="TP-Link", hostname="router.lan", mac="AA:BB:CC:00:00:01")
    add("192.168.1.5", 53, 88, 135, 139, 389, 445, 464, 3268, 3389, hostname="dc01.office.lan")
    add("192.168.1.30", 554, 80, 23, vendor="Hikvision", mac="AA:BB:CC:00:00:30")
    add("192.168.1.40",
        PortInfo(3306, "tcp", "open", "mysql", "MySQL", "5.7.44"),
        PortInfo(22, "tcp", "open", "ssh", "OpenSSH", "6.6.1p1"),
        hostname="db01")
    add("192.168.1.77", PortInfo(8443, "tcp", "open", "https", FORMULA_BANNER, HOSTILE_BANNER))
    add("192.168.1.20", 9100, 631, 515, hostname="printer")

    result.finish()
    return classify_result(result)


def office_report(traced: bool = True, **kwargs) -> dict:
    result = office_scan(traced)
    risk = analyze(result)
    return build_report_data(result, risk, build_network_map(result), scan_id=12, **kwargs)
