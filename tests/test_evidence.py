from argus.modules.evidence import ScanEvidence, format_port_list, parse_port_list


class RecordingScanner:
    def __init__(self, info=None, raw=None):
        self._info = info or {}
        self._raw = raw

    def scaninfo(self):
        return self._info

    def get_nmap_last_output(self):
        return self._raw


def test_port_list_round_trip():
    ports = parse_port_list("1,3-5,80,8000-8002")

    assert ports == {1, 3, 4, 5, 80, 8000, 8001, 8002}
    assert format_port_list(ports) == "1,3-5,80,8000-8002"


def test_bad_pieces_are_skipped_and_ranges_clamped():
    assert parse_port_list("22,abc,,0-2,65535-70000") == {1, 2, 22, 65535}
    assert parse_port_list(None) == set()
    assert format_port_list([]) == ""


def test_record_collects_coverage_and_raw_output():
    evidence = ScanEvidence()
    evidence.record(
        "tcp_scan",
        RecordingScanner({"tcp": {"method": "connect", "services": "22,80-81"}}, "<xml/>"),
    )
    evidence.record("udp_scan", RecordingScanner({"udp": {"services": "53"}}, b"<udp/>"))

    assert evidence.coverage == {"tcp": {22, 80, 81}, "udp": {53}}
    assert evidence.raw_outputs == [("tcp_scan", "<xml/>"), ("udp_scan", "<udp/>")]
    assert evidence.covers("tcp", 81)
    assert not evidence.covers("tcp", 443)
    assert not evidence.covers("udp", 22)


def test_runs_without_kept_ports_do_not_widen_coverage():
    evidence = ScanEvidence()
    evidence.record(
        "os_estimation",
        RecordingScanner({"tcp": {"services": "1-100"}}, "<os/>"),
        coverage=False,
    )

    assert evidence.coverage == {}
    assert evidence.raw_outputs == [("os_estimation", "<os/>")]


def test_test_doubles_without_these_methods_are_ignored(fake_scanner):
    evidence = ScanEvidence()
    evidence.record("tcp_scan", fake_scanner())

    assert evidence.coverage == {}
    assert evidence.raw_outputs == []
