from argus.modules.models import ScanResult
from argus.utils.session import Session


def test_new_session_is_inactive():
    session = Session()

    assert not session.is_active
    assert session.started_at is None
    assert session.scan_result is None


def test_set_target_starts_session():
    session = Session()

    session.set_target("Single IP", ["192.168.1.1"])

    assert session.is_active
    assert session.target_type == "Single IP"
    assert session.target == ["192.168.1.1"]
    assert session.started_at is not None


def test_replacing_target_keeps_start_time():
    session = Session()

    session.set_target("Single IP", ["192.168.1.1"])
    first_start = session.started_at

    session.set_target("CIDR Range", ["10.0.0.0/24"])

    assert session.started_at == first_start
    assert session.target_type == "CIDR Range"
    assert session.target == ["10.0.0.0/24"]


def test_clear_resets_everything():
    session = Session()
    session.set_target("Single IP", ["192.168.1.1"])
    session.scan_result = ScanResult(targets=["192.168.1.1"], profile="quick")

    session.clear()

    assert not session.is_active
    assert session.target_type is None
    assert session.target is None
    assert session.started_at is None
    assert session.scan_result is None


def test_new_session_after_clear_gets_new_start_time():
    session = Session()

    session.set_target("Single IP", ["192.168.1.1"])
    first_start = session.started_at

    session.clear()
    session.set_target("Single IP", ["192.168.1.2"])

    assert session.started_at is not None
    assert session.started_at >= first_start


def test_set_target_stores_a_copy():
    session = Session()
    targets = ["192.168.1.1"]

    session.set_target("Multiple IPs", targets)
    targets.append("10.0.0.1")

    assert session.target == ["192.168.1.1"]


def test_scan_result_survives_target_replacement():
    session = Session()
    session.set_target("Single IP", ["192.168.1.1"])
    result = ScanResult(targets=["192.168.1.1"], profile="quick")
    session.scan_result = result

    session.set_target("Single IP", ["192.168.1.2"])

    assert session.scan_result is result