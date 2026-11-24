
import pytest

from argus.utils.validators import (
    validate_ip,
    validate_cidr,
    validate_ip_list,
    get_scope_warnings,
)


# -------------------------
# validate_ip()
# -------------------------

def test_valid_ip():
    assert validate_ip("192.168.1.10") == "192.168.1.10"


def test_ip_with_spaces():
    assert validate_ip(" 192.168.1.10 ") == "192.168.1.10"


def test_invalid_ip():
    with pytest.raises(ValueError):
        validate_ip("999.999.1.1")


def test_empty_ip():
    with pytest.raises(ValueError):
        validate_ip("")


# -------------------------
# validate_cidr()
# -------------------------

def test_valid_cidr():
    assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"


def test_cidr_host_bits():
    assert validate_cidr("192.168.7.7/24") == "192.168.7.0/24"


def test_invalid_cidr():
    with pytest.raises(ValueError):
        validate_cidr("192.168.1.0/33")


def test_cidr_size_limit():
    with pytest.raises(ValueError):
        validate_cidr("10.0.0.0/8")


# -------------------------
# validate_ip_list()
# -------------------------

def test_valid_ip_list():
    valid, invalid = validate_ip_list([
        "192.168.1.10",
        "192.168.1.20"
    ])

    assert valid == ["192.168.1.10", "192.168.1.20"]
    assert invalid == []


def test_ip_list_with_invalid_entry():
    valid, invalid = validate_ip_list([
        "192.168.1.10",
        "invalid"
    ])

    assert valid == ["192.168.1.10"]
    assert len(invalid) == 1


# -------------------------
# get_scope_warnings()
# -------------------------

def test_public_ip_warning():
    warnings = get_scope_warnings("8.8.8.8")
    assert len(warnings) == 1
    assert "Public IP" in warnings[0]


def test_loopback_warning():
    warnings = get_scope_warnings("127.0.0.1")
    assert len(warnings) == 1
    assert "Loopback" in warnings[0]


def test_private_ip_no_warning():
    warnings = get_scope_warnings("192.168.1.10")
    assert warnings == []


def test_loopback_cidr_warning():
    warnings = get_scope_warnings("127.0.0.0/8")
    assert len(warnings) == 1
    assert "Loopback" in warnings[0]
