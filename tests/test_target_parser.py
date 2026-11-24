
import pytest

from argus.utils.target_parser import parse_targets


# -------------------------
# Single IP
# -------------------------

def test_parse_single_ip():
    valid, invalid = parse_targets(
        "single ip",
        "192.168.1.10"
    )

    assert valid == ["192.168.1.10"]
    assert invalid == []


# -------------------------
# CIDR
# -------------------------

def test_parse_cidr():
    valid, invalid = parse_targets(
        "cidr range",
        "192.168.7.7/24"
    )

    assert valid == ["192.168.7.0/24"]
    assert invalid == []


# -------------------------
# Multiple IPs
# -------------------------

def test_parse_multiple_ips():
    valid, invalid = parse_targets(
        "multiple ips",
        "192.168.1.10, 192.168.1.20"
    )

    assert valid == [
        "192.168.1.10",
        "192.168.1.20"
    ]

    assert invalid == []


def test_remove_duplicate_ips():
    valid, invalid = parse_targets(
        "multiple ips",
        "192.168.1.10, 192.168.1.10"
    )

    assert valid == ["192.168.1.10"]
    assert invalid == []


def test_invalid_ip_in_list():
    valid, invalid = parse_targets(
        "multiple ips",
        "192.168.1.10, invalid"
    )

    assert valid == ["192.168.1.10"]
    assert len(invalid) == 1


# -------------------------
# Unsupported target type
# -------------------------

def test_unsupported_target_type():
    with pytest.raises(ValueError):
        parse_targets("invalid type", "192.168.1.10")
