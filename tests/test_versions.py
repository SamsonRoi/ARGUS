import pytest

from argus.modules.versions import parse_version, version_below, version_matches


@pytest.mark.parametrize("text, expected", [
    ("8.9p1", (8, 9)),
    ("7.4p1 Debian 10+deb9u7", (7, 4)),
    ("2.4.41", (2, 4, 41)),
    ("1.3.5rc3", (1, 3, 5)),
    ("5.5.5-10.6.12-MariaDB", (5, 5, 5)),
    ("", None),
    (None, None),
    ("unknown", None),
])
def test_parse_version(text, expected):
    assert parse_version(text) == expected


def test_version_below():
    assert version_below("6.6.1p1", "7.4") is True
    assert version_below("7.4", "7.4") is False
    assert version_below("7.4p1", "7.4") is False
    assert version_below("2.2.34", "2.4") is True
    assert version_below("2.4", "2.4.0") is False
    assert version_below("10", "9.6") is False
    assert version_below(None, "7.4") is None
    assert version_below("abc", "7.4") is None


def test_version_matches():
    assert version_matches("2.3.4", "2.3.4") is True
    assert version_matches("2.3.40", "2.3.4") is False
    assert version_matches("2.3", "2.3.4") is False
    assert version_matches(None, "2.3.4") is None
