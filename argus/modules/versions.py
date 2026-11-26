"""Compare software version numbers taken from service banners.

Banners are messy: '8.9p1', '2.4.41', '1.3.5rc3', '7.4p1 Debian 10+deb9u7'.
Only the leading numbers are compared, which is enough for rules such as
"older than 7.4". Anything after them (patch letters, distribution tags)
is ignored, and the caller is told when a version could not be read.

Remember that Linux distributions often fix security problems without
changing the version number, so an "old" banner is a reason to check, not
proof of a vulnerability.
"""

import re


_LEADING_NUMBERS = re.compile(r"\d+(?:\.\d+)*")


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """Return the leading numeric parts of a version, e.g. '8.9p1' -> (8, 9).

    Returns None when the text holds no version number.
    """
    if not text:
        return None

    match = _LEADING_NUMBERS.search(str(text))

    if match is None:
        return None

    return tuple(int(part) for part in match.group(0).split("."))


def _padded(first: tuple[int, ...], second: tuple[int, ...]):
    length = max(len(first), len(second))
    return (
        first + (0,) * (length - len(first)),
        second + (0,) * (length - len(second)),
    )


def version_below(version: str | None, limit: str) -> bool | None:
    """True if version < limit, False if not, None if it cannot be told."""
    found, wanted = parse_version(version), parse_version(limit)

    if found is None or wanted is None:
        return None

    found, wanted = _padded(found, wanted)
    return found < wanted


def version_matches(version: str | None, exact: str) -> bool | None:
    """True if the version starts with exactly these numbers ('2.3.4')."""
    found, wanted = parse_version(version), parse_version(exact)

    if found is None or wanted is None:
        return None

    return found[: len(wanted)] == wanted and len(found) >= len(wanted)
