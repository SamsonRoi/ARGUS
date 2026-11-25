"""A safe wrapper around the Nmap program.

Every scan in ARGUS goes through run_scan(). It checks the targets and the
Nmap options before anything is executed, starts Nmap itself so that it can
always be stopped, and turns failures into clear ARGUS errors.

python-nmap is only used to read Nmap's XML output.
"""

import ctypes
import os
import re
import shlex
import shutil
import subprocess

import nmap

from argus.utils.validators import validate_cidr, validate_ip


# Nmap options that ARGUS never allows:
#   --script*, -sC, -A  run Nmap Scripting Engine scripts (no vulnerability probing)
#   -iL, -iR            read targets from a file / pick random targets,
#                       which would bypass the validated targets
FORBIDDEN_PREFIXES = ("--script", "-sC", "-A", "-iL", "-iR")

# Pieces of Nmap error text that mean "you need more privileges".
PRIVILEGE_HINTS = (
    "root privileges",
    "raw socket",
    "operation not permitted",
    "administrator",
    "npcap",
    "winpcap",
    "dnet",
)

PRIVILEGE_MESSAGE = (
    "This scan needs higher privileges. On Windows, run the terminal as "
    "Administrator and make sure Npcap is installed. On Linux or macOS, "
    "run ARGUS with sudo."
)


class ScannerError(Exception):
    """Base class for every scanner error in ARGUS."""


class NmapNotFoundError(ScannerError):
    """Nmap is not installed, or it is not on the PATH."""


class InvalidScanRequestError(ScannerError):
    """The targets or options for a scan were not acceptable."""


class ScanTimeoutError(ScannerError):
    """The scan took longer than the allowed time."""


class ScanFailedError(ScannerError):
    """Nmap started but reported an error."""


class ScanInterruptedError(ScannerError):
    """Nmap stopped before it finished, so its output was incomplete.

    This happens when a scan is cancelled with Ctrl+C or Nmap is killed.
    """


def find_nmap() -> str | None:
    """Return the full path to the Nmap program, or None if not found."""
    return shutil.which("nmap")


def get_nmap_version(nmap_path: str | None = None) -> str:
    """Ask Nmap for its version number, for example '7.993'."""
    path = nmap_path or find_nmap()

    if path is None:
        raise NmapNotFoundError(
            "Nmap was not found. Install it from https://nmap.org and "
            "make sure it is on your PATH."
        )

    try:
        completed = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
            check=False,
        )

    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScanFailedError("Could not run Nmap to read its version.") from error

    match = re.search(r"Nmap version (\S+)", completed.stdout)

    if match is None:
        raise ScanFailedError("Nmap ran, but its version could not be read.")

    return match.group(1)


def is_privileged() -> bool:
    """Return True if ARGUS runs as Administrator (Windows) or root (Linux/macOS)."""
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())

        return os.geteuid() == 0

    except (AttributeError, OSError):
        return False


def validate_targets(targets: list[str]) -> list[str]:
    """Check every target again and return the cleaned list.

    Without this check, a "target" such as "--script x" could be read by
    Nmap as an option instead of an address.
    """
    if not targets:
        raise InvalidScanRequestError("No targets were provided.")

    clean_targets = []

    for target in targets:
        try:
            if "/" in target:
                clean_targets.append(validate_cidr(target))
            else:
                clean_targets.append(validate_ip(target))

        except ValueError as error:
            raise InvalidScanRequestError(str(error)) from error

    return clean_targets


def check_arguments(arguments: str) -> None:
    """Refuse Nmap options that ARGUS does not allow."""
    try:
        tokens = shlex.split(arguments)

    except ValueError as error:
        raise InvalidScanRequestError("The scan options could not be read.") from error

    for token in tokens:
        if token.startswith(FORBIDDEN_PREFIXES):
            raise InvalidScanRequestError(
                f"This Nmap option is not allowed in ARGUS: {token}"
            )


def _clean_nmap_message(raw_message: str) -> str:
    """Tidy error text from Nmap."""
    text = str(raw_message).replace("\\n", "\n").strip()

    if text.startswith(("b'", 'b"')):
        text = text[1:]

    text = text.strip("'\"").strip()

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and line.strip().upper() != "QUITTING!"
    ]

    return " ".join(lines)


def _explain_error(raw_message: str) -> str:
    """Turn a raw Nmap error into a friendly message."""
    message = _clean_nmap_message(raw_message)
    lowered = message.lower()

    if any(hint in lowered for hint in PRIVILEGE_HINTS):
        return PRIVILEGE_MESSAGE

    return f"Nmap reported an error: {message or 'unknown error'}"


def _error_lines(stderr: str) -> list[str]:
    """Pick the real errors out of Nmap's error stream, ignoring plain warnings."""
    return [
        line.strip()
        for line in stderr.splitlines()
        if line.strip() and not line.strip().lower().startswith("warning:")
    ]


def _run_nmap(command: list[str], timeout: int) -> tuple[str, str]:
    """Run Nmap and return (output, errors). Nmap is never left running."""
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    except OSError as error:
        raise ScanFailedError("Nmap could not be started.") from error

    try:
        return process.communicate(timeout=timeout)

    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate()

        raise ScanTimeoutError(
            f"The scan did not finish within {timeout} seconds."
        ) from error

    except BaseException:
        # Ctrl+C or any other interruption: stop Nmap, then let it continue.
        process.kill()
        process.wait()
        raise


def run_scan(
    targets: list[str],
    arguments: str,
    ports: str | None = None,
    timeout: int = 300,
) -> nmap.PortScanner:
    """Run Nmap safely and return the python-nmap scanner holding the results.

    Raises a ScannerError subclass if anything goes wrong.
    """
    # Check everything BEFORE touching Nmap.
    clean_targets = validate_targets(targets)
    check_arguments(arguments)

    if ports is not None and not re.fullmatch(r"[0-9,\-]+", ports):
        raise InvalidScanRequestError(f"Invalid port list: {ports}")

    nmap_path = find_nmap()

    if nmap_path is None:
        raise NmapNotFoundError(
            "Nmap was not found. Install it from https://nmap.org and "
            "make sure it is on your PATH."
        )

    try:
        scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))

    except nmap.PortScannerError as error:
        raise NmapNotFoundError("Nmap could not be started.") from error

    # Every target is its own list item, so none can turn into an option.
    command = [nmap_path, "-oX", "-"] + clean_targets

    if ports:
        command += ["-p", ports]

    command += shlex.split(arguments)

    output, errors = _run_nmap(command, timeout)

    problems = _error_lines(errors)

    if problems:
        raise ScanFailedError(_explain_error("\n".join(problems)))

    try:
        scanner.analyse_nmap_xml_scan(nmap_xml_output=output)

    except nmap.PortScannerError as error:
        raise ScanInterruptedError(
            "Nmap stopped before it finished, so its results could not be read."
        ) from error

    return scanner