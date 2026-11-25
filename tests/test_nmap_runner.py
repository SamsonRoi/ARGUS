from types import SimpleNamespace

import pytest

from argus.modules import nmap_runner
from argus.modules.nmap_runner import (
    InvalidScanRequestError,
    NmapNotFoundError,
    ScanFailedError,
    ScannerError,
    check_arguments,
    find_nmap,
    get_nmap_version,
    is_privileged,
    run_scan,
    validate_targets,
)


# ---------- validate_targets ----------

def test_validate_targets_accepts_ip_and_cidr():
    assert validate_targets(["192.168.1.10", "10.0.0.5/24"]) == [
        "192.168.1.10",
        "10.0.0.0/24",
    ]


def test_validate_targets_rejects_empty_list():
    with pytest.raises(InvalidScanRequestError):
        validate_targets([])


@pytest.mark.parametrize(
    "bad_target",
    ["--script vuln", "-iL targets.txt", "1.1.1.1 --version", "not-an-ip", ""],
)
def test_validate_targets_rejects_bad_text(bad_target):
    with pytest.raises(InvalidScanRequestError):
        validate_targets([bad_target])


# ---------- check_arguments ----------

@pytest.mark.parametrize(
    "arguments",
    ["-sT -T4", "-sV --open", "-sn -PE", "-sU -p 53,161", "-O"],
)
def test_check_arguments_allows_normal_options(arguments):
    check_arguments(arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        "--script vuln",
        "--script=default",
        "-sC",
        "-sV -A",
        "-iL targets.txt",
        "-iR 100",
    ],
)
def test_check_arguments_blocks_forbidden_options(arguments):
    with pytest.raises(InvalidScanRequestError):
        check_arguments(arguments)


def test_check_arguments_rejects_unreadable_text():
    with pytest.raises(InvalidScanRequestError):
        check_arguments('-sT "unclosed quote')


# ---------- error cleaning ----------

def test_privilege_error_is_explained():
    raw = "'You requested a scan type which requires root privileges.\\nQUITTING!\\n'"

    assert nmap_runner._explain_error(raw) == nmap_runner.PRIVILEGE_MESSAGE


def test_other_errors_are_cleaned():
    raw = "\"nmap: unrecognized option '--bogus'\\nSee the output of nmap -h.\\n\""

    message = nmap_runner._explain_error(raw)

    assert message.startswith("Nmap reported an error:")
    assert "unrecognized option" in message
    assert "\\n" not in message


def test_empty_error_message():
    assert "unknown error" in nmap_runner._explain_error("''")


# ---------- finding and asking Nmap (with fake replacements) ----------

def test_run_scan_without_nmap_raises(monkeypatch):
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda: None)

    with pytest.raises(NmapNotFoundError):
        run_scan(["127.0.0.1"], "-sT")


def test_run_scan_checks_input_before_looking_for_nmap(monkeypatch):
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda: None)

    with pytest.raises(InvalidScanRequestError):
        run_scan(["--version"], "-sT")


def test_get_nmap_version_reads_version(monkeypatch):
    fake_output = SimpleNamespace(
        stdout="Nmap version 7.993 ( https://nmap.org )\nPlatform: x\n"
    )
    monkeypatch.setattr(nmap_runner.subprocess, "run", lambda *a, **k: fake_output)

    assert get_nmap_version("fake-nmap") == "7.993"


def test_get_nmap_version_unreadable_output(monkeypatch):
    fake_output = SimpleNamespace(stdout="something unexpected")
    monkeypatch.setattr(nmap_runner.subprocess, "run", lambda *a, **k: fake_output)

    with pytest.raises(ScanFailedError):
        get_nmap_version("fake-nmap")


def test_get_nmap_version_when_not_installed(monkeypatch):
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda: None)

    with pytest.raises(NmapNotFoundError):
        get_nmap_version()


def test_all_scanner_errors_share_one_base_class():
    assert issubclass(NmapNotFoundError, ScannerError)
    assert issubclass(InvalidScanRequestError, ScannerError)
    assert issubclass(ScanFailedError, ScannerError)


def test_is_privileged_returns_a_bool():
    assert isinstance(is_privileged(), bool)


# ---------- one real scan of your own machine ----------

@pytest.mark.skipif(find_nmap() is None, reason="Nmap is not installed")
def test_real_scan_of_localhost():
    scanner = run_scan(["127.0.0.1"], "-sT -Pn", ports="1", timeout=60)

    assert "127.0.0.1" in scanner.all_hosts()