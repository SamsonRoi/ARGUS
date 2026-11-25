import sys

import pytest

from argus.modules import nmap_runner
from argus.modules.nmap_runner import (
    InvalidScanRequestError,
    ScanFailedError,
    ScanInterruptedError,
    ScanTimeoutError,
    _error_lines,
    _run_nmap,
    find_nmap,
    run_scan,
)

needs_nmap = pytest.mark.skipif(find_nmap() is None, reason="Nmap is not installed")

EMPTY_SCAN_XML = (
    '<?xml version="1.0"?><nmaprun scanner="nmap" args="x" start="1" '
    'startstr="x" version="7.94" xmloutputversion="1.05">'
    '<scaninfo type="connect" protocol="tcp" numservices="1" services="80"/>'
    '<verbose level="0"/><debugging level="0"/>'
    '<runstats><finished time="1" timestr="x" elapsed="0.1" summary="x" '
    'exit="success"/><hosts up="0" down="0" total="0"/></runstats></nmaprun>'
)


# ---------- running a program (a harmless Python one-liner stands in for Nmap) ----------

def test_run_nmap_returns_output_and_errors():
    command = [
        sys.executable,
        "-c",
        "import sys; print('out'); print('err', file=sys.stderr)",
    ]

    output, errors = _run_nmap(command, timeout=30)

    assert output.strip() == "out"
    assert errors.strip() == "err"


def test_run_nmap_times_out():
    command = [sys.executable, "-c", "import time; time.sleep(60)"]

    with pytest.raises(ScanTimeoutError):
        _run_nmap(command, timeout=1)


def test_run_nmap_missing_program():
    with pytest.raises(ScanFailedError):
        _run_nmap(["this-program-does-not-exist-argus"], timeout=5)


class FakeProcess:
    """A process whose communicate() is interrupted, like pressing Ctrl+C."""

    def __init__(self):
        self.killed = False
        self.waited = False

    def communicate(self, timeout=None):
        raise KeyboardInterrupt

    def kill(self):
        self.killed = True

    def wait(self):
        self.waited = True


def test_ctrl_c_kills_nmap_and_keeps_going_up(monkeypatch):
    fake = FakeProcess()
    monkeypatch.setattr(nmap_runner.subprocess, "Popen", lambda *a, **k: fake)

    with pytest.raises(KeyboardInterrupt):
        _run_nmap(["nmap"], timeout=5)

    assert fake.killed
    assert fake.waited


# ---------- reading Nmap's error stream ----------

def test_warnings_are_not_errors():
    stderr = "Warning: Hostname x resolves to 2 IPs.\n\nWARNING: something minor\n"

    assert _error_lines(stderr) == []


def test_real_errors_are_kept():
    stderr = "Warning: minor\nYou requested a scan type which requires root privileges.\nQUITTING!\n"

    assert _error_lines(stderr) == [
        "You requested a scan type which requires root privileges.",
        "QUITTING!",
    ]


# ---------- run_scan with a fake Nmap run ----------

def test_bad_port_list_never_reaches_nmap(monkeypatch):
    def must_not_run(*args, **kwargs):
        raise AssertionError("Nmap should not have been started")

    monkeypatch.setattr(nmap_runner, "_run_nmap", must_not_run)

    with pytest.raises(InvalidScanRequestError):
        run_scan(["127.0.0.1"], "-sT", ports="80;ls")


@needs_nmap
def test_targets_become_separate_command_items(monkeypatch):
    captured = {}

    def fake_run(command, timeout):
        captured["command"] = command
        return EMPTY_SCAN_XML, ""

    monkeypatch.setattr(nmap_runner, "_run_nmap", fake_run)

    run_scan(["10.0.0.5", "192.168.1.0/24"], "-sT -Pn", ports="80,443")

    command = captured["command"]

    assert command[1:3] == ["-oX", "-"]
    assert command[3:5] == ["10.0.0.5", "192.168.1.0/24"]
    assert command[5:7] == ["-p", "80,443"]
    assert command[7:] == ["-sT", "-Pn"]


@needs_nmap
def test_privilege_error_becomes_friendly_message(monkeypatch):
    stderr = "You requested a scan type which requires root privileges.\nQUITTING!\n"
    monkeypatch.setattr(nmap_runner, "_run_nmap", lambda *a, **k: ("", stderr))

    with pytest.raises(ScanFailedError) as caught:
        run_scan(["127.0.0.1"], "-sS")

    assert str(caught.value) == nmap_runner.PRIVILEGE_MESSAGE


@needs_nmap
def test_half_finished_output_means_interrupted(monkeypatch):
    half_finished = '<?xml version="1.0"?><nmaprun scanner="nmap"><scaninfo'
    monkeypatch.setattr(nmap_runner, "_run_nmap", lambda *a, **k: (half_finished, ""))

    with pytest.raises(ScanInterruptedError):
        run_scan(["127.0.0.1"], "-sT")


@needs_nmap
def test_empty_output_means_interrupted(monkeypatch):
    monkeypatch.setattr(nmap_runner, "_run_nmap", lambda *a, **k: ("", ""))

    with pytest.raises(ScanInterruptedError):
        run_scan(["127.0.0.1"], "-sT")