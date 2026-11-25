import pytest

from argus.modules import os_detect
from argus.modules.nmap_runner import InvalidScanRequestError
from argus.modules.os_detect import build_os_arguments, estimate_os, is_loopback


def test_is_loopback():
    assert is_loopback("127.0.0.1")
    assert is_loopback("127.0.0.0/8")
    assert not is_loopback("192.168.1.1")
    assert not is_loopback("8.8.8.8")


def test_os_arguments():
    arguments = build_os_arguments()

    assert "-O" in arguments
    assert "--osscan-limit" in arguments


def test_loopback_only_does_not_start_nmap(monkeypatch):
    def must_not_run(*args, **kwargs):
        raise AssertionError("Nmap should not have been started")

    monkeypatch.setattr(os_detect, "run_scan", must_not_run)

    assert estimate_os(["127.0.0.1"]) == []


def test_loopback_is_filtered_from_mixed_targets(monkeypatch, fake_scanner):
    captured = {}

    def fake_run_scan(targets, arguments, ports=None, timeout=300):
        captured["targets"] = targets
        return fake_scanner()

    monkeypatch.setattr(os_detect, "run_scan", fake_run_scan)

    estimate_os(["127.0.0.1", "10.0.0.5"])

    assert captured["targets"] == ["10.0.0.5"]


def test_guess_is_returned_with_accuracy(monkeypatch, fake_scanner):
    fake = fake_scanner(
        hosts={
            "10.0.0.5": {
                "status": {"state": "up"},
                "osmatch": [{"name": "Linux 5.4", "accuracy": "96"}],
            }
        }
    )
    monkeypatch.setattr(os_detect, "run_scan", lambda *a, **k: fake)

    hosts = estimate_os(["10.0.0.5"])

    assert hosts[0].os_guess.name == "Linux 5.4"
    assert hosts[0].os_guess.accuracy == 96


def test_host_without_a_guess_is_still_returned(monkeypatch, fake_scanner):
    fake = fake_scanner(hosts={"10.0.0.5": {"status": {"state": "up"}}})
    monkeypatch.setattr(os_detect, "run_scan", lambda *a, **k: fake)

    assert estimate_os(["10.0.0.5"])[0].os_guess is None


def test_bad_target_is_rejected():
    with pytest.raises(InvalidScanRequestError):
        estimate_os(["--version"])