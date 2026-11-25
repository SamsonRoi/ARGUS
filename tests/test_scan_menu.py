
from argus import menus, scan_menu
from argus.modules.models import ScanResult
from argus.modules.nmap_runner import NmapNotFoundError
from argus.modules.scan_manager import ScanOptions
from argus.scan_menu import (
    ask_scan_options,
    ask_scanning_choice,
    describe_target,
    run_scan_flow,
    show_scope_check,
)
from argus.utils.session import Session


def feed(monkeypatch, module, name, answers):
    """Replace a prompt function with a ready-made list of answers."""
    remaining = iter(answers)
    monkeypatch.setattr(module, name, lambda *a, **k: next(remaining))


# ---------- showing targets ----------

def test_describe_target():
    assert describe_target("10.0.0.5") == "10.0.0.5"
    assert describe_target("192.168.1.0/24") == "192.168.1.0/24 (256 addresses)"
    assert describe_target("10.0.0.0/16") == "10.0.0.0/16 (65,536 addresses)"


def test_scope_check_shows_warnings_and_reminder(capsys):
    show_scope_check(["8.8.8.8", "127.0.0.1", "192.168.1.0/24"])

    text = capsys.readouterr().out

    assert "256 addresses" in text
    assert "Public IP address detected" in text
    assert "Loopback address detected" in text
    assert "does not check whether you are authorized" in text


def test_scope_check_without_warnings_is_still_shown(capsys):
    show_scope_check(["192.168.1.10"])

    text = capsys.readouterr().out

    assert "Target: 192.168.1.10" in text
    assert "[WARNING]" not in text


# ---------- choosing a scanning operation ----------

def test_scanning_menu_shows_all_options(monkeypatch, capsys):
    feed(monkeypatch, scan_menu, "get_menu_choice", [0])

    assert ask_scanning_choice() is None

    text = capsys.readouterr().out

    assert "SCANNING OPTIONS" in text
    assert "1. Host Discovery" in text
    assert "2. Quick" in text
    assert "3. Standard" in text
    assert "4. Full TCP" in text
    assert "5. Custom ports" in text


def test_choosing_host_discovery(monkeypatch):
    feed(monkeypatch, scan_menu, "get_menu_choice", [1])

    assert ask_scanning_choice() == ("discovery", None)


def test_choosing_quick_scan(monkeypatch):
    feed(monkeypatch, scan_menu, "get_menu_choice", [2])

    assert ask_scanning_choice() == ("quick", None)


def test_choosing_standard_scan(monkeypatch):
    feed(monkeypatch, scan_menu, "get_menu_choice", [3])

    assert ask_scanning_choice() == ("standard", None)


def test_choosing_full_scan(monkeypatch):
    feed(monkeypatch, scan_menu, "get_menu_choice", [4])

    assert ask_scanning_choice() == ("full", None)


def test_choosing_back(monkeypatch):
    feed(monkeypatch, scan_menu, "get_menu_choice", [0])

    assert ask_scanning_choice() is None


def test_custom_ports_ask_again_until_valid(monkeypatch, capsys):
    feed(monkeypatch, scan_menu, "get_menu_choice", [5])
    feed(
        monkeypatch,
        scan_menu,
        "get_text_input",
        ["80;ls", "70000", "22, 80"],
    )

    assert ask_scanning_choice() == ("standard", "22,80")

    text = capsys.readouterr().out
    assert "Invalid port entry" in text
    assert "between 1 and 65535" in text


# ---------- choosing optional TCP extras ----------

def test_all_extras_chosen(monkeypatch):
    feed(monkeypatch, scan_menu, "ask_yes_no", [True, True, True])

    options = ask_scan_options(("standard", None))

    assert options.profile_key == "standard"
    assert options.service_detection
    assert options.udp_scan
    assert options.os_estimation


def test_no_extras_chosen(monkeypatch):
    feed(monkeypatch, scan_menu, "ask_yes_no", [False, False, False])

    options = ask_scan_options(("full", None))

    assert options.profile_key == "full"
    assert not (
        options.service_detection
        or options.udp_scan
        or options.os_estimation
    )


def test_custom_ports_are_preserved(monkeypatch):
    feed(monkeypatch, scan_menu, "ask_yes_no", [False, False, False])

    options = ask_scan_options(("standard", "22,80"))

    assert options.profile_key == "standard"
    assert options.ports == "22,80"


# ---------- the whole scan screen ----------

def make_session():
    session = Session()
    session.set_target("Single IP", ["10.0.0.5"])
    return session


def patch_flow(monkeypatch, *, confirm=True, runner=None):
    shown = []
    ran = []

    monkeypatch.setattr(
        scan_menu,
        "ask_scanning_choice",
        lambda: ("quick", None),
    )
    monkeypatch.setattr(
        scan_menu,
        "ask_scan_options",
        lambda *args, **kwargs: ScanOptions(),
    )
    monkeypatch.setattr(
        scan_menu,
        "ask_yes_no",
        lambda prompt: confirm,
    )
    monkeypatch.setattr(
        scan_menu,
        "wait_for_enter",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        scan_menu,
        "show_scan_results",
        lambda result, **k: shown.append(result),
    )

    def default_runner(targets, options):
        ran.append(targets)
        return ScanResult(
            targets=targets,
            profile=options.describe(),
        )

    monkeypatch.setattr(
        scan_menu,
        "run_with_progress",
        runner or default_runner,
    )

    return shown, ran


def test_flow_without_targets_does_nothing(monkeypatch, capsys):
    shown, ran = patch_flow(monkeypatch)

    run_scan_flow(Session())

    assert ran == []
    assert "No targets are stored" in capsys.readouterr().out


def test_flow_runs_stores_and_shows_the_result(monkeypatch):
    shown, ran = patch_flow(monkeypatch)
    session = make_session()

    run_scan_flow(session)

    assert ran == [["10.0.0.5"]]
    assert session.scan_result is shown[0]
    assert session.scan_result.profile == "Standard TCP"


def test_flow_declined_scan_does_not_run(monkeypatch, capsys):
    shown, ran = patch_flow(monkeypatch, confirm=False)
    session = make_session()

    run_scan_flow(session)

    assert ran == []
    assert session.scan_result is None
    assert "Scan not started" in capsys.readouterr().out


def test_flow_backing_out_of_menu_does_not_run(monkeypatch, capsys):
    shown, ran = patch_flow(monkeypatch)
    monkeypatch.setattr(
        scan_menu,
        "ask_scanning_choice",
        lambda: None,
    )

    run_scan_flow(make_session())

    assert ran == []
    assert "Scanning setup cancelled" in capsys.readouterr().out


def test_flow_shows_scanner_errors_in_plain_words(monkeypatch, capsys):
    def failing(targets, options):
        raise NmapNotFoundError(
            "Nmap was not found. [bold]Install it[/bold]."
        )

    shown, ran = patch_flow(monkeypatch, runner=failing)
    session = make_session()

    run_scan_flow(session)

    text = capsys.readouterr().out

    assert "The scan could not run" in text
    assert "Nmap was not found" in text
    assert "[bold]Install it[/bold]" in text
    assert session.scan_result is None
    assert shown == []


def test_host_discovery_choice_calls_discovery_flow(monkeypatch):
    session = make_session()
    called = []

    monkeypatch.setattr(
        scan_menu,
        "ask_scanning_choice",
        lambda: ("discovery", None),
    )
    monkeypatch.setattr(
        scan_menu,
        "run_discovery_flow",
        lambda current_session: called.append(current_session),
    )

    run_scan_flow(session)

    assert called == [session]


# ---------- connecting the scan screen to the menus ----------

def patch_collect(monkeypatch, scan_now):
    session = Session()
    started = []

    monkeypatch.setattr(menus, "current_session", session)
    monkeypatch.setattr(
        menus,
        "get_text_input",
        lambda prompt: "10.0.0.5",
    )
    monkeypatch.setattr(
        menus,
        "ask_yes_no",
        lambda prompt: scan_now,
    )
    monkeypatch.setattr(
        menus,
        "run_scan_flow",
        lambda current_session: started.append(current_session),
    )

    return session, started


def test_storing_a_target_can_start_a_scan(monkeypatch):
    session, started = patch_collect(monkeypatch, scan_now=True)

    menus.collect_target("Single IP", "Enter IP address:")

    assert session.target == ["10.0.0.5"]
    assert started == [session]


def test_storing_a_target_without_scanning(monkeypatch):
    session, started = patch_collect(monkeypatch, scan_now=False)

    menus.collect_target("Single IP", "Enter IP address:")

    assert session.target == ["10.0.0.5"]
    assert started == []
