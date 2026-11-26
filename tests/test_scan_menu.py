
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
    feed(monkeypatch, scan_menu, "ask_yes_no", [True, True, True, True, True])

    options = ask_scan_options(("standard", None))

    assert options.profile_key == "standard"
    assert options.service_detection
    assert options.udp_scan
    assert options.os_estimation
    assert options.traceroute


def test_no_extras_chosen(monkeypatch):
    feed(monkeypatch, scan_menu, "ask_yes_no", [False, False, False, False, True])

    options = ask_scan_options(("full", None))

    assert options.profile_key == "full"
    assert not (
        options.service_detection
        or options.udp_scan
        or options.os_estimation
    )


def test_custom_ports_are_preserved(monkeypatch):
    feed(monkeypatch, scan_menu, "ask_yes_no", [False, False, False, False, True])

    options = ask_scan_options(("standard", "22,80"))

    assert options.profile_key == "standard"
    assert options.ports == "22,80"


def test_recommended_discovery_methods_are_the_default(monkeypatch):
    feed(monkeypatch, scan_menu, "ask_yes_no", [False, False, False, False, True])

    options = ask_scan_options(("quick", None))

    assert options.discovery_methods is None


def test_tcp_scan_can_choose_discovery_methods(monkeypatch):
    feed(monkeypatch, scan_menu, "ask_yes_no", [False, False, False, False, False])
    monkeypatch.setattr(
        scan_menu, "choose_methods_manually", lambda: ["tcp_syn", "udp"]
    )

    options = ask_scan_options(("quick", None))

    assert options.discovery_methods == ["tcp_syn", "udp"]


def test_choosing_no_methods_falls_back_to_recommended(monkeypatch, capsys):
    feed(monkeypatch, scan_menu, "ask_yes_no", [False, False, False, False, False])
    monkeypatch.setattr(scan_menu, "choose_methods_manually", lambda: None)

    options = ask_scan_options(("quick", None))

    assert options.discovery_methods is None
    assert "recommended discovery methods instead" in capsys.readouterr().out


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


def test_menu_numbers_follow_the_entry_list(monkeypatch):
    from argus.modules.port_scan import TCP_PROFILES

    entries = scan_menu.scanning_menu_entries()

    assert entries[0][1] == "discovery"
    assert entries[-1][1] == "custom"
    assert [action for _, action in entries[1:-1]] == list(TCP_PROFILES)

    for number, (_label, action) in enumerate(entries[1:-1], start=2):
        feed(monkeypatch, scan_menu, "get_menu_choice", [number])
        assert ask_scanning_choice() == (action, None)


def patch_discovery(monkeypatch, discover):
    monkeypatch.setattr(scan_menu, "ask_discovery_methods", lambda: ["tcp_syn"])
    monkeypatch.setattr(scan_menu, "ask_yes_no", lambda prompt: True)
    monkeypatch.setattr(scan_menu, "wait_for_enter", lambda *a, **k: None)
    monkeypatch.setattr(scan_menu, "discover_hosts", discover)
    shown = []
    monkeypatch.setattr(
        scan_menu, "show_scan_results", lambda result, **k: shown.append(result)
    )
    return shown


def test_discovery_result_is_stored_in_the_session(monkeypatch):
    result = ScanResult(targets=["10.0.0.5"], profile="discovery")
    shown = patch_discovery(monkeypatch, lambda targets, methods: result)
    session = make_session()

    scan_menu.run_discovery_flow(session)

    assert session.scan_result is result
    assert shown == [result]


def test_discovery_can_be_cancelled_with_ctrl_c(monkeypatch, capsys):
    def interrupted(targets, methods):
        raise KeyboardInterrupt

    shown = patch_discovery(monkeypatch, interrupted)
    session = make_session()

    scan_menu.run_discovery_flow(session)

    assert session.scan_result is None
    assert shown == []
    assert "Host discovery was cancelled" in capsys.readouterr().out


def test_discovery_errors_are_shown_and_not_stored(monkeypatch, capsys):
    def failing(targets, methods):
        raise NmapNotFoundError("Nmap was not found.")

    patch_discovery(monkeypatch, failing)
    session = make_session()

    scan_menu.run_discovery_flow(session)

    assert session.scan_result is None
    assert "Host discovery could not run" in capsys.readouterr().out


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
