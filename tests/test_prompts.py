import pytest

from argus.utils import prompts
from argus.utils.prompts import ask_yes_no, get_menu_choice, get_text_input


def feed(monkeypatch, answers):
    """Make the prompts read from a ready-made list instead of the keyboard."""
    remaining = iter(answers)
    monkeypatch.setattr(prompts.console, "input", lambda *a, **k: next(remaining))


@pytest.mark.parametrize("answer", ["y", "Y", "yes", " YES "])
def test_yes_answers(monkeypatch, answer):
    feed(monkeypatch, [answer])

    assert ask_yes_no("Continue?") is True


@pytest.mark.parametrize("answer", ["n", "N", "no", " No "])
def test_no_answers(monkeypatch, answer):
    feed(monkeypatch, [answer])

    assert ask_yes_no("Continue?") is False


def test_yes_no_asks_again_after_bad_input(monkeypatch):
    feed(monkeypatch, ["maybe", "", "42", "y"])

    assert ask_yes_no("Continue?") is True


def test_menu_choice_rejects_bad_input_then_accepts(monkeypatch):
    feed(monkeypatch, ["", "abc", "²", "9", "-1", " 2 "])

    assert get_menu_choice("Pick:", [0, 1, 2]) == 2


def test_text_input_skips_empty_lines(monkeypatch):
    feed(monkeypatch, ["", "   ", " hello "])

    assert get_text_input("Say something:") == "hello"


@pytest.mark.parametrize("error", [KeyboardInterrupt, EOFError])
def test_ctrl_c_and_ctrl_d_leave_quietly(monkeypatch, error):
    def raise_error(*args, **kwargs):
        raise error

    monkeypatch.setattr(prompts.console, "input", raise_error)

    with pytest.raises(SystemExit):
        get_menu_choice("Pick:", [0, 1])