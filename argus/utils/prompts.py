
from rich.console import Console # type: ignore

console = Console()


def handle_exit():
    console.print("\n[yellow]Leaving ARGUS. Stay sharp.[/yellow]")
    raise SystemExit(0)


def get_menu_choice(prompt, valid_choices):
    while True:
        try:
            choice = console.input(
                f"\n[bold cyan]{prompt}[/bold cyan] "
            )

            if not choice.strip():
                console.print(
                    "[bold red]No input detected. Try again.[/bold red]"
                )
                continue

            if not choice.strip().isdigit():
                console.print(
                    "[bold red]Invalid input. Enter a number.[/bold red]"
                )
                continue

            choice = int(choice.strip())

            if choice not in valid_choices:
                console.print(
                    "[bold red]Invalid selection. Choose an available option.[/bold red]"
                )
                continue

            return choice

        except (KeyboardInterrupt, EOFError):
            handle_exit()


def get_text_input(prompt):
    while True:
        try:
            text = console.input(
                f"\n[bold cyan]{prompt}[/bold cyan] "
            ).strip()

            if not text:
                console.print(
                    "[bold red]Input cannot be empty. Try again.[/bold red]"
                )
                continue

            return text

        except (KeyboardInterrupt, EOFError):
            handle_exit()


def wait_for_enter(prompt="Press Enter to continue..."):
    try:
        console.input(f"\n[dim]{prompt}[/dim]")

    except (KeyboardInterrupt, EOFError):
        handle_exit()
