import os
from argus.banner import show_banner
from argus.menus import main_menu
from rich.console import Console

console= Console()

def main():
    console.clear()

    show_banner(clear=False)
    main_menu()


if __name__ == "__main__":
    main()
