import os
from argus.banner import show_banner
from argus.menus import main_menu


def main():
    os.system("cls" if os.name == "nt" else "clear")

    show_banner()
    main_menu()


if __name__ == "__main__":
    main()
