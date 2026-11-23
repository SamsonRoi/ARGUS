from argus.utils.prompts import (
    get_menu_choice,
    get_text_input,
    wait_for_enter
)

from argus.utils.session import Session

current_session = Session()

def show_main_menu():
    print("\nMAIN MENU")
    print("1. New Scan")
    print("2. Current Session")
    print("3. Scan History")
    print("4. Reports")
    print("5. About / Help")
    print("0. Exit")


def show_new_scan_menu():
    print("\nNEW SCAN")
    print("1. Scan a CIDR range")
    print("2. Scan a single IP")
    print("3. Scan several IPs")
    print("0. Back")




def collect_target(target_type, prompt):
    print("\nTARGET CONFIGURATION")
    print(f"Selected target type: {target_type}")

    target = get_text_input(prompt)

    if current_session.is_active:
        print("\nEXISTING TARGET DETECTED")
        print("-" * 35)
        print(f"Current Target: {current_session.target}")
        print(f"New Target:     {target}")

        while True:
            confirmation = get_text_input(
                "Replace current target? (y/n):"
            ).lower()

            if confirmation == "y":
                break

            elif confirmation == "n":
                print("\nExisting target preserved.")
                print("New target discarded.")
                return None

            else:
                print("\nInvalid response. Enter y or n.")

    current_session.set_target(target_type, target)

    print("\nTarget successfully stored in session.")
    print(f"Target Type: {current_session.target_type}")
    print(f"Target: {current_session.target}")

    return target



def new_scan_menu():
    valid_choices = [0, 1, 2, 3]

    while True:
        show_new_scan_menu()

        choice = get_menu_choice(
            "Your next move:",
            valid_choices
        )

        
        if choice == 1:
            collect_target(
                "CIDR Range",
                "Enter the network range:"
            )

        elif choice == 2:
            collect_target(
                "Single IP",
                "Enter IP address:"
            )

        elif choice == 3:
            collect_target(
                "Multiple IPs",
                "Enter IPs separated by commas:"
            )

        elif choice == 0:
            break


def about_menu():
    print("\n" + "=" * 45)
    print("                 ABOUT ARGUS")
    print("=" * 45)

    print("\nARGUS - Network Attack Surface Mapper")
    print("See everything. Miss nothing.")

    print("\nPURPOSE")
    print("Discover and map network assets.")
    print("Identify potential security exposures.")
    print("Help prioritize defensive improvements.")

    print("\nAUTHORIZED USE")
    print("Only scan networks you own or have")
    print("explicit permission to assess.")

    print("\nSTATUS")
    print("ARGUS is currently under development.")

    wait_for_enter("Press Enter to return to the main menu...")


def show_scan_history():
    print("\nScan History is not built yet.")
    wait_for_enter("Press Enter to return to the main menu...")


def show_reports():
    print("\nReport generation is not built yet.")
    wait_for_enter("Press Enter to return to the main menu...")


def current_session_menu():
    while True:
        print("\nCURRENT SESSION")
        print("-" * 35)

        if current_session.is_active:
            print("Status: Active")
            print(f"Target Type: {current_session.target_type}")
            print(f"Target: {current_session.target}")
            print(
                "Started:",
                current_session.started_at.strftime(
                    "%d %B %Y, %I:%M %p %Z"
                )
            )

            print("\n1. Clear Session")
            print("0. Back")

            choice = get_menu_choice(
                "Your next move:",
                [0, 1]
            )

            if choice == 1:
                current_session.clear()
                print("\nSession cleared successfully.")

            elif choice == 0:
                break

        else:
            print("Status: No active session")
            print("Targets: None")
            print("Start time: None")

            wait_for_enter("Press Enter to return to the main menu...")
            break

def main_menu():
    valid_choices = [0, 1, 2, 3, 4, 5]

    while True:
        show_main_menu()

        choice = get_menu_choice(
            "Your next move:",
            valid_choices
        )

        if choice == 1:
            new_scan_menu()

        elif choice == 2:
            current_session_menu()

        elif choice == 3:
            show_scan_history()

        elif choice == 4:
            show_reports()

        elif choice == 5:
            about_menu()

        elif choice == 0:
            print("\nLeaving ARGUS. Stay sharp.")
            break
