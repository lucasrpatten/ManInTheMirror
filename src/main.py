"""Program entry point"""

from cmd_line_args import args
import attack


def disclaimer_signed() -> bool:
    """Checks if the disclaimer has been signed.

    Returns:
        bool: True if disclaimer has been accepted
    """
    with open("disclaimer.txt", "r", encoding="utf-8") as file:
        line = ""
        for line in file:
            pass
        if line != "I agree":
            print("[!] Disclaimer not accepted")
            print("Please read disclaimer.txt carefully.")
            print("Write 'I agree' on the final line to signify your agreement.")
            return False
        return True


if __name__ == "__main__":
    if not disclaimer_signed():
        exit()
    attack.attack()
