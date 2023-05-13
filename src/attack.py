from cmd_line_args import args
import scanner


def selection()


def attack() -> None:
    s = scanner.NetworkScanner(verbosity=args.verbosity)
    s.scan()
    devices = s.get_hw_addresses()
    print(devices)
