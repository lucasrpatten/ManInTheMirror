from cmd_line_args import args
import scanner
import curses
import atexit


def get_vendor(mac) -> str:
    with open("mac-vendor.txt", "r", encoding="utf-8") as file:
        for line in file:
            addr, vendor = line.split()
            if addr.lower() == mac[:6]:
                return vendor
    return "unknown"


def selection(devices):
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
            device_str = f"{device[0]} ({device[1]})\tVendor: {get_vendor(device[0])}"
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
    s = scanner.NetworkScanner(verbosity=args.verbosity)
    s.scan()
    local_mac, gateway_ip, gateway_mac, devices = s.get_hw_addresses()

    selected_device = selection(devices)

    print("\n[*]Selected device:", selected_device)
