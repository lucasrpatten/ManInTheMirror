"""Manages command line arguments"""

import argparse

from network_scanner import NetworkScanner

scanner = NetworkScanner()
parser = argparse.ArgumentParser(prog="ManInTheMirror")
parser.add_argument("-o", "--option", action="store_true")

parser.add_argument("-t", "--thread_count",
                    help="Set number of threads to run the program with. Default=2 Minimum=2")

args = parser.parse_args()


def parse_cmd_line():
    """Parses command line arguments
    """
    if args.option:
        print('a')
    else:
        scanner.scan()
        print(scanner.menu())
