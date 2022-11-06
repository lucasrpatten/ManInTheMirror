"""Manages command line arguments"""

import argparse
from network_scanner import send_arp


parser = argparse.ArgumentParser(prog="ManInTheMirror")
parser.add_argument("-o", "--option")
args = parser.parse_args()


if parser.option:
    pass
else:
    send_arp()
