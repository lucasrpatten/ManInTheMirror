"""Manages command line arguments"""

import argparse
import os
import time

from Recon.network_scanner import NetworkScanner
from GainingAccess.arp_poison import ArpSpoof  # pylint: disable=fixme, no-name-in-module

scanner = NetworkScanner()
parser = argparse.ArgumentParser(prog="ManInTheMirror",
                                 description="Suite of tools to perform man in the middle attacks")

parser.add_argument("-A", "--arp_spoof", action="store_true", help="Perform mitm via ARP poisoning")
parser.add_argument("-t", "--thread_count",
                    help="Set number of threads to run the program with. Default=2 Minimum=2")

args = parser.parse_args()


def access_method_menu():
    """Menu to select required gaining access values if not provided
    """
    os.system("clear")
    selection = None
    while True:
        print("[1]: Arp Poisoning")
        try:
            selection = int(input("Select method to gain access: "))
            if selection in [1]:
                break
        except ValueError:
            pass
        print("Not A Valid Selection\n")
    return selection


def parse_cmd_line():
    """Parses command line arguments
    """
    access = None
    if args.arp_spoof:
        access = 1  # Code for arp spoofing

    else:
        access = access_method_menu()
    if access == 1:
        scanner.scan()
        spoofer = ArpSpoof(scanner)
        spoofer.poison()
