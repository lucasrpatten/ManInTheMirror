"""Manages command line arguments"""

import argparse

from Recon.network_scanner import NetworkScanner
from GainingAccess.arp_poison import ArpSpoof  # pylint: disable=fixme, no-name-in-module

scanner = NetworkScanner()
parser = argparse.ArgumentParser(prog="ManInTheMirror",
                                 description="Suite of tools to perform man in the middle attacks")

parser.add_argument("-A", "--arp_spoof", action="store_true", help="Perform mitm via ARP poisoning")

parser.add_argument("-t", "--thread_count",
                    help="Set number of threads to run the program with. Default=2 Minimum=2")

args = parser.parse_args()


def parse_cmd_line():
    """Parses command line arguments
    """
    access = None
    if args.arp_spoof:
        access = 0 # Code for arp spoofing
    else:
        scanner.scan()
        spoofer = ArpSpoof(scanner)
        spoofer.poison()
parse_cmd_line()