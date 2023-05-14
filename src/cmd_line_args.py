"""Manages command line arguments"""

import argparse
from socket import if_nameindex


parser = argparse.ArgumentParser(prog="ManInTheMirror",
                                 description="Suite of tools to perform man in the middle attacks. Written by lucasrpatten.",
                                 formatter_class=argparse.RawTextHelpFormatter)

VERBOSITY_HELP = """\
logging message verbosity (default: %(default)s)
    0 = silent
    1 = minimal
    2 = normal
    3 = verbose
    4 = very verbose
"""
parser.add_argument("-v", "--verbosity", type=int,
                    default=2,
                    help=VERBOSITY_HELP)
parser.add_argument("-i", "--interface", type=str,
                    default=if_nameindex()[1][1],
                    help="Wireleses interface to use")

parser.add_argument("--version", action="version",
                    version="%(prog)s v. pre-alpha")


args = parser.parse_args()
