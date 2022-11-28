"""Scans the network"""

import struct
import os
import socket
import subprocess
import time
import uuid
import threading
from arp import Arp  # pylint: disable=fixme, no-name-in-module


class NetworkScanner:
    """Class containing network scanning tools
    """

    def __init__(self):
        self.get_mac_addr()
        self.get_ip_addr()
        self.passive_arp = True
        self.net_list: list[tuple[str, str]] = []
        self.arp = Arp()

    def get_mac_addr(self):
        """get local mac address

        Returns:
            bytes: mac address
        """
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]  # mac as 48 bit int
        self.mac_addr = bytes.fromhex(mac)

    def get_ip_addr(self):
        """get local ip address

        Returns:
            _RetAddress: local ip
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # pylint: disable=fixme, invalid-name
        # Use invalid/unused IP address
        s.connect(('12.12.12.12', 6900))
        local_ip = s.getsockname()[0]
        s.close()
        self.ip_addr = str(local_ip)

    def scan(self):
        """ Scan the local network
        """

        def recv_arp():
            while scan_arp is True:
                time.sleep(0.01)
                returned_value = self.arp.recv_arp(self.net_list)
                if returned_value is not None:
                    self.net_list.append(returned_value)

        scan_arp = True
        print("[*] Scanning...")

        arp_receiver = threading.Thread(target=recv_arp)
        arp_scanner = threading.Thread(target=self.scan_with_arp)
        arp_receiver.start()
        arp_scanner.start()
        arp_scanner.join()
        scan_arp = False  # stop scanning
        arp_receiver.join()

    def scan_with_arp(self, lower=0, upper=256):
        """Scan all ports with arp"""
        for i in range(lower, upper):
            ip = '.'.join([i for i in self.ip_addr.split('.')[:-1]]) + f".{i}"
            self.arp.send_arp(self.mac_addr, self.ip_addr, ip)

    def get_gate(self):
        """Read the default gateway directly from /proc."""
        with open("/proc/net/route", encoding="utf-8") as file:
            for line in file:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    # If not default route or not RTF_GATEWAY, skip it
                    continue

                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

    def format_menu(self, index, values):
        """Format Menu Items"""
        print(f"{index :>5}:  {values[0] :<17}{values[1] :^17}")

    def menu(self):
        """Display the menu to choose who to perform attack on
        """

        os.system('clear')
        menu_items = {

        }
        for count, value in enumerate(self.net_list):
            menu_items[count] = value
        self.format_menu("Index", ("IP Address", "MAC Address"))
        for key, value in menu_items.items():
            self.format_menu(key+1, value)
        while True:
            try:
                target_index: int = int(input("Select the host to attack (via index): "))
                target_index -= 1  # to get index right
                return menu_items[target_index]
            except (ValueError, KeyError) as exception:  # pylint: disable=fixme, unused-variable
                print("Not a valid input - Please try again")
