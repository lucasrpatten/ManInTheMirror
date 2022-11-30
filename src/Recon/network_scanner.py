"""Scans the network"""

import struct
import os
import socket
import time
import uuid
import threading
from arp import Arp  # pylint: disable=fixme, no-name-in-module


class NetworkScanner:
    """Class containing network scanning tools
    """

    def __init__(self):
        self.mac_addr = self.get_mac_addr()
        self.ip_addr = self.get_ip_addr()
        self.passive_arp = True
        self.net_list: list[tuple[str, str]] = []
        self.arp = Arp()
        self.interface = socket.if_nameindex()[1][1]

    @staticmethod
    def get_mac_addr():
        """get local mac address

        Returns:
            bytes: mac address
        """
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]  # mac as 48 bit int
        return bytes.fromhex(mac)

    @staticmethod
    def get_ip_addr():
        """get local ip address

        Returns:
            _RetAddress: local ip
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # pylint: disable=fixme, invalid-name
        # Use invalid/unused IP address
        s.connect(('12.12.12.12', 6900))
        local_ip = s.getsockname()[0]
        s.close()
        return str(local_ip)

    @staticmethod
    def get_gate():
        """Read the default gateway directly from /proc."""
        with open("/proc/net/route", encoding="utf-8") as file:
            for line in file:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    # If not default route or not RTF_GATEWAY, skip it
                    continue

                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

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
            target = '.'.join([i for i in self.ip_addr.split('.')[:-1]]) + f".{i}"
            self.arp.send_arp(self.mac_addr, self.ip_addr, target)
