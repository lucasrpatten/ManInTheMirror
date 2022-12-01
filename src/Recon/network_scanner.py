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

    def __init__(self, method):
        self.mac_addr = self.get_mac_addr()
        self.scan_method = method
        self.ip_addr = self.get_ip_addr()
        self.passive_arp = True
        self.net_list: list[tuple[str, str]] = []
        self.ip_list = []
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

        arp_receiver = threading.Thread(target=recv_arp)
        scanner = None
        if self.scan_method == "arp":
            scanner = threading.Thread(target=self.scan_with_arp)
        elif self.scan_method == "tcp":
            scanner = threading.Thread(target=self.scan_with_tcp)
        else:
            RuntimeError("No Scanner Selected")
        arp_receiver.start()
        print("[*] Sniffing Arp...")
        scanner.start()
        print("[*] Scanning...")
        scanner.join()
        scan_arp = False  # stop scanning
        arp_receiver.join()

    def scan_with_arp(self, lower=0, upper=256):
        """Scan all ports with arp
        Args:
            lower (int, optional): Lower IP Range. Defaults to 0.
            upper (int, optional): Upper IP Range. Defaults to 256.
        """
        for i in range(lower, upper):
            target = '.'.join([i for i in self.ip_addr.split('.')[:-1]]) + f".{i}"
            self.arp.send_arp(self.mac_addr, self.ip_addr, target)
        time.sleep(10)

    def scan_with_tcp(self, lower=0, upper=256):
        """Scan network for connected ip's via tcp

        Args:
            lower (int, optional): Lower IP Range. Defaults to 0.
            upper (int, optional): Upper IP Range. Defaults to 256.
        """
        socket.setdefaulttimeout(1)
        for i in range(lower, upper):

            target = '.'.join([i for i in self.ip_addr.split('.')[:-1]]) + f".{i}"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            res = sock.connect_ex((target, 6910))
            if res == 0:
                self.ip_list.append(target)
            else:
                pass
