"""Scans the network"""

import re
import struct
import socket
import subprocess
import time
import uuid
import threading
from arp import ARP
from dataclasses import dataclass
from arp import ArpRequest


class Local:
    def __init__(self) -> None:
        self.mac_addr = self.__get_mac_addr()
        self.ip_addr = self.__get_ip_addr()
        self.gateway = self.__get_gateway()

    def __get_mac_addr(self) -> bytes:
        """get local mac address

        Returns:
            bytes: mac address
        """
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]  # mac as 48 bit int
        return bytes.fromhex(mac)

    def __get_ip_addr(self) -> str:
        """get local ip address

        Returns:
            str(_RetAddress): local ip
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        local_ip = sock.getsockname()[0]
        sock.close()
        return str(local_ip)

    def __get_gateway(self) -> str:
        """Read the default gateway directly from /proc.

        Returns:
            str: default gateway
        """
        with open("/proc/net/route", encoding="utf-8") as file:
            for line in file:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    # If not default route or not RTF_GATEWAY, skip it
                    continue

                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))


@dataclass
class Device:
    hw_addr: str
    ip_addr: str


class NetworkScanner(Local):
    """Class containing network scanning tools
    """

    def __init__(self, method):
        super().__init__()
        self.scan_method = method
        self.passive_arp = True
        self.net_list: list[Device] = []
        self.local_ips: list[str] = []
        self.arp = ARP()
        self.interface = socket.if_nameindex()[1][1]

    def passive_scan(self):
        """Listen to the local network (quietly)
        """
        ETHER_PROTOCOL = 0x0003
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETHER_PROTOCOL))
        while True:
            packet, address = sock.recvfrom(4096)
            # Extract the source and destination IP addresses and ports from the packet
            ip_header = packet[14:34]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])
            tcp_header = packet[34:54]
            src_port = int.from_bytes(tcp_header[0:2], byteorder='big')
            dst_port = int.from_bytes(tcp_header[2:4], byteorder='big')

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
        if self.scan_method == "arp":  # Arp
            scanner = threading.Thread(target=self.scan_with_arp)
        elif self.scan_method == "tcp":
            scanner = threading.Thread(target=self.scan_with_tcp)
        else:
            raise RuntimeError("No Scanner Selected")
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
            target = '.'.join(
                [i for i in self.ip_addr.split('.')[:-1]]) + f".{i}"
            self.arp.send_arp(self.mac_addr, self.ip_addr, target)
        time.sleep(10)

    def get_arp_tables(self):
        """
            Get current system arp tables
        """
        arp_tables = subprocess.check_output(["arp", "-a"]).decode()
        arp_tables = [re.sub(r"(.*?\()|(\) at)|( \[.*?\] on .*\n)", "", arp_tables).split(" ")
                      for i in arp_tables.splitlines()]
        _ = [self.ip_list.append(arp_tables[i]) for i in arp_tables]

    def scan_with_tcp(self, lower=0, upper=256):
        """Scan network for connected ip's via tcp

        Args:
            lower (int, optional): Lower IP Range. Defaults to 0.
            upper (int, optional): Upper IP Range. Defaults to 256.
        """
        socket.setdefaulttimeout(.1)
        for i in range(lower, upper):

            target = '.'.join(
                [i for i in self.ip_addr.split('.')[:-1]]) + f".{i}"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # only works with windows devices - need to add ports to get mac, iphone, android, and linux
            res = sock.connect_ex((target, 135))
            print(i)
            if res == 0:
                self.ip_list.append(target)
            else:
                pass
        print(self.ip_list)
        time.sleep(40)
