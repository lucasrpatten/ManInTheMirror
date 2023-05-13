"""Scans the network"""

import re
import struct
import socket
import subprocess
import uuid
from multiprocessing import Process, Manager
from arp import ARP
from dataclasses import dataclass
from arp import ArpRequest
import ipaddress
from progress_bar import ProgressBar


class Local:
    def __init__(self, interface) -> None:
        self.interface = interface
        self.mac_addr: bytes = self.__get_mac_addr()
        self.ip_addr = self.__get_ip_addr()
        self.gateway = self.__get_gateway()
        self.subnet_mask = self.__get_subnet_mask()

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
        sock.connect(('8.8.8.8', 80))
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
        raise ValueError("Could not determine default gateway")

    def __get_subnet_mask(self) -> str:
        """get local subnet mask

        Returns:
            str: subnet mask
        """
        proc = subprocess.Popen(
            ["ifconfig", self.interface], stdout=subprocess.PIPE)
        output = proc.communicate()[0].decode("utf-8")

        mask = re.search(r"netmask\s+([^\s]+)", output)
        if mask:
            return mask.group(1)
        else:
            raise ValueError("Could not determine subnet mask")


class NetworkScanner(Local):
    """Class containing network scanning tools
    """

    def __init__(self, verbosity=2, interface=socket.if_nameindex()[1][1]) -> None:
        super().__init__(interface)
        self.scanning = True
        self.verbosity = verbosity
        self.local_ips = Manager().list()

    def scan(self):
        if self.verbosity > 0:
            print("[*] Scanning local network")
        active = Process(target=self.active_scan)
        passive = Process(target=self.passive_scan)
        active.start()
        passive.start()

        active.join()
        passive.terminate()

        print(self.local_ips)

    def is_local_ip(self, ip_address):
        """Check if the given IP address is within the same IP network range as the local network"""
        try:
            lan = ipaddress.IPv4Network(f"{self.ip_addr}/{self.subnet_mask}")
            return ipaddress.IPv4Address(ip_address) in lan
        except ValueError:
            return False

    def passive_scan(self):
        """Listen to the local network (quietly)
        """

        ETHER_PROTOCOL = 0x0003
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETHER_PROTOCOL))
        print(
            f"[*] Listening for packets on interface {self.interface} (passive scan)")
        while self.scanning:
            packet, address = sock.recvfrom(4096)
            # Extract the source and destination IP addresses and ports from the packet
            ip_header = packet[14:34]
            try:
                src_ip = socket.inet_ntoa(ip_header[12:16])
                dst_ip = socket.inet_ntoa(ip_header[16:20])
            except OSError:
                continue
            if self.is_local_ip(src_ip) and src_ip not in self.local_ips and src_ip != self.ip_addr:
                self.local_ips.append(src_ip)
            if self.is_local_ip(dst_ip) and dst_ip not in self.local_ips and dst_ip != self.ip_addr:
                self.local_ips.append(dst_ip)
        return

    def active_scan(self):
        if self.verbosity > 0:
            print(
                f"[*] Scanning local network with subnet {self.subnet_mask} and gateway {self.gateway} (active scan)")
        network_addr = f"{self.ip_addr}/{self.subnet_mask}"
        network = ipaddress.IPv4Network(network_addr, strict=False)
        for ip_addr in set(network.hosts()):
            self.__active_scan_helper(ip_addr)
        self.scanning = False
        return

    def __active_scan_helper(self, ip_addr):
        if ip_addr in self.local_ips:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.01)
                sock.connect((str(ip_addr), 80))
        except (ConnectionRefusedError):
            self.local_ips.append(str(ip_addr))
        except (socket.timeout):
            pass
        return

    def get_hw_addresses(self):
        devices = []
        for addr in self.local_ips:
            ARP.send_arp(self.mac_addr, self.ip_addr, addr,
                         ARP.OPCODE_REQUEST, interface=self.interface)
            arp_ip = ""
            a = ""
            while arp_ip != addr:
                a = ARP.recv_arp()
                if a is not None:
                    arp_ip = a.spa

            print(a)


a = NetworkScanner()
a.local_ips = ["192.168.1.174"]
a.get_hw_addresses()
