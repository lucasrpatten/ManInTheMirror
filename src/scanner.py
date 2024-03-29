"""Scans the network"""

import binascii
import ipaddress
import re
import socket
import struct
import subprocess
import time
import uuid
from multiprocessing import Manager, Process

from arp import ARP


class Local:
    """Contains information about the local device

    Args:
        interface (str): Interface to scan
    """

    def __init__(self, interface) -> None:
        self.interface: str = interface
        self.mac_addr: str = self.__get_mac_addr()
        self.ip_addr: str = self.__get_ip_addr()
        self.gateway: str = self.__get_gateway()
        self.subnet_mask: str = self.__get_subnet_mask()

    def __get_mac_addr(self) -> str:
        """get local mac address

        Returns:
            str: mac address
        """
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]  # mac as 48 bit int
        return mac

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

    Args:
        verbosity (int, optional): Logging message verbosity.
            0 = silent, 1 = minimal, 2 = normal, 3 = verbose, 4 = very verbose

        interface(str): Interface to scan with.
    """

    def __init__(self, verbosity, interface) -> None:
        super().__init__(interface)
        self.scanning: bool = True
        self.verbosity: int = verbosity
        self.local_ips = Manager().list()
        if self.verbosity > 3:
            print("[*] Local Device Info")
            print(f"\t[-] Interface: {self.interface}")
            print(f"\t[-] Mac Address: {self.mac_addr}")
            print(f"\t[-] IP Address: {self.ip_addr}")
            print(f"\t[-] Gateway: {self.gateway}")
            print(f"\t[-] Subnet Mask: {self.subnet_mask}")

    def scan(self):
        if self.verbosity > 0:
            print("[*] Scanning local network...")
        active = Process(target=self.active_scan)
        passive = Process(target=self.passive_scan)
        active.start()
        passive.start()

        active.join()
        passive.terminate()
        if self.verbosity > 0:
            print(
                f"[*] Network Scan Completed. Found {len(self.local_ips)} IP's")
        if self.verbosity > 2:
            print(f"[*] Active IP's {(i for i in self.local_ips)}")

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
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHER_PROTOCOL)) as sock:
            print("[*] Passive Scanning Started...")
            while self.scanning:
                packet, _ = sock.recvfrom(4096)
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

    def active_scan(self):
        if self.verbosity > 0:
            print("[*] Active Scanning Started...")
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
                sock.settimeout(0.5)
                sock.connect((str(ip_addr), 80))
        except ConnectionRefusedError:
            self.local_ips.append(str(ip_addr))
        except socket.timeout:
            pass
        return

    def get_hw_addresses(self):
        if self.verbosity > 0:
            print("[*] Sending ARP requests to get hw addresses...")
        devices: list[tuple[str, str]] = []
        gateway_mac = ""
        REQUEST_INTERVAL = 5
        RUN_FOR = 30
        start_time = time.monotonic()
        last_request = time.monotonic()
        while (time.monotonic() - start_time < RUN_FOR or gateway_mac == "") and len(devices) < len(self.local_ips):
            if time.monotonic() - last_request >= REQUEST_INTERVAL:
                last_request = time.monotonic()
                for addr in self.local_ips:
                    ARP.send_arp(binascii.unhexlify(self.mac_addr), self.ip_addr, addr,
                                 ARP.OPCODE_REQUEST, interface=self.interface)
            response = ARP.recv_arp()
            if response is not None:
                src_ip = response.spa
                src_mac = response.sha
                dst_ip = response.tpa
                dst_mac = response.tha
                if (src_mac, src_ip) not in devices:
                    if src_ip == self.gateway and gateway_mac == "":
                        gateway_mac = src_mac
                        if self.verbosity > 2:
                            print(
                                f"[*] Gateway MAC found: MAC={src_mac}")
                    else:
                        devices.append((src_mac, src_ip))
                        if self.verbosity > 2:
                            print(
                                f"[*] New device discovered: MAC={src_mac}, IP={src_ip}")
                dst_not_exist = (dst_mac, dst_ip) not in devices
                not_broadcast = dst_mac not in (
                    "000000000000", "ffffffffffff")
                if not_broadcast and dst_not_exist:
                    if dst_ip == self.gateway and gateway_mac == "":
                        gateway_mac = dst_mac
                        if self.verbosity > 2:
                            print(
                                f"[*] Gateway MAC found: MAC={dst_mac}")
                    else:
                        devices.append((dst_mac, dst_ip))
                        if self.verbosity > 2:
                            print(
                                f"[*] New device discovered: MAC={dst_mac}, IP={dst_ip}")

        return self.mac_addr, self.gateway, gateway_mac, [i for i in devices if i[1] != self.ip_addr]
