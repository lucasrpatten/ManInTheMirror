"""Scans the network"""

import os
import socket
import struct
import uuid
import binascii
import threading


class NetworkScanner:
    """Class containing network scanning tools
    """

    def __init__(self):
        self.get_mac_addr()
        self.get_ip_addr()
        self.run = True
        self.net_list: list[tuple(str, str)] = []

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

    def recv_arp(self):
        """ Scans the current network for arp responses
        """
        # sniff everything
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(
            0x0003))  # pylint: disable=fixme, invalid-name
        while True:
            if self.run is False:
                break

            packet = sock.recvfrom(2048)

            ethernet_header = packet[0][0:14]
            ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

            arp_header = packet[0][14:42]
            arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

            # skip non-ARP packets
            ethertype = ethernet_detailed[2]
            if ethertype != b'\x08\x06':
                continue

            ethertype = binascii.hexlify(ethertype)
            hardware_type = binascii.hexlify(arp_detailed[0])  # pylint: disable=fixme, unused-variable
            protocol_type = binascii.hexlify(arp_detailed[1])  # pylint: disable=fixme, unused-variable
            hardware_size = binascii.hexlify(arp_detailed[2])  # pylint: disable=fixme, unused-variable
            protocol_size = binascii.hexlify(arp_detailed[3])  # pylint: disable=fixme, unused-variable
            opcode = binascii.hexlify(arp_detailed[4])  # pylint: disable=fixme, unused-variable
            source_mac = binascii.hexlify(arp_detailed[5])
            source_ip = socket.inet_ntoa(arp_detailed[6])
            dest_mac = binascii.hexlify(arp_detailed[7])  # pylint: disable=fixme, unused-variable
            dest_ip = socket.inet_ntoa(arp_detailed[8])  # pylint: disable=fixme, unused-variable
            response = (source_ip, source_mac.decode())
            if response not in self.net_list:
                self.net_list.append(response)
        sock.close()
        self.run = True
        return

    def send_arp(self, ip_number):
        """sends an arp request
        """
        interface = socket.if_nameindex()[1][1]

        destination = b'\xff\xff\xff\xff\xff\xff'
        split_ip = self.ip_addr.split('.')
        dst_ip = '.'.join(i for i in split_ip[:-1]) + '.' + str(ip_number)
        protocol = 0x0806  # 0x0806 is reserved for ARP

        eth_header = struct.pack("!6s6sH", destination, self.mac_addr, protocol)

        htype = 1  # Hardware type: Ethernet
        ptype = 0x0800  # Protocol type: TCP IPV4
        hlen = 6  # Hardware Address Length
        plen = 4  # Protocl Address Length
        operation = 1  # request operations
        src = socket.inet_aton(self.ip_addr)
        dst = socket.inet_aton(dst_ip)
        arp_header = struct.pack("!HHBBH6s4s6s4s", htype, ptype,
                                 hlen, plen, operation, self.mac_addr, src, destination, dst)

        arp_packet = eth_header + arp_header

        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.bind((interface, socket.htons(0x0800)))

        sock.send(arp_packet)
        sock.close()

    def scan_with_arp(self):
        """Scan all ports with arp"""
        for i in range(0, 256):
            self.send_arp(i)

    def scan(self):
        """ Scan the local network
        """
        arp_receiver = threading.Thread(target=self.recv_arp)
        arp_scanner = threading.Thread(target=self.scan_with_arp)
        arp_receiver.start()
        arp_scanner.start()
        arp_scanner.join()
        self.run = False
        arp_receiver.join()

    def menu(self):
        """Display the menu to choose who to perform attack on
        """
        os.system('clear')
        for i in self.net_list:
            print(i)


ns = NetworkScanner()

ns.scan()
