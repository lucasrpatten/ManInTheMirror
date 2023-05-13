"""Arp Related Functions, Classes, and Methods
"""

import binascii
import socket
import struct
from dataclasses import dataclass


@dataclass
class ArpRequest:
    htype: bytes
    ptype: bytes
    hlen: bytes
    plen: bytes
    opcode: bytes
    sha: str
    spa: str
    tha: str
    tpa: str


class ARP:
    """Arp related methods"""
    ETHERNET_TYPE = b'\x08\x06'
    ETHERNET_PROTOCOL = 0x0003
    HARDWARE_TYPE_ETHERNET = 1
    PROTOCOL_TYPE_IPV4 = 0x0800
    PROTOCOL_TYPE_ARP = 0x0806
    HARDWARE_SIZE_ETHERNET = 6
    PROTOCOL_SIZE_IPV4 = 4
    OPCODE_REQUEST = 1
    OPCODE_REPLY = 2

    @staticmethod
    def recv_arp():
        """ Scans the current network for arp responses
        """
        # sniff everything
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(
            ARP.ETHERNET_PROTOCOL))

        packet = sock.recvfrom(2048)

        ethernet_header = packet[0][0:14]
        ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

        # skip non-ARP packets
        ethertype = ethernet_detailed[2]
        if ethertype != ARP.ETHERNET_TYPE:
            return

        arp_header = packet[0][14:42]
        arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
        request = ArpRequest(
            htype=binascii.hexlify(arp_detailed[0]),
            ptype=binascii.hexlify(arp_detailed[1]),
            hlen=binascii.hexlify(arp_detailed[2]),
            plen=binascii.hexlify(arp_detailed[3]),
            opcode=binascii.hexlify(arp_detailed[4]),
            sha=binascii.hexlify(arp_detailed[5]).decode(),
            spa=socket.inet_ntoa(arp_detailed[6]),
            tha=binascii.hexlify(arp_detailed[7]).decode(),
            tpa=socket.inet_ntoa(arp_detailed[8])
        )
        sock.close()
        return request

    @staticmethod
    def send_arp(src_mac, src_ip, dst_ip, operation=1, dst_mac=b'\xff\xff\xff\xff\xff\xff', interface=None):
        """sends an arp request
        """

        if not interface:
            interface = socket.if_nameindex()[1][1]

        protocol = ARP.PROTOCOL_TYPE_ARP
        eth_header = struct.pack("!6s6sH", dst_mac, src_mac, protocol)

        htype = ARP.HARDWARE_TYPE_ETHERNET
        ptype = ARP.PROTOCOL_TYPE_IPV4
        hlen = ARP.HARDWARE_SIZE_ETHERNET
        plen = ARP.PROTOCOL_SIZE_IPV4
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)
        arp_header = struct.pack("!HHBBH6s4s6s4s", htype, ptype,
                                 hlen, plen, operation, src_mac, src, dst_mac, dst)

        arp_packet = eth_header + arp_header

        sock = socket.socket(
            socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ARP.PROTOCOL_TYPE_IPV4))
        sock.bind((interface, socket.htons(ARP.PROTOCOL_TYPE_IPV4)))

        sock.send(arp_packet)
        sock.close()
