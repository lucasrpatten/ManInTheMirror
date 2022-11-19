"""Arp Related Functions, Classes, and Methods
"""

import binascii
import socket
import struct


class Arp:
    "Arp related methods"

    def recv_arp(self, net_list):
        """ Scans the current network for arp responses
        """
        # sniff everything
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(
            0x0003))  # pylint: disable=fixme, invalid-name

        packet = sock.recvfrom(2048)

        ethernet_header = packet[0][0:14]
        ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

        arp_header = packet[0][14:42]
        arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

        # skip non-ARP packets
        ethertype = ethernet_detailed[2]
        if ethertype != b'\x08\x06':
            pass
        else:
            ethertype = binascii.hexlify(ethertype)
            hardware_type = binascii.hexlify(arp_detailed[0])  # pylint: disable=fixme, unused-variable
            protocol_type = binascii.hexlify(arp_detailed[1])  # pylint: disable=fixme, unused-variable
            hardware_size = binascii.hexlify(arp_detailed[2])  # pylint: disable=fixme, unused-variable
            protocol_size = binascii.hexlify(arp_detailed[3])  # pylint: disable=fixme, unused-variable
            opcode = binascii.hexlify(arp_detailed[4])  # pylint: disable=fixme, unused-variable
            source_mac = binascii.hexlify(arp_detailed[5]).decode()
            source_ip = socket.inet_ntoa(arp_detailed[6])
            dest_mac = binascii.hexlify(arp_detailed[7])  # pylint: disable=fixme, unused-variable
            dest_ip = socket.inet_ntoa(arp_detailed[8])  # pylint: disable=fixme, unused-variable
            source_mac = ':'.join(source_mac[i:i+2] for i in range(0, len(source_mac), 2))
            response = (source_ip, source_mac)
            if response not in net_list:
                sock.close()
                return response

    def send_arp(self, ip_number, mac_addr, ip_addr):
        """sends an arp request
        """
        interface = socket.if_nameindex()[1][1]

        destination = b'\xff\xff\xff\xff\xff\xff'
        split_ip = ip_addr.split('.')
        dst_ip = '.'.join(i for i in split_ip[:-1]) + '.' + str(ip_number)
        protocol = 0x0806  # 0x0806 is reserved for ARP

        eth_header = struct.pack("!6s6sH", destination, mac_addr, protocol)

        htype = 1  # Hardware type: Ethernet
        ptype = 0x0800  # Protocol type: TCP IPV4
        hlen = 6  # Hardware Address Length
        plen = 4  # Protocol Address Length
        operation = 1  # request operations
        src = socket.inet_aton(ip_addr)
        dst = socket.inet_aton(dst_ip)
        arp_header = struct.pack("!HHBBH6s4s6s4s", htype, ptype,
                                 hlen, plen, operation, mac_addr, src, destination, dst)

        arp_packet = eth_header + arp_header

        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.bind((interface, socket.htons(0x0800)))

        sock.send(arp_packet)
        sock.close()
