"""Scans the network"""

import socket
import struct
import uuid
import binascii


def get_mac_addr():
    """get local mac address

    Returns:
        bytes: mac address
    """
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]  # mac as 48 bit int
    return bytes.fromhex(mac)


def get_ip_addr():
    """get local ip address

    Returns:
        _RetAddress: local ip
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # pylint: disable=fixme, invalid-name
    # Use invalid/unused IP address
    s.connect(('12.12.12.12', 6900))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip


def recv_arp():
    """ Scans the current network for arp responses
    """
    # sniff everything
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # pylint: disable=fixme, invalid-name
    while True:

        packet = s.recvfrom(2048)

        ethernet_header = packet[0][0:14]
        ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

        arp_header = packet[0][14:42]
        arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

        # skip non-ARP packets
        ethertype = ethernet_detailed[2]
        if ethertype != b'\x08\x06':
            continue

        print("Dest MAC:        ", binascii.hexlify(ethernet_detailed[0]))
        print("Source MAC:      ", binascii.hexlify(ethernet_detailed[1]))
        print("Type:            ", binascii.hexlify(ethertype))
        print("Hardware type:   ", binascii.hexlify(arp_detailed[0]))
        print("Protocol type:   ", binascii.hexlify(arp_detailed[1]))
        print("Hardware size:   ", binascii.hexlify(arp_detailed[2]))
        print("Protocol size:   ", binascii.hexlify(arp_detailed[3]))
        print("Opcode:          ", binascii.hexlify(arp_detailed[4]))
        print("Source MAC:      ", binascii.hexlify(arp_detailed[5]))
        print("Source IP:       ", socket.inet_ntoa(arp_detailed[6]))
        print("Dest MAC:        ", binascii.hexlify(arp_detailed[7]))
        print("Dest IP:         ", socket.inet_ntoa(arp_detailed[8]))
        return


def send_arp():
    """sends an arp request
    """
    interface = socket.if_nameindex()[1][1]
    local_ip = get_ip_addr()

    mac_addr = get_mac_addr()
    destination = b'\xff\xff\xff\xff\xff\xff'
    dst_ip = open('./.env', 'r', encoding='utf-8').read()
    protocol = 0x0806  # 0x0806 is reserved for ARP

    eth_header = struct.pack("!6s6sH", destination, mac_addr, protocol)

    htype = 1  # Hardware type: Ethernet
    ptype = 0x0800  # Protocol type: TCP IPV4
    hlen = 6  # Hardware Address Length
    plen = 4  # Protocl Address Length
    operation = 1  # request operations
    src = socket.inet_aton(local_ip)
    dst = socket.inet_aton(dst_ip)
    arp_header = struct.pack("!HHBBH6s4s6s4s", htype, ptype,
                             hlen, plen, operation, mac_addr, src, destination, dst)

    arp_packet = eth_header + arp_header

    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  # pylint: disable=fixme, invalid-name
    s.bind((interface, socket.htons(0x0800)))

    s.send(arp_packet)
    recv_arp()
    s.close()
