import socket
import time


def capture_traffic(gateway_ip, gateway_mac, target_ip, target_mac, interface, log_path="log.txt"):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.ntohs(0x0003))

    sock.settimeout(1)

    with open(log_path, "a", encoding="utf-8") as f:

        while True:
            try:
                packet, _ = sock.recvfrom(65535)
                ip_header = packet[14:34]
                source_ip = socket.inet_ntoa(ip_header[12:16])
                dest_ip = socket.inet_ntoa(ip_header[16:20])

                if source_ip == target_ip and dest_ip == gateway_ip:
                    f.write(
                        f"""\
Time: {time.time()}
Source: {source_ip}
Destination: {dest_ip}
Packet: {packet.hex()}

""")
                elif source_ip == gateway_ip and dest_ip == target_ip:
                    f.write(
                        f"""\
Time: {time.time()}
Source: {source_ip}
Destination: {dest_ip}
Packet: {packet.hex()}

""")
            except socket.timeout:
                continue
