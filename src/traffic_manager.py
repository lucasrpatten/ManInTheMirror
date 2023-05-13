import socket


def capture_traffic(gateway_mac, gateway_ip, target_mac, target_ip, log_path="log.txt"):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.ntohs(0x0003))
    sock.settimeout(1)

    with open(log_path, "a") as f:
        while True:
            try
