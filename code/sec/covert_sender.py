import os
import socket
import time

from scapy.all import IP, UDP, TCP, send
import time

# Configuration (set receiver IP and common port)
DST_IP = os.getenv('INSECURENET_HOST_IP')   # Replace with your receiver's IP address
DST_PORT = 8888             # The common port for both TCP and UDP

def send_covert_bit(bit):
    ip = IP(dst=DST_IP)
    if bit == "1":
        # For a covert bit of 1, send a TCP packet.
        pkt = ip/TCP(sport=12345, dport=DST_PORT)/b"CovertTCP"
        print("Sending TCP packet for covert bit 1")
    elif bit == "0":
        # For a covert bit of 0, send a UDP packet.
        pkt = ip/UDP(sport=12345, dport=DST_PORT)/b"CovertUDP"
        print("Sending UDP packet for covert bit 0")
    else:
        print("Invalid bit:", bit)
        return
    send(pkt, verbose=False)

if __name__ == "__main__":
    # Example covert message. Each bit is encoded as per the above:
    covert_message = "1010"
    for bit in covert_message:
        send_covert_bit(bit)
        time.sleep(1)  # Delay between packets for clarity