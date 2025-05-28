import random
import time
from scapy.all import IP, TCP, UDP, send
from scapy.config import conf

def generate_fixed_bytes(size, value=17):
    """Generate a bytes object of specified size with all values set to the given value."""
    return bytes([value]) * size

def encode_packet(bit, dst_ip):
    """Create a packet for a bit: TCP (6) for 0, UDP (17) for 1."""
    if bit == 0:
        return IP(dst=dst_ip, proto=6) / TCP(sport=12345, dport=80)
    else:  # bit == 1
        return IP(dst=dst_ip, proto=17) / UDP(sport=12345, dport=80)

def send_data(dst_ip, data):
    """Send data as a sequence of TCP/UDP packets encoding bits."""
    packets = []
    bits_sent = 0
    for byte in data:
        # Convert byte to 8-bit binary string (e.g., 65 -> '01000001')
        binary = format(byte, '08b')
        for bit in binary:
            bit_val = int(bit)
            packets.append(encode_packet(bit_val, dst_ip))
            bits_sent += 1
    
    start_time = time.time()
    send(packets, verbose=False)
    elapsed_time = time.time() - start_time
    bytes_sent = len(data)
    throughput = bytes_sent / elapsed_time if elapsed_time > 0 else 0
    print(f"Sent data: {bytes_sent} bytes ({bits_sent} bits), Throughput: {throughput:.2f} B/s")
    return bytes_sent, throughput