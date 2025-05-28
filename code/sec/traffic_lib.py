import os
import random
import time
import numpy as np
from scapy.all import IP, TCP, UDP, send
from scapy.config import conf

def encode_packet(bit, dst_ip,sport,dport):
    """Create a packet for a bit: TCP (6) for 0, UDP (17) for 1."""
    if bit == 0:
        return IP(dst=dst_ip, proto=6) / TCP(sport=sport, dport=dport)
    else:  # bit == 1
        return IP(dst=dst_ip, proto=17) / UDP(sport=sport, dport=dport)

def send_data(dst_ip,dport, sport, bit_val, Pareto_a, Pareto_b):
    """Send data as a sequence of TCP/UDP packets encoding bits."""
    packets = []
    burst_size = (np.random.pareto(Pareto_a) + 1) * Pareto_b
    for index in range(burst_size):
        packets.append(encode_packet(bit_val, dst_ip,sport,dport))
    
    start_time = time.time()
    send(packets, verbose=False)
    elapsed_time = time.time() - start_time
    throughput = burst_size / elapsed_time if elapsed_time > 0 else 0
    print(f"Sent data: {burst_size} packets, Throughput: {throughput:.2f} Packet/s")
    return burst_size, throughput