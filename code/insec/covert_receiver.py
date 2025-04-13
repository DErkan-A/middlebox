import os
import argparse
from scapy.all import sniff, IP, send
from collections import deque

chunk_size = 6

class Receiver:
    def __init__(self, sender_ip):
        self.sender_ip = sender_ip
        self.message = ""
        self.chunk_buffer = []
        self.recent_seq_nums = deque(maxlen=16)  # Track last 16 sequence numbers

    def send_ack(self, seq_num):
        """Send single ACK (6) followed by sequence number."""
        pkt_ack = IP(dst=self.sender_ip, proto=6)
        send(pkt_ack, verbose=False)
        pkt_seq = IP(dst=self.sender_ip, proto=seq_num)
        send(pkt_seq, verbose=False)
        print(f"Sent ACK: proto=6, SEQ={seq_num}")

    def process_packet(self, pkt):
        if IP in pkt and pkt[IP].src == self.sender_ip:
            proto_val = pkt[IP].proto
            print(f"Received: proto={proto_val}, char='{chr(proto_val) if 32 <= proto_val <= 126 else ''}'")
            # Append all packets (no SOT reset to handle out-of-order delivery)
            self.chunk_buffer.append(proto_val)
            if len(self.chunk_buffer) == chunk_size + 3:  # 6 data + SOT + seq_num + EOT = 9
                self.process_chunk()

    def process_chunk(self):
        """Validate and process chunk."""
        print("Processing")
        if (len(self.chunk_buffer) == chunk_size + 3 and 
            self.chunk_buffer[0] == 1 and 
            self.chunk_buffer[-1] == 4):
            seq_num = self.chunk_buffer[-2]  # Sequence number is second-to-last packet
            if seq_num not in self.recent_seq_nums:
                data = [chr(p) for p in self.chunk_buffer[1:7] if p != 0]  # Data packets 2–7
                self.message += ''.join(data)
                self.recent_seq_nums.append(seq_num)
                print(f"Valid chunk received, seq={seq_num}, message='{self.message}'")
            else:
                print(f"Duplicate chunk, seq={seq_num}, sending ACK")
            self.send_ack(seq_num)
        else:
            print("Invalid chunk, no ACK sent")
        self.chunk_buffer = []

def covert_receive(interface):
    print(f"Sniffing for covert channel packets from {ALLOWED_IP} on interface '{interface}'...")
    receiver = Receiver(ALLOWED_IP)
    
    try:
        sniff(iface=interface, filter=f"ip and src host {ALLOWED_IP}", 
              prn=receiver.process_packet, store=False)
    except Exception as e:
        print(f"An error occurred while sniffing: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Receiver: Sniff for covert channel packets")
    parser.add_argument("-i", "--iface", type=str, default="eth0",
                        help="Network interface to sniff on (default: eth0)")
    args = parser.parse_args()
    
    ALLOWED_IP = os.getenv("SECURENET_HOST_IP")
    if not ALLOWED_IP:
        print("Environment variable SECURENET_HOST_IP is not set.")
        exit(1)
    
    covert_receive(args.iface)