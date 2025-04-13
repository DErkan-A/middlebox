import os
import argparse
import time
from scapy.all import sniff, IP, send
from collections import deque

chunk_size = 8
benchmark_data_size = 16 #Data size in bytes
benchmark_repetitions = 10 #Number of times the benchmark is repeated
class Receiver:
    def __init__(self, sender_ip, benchmark=False):
        self.sender_ip = sender_ip
        self.message = ""
        self.chunk_buffer = []
        self.recent_seq_nums = deque(maxlen=16)  # Track last 16 sequence numbers
        self.benchmark = benchmark
        self.total_bytes_received = 0  # Track total valid data bytes
        self.start_time = None  # Track start of transmission

    def send_ack(self):
        """Send single ACK (6)."""
        time.sleep(0.3)  # 300ms delay to reduce network overload
        pkt_ack = IP(dst=self.sender_ip, proto=6)
        send(pkt_ack, verbose=False)
        print(f"Sent ACK: proto=6")

    def process_packet(self, pkt):
        if IP in pkt and pkt[IP].src == self.sender_ip:
            proto_val = pkt[IP].proto
            print(f"Received: proto={proto_val}, char='{chr(proto_val) if 32 <= proto_val <= 126 else ''}'")
            # Set start time on first packet if benchmarking
            if self.benchmark and self.start_time is None:
                self.start_time = time.time()
            # Append all packets
            self.chunk_buffer.append(proto_val)
            if len(self.chunk_buffer) == chunk_size + 3:  # chunk_size data + SOT + seq_num + EOT = 9
                self.process_chunk()

    def process_chunk(self):
        """Validate and process chunk."""
        print("Processing")
        if (len(self.chunk_buffer) == chunk_size + 3 and 
            self.chunk_buffer[0] == 1 and 
            self.chunk_buffer[-1] == 4):
            seq_num = self.chunk_buffer[-2]  # Sequence number is second-to-last packet
            if seq_num not in self.recent_seq_nums:
                data = [chr(p) for p in self.chunk_buffer[1:chunk_size+1] if p != 0]  # Data packets 2–7
                self.message += ''.join(data)
                self.recent_seq_nums.append(seq_num)
                print(f"Valid chunk received, seq={seq_num}, message_len={len(self.message)}")
            else:
                print(f"Duplicate chunk, seq={seq_num}, sending ACK")
            self.send_ack()
            # Update total bytes for benchmark
            if self.benchmark:
                self.total_bytes_received += len(data)
                # Check if we've received approximately 1MB
                if self.total_bytes_received >= benchmark_data_size:
                    self.calculate_throughput()
                    return  # Stop processing to end benchmark
        else:
            print("Invalid chunk, no ACK sent")
        self.chunk_buffer = []

    def calculate_throughput(self):
        """Calculate and print throughput for benchmark mode."""
        if not self.benchmark or self.start_time is None:
            return
        end_time = time.time()
        elapsed_time = end_time - self.start_time
        if elapsed_time > 0:
            throughput_Bps = self.total_bytes_received / elapsed_time
            print(f"\nBenchmark Complete:")
            print(f"Total Data Received: {self.total_bytes_received} bytes")
            print(f"Elapsed Time: {elapsed_time:.2f} seconds")
            print(f"Throughput: {throughput_Bps:.2f} B/s")
            # Write result to file
            try:
                with open("benchmark_result.txt", "w") as f:
                    f.write(f"{elapsed_time:.6f}\n")
                    self.total_bytes_received = 0
            except Exception as e:
                print(f"Failed to write benchmark result to file: {e}")
        else:
            print("Elapsed time too small to calculate throughput.")

def covert_receive(interface, benchmark_flag):
    print(f"Sniffing for covert channel packets from {ALLOWED_IP} on interface '{interface}'...")
    receiver = Receiver(ALLOWED_IP, benchmark=benchmark_flag)
    try:
        sniff(iface=interface, filter=f"ip and src host {ALLOWED_IP}", 
              prn=receiver.process_packet, store=False)
    except Exception as e:
        print(f"An error occurred while sniffing: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Receiver: Sniff for covert channel packets")
    parser.add_argument("-i", "--iface", type=str, default="eth0",
                        help="Network interface to sniff on (default: eth0)")
    parser.add_argument("--benchmark", action="store_true",
                        help="Calculate throughput for 1MB of random data")
    args = parser.parse_args()

    ALLOWED_IP = os.getenv("SECURENET_HOST_IP")
    if not ALLOWED_IP:
        print("Environment variable SECURENET_HOST_IP is not set.")
        exit(1)
    
    covert_receive(args.iface, args.benchmark)