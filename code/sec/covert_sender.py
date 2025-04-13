import os
import time
import argparse
import threading
from scapy.all import IP, send, sniff
from scapy.config import conf

chunk_size = 6  # Data packets per chunk (excluding SOT, seq_num, EOT)
window_size = chunk_size  # Sliding window size

def encode_packet(char):
    """Encode a character or value into the protocol field."""
    return ord(char) if isinstance(char, str) else char

def send_chunk(dst_ip, chunk_data, seq_num):
    """Send a chunk of 9 packets: SOT, 6 data (or NUL), seq_num, EOT."""
    packets = []
    packets.append((1, 'SOT'))  # proto=1
    for i in range(chunk_size):
        if i < len(chunk_data):
            packets.append((ord(chunk_data[i]), chunk_data[i]))
        else:
            packets.append((0, 'NUL'))
    packets.append((seq_num, f'SEQ{seq_num}'))  # Sequence number
    packets.append((4, 'EOT'))  # proto=4
    
    for proto_val, label in packets:
        pkt = IP(dst=dst_ip, proto=proto_val)
        send(pkt, verbose=False)
        print(f"Sent packet: proto={proto_val}, label='{label}'")
    
    return packets

def ack_listener(dst_ip, iface, last_acked_seq, lock):
    """Thread to continuously read ACKs and update last_acked_seq."""
    conf.use_pcap = True
    expected_ack = False
    expected_seq = None
    
    while True:
        # Filter for ACK=6 or any seq_num (0–255)
        packets = sniff(iface=iface, 
                       filter=f"ip and src host {dst_ip} and (ip proto 6 or ip proto 0-255)",
                       timeout=0.1, count=1)
        if packets:
            proto_val = packets[0][IP].proto
            rtt = time.time()  # Approximate for logging
            if proto_val == 6:
                expected_ack = True
                print(f"Received ACK, time={rtt:.3f}s")
            elif expected_ack and 0 <= proto_val <= 255:
                with lock:
                    if proto_val > last_acked_seq[0] or (
                        proto_val == 0 and last_acked_seq[0] == 255):
                        last_acked_seq[0] = proto_val
                        print(f"Updated last_acked_seq={proto_val}, time={rtt:.3f}s")
                expected_ack = False
                expected_seq = None

def covert_send(dst_ip, message, iface):
    rtt_estimate = 3.0  # Initial timeout
    base = 0  # Window base seq_num
    next_seq = 0  # Next seq_num to send
    last_acked_seq = [-1]  # Shared variable, using list for mutability
    lock = threading.Lock()
    chunk_timestamps = {}  # Track send time for each seq_num
    chunks = {}  # Store chunks for retransmission
    
    # Start ACK listener thread
    ack_thread = threading.Thread(target=ack_listener, 
                                args=(dst_ip, iface, last_acked_seq, lock), 
                                daemon=True)
    ack_thread.start()
    
    # Split message into chunks
    while next_seq < (len(message) + chunk_size - 1) // chunk_size:
        # Send chunks within window
        while next_seq < base + window_size and next_seq < (len(message) + chunk_size - 1) // chunk_size:
            chunk_data = message[next_seq * chunk_size:(next_seq + 1) * chunk_size]
            print(f"Sending chunk: {chunk_data}, seq={next_seq}, timeout={rtt_estimate:.3f}s")
            send_chunk(dst_ip, chunk_data, next_seq)
            chunk_timestamps[next_seq] = time.time()
            chunks[next_seq] = chunk_data
            next_seq += 1
        
        # Check for timeouts and retransmissions
        current_time = time.time()
        for seq in range(base, next_seq):
            if seq in chunk_timestamps and current_time - chunk_timestamps[seq] > rtt_estimate:
                print(f"Timeout for seq={seq}, retransmitting")
                send_chunk(dst_ip, chunks[seq], seq)
                chunk_timestamps[seq] = time.time()
        
        # Update window based on last_acked_seq
        with lock:
            if last_acked_seq[0] >= base or (
                last_acked_seq[0] == 0 and base == 255):
                base = last_acked_seq[0] + 1
                # Update RTT based on earliest acked chunk
                if base - 1 in chunk_timestamps:
                    rtt = current_time - chunk_timestamps[base - 1]
                    rtt_estimate = 0.6 * rtt_estimate + 0.4 * max(rtt, 0.01)
                    print(f"Updated RTT estimate: {rtt_estimate:.3f}s")
                    # Clean up
                    for s in range(base):
                        chunk_timestamps.pop(s, None)
                        chunks.pop(s, None)
        
        time.sleep(0.01)  # Prevent tight loop

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Sender: Send covert channel packets")
    parser.add_argument("-i", "--iface", type=str, default="eth0",
                        help="Network interface to use (default: eth0)")
    args = parser.parse_args()
    
    destination_ip = os.getenv('INSECURENET_HOST_IP')
    if not destination_ip:
        print("Environment variable INSECURENET_HOST_IP is not set.")
        exit(1)
    
    covert_message = "HELLO WORLD"
    covert_send(destination_ip, covert_message, args.iface)