import os
import time
import argparse
from scapy.all import IP, send, sniff
from scapy.config import conf

chunk_size = 6  # Data packets per chunk (excluding SOT, seq_num, EOT)

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

def wait_for_response(dst_ip, timeout, iface):
    """Wait for ACK (6) and sequence number packet."""
    conf.use_pcap = True
    start_time = time.time()
    got_ack = False
    
    # Filter for ACK (6) or expected seq_num
    packets = sniff(iface=iface, timeout = timeout,
                    filter=f"ip and src host {dst_ip}",count=1)
    if packets:
        proto_val = packets[0][IP].proto
        rtt = time.time() - start_time
        if proto_val == 6:
            got_ack = True
            print(f"Received ACK, measured RTT={rtt:.3f}s")
        if got_ack:
            return True, rtt
    print(f"Timeout after {timeout:.3f}s, got_ack={got_ack}")
    return False, timeout

def covert_send(dst_ip, message, iface):
    rtt_estimate = 3.0  # Initial timeout, tuned to reduce retransmissions
    seq_num = 0  # Start sequence number
    
    # Split message into chunks
    for i in range(0, len(message), chunk_size):
        chunk_data = message[i:i + chunk_size]
        while True:
            print(f"Sending chunk: {chunk_data}, seq={seq_num}, timeout={rtt_estimate:.3f}s")
            send_chunk(dst_ip, chunk_data, seq_num)
            success, rtt = wait_for_response(dst_ip, rtt_estimate, iface)
            if success:
                rtt_estimate = 0.6 * rtt_estimate + 0.4 * max(rtt, 0.01)
                print(f"Updated RTT estimate: {rtt_estimate:.3f}s")
                seq_num = (seq_num + 1) % 256  # Increment sequence number
                break
            else:
                print("Retransmitting chunk")
                rtt_estimate = min(rtt_estimate * 1.5, 4.0)

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