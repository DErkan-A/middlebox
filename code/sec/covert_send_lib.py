from scapy.all import IP, send
import time

def send_data(dst_ip, data):
    packets = []
    for value in data:
        if(value > 0xFF):
            print(f"Cannot send value larger than 0xFF: {value}")
            exit(1)
        packets.append(IP(dst=dst_ip, proto=value))
    
    # Send all packets at once
    start_time = time.time()
    send(packets, verbose=False)
    elapsed_time = time.time() - start_time
    bytes_sent = len(data)
    throughput = bytes_sent / elapsed_time if elapsed_time > 0 else 0
    print(f"Sent data: {bytes_sent} bytes, Throughput: {throughput:.2f} B/s")