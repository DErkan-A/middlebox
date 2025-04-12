import socket, os
from scapy.all import sniff, UDP, IP

def udp_packet_handler(packet):
    """
    Callback function to process each captured UDP packet.
    It extracts the source IP, source port, destination port, and payload.
    """
    print("received")
    # Check if packet has a UDP layer
    if UDP in packet and IP in packet:
        src_ip = packet[IP].src
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        # Extract the UDP payload as bytes and attempt to decode it
        payload = bytes(packet[UDP].payload)
        try:
            payload_text = payload.decode('utf-8')
        except UnicodeDecodeError:
            payload_text = payload
        print(f"Received UDP packet from {src_ip}:{src_port} to port {dst_port} with payload: {payload_text}")

def udp_receiver():
    """
    Sniffs for incoming UDP traffic on all interfaces.
    Adjust the BPF filter if you want to restrict to a specific port.
    """
    print("Listening for UDP traffic...")
    # Optionally, restrict to port 8888 (as used by the sender) by uncommenting the filter below:
    filter_str = "udp and port 8888"
    sniff(filter=filter_str, prn=udp_packet_handler, store=False)
    #sniff(filter="udp", prn=udp_packet_handler, store=False)

if __name__ == "__main__":
    udp_receiver()