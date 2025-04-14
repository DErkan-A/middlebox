import threading
from scapy.all import sniff, IP

class Receiver:
    def __init__(self, sender_ip):
        self.sender_ip = sender_ip
        self.message = bytearray()  # Shared buffer for binary data
        self.lock = threading.Lock()  # Ensure thread-safe access
        self.stop_event = threading.Event()  # Signal to stop sniffing

    def process_packet(self, pkt):
        if IP in pkt and pkt[IP].src == self.sender_ip:
            proto_val = pkt[IP].proto
            with self.lock:
                self.message.append(proto_val)  # Store raw 8-bit value
            #print(f"Received: proto={proto_val:02x} (hex)")

    def get_message(self):
        with self.lock:
            message_copy = bytes(self.message)  # Return a copy as bytes
            self.message.clear()  # Clear the shared buffer
            #print("Message buffer cleared")
            return message_copy

    def stop(self):
        self.stop_event.set()

def packet_sniffer(interface, receiver):
    """Run packet sniffing in a separate thread."""
    try:
        sniff(
            iface=interface,
            filter=f"ip and src host {receiver.sender_ip}",
            prn=receiver.process_packet,
            store=False,
            stop_filter=lambda x: receiver.stop_event.is_set()
        )
    except Exception as e:
        print(f"An error occurred while sniffing: {e}")

def start_receiver(interface, sender_ip):
    """Start the receiver in a separate thread and return the Receiver object."""
    receiver = Receiver(sender_ip)
    sniff_thread = threading.Thread(target=packet_sniffer, args=(interface, receiver))
    sniff_thread.daemon = True  # Allow program to exit even if thread is running
    sniff_thread.start()
    return receiver