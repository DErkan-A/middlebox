import threading
import time
from scapy.all import sniff, IP, TCP, UDP

class Receiver:
    def __init__(self, sender_ip):
        self.sender_ip = sender_ip
        self.message = bytearray()  # Shared buffer for decoded bytes
        self.bit_buffer = []  # Temporary buffer for bits (0 or 1)
        self.lock = threading.Lock()  # Ensure thread-safe access
        self.stop_event = threading.Event()  # Signal to stop receiving
        self.total_bytes = 0  # Track total bytes for throughput

    def process_packet(self, pkt):
        """Process Scapy packet to decode bit based on protocol."""
        if IP in pkt and pkt[IP].src == self.sender_ip:
            bit = None
            if pkt[IP].proto == 6:  # TCP
                bit = 0
            elif pkt[IP].proto == 17:  # UDP
                bit = 1

            if bit is not None:
                with self.lock:
                    self.bit_buffer.append(bit)
                    #print(f"Received: proto={pkt[IP].proto} (bit={bit})")
                    if len(self.bit_buffer) == 8:
                        byte_val = sum(b << (7 - i) for i, b in enumerate(self.bit_buffer))
                        self.message.append(byte_val)
                        self.total_bytes += 1
                        #print(f"Decoded byte: {hex(byte_val)}")
                        self.bit_buffer.clear()

    def get_message(self):
        """Return a bytes copy of the message and clear the buffer."""
        with self.lock:
            message_copy = bytes(self.message)
            self.message.clear()
            return message_copy

    def stop(self):
        self.stop_event.set()

def packet_receiver(interface, receiver):
    """Run packet sniffing in a separate thread."""
    try:
        sniff(
            iface=interface,
            filter=f"ip and src host {receiver.sender_ip} and (tcp or udp)",
            prn=receiver.process_packet,
            store=False,
            stop_filter=lambda x: receiver.stop_event.is_set()
        )
    except Exception as e:
        print(f"Error sniffing packets: {e}. Ensure interface '{interface}' exists and has traffic.")

def start_receiver(interface, sender_ip):
    """Start the receiver in a separate thread and return the Receiver object."""
    receiver = Receiver(sender_ip)
    recv_thread = threading.Thread(target=packet_receiver, args=(interface, receiver))
    recv_thread.daemon = True
    recv_thread.start()
    return receiver