import threading
import socket
import struct
import time

class Receiver:
    def __init__(self, sender_ip):
        self.sender_ip = sender_ip
        self.message = bytearray()  # Shared buffer for decoded bytes
        self.bit_buffer = []  # Temporary buffer for bits (0 or 1)
        self.lock = threading.Lock()  # Ensure thread-safe access
        self.stop_event = threading.Event()  # Signal to stop receiving
        self.total_bytes = 0  # Track total bytes for throughput
        self.start_time = time.time()  # Track start time for throughput

    def process_packet(self, packet, protocol):
        """Process raw packet to decode bit based on protocol."""
        # Parse IP header (first 20 bytes, assuming no options)
        if len(packet) < 20:
            return
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
        pkt_protocol = ip_header[6]  # Protocol field
        src_ip = socket.inet_ntoa(ip_header[8])  # Source IP

        if src_ip != self.sender_ip or pkt_protocol != protocol:
            return

        bit = None
        if protocol == 6:  # TCP
            bit = 0
        elif protocol == 17:  # UDP
            bit = 1

        if bit is not None:
            with self.lock:
                self.bit_buffer.append(bit)
                #print(f"Received: proto={protocol} (bit={bit})")
                # Check if we have 8 bits to form a byte
                if len(self.bit_buffer) == 8:
                    # Convert bits to byte (MSB first)
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

    def get_throughput(self):
        """Calculate throughput in bytes per second since start or reset."""
        with self.lock:
            elapsed_time = time.time() - self.start_time
            if elapsed_time <= 0:
                return 0.0, self.total_bytes
            throughput = self.total_bytes / elapsed_time
            return throughput, self.total_bytes

    def reset_throughput(self):
        """Reset throughput counters."""
        with self.lock:
            self.total_bytes = 0
            self.start_time = time.time()

    def stop(self):
        self.stop_event.set()

def socket_receiver(interface, receiver, protocol):
    """Receive packets for a specific protocol (TCP or UDP) in a separate thread."""
    proto_name = "TCP" if protocol == 6 else "UDP"
    try:
        # Create raw socket for the specified protocol
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
        s.settimeout(1.0)  # Timeout to check stop_event
        # Bind to interface if specified (Linux-specific)
        if interface:
            try:
                s.bind((interface, 0))
            except socket.error as e:
                print(f"Warning: Failed to bind {proto_name} socket to {interface}: {e}")

        while not receiver.stop_event.is_set():
            try:
                packet, _ = s.recvfrom(65535)
                receiver.process_packet(packet, protocol)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"{proto_name} socket error: {e}")
        s.close()
    except PermissionError:
        print(f"Error: {proto_name} raw socket requires root/admin privileges. Run with sudo.")
    except Exception as e:
        print(f"Error setting up {proto_name} socket: {e}. Ensure interface '{interface}' exists.")

def start_receiver(interface, sender_ip):
    """Start the receiver with separate TCP and UDP sockets in threads."""
    receiver = Receiver(sender_ip)
    # Start TCP socket thread
    tcp_thread = threading.Thread(target=socket_receiver, args=(interface, receiver, 6))
    tcp_thread.daemon = True
    tcp_thread.start()
    # Start UDP socket thread
    udp_thread = threading.Thread(target=socket_receiver, args=(interface, receiver, 17))
    udp_thread.daemon = True
    udp_thread.start()
    return receiver