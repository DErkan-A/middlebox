import threading
from scapy.all import sniff, IP, TCP, UDP

secure_port = 12345
insec_port  = 12345

class Receiver:
    def __init__(self, sender_ip):
        self.sender_ip = sender_ip
        self.message    = bytearray()  # decoded bytes
        self.bit_buffer = []           # collected bits
        self.lock       = threading.Lock()
        self.stop_event = threading.Event()
        self.total_bytes = 0

    def process_packet(self, pkt):
        """Only decode bits from TCP/UDP pkts matching secure→insec ports."""
        # must be IP from our sender
        if IP not in pkt or pkt[IP].src != self.sender_ip:
            return

        bit = None
        # TCP?
        if pkt.haslayer(TCP):
            l4 = pkt[TCP]
            if l4.sport == secure_port and l4.dport == insec_port:
                bit = 0
        # UDP?
        elif pkt.haslayer(UDP):
            l4 = pkt[UDP]
            if l4.sport == secure_port and l4.dport == insec_port:
                bit = 1

        if bit is not None:
            with self.lock:
                self.bit_buffer.append(bit)
                if len(self.bit_buffer) == 8:
                    byte_val = sum(b << (7 - i) for i, b in enumerate(self.bit_buffer))
                    self.message.append(byte_val)
                    self.total_bytes += 1
                    self.bit_buffer.clear()

    def get_message(self):
        with self.lock:
            msg = bytes(self.message)
            self.message.clear()
            return msg

    def stop(self):
        self.stop_event.set()


def packet_receiver(interface, receiver):
    """Sniff only secure→insecure TCP or UDP from sender_ip."""
    bpf = (
        f"ip "
        f"and src host {receiver.sender_ip} "
        f"and ("
          f"(tcp   and src port {secure_port} and dst port {insec_port}) or "
          f"(udp   and src port {secure_port} and dst port {insec_port})"
        f")"
    )

    try:
        sniff(
            iface=interface,
            filter=bpf,
            prn=receiver.process_packet,
            store=False,
            stop_filter=lambda pkt: receiver.stop_event.is_set()
        )
    except Exception as e:
        print(f"Error sniffing packets: {e}")


def start_receiver(interface, sender_ip):
    receiver = Receiver(sender_ip)
    t = threading.Thread(target=packet_receiver, args=(interface, receiver))
    t.daemon = True
    t.start()
    return receiver
