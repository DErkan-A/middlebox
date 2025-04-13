import os
from scapy.all import IP, send

def covert_send(dst_ip, message):
    """
    Send a covert message by encoding each character into the IP protocol field.
    :param dst_ip: Destination IP address (e.g., receiver host IP)
    :param message: String message to send covertly
    """
    for char in message:
        proto_val = ord(char)  # Convert character to its ASCII integer value.
        # Craft the packet: set the protocol field to this ASCII value.
        pkt = IP(dst=dst_ip, proto=proto_val) / b"CovertPayload"
        send(pkt, verbose=False)
        print(f"Sent packet with protocol {proto_val} (char: '{char}')")

if __name__ == "__main__":
    # Replace with the IP address of your receiver machine.
    destination_ip = os.getenv('INSECURENET_HOST_IP')
    covert_message = "HELLO"
    covert_send(destination_ip, covert_message)