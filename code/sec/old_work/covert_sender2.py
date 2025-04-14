import socket
import struct
import time
import os

def create_ip_header(src_ip, dst_ip, proto):
    # IP header fields (20 bytes)
    ver_ihl = 0x45  # Version 4, IHL 5 (20 bytes)
    tos = 0
    tot_len = 20 + 8  # IP header + 8 bytes dummy payload
    id = 54321  # Arbitrary ID
    frag_off = 0
    ttl = 255
    checksum = 0  # Kernel will calculate
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    # Pack header (big-endian)
    ip_header = struct.pack('!BBHHHBBH4s4s', ver_ihl, tos, tot_len, id, frag_off, ttl, proto, checksum, src, dst)
    return ip_header

def send_covert_message(src_ip, dst_ip, message):
    try:
        # Create raw socket (IPPROTO_RAW to control IP header)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        print("Error: Run as root (raw sockets require admin privileges).")
        return
    except Exception as e:
        print(f"Error creating socket: {e}")
        return

    print(f"Sending covert message: {message}")
    for char in message:
        # Create IP header with protocol = ASCII value of char
        ip_header = create_ip_header(src_ip, dst_ip, ord(char))
        # Dummy payload (8 bytes)
        payload = b'dummy123'
        packet = ip_header + payload
        # Send packet
        try:
            sock.sendto(packet, (dst_ip, 0))  # Port ignored for raw
            print(f"Sent packet with proto={ord(char)} for char '{char}'")
            #time.sleep(0.1)  # Avoid overwhelming receiver
        except Exception as e:
            print(f"Error sending packet: {e}")
    # Send end-of-message signal (proto=0)
    ip_header = create_ip_header(src_ip, dst_ip, 0)
    packet = ip_header + b'dummy123'
    sock.sendto(packet, (dst_ip, 0))
    print("Sent end-of-message signal")
    sock.close()

if __name__ == "__main__":
    SRC_IP = os.getenv("SECURENET_HOST_IP")  # Sender's IP
    DST_IP = os.getenv("INSECURENET_HOST_IP")  # Receiver's IP
    MESSAGE = "HELLO INSECURENET I AM YOUR COVERT SENDER GUY" * 256          # Message to send
    send_covert_message(SRC_IP, DST_IP, MESSAGE)