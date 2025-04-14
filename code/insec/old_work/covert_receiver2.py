import socket
import struct
import os

def receive_covert_message(src_ip):
    try:
        # Create raw socket to capture IP packets
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.bind(('', 0))  # Bind to all interfaces
    except PermissionError:
        print("Error: Run as root (raw sockets require admin privileges).")
        return
    except Exception as e:
        print(f"Error creating socket: {e}")
        return

    print(f"Listening for covert message from {src_ip}...")
    message = ""
    while True:
        try:
            # Receive packet (max 65535 bytes)
            packet, addr = sock.recvfrom(65535)
            # Check if packet is from source IP
            print("Received a packet!")
            if addr[0] == src_ip:
                # Unpack IP header (first 20 bytes)
                ip_header = packet[:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                proto = iph[6]  # Protocol field
                if proto == 0:
                    print("Received end-of-message signal")
                    break
                if proto != 0:
                    char = chr(proto)
                    print(f"Received char: {char} (proto={proto})")
                    message += char
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue
    sock.close()
    print(f"Covert message received: {message}")
    return message

if __name__ == "__main__":
    SRC_IP = os.getenv("SECURENET_HOST_IP")  # Sender's IP
    receive_covert_message(SRC_IP)