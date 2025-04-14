from scapy.all import IP, send

def send_data(dst_ip, data):
    packets = []
    for value in data:
        if(value > 0xFF):
            print(f"Cannot send value larger than 0xFF: {value}")
            exit(1)
        packets.append(IP(dst=dst_ip, proto=value))
    
    # Send all packets at once
    send(packets, verbose=False)
    #print(f"Sent data: {data}")