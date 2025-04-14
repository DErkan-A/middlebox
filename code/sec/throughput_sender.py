import covert_send_lib
import os
import argparse
import random

expected_size = 4096

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Sender: Send covert channel packets")
    parser.add_argument("-i", "--iface", type=str, default="eth0",
                        help="Network interface to use (default: eth0)")
    args = parser.parse_args()
    
    destination_ip = os.getenv('INSECURENET_HOST_IP')
    if not destination_ip:
        print("Environment variable INSECURENET_HOST_IP is not set.")
        exit(1)
    
    # For testing, use a mix of ASCII and non-ASCII bytes
    #covert_message = b"HELLO\x00\xFF\x80WORLD"
    covert_message = bytes([5]) * expected_size
    print(f"Generated data for sending")
    
    covert_send_lib.send_data(destination_ip, covert_message)