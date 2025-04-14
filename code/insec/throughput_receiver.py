import covert_receive_lib
import os
import argparse

expected_size = 512

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Receiver: Sniff for covert channel packets")
    parser.add_argument("-i", "--iface", type=str, default="eth0",
                        help="Network interface to sniff on (default: eth0)")
    args = parser.parse_args()

    ALLOWED_IP = os.getenv("SECURENET_HOST_IP")
    if not ALLOWED_IP:
        print("Environment variable SECURENET_HOST_IP is not set.")
        exit(1)
    
    # Start the receiver
    receiver = covert_receive_lib.start_receiver(args.iface, ALLOWED_IP)
    print(f"Receiver started, sniffing on {args.iface} for packets from {ALLOWED_IP}")
    full_message = bytes()
    start_time = 0
    # Example: Main thread interacts with the shared buffer
    try:
        import time
        while(len(full_message)< expected_size):  # Run for a few iterations as a demo
            time.sleep(0.01)  # Wait to collect some packets
            message = receiver.get_message()
            #print(message)
            if(len(full_message)== 0):
                start_time = time.time()
            full_message = full_message + message    
        latency = time.time() - start_time
        throughput =  expected_size / latency
        print(f"Latenct is {latency} sec")
        print(f"Throughput is {throughput} B/s ")
        receiver.stop()    
    except KeyboardInterrupt:
        print("\nStopping receiver...")
        receiver.stop()
        print(f"The full message: {[hex(b) for b in full_message]}")