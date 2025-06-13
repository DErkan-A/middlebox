import covert_receive_lib_binary as covert_channel
import os
import argparse
import time

benchmark_iteration = 30
def benchmark(receiver, expected_size):
    full_message = bytes()
    start_time = 0
    # Example: Main thread interacts with the shared buffer
    import time
    while(len(full_message)< expected_size):  # Run for a few iterations as a demo
        time.sleep(0.1)  # Wait to collect some packets
        message = receiver.get_message()
        #print(message)
        if(len(full_message)== 0):
            start_time = time.time()
        full_message = full_message + message    
    latency = time.time() - start_time
    throughput =  expected_size / latency
    print(f"Latency is {latency} sec")
    print(f"Throughput is {throughput} B/s ")
    return (latency)


def standard_receiver(receiver):
    full_message = bytes()
    # Example: Main thread interacts with the shared buffer
    try:
        import time
        while(True):  # Run for a few iterations as a demo
            time.sleep(0.01)  # Wait to collect some packets
            message = receiver.get_message()
            if(len(message)!= 0):
                print(f"Current message: {[hex(b) for b in message]}")
                full_message = full_message + message
    except KeyboardInterrupt:
        print("\nStopping receiver...")
        receiver.stop()
        print("Message length: ", len(full_message))
        print(f"The full message: {[hex(b) for b in full_message]}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Receiver: Sniff for covert channel packets")
    parser.add_argument("-i", "--iface", type=str, default="eth0",
                        help="Network interface to sniff on (default: eth0)")
    parser.add_argument("--benchmark",type=int, default=0,
                        help="Calculate throughput for random data")
    args = parser.parse_args()

    ALLOWED_IP = os.getenv("SECURENET_HOST_IP")
    if not ALLOWED_IP:
        print("Environment variable SECURENET_HOST_IP is not set.")
        exit(1)
    
    # Start the receiver
    receiver = covert_channel.start_receiver(args.iface, ALLOWED_IP)
    print(f"Receiver started, sniffing on {args.iface} for packets from {ALLOWED_IP}")
    if args.benchmark != 0:
        try:
            for i in range(benchmark_iteration):
                latency = benchmark(receiver, args.benchmark)
                try:
                    with open("benchmark_result.txt", "a") as f:
                        f.write(f"{latency:.6f}\n")
                except Exception as e:
                    print(f"Failed to write benchmark result to file: {e}")
            receiver.stop()
        except KeyboardInterrupt:
            print("\nStopping receiver...")
            receiver.stop() 
    else:
        standard_receiver(receiver)    