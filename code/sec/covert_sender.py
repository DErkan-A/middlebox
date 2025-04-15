import covert_send_lib_binary as covert_channel
import os
import argparse
import time

benchmark_iteration = 30
def benchmark(data_size):
    covert_message = bytes([5]) * data_size
    print(f"Generated data for sending")
    covert_channel.send_data(destination_ip, covert_message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Sender: Send covert channel packets")
    parser.add_argument("-i", "--iface", type=str, default="eth0",
                        help="Network interface to use (default: eth0)")
    parser.add_argument("--benchmark",type=int, default=0,
                        help="Calculate throughput for random data")
    parser.add_argument("--message",type=str, default="HELLO INSECURENET",
                        help="Calculate throughput for random data")
    args = parser.parse_args()
    
    destination_ip = os.getenv('INSECURENET_HOST_IP')
    if not destination_ip:
        print("Environment variable INSECURENET_HOST_IP is not set.")
        exit(1)
    
    if args.benchmark != 0:
        for i in range(benchmark_iteration):
            benchmark(args.benchmark)
            time.sleep(5)
    else:
       covert_channel.send_data(destination_ip, args.message)