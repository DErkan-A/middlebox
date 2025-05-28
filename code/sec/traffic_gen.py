import covert_send_lib_hidden as covert_channel
import os
import argparse
import random

benchmark_iteration = 30
def benchmark(data_size):
    # generate data_size random bytes
    print(f"Generated data for sending")
    covert_channel.send_data(destination_ip, covert_message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Sender: Send covert channel packets")
    parser.add_argument("--num_process",type=int, default=1,
                        help="Number for processes generating traffic")
    
    destination_ip = os.getenv('INSECURENET_HOST_IP')
    if not destination_ip:
        print("Environment variable INSECURENET_HOST_IP is not set.")
        exit(1)
    
    if args.num_process != 0:
         bit_val = random.getrandbits(1)
         print("Under construction")
    else:
        print("Cannot have less than 1 process")
        exit(1)