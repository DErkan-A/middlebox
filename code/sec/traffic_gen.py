import os
import argparse
import random
import threading
import time

import traffic_lib as traffic

def worker(socket_type,dst_ip, sport, dport, pareto_a, pareto_b, stop_event):
    """Thread body: loop send_data until stop_event is set."""
    while not stop_event.is_set():
        try:
            traffic.send_data(dst_ip, dport, sport, socket_type, pareto_a, pareto_b)
        except Exception as e:
            print(f"[{sport}->{dport}] error: {e}")
        # sleep for a uniform random time between 0 and 1 second
        time.sleep(random.uniform(0, 1))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Background traffic generator (Pareto bursts over TCP/UDP)"
    )
    parser.add_argument(
        "--num_process", type=int, default=1,
        help="Number of parallel traffic threads (>=1)"
    )
    parser.add_argument(
        "--pareto_a", type=float, default=1.0,
        help="Pareto shape parameter (α)"
    )
    parser.add_argument(
        "--pareto_b", type=float, default=1.0,
        help="Pareto scale parameter (β)"
    )
    args = parser.parse_args()

    dst_ip = os.getenv('INSECURENET_HOST_IP')
    if not dst_ip:
        print("Error: INSECURENET_HOST_IP is not set.")
        exit(1)

    if args.num_process < 1:
        print("Error: --num_process must be at least 1.")
        exit(1)

    stop_event = threading.Event()
    threads = []

    # spawn threads, each with unique ports in the 10000+ range
    for i in range(args.num_process):
        sport = 10000 + i
        dport = 10000 + i
        socket_type = random.choice([0, 1])
        t = threading.Thread(
            target=worker,
            args=(socket_type,dst_ip, sport, dport, args.pareto_a, args.pareto_b, stop_event),
            daemon=True
        )
        t.start()
        threads.append(t)
        print(f"Started thread #{i+1} ⇒ sport={sport}, dport={dport}")

    print(f"\n{len(threads)} traffic threads running. Press Ctrl+C to stop.\n")

    try:
        # keep main alive until Ctrl+C
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received; stopping threads…")
        stop_event.set()
        for t in threads:
            t.join()
        print("All threads stopped. Exiting.")