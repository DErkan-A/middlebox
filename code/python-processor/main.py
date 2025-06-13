import asyncio
from nats.aio.client import Client as NATS
import os, random
from scapy.all import Ether, IP, TCP, UDP
import Active_Warden

adjust_interval = 256
error_margin = 0.1

def print_packet(packet):
        l4 = None
        if packet[IP].proto == 6:
            l4 = packet[TCP]
        elif packet[IP].proto == 17:
            l4 = packet[UDP]
        print("Procotol", packet[IP].proto, "Source port: ", l4.sport, "Destination Port: ", l4.dport)

async def run():
    nc = NATS()

    warden = Active_Warden.ActiveWarden()   
    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)

    async def message_handler(msg):
        if(warden._total % adjust_interval == 0):
            warden.adjust_actions_for_balanced_pairs(error_margin)
        subject = msg.subject
        data = msg.data #.decode()
        #print(f"Received a message on '{subject}': {data}")
        packet = Ether(data)
        #print(packet.show())
        # Publish the received message to outpktsec and outpktinsec
        delay = random.expovariate(1 / 8e-3)
        await asyncio.sleep(delay)
        if subject == "inpktsec":
            RID, action = match_result=warden.record_packet(packet)
            #If not match result add the packet header as a rule (Only adds TCP or UDP for now)
            if(RID == None):
                warden.add_rule_from_packet(packet)
            if(action !=1):
                await nc.publish("outpktinsec", msg.data)
            else:
                print("Dropped the packet")
                print_packet(packet)    
        else:
            await nc.publish("outpktsec", msg.data)
   
    # Subscribe to inpktsec and inpktinsec topics
    await nc.subscribe("inpktsec", cb=message_handler)
    await nc.subscribe("inpktinsec", cb=message_handler)

    print("Subscribed to inpktsec and inpktinsec topics")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Disconnecting...")
        await nc.close()

if __name__ == '__main__':
    asyncio.run(run())