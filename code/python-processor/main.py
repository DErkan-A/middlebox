import asyncio
from nats.aio.client import Client as NATS
import os, random
from scapy.all import Ether
import Active_Warden

async def run():
    nc = NATS()

    warden = Active_Warden.ActiveWarden()   
    warden.add_rule(17, 12345, 80)
    warden.add_rule(6, 12345, 80) 
    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)

    async def message_handler(msg):
        subject = msg.subject
        data = msg.data #.decode()
        print(f"Received a message on '{subject}': {data}")
        packet = Ether(data)
        #print(packet.show())
        # Publish the received message to outpktsec and outpktinsec
        delay = random.expovariate(1 / 8e-3)
        await asyncio.sleep(delay)
        if subject == "inpktsec":
            match_result=warden.match_packet(packet)
            print("The match result is ", match_result)
            #If not match result add the packet header as a rule (Only adds TCP or UDP for now)
            if(match_result == None):
                warden.add_rule_from_packet(packet)
            await nc.publish("outpktinsec", msg.data)
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