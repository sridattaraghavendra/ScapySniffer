# The client should read a configuration file, which is a json file that contains the rules configured for a machine on the firewall, for allow rules
# try all the protocol combinations to make sure that the firewall rules are enforced correctly.
from scapy.all import *
import sys
import json

def read_config():
    with open('rules.json', 'r') as f:
        config = json.load(f)
    return config

def handle_response_packet(packet):
    if packet.haslayer(IP):
        print("Received reply from server : ", packet.summary())

def send_packet(destination):
    print("Sending packet to", destination)
    packet = IP(dst=destination) / TCP(dport=80, flags="S")
    send(packet)

    sniff(filter="tcp and host " + destination, prn=handle_response_packet, timeout=1000)



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scapy-client.py <destination>")
        sys.exit(1)
    destination = sys.argv[1]
    conf = read_config()
    send_packet(destination)