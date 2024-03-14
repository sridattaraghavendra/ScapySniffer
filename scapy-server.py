# The server should listen on all possible ports and log any data received from any client and send it back.
from scapy.all import *
import sys

def handle_packet(packet):
    print("Responding to client with:", packet.summary())
    send(packet)

def start_server(ports):
    print("Starting server")
    for port in ports:
        sniff(filter=f"port {port} and host 127.0.0.1", prn=handle_packet, iface=interface_name, store=0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scapy-server.py <interface_name>")
        sys.exit(1)
    interface_name = sys.argv[1]
    ports = [80]
    start_server(ports)