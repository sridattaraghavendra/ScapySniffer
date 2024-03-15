# The server should listen on all possible ports and log any data received from any client and send it back.
from scapy.all import *
import sys
import json
import csv
from datetime import datetime
import netifaces

def read_port_info():
    with open('server_ports.json', 'r') as f:
        config = json.load(f)
    return config

def get_ip_address(interface_name):
    try:
        # Get the addresses of the specified interface
        addresses = netifaces.ifaddresses(interface_name)
        # Extract and return the IPv4 address
        ipv4_address = addresses[netifaces.AF_INET][0]['addr']
        return ipv4_address
    except (KeyError, ValueError):
        return None
    

def handle_packet(packet):
    packet_details = {
        "timestamp": str(datetime.now()),
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "packet_length": len(packet)
    }

    if packet.haslayer(TCP):
        handle_tcp(packet)
        packet_details["source_port"] = packet[TCP].sport
        packet_details["destination_port"] = packet[TCP].dport
        packet_details["flags"] = packet[TCP].flags
    elif packet.haslayer(UDP):
        handle_udp(packet)
        packet_details["source_port"] = packet[UDP].sport
        packet_details["destination_port"] = packet[UDP].dport
    elif packet.haslayer(ICMP):
        handle_icmp(packet)
        packet_details["icmp_type"] = packet[ICMP].type
        packet_details["icmp_code"] = packet[ICMP].code

    with open("packet_details.csv", "a", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=packet_details.keys())
        if csv_file.tell() == 0:  # Check if file is empty, write headers if needed
            writer.writeheader()
        writer.writerow(packet_details)


def handle_tcp(packet):
    if packet[TCP].flags & 0x02:  # Check if packet is SYN
        print("Received TCP SYN packet from", packet[IP].src)

        # Craft TCP SYN-ACK reply
        reply = IP(dst=packet[IP].src) / TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="SA")
        send(reply)

        print("Sent TCP SYN-ACK reply to", packet[IP].src)


def handle_udp(packet):
    print("Received UDP packet from", packet[IP].src)

    # Craft UDP reply
    reply = IP(dst=packet[IP].src) / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
    send(reply)

    print("Sent UDP reply to", packet[IP].src)


def handle_icmp(packet):
    if packet[ICMP].type == 8:  # Check if packet is ICMP echo request
        print("Received ICMP Echo Request from", packet[IP].src)

        # Craft ICMP Echo Reply
        reply = IP(dst=packet[IP].src) / ICMP(type=0) / packet[Raw].load
        send(reply)

        print("Sent ICMP Echo Reply to", packet[IP].src)


def start_server(ports, src_ip, host):
    print("Started server on", host, "on ports", ports)
    for port in ports:
        sniff(filter=f"(tcp or udp or icmp) and port {port} and host {src_ip} and not src host {host}", prn=handle_packet, iface=interface_name, store=0)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scapy-server.py <interface_name> <src_ip> <--all-ports>")
        sys.exit(1)
    interface_name = sys.argv[1]
    src_ip = sys.argv[2]
    host = get_ip_address(interface_name)
    print(f"Server IP: {host}")
    ports = read_port_info()["ports"]

    if "--all-ports" in sys.argv:
        ports = list(range(1, 65535))

    start_server(ports, src_ip, host)