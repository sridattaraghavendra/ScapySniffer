# The client should read a configuration file, which is a json file that contains the rules configured for a machine on the firewall, for allow rules
# try all the protocol combinations to make sure that the firewall rules are enforced correctly.
from scapy.all import *
import sys
import json
from functools import partial
import csv

def read_config():
    with open('rules.json', 'r') as f:
        config = json.load(f)
    return config

def send_tcp(target_ip, target_port, rule):
    print(target_ip, target_port, rule)    
    tcp_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    send(tcp_packet)

    sniff(filter=f"tcp and src host {target_ip}", prn=handle_response(partial(match_rule_to_reply, arg1=rule)), timeout=2)

def send_udp(target_ip, target_port, rule):
    udp_packet = IP(dst=target_ip) / UDP(dport=target_port)
    send(udp_packet)

    sniff(filter=f"udp and src host {target_ip}", prn=handle_response(partial(match_rule_to_reply, arg1=rule)), timeout=2)


def send_icmp(target_ip, rule):
    icmp_packet = IP(dst=target_ip) / ICMP()
    send(icmp_packet)
    
    sniff(filter=f"icmp and src host {target_ip}", prn=handle_response(partial(match_rule_to_reply, arg1=rule)), timeout=2)


def handle_response(callback, *args, **kwargs):
    def wrapper(packet):
        if packet.haslayer(TCP) and packet[TCP].flags & 0x12:  # Check if packet is TCP SYN-ACK
            print("Received TCP SYN-ACK reply from", packet[IP].src)
            # Call the callback function if a TCP reply is received
            callback(packet, *args, **kwargs)
        elif packet.haslayer(UDP):
            print("Received UDP reply from", packet[IP].src)
            # Call the callback function if a UDP reply is received
            callback(packet, *args, **kwargs)
        elif packet.haslayer(ICMP):
            print("Received ICMP reply from", packet[IP].src)
            # Call the callback function if an ICMP reply is received
            callback(packet, *args, **kwargs)
        else:
            print("No expected reply received")
            # Call another function if no expected reply is received
            match_rule_to_no_response(*args)

    return wrapper

def match_rule_to_reply(packet,rule):
    print(f"Response for rule: {rule['name']}")

    packet_details = {
        "timestamp": str(datetime.now()),
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "packet_length": len(packet),
        # Add more fields as needed
    }

    if packet.haslayer(ICMP):
        packet_details["icmp_type"] = packet[ICMP].type
        packet_details["icmp_code"] = packet[ICMP].code

    elif packet.haslayer(UDP):
        packet_details["udp_source_port"] = packet[UDP].sport
        packet_details["udp_destination_port"] = packet[UDP].dport

    elif packet.haslayer(TCP):
        packet_details["tcp_source_port"] = packet[TCP].sport
        packet_details["tcp_destination_port"] = packet[TCP].dport
        packet_details["tcp_flags"] = packet[TCP].flags

    if(packet_details["protocol"].lower() == rule["ip_protocol"].lower()):
        packet_details["Test Result"] = "Passed"
    else:
        packet_details["Test Result"] = "Failed"
    
    write_to_csv(packet_details)

    
def match_rule_to_no_response(rule):
    print(f"No response for rule: {rule['name']}")

    packet_details = {
        "timestamp": str(datetime.now())
    }
    if(packet_details["protocol"].lower() == rule["ip_protocol"].lower()):
        packet_details["Test Result"] = "Failed"
    else:
        packet_details["Test Result"] = "Passed"
    
    write_to_csv(packet_details)

def write_to_csv(packet_details):
    with open("test_results.csv", "a", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=packet_details.keys())
        if csv_file.tell() == 0:  # Check if file is empty, write headers if needed
            writer.writeheader()
        writer.writerow(packet_details)

def send_packet(config, destination):
    print(f"Sending packet to {destination}")
    print(config['firewall_rules'])
    for rule in config['firewall_rules']:
        print(f'Checking rule: {rule["name"]}')
        print(f"Allowed Protocol: {rule['ip_protocol']}")
        print(f"Allowed Port Range: {rule['from_port']}-{rule['to_port']}")
        for port in range(rule['from_port'], rule['to_port'] + 1):
            send_tcp(destination, port, rule)
            #send_udp(destination, port, rule)
            #send_icmp(destination, rule)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scapy-client.py <destination>")
        sys.exit(1)
    destination = sys.argv[1]
    config = read_config()
    print(config)
    send_packet(config,destination)