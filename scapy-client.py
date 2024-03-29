# The client should read a configuration file, which is a json file that contains the rules configured for a machine on the firewall, for allow rules
# try all the protocol combinations to make sure that the firewall rules are enforced correctly.
from scapy.all import *
import sys
import json
import csv

def read_config():
    with open('rules.json', 'r') as f:
        config = json.load(f)
    return config

def send_tcp(target_ip, target_port, config):
    print(target_ip, target_port)    
    tcp_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")

    # filter rule from config if not None
    rule = filter_rule(config, "tcp", target_port)
    reply = sr(tcp_packet,timeout=5)
    if(len(reply[0].res) > 0):
        handle_response_blocking(reply[0].res[0].answer, rule, tcp_packet)
    else:
        handle_response_blocking(None, rule, tcp_packet)


def send_udp(target_ip, target_port, rule):
    udp_packet = IP(dst=target_ip) / UDP(dport=target_port)

    rule = filter_rule(config, "udp", target_port)
    reply = sr(udp_packet,timeout=5)
    if(len(reply[0].res) > 0):
        handle_response_blocking(reply[0].res[0].answer, rule, udp_packet)
    else:
        handle_response_blocking(None, rule, udp_packet)

def send_icmp(target_ip, rule):
    icmp_packet = IP(dst=target_ip) / ICMP()

    rule = filter_rule(config, "icmp", None)
    reply = sr(icmp_packet,timeout=5)
    if(len(reply[0].res) > 0):
        handle_response_blocking(reply[0].res[0].answer, rule, icmp_packet)
    else:
        handle_response_blocking(None, rule, icmp_packet)

def filter_rule(config, protocol, port):
    for rule in config['firewall_rules']:
        if rule['ip_protocol'] == protocol and (rule['port'] == port or port == None):
            return rule

def handle_response_blocking(packet, rule, sent_packet):
    if packet is None:
        print("No expected reply received")
        match_rule_to_no_response(rule, sent_packet)
    else:
        if packet.haslayer(TCP) and packet[TCP].flags & 0x12:
            print("Received TCP SYN-ACK reply from", packet[IP].src)
            match_rule_to_reply(packet, rule)
        elif packet.haslayer(UDP):
            print("Received UDP reply from", packet[IP].src)
            match_rule_to_reply(packet, rule)
        elif packet.haslayer(ICMP):
            print("Received ICMP reply from", packet[IP].src)
            match_rule_to_reply(packet, rule)
        else:
            print("No expected reply received")
            match_rule_to_no_response(rule, sent_packet)

def match_rule_to_reply(packet,rule):
    if rule is not None:
        print(f"Response for rule: {rule['name']}")

        packet_details = packet_to_object(packet)
        
        if(packet_details["protocol"] == 6 and rule["ip_protocol"] == "tcp"):
            packet_details["Test Result"] = "Passed"
        elif(packet_details["protocol"] == 17 and rule["ip_protocol"] == "udp"):
            packet_details["Test Result"] = "Passed"
        elif(packet_details["protocol"] == 1 and rule["ip_protocol"] == "icmp"):
            packet_details["Test Result"] = "Passed"
        else:
            packet_details["Test Result"] = "Failed"
        
        write_to_csv(packet_details)
    else:
        print("No matching rule found")
        packet_details = packet_to_object(packet)
        packet_details["Test Result"] = "Failed"
        write_to_csv(packet_details)

    
def match_rule_to_no_response(rule, packet):
    if rule is not None:
        print(f"No response for rule: {rule['name']}")

        packet_details = packet_to_object(packet)
        
        if(packet_details["protocol"] == 6 and rule["ip_protocol"] == "tcp"):
            packet_details["Test Result"] = "Failed"
        elif(packet_details["protocol"] == 17 and rule["ip_protocol"] == "udp"):
            packet_details["Test Result"] = "Failed"
        elif(packet_details["protocol"] == 1 and rule["ip_protocol"] == "icmp"):
            packet_details["Test Result"] = "Failed"
        else:
            packet_details["Test Result"] = "Passed"
        
        write_to_csv(packet_details)
    else:
        print("No matching rule found")
        packet_details = packet_to_object(packet)
        packet_details["Test Result"] = "Passed"
        write_to_csv(packet_details)

def write_to_csv(packet_details):
    with open("test_results.csv", "a", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=packet_details.keys())
        if csv_file.tell() == 0:
            writer.writeheader()
        writer.writerow(packet_details)


def packet_to_object(packet):
    packet_details = {
        "timestamp": str(datetime.now()),
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "packet_length": len(packet)
    }

    if packet.haslayer(ICMP):
        packet_details["icmp_type"] = packet[ICMP].type
        packet_details["icmp_code"] = packet[ICMP].code

    elif packet.haslayer(UDP):
        packet_details["source_port"] = packet[UDP].sport
        packet_details["destination_port"] = packet[UDP].dport

    elif packet.haslayer(TCP):
        packet_details["source_port"] = packet[TCP].sport
        packet_details["destination_port"] = packet[TCP].dport
        packet_details["flags"] = packet[TCP].flags

    return packet_details


def send_packet(config, destination):
    print(f"Sending packet to {destination}")
    send_icmp(destination, config)
    for port in range(1, 65535):
        print(f"Checking port: {port}")
        send_tcp(destination, port, config)
        send_udp(destination, port, config)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scapy-client.py <destination>")
        sys.exit(1)
    destination = sys.argv[1]
    config = read_config()
    send_packet(config,destination)