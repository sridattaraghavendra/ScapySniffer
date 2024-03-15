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
    # send(tcp_packet)

    # sniff(filter=f"tcp and src host {target_ip}", prn=handle_response(partial(match_rule_to_reply, rule=rule)), timeout=2)
    ans, unans = sr(tcp_packet,timeout=10)
    print("TCP response : ",ans.show())
    print("Unanswered : ",unans.show())
    # if response and isinstance(response, list) and len(response) > 0:
    #     response_pkt = response[0][1]
    #     handle_response_blocking(response_pkt, rule, tcp_packet)
    # else:
    #     print("No response received")


def send_udp(target_ip, target_port, rule):
    udp_packet = IP(dst=target_ip) / UDP(dport=target_port)
    # send(udp_packet)

    # sniff(filter=f"udp and src host {target_ip}", prn=handle_response(partial(match_rule_to_reply, rule=rule)), timeout=2)
    ans, unans = sr(udp_packet,timeout=10)
    print("UDP response : ",ans.show())
    print("Unanswered : ",unans.show())
    # if response and isinstance(response, list) and len(response) > 0:
    #     response_pkt = response[0][1]
    #     handle_response_blocking(response_pkt, rule, udp_packet)
    # else:
    #     print("No response received")


def send_icmp(target_ip, rule):
    icmp_packet = IP(dst=target_ip) / ICMP()
    # send(icmp_packet)
    
    # sniff(filter=f"icmp and src host {target_ip}", prn=handle_response(partial(match_rule_to_reply, arg1=rule)), timeout=2)
    ans, unans = sr(icmp_packet,timeout=10)
    print("ICMP response : ",ans.show())
    print("Unanswered : ",unans.show())
    # if response and isinstance(response, list) and len(response) > 0:
    #     response_pkt = response[0][1]
    #     handle_response_blocking(response_pkt, rule, icmp_packet)
    # else:
    #     print("No response received")


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

# def handle_response(callback, *args, **kwargs):
#     def wrapper(packet):
#         if packet.haslayer(TCP) and packet[TCP].flags & 0x12:
#             print("Received TCP SYN-ACK reply from", packet[IP].src)
#             callback(packet, *args, **kwargs)
#         elif packet.haslayer(UDP):
#             print("Received UDP reply from", packet[IP].src)
#             callback(packet, *args, **kwargs)
#         elif packet.haslayer(ICMP):
#             print("Received ICMP reply from", packet[IP].src)
#             callback(packet, *args, **kwargs)
#         else:
#             print("No expected reply received")
#             match_rule_to_no_response(*args)

#     return wrapper

def match_rule_to_reply(packet,rule):
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

    
def match_rule_to_no_response(rule, packet):
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
        packet_details["udp_source_port"] = packet[UDP].sport
        packet_details["udp_destination_port"] = packet[UDP].dport

    elif packet.haslayer(TCP):
        packet_details["tcp_source_port"] = packet[TCP].sport
        packet_details["tcp_destination_port"] = packet[TCP].dport
        packet_details["tcp_flags"] = packet[TCP].flags

    return packet_details


def send_packet(config, destination):
    print(f"Sending packet to {destination}")
    for rule in config['firewall_rules']:
        print(f'Checking rule: {rule["name"]}')
        print(f"Allowed Protocol: {rule['ip_protocol']}")
        print(f"Allowed Port Range: {rule['from_port']}-{rule['to_port']}")
        for port in range(rule['from_port'], rule['to_port'] + 1):
            send_tcp(destination, port, rule)
            send_udp(destination, port, rule)
            #send_icmp(destination, rule)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scapy-client.py <destination>")
        sys.exit(1)
    destination = sys.argv[1]
    config = read_config()
    send_packet(config,destination)