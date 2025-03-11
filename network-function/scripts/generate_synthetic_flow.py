#! /usr/bin/python3
import argparse
import random

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import *

SRC_MAC = "bd:00:00:00:10:42"
DST_MAC = "bd:00:00:00:10:47"


def build_packet():
    pass
    # Generate UDP packet.


def generate_random_ip():
    return str(random.randint(1, 255)) + "." + str(random.randint(1, 255)) + "." + str(
        random.randint(1, 255)) + "." + str(
        random.randint(1, 255))


def generate_packets(args):
    pkt_list = []
    for group_idx in range(args.slf_group_count):
        for flow_idx in range(args.flow_num):
            src_ip = generate_random_ip()
            dst_ip = generate_random_ip()
            src_port = random.randint(1024, 65536)
            dst_port = random.randint(1024, 65536)
            for i in range(args.slf):
                pkt_size = random.randint(200, 300)
                eth = Ether(src=SRC_MAC, dst=DST_MAC)
                ip = IP(src=src_ip, dst=dst_ip)
                udp = UDP(sport=src_port, dport=dst_port, len=pkt_size)
                pkt = eth / ip / udp
                pkt_list.append(pkt)
    return pkt_list


def store_packets_to_pcap_file(packets_list):
    wrpcap("./synthetic_packets", packets_list)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--slf", help="spacial locality factor(SLF)", type=int, default=1)
    parser.add_argument(
        "--flow-num", help="total number of flow", type=int, default=50)
    parser.add_argument(
        "--slf-group-count", help="total_packets_per_flow = slf_group_count * slf", type=int, default=20)
    parser.add_argument(
        "--seed", help="seed for generating random number", type=int, default=42)
    args = parser.parse_args()
    print(args.seed)
    print(args.flow_num)
    # For reproducible experiments
    random.seed(args.seed)
    packets = generate_packets(args=args)
    store_packets_to_pcap_file(packets)
