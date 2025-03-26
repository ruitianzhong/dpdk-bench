#! /usr/bin/python3
import time
import random
import argparse

from scapy.layers.inet import IP, UDP
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

SRC_MAC = "6C:B3:11:50:D3:DA"
DST_MAC = "3C:FD:FE:EC:48:11"


def generate_random_ip():
    return str(random.randint(1, 255)) + "." + str(random.randint(1, 255)) + "." + str(
        random.randint(1, 255)) + "." + str(
        random.randint(1, 255))

# Not used for now
class Packet:
    def __init__(self, args):
        self.slf = args.slf
        self.flow_num = args.flow_num
        self.slf_group_count = args.slf_group_count
        self.flows_list = [None] * args.flow_num
        self.length = self.slf * self.flow_num * self.slf_group_count
        for flow_idx in range(args.flow_num):
            src_ip = generate_random_ip()
            dst_ip = generate_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1024, 65535)
            eth = Ether(src=SRC_MAC, dst=DST_MAC)
            ip = IP(src=src_ip, dst=dst_ip)
            udp = UDP(sport=src_port, dport=dst_port)
            http = HTTP()
            httpreq = HTTPRequest()
            # It may not be realistic for HTTP over UDP, but it's a synthetic test and
            # we use it anyway.
            pkt = eth / ip / udp / http / httpreq
            self.flows_list[flow_idx] = pkt

    def __len__(self):
        print(self.slf * self.flow_num * self.slf_group_count)
        return self.length

    def __iter__(self):
        self.current_flow = 0
        self.cnt = 0
        return self

    def __next__(self):

        if self.cnt == self.length:
            raise StopIteration

        f = self.current_flow

        self.cnt += 1
        if self.cnt % self.slf == 0:
            self.current_flow = (self.current_flow+1) % self.flow_num
        # print("next")
        return self.flows_list[f]


def generate_packets(args):
    cnt = 0
    total_size = args.flow_num * args.slf_group_count * args.slf
    pkt_list = [None] * total_size
    flows_list = [None] * args.flow_num
    for flow_idx in range(args.flow_num):
        src_ip = generate_random_ip()
        dst_ip = generate_random_ip()
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)
        eth = Ether(src=SRC_MAC, dst=DST_MAC)
        ip = IP(src=src_ip, dst=dst_ip)
        udp = UDP(sport=src_port, dport=dst_port)
        http = HTTP()
        httpreq = HTTPRequest()
        # It may not be realistic for HTTP over UDP, but it's a synthetic test and
        # we use it anyway.
        pkt = eth / ip / udp / http / httpreq
        flows_list[flow_idx] = pkt
    print("Setup all the flows")

    for group_idx in range(args.slf_group_count):
        for flow_idx in range(args.flow_num):
            # src_ip, dst_ip, src_port, dst_port = flows_list[flow_idx]
            for i in range(args.slf):
                # pkt_size = random.randint(200, 300)
                pkt_list[cnt] = flows_list[flow_idx]
                cnt += 1
    return pkt_list


def store_packets_to_pcap_file(args, packets_list):
    print("Store the generated packets to synthetic_packets.pcap")
    print(f"Total packets: {len(packets_list)}")
    filename = f"synthetic_slf{args.slf}_flow_num{args.flow_num}_count{args.slf_group_count}_seed{args.seed}.pcap"
    wrpcap(filename, packets_list)
    print("Done!")


"""
Make sure you have installed scapy: pip install scapy
To view the parameter, please run the following command:
./generate_synthetic_flow.py -h 
"""
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--slf", help="spacial locality factor(SLF)", type=int, default=1)
    parser.add_argument(
        "--flow-num", help="total number of flow", type=int, default=10000)
    parser.add_argument(
        "--slf-group-count", help="total_packets_per_flow = slf_group_count * slf", type=int, default=1)
    parser.add_argument(
        "--seed", help="seed for generating random number", type=int, default=42)
    args = parser.parse_args()
    # For reproducible experiments
    random.seed(args.seed)
    start_time = time.time_ns()
    packets = generate_packets(args=args)
    store_packets_to_pcap_file(args, packets)
    end_time = time.time_ns()
    print(f"Total time: {(end_time - start_time) / 1000 / 1000} ms")
