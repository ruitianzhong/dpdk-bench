#! /bin/python
import subprocess
import argparse
import re
from run_evaluation import print_figure
from util import *


def run_motivation(enable_cache, slf, flow_num=10000, count=1):
    filename = f"synthetic_slf{slf}_flow_num{flow_num}_count{count}_seed42.pcap"

    cmd = f"perf stat -e L1-dcache-load-misses,L1-dcache-load taskset -c 0 ./motivation/nat --enable-cache {1 if enable_cache else 0} --pcap {filename}"
    cmd = cmd.split()

    per_packet_ns = 0.0
    miss_percent = 0.0
    miss_cnt = 0.0
    repeat = 4
    total_packets = 0
    for _ in range(repeat):
        reuslt = subprocess.run(
            cmd, text=True, capture_output=True, check=True)
        print(reuslt.stdout)
        print(reuslt.stderr)
        lines = reuslt.stdout.split('\n')

        for line in lines:
            ret = re.findall(r'Average time per packet: (\S+)', line)

            if len(ret) == 1:
                per_packet_ns += float(ret[0])

            ret = re.findall(r'Total Packest handled: (\S+)', line)

            if len(ret) == 1:
                total_packets = int(ret[0])

        lines = reuslt.stderr.split('\n')

        for line in lines:
            ret = re.findall(r'(\S+)% of all L1-dcache hits', line)

            if len(ret) == 1:
                miss_percent += float(ret[0])

            ret = re.findall(r'(\S+)\s+L1-dcache-load-misses', line)

            if len(ret) == 1:
                s = str(ret[0])
                miss_cnt += float(s.replace(',', ''))

    per_packet_ns /= repeat
    miss_percent /= repeat
    miss_cnt /= repeat

    miss_cnt /= float(total_packets)

    result = {}
    result['per_packet_ns'] = per_packet_ns
    result['miss_percent'] = miss_percent
    result['miss_count'] = miss_cnt
    return result


def run_prepare(flow_num=512, group_count=19):
    for slf in range(1, 17):
        cmd = f"./scripts/generate_synthetic_flow.py --slf {slf} --slf-group-count {group_count} --flow-num {flow_num}"
        print(cmd)
        cmd = cmd.split()
        subprocess.run(cmd)
        print("Done!")


def generate_fig(with_cached, without_cached, filename_prefix=''):

    x = range(1, 17)
    y1 = [e['per_packet_ns'] for e in with_cached]
    y2 = [e['per_packet_ns'] for e in without_cached]

    print_figure(x, y1, "w/ cache", y2, "w/o cache", '', 'F',
                 'Average Processing Time Per Packet (ns)', filename_prefix+'per_packet.png')
    print_figure(x, y1, "w/ cache", y2, "w/o cache", '', 'F',
                 'Average Processing Time Per Packet (ns)', filename_prefix+'per_packet.eps')

    y1 = [e['miss_percent'] for e in with_cached]
    y2 = [e['miss_percent'] for e in without_cached]
    print_figure(x, y1, "w/ cache", y2, "w/o cache", '', 'F',
                 'L1-dcache Load Misses Rate (%)', filename_prefix+'miss_rate.png')
    print_figure(x, y1, "w/ cache", y2, "w/o cache", '', 'F',
                 'L1-dcache Load Misses Rate (%)', filename_prefix+'miss_rate.eps')


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", default=False, action="store_true")
    parser.add_argument("--run", action="store_true", default=False)

    args = parser.parse_args()
    print(args.prepare)
    if args.prepare:
        run_prepare()

    if args.run:
        # run_motivation(False, 1)
        with_cache_result = []
        without_cache_result = []
        for slf in range(1, 17):
            ret = run_motivation(True, slf)
            with_cache_result.append(ret)

            ret = run_motivation(False, slf)
            without_cache_result.append(ret)

        generate_fig(with_cached=with_cache_result,
                     without_cached=without_cache_result)

        write_json(JSON_PATH+'motivation_with_cache.json', with_cache_result)
        write_json(JSON_PATH+'motivation_without_cache.json',
                   without_cache_result)

        flow_nums = [32, 128, 512, 1000]
        cnts = [300, 75, 19, 10]

        for idx, flow_num in enumerate(flow_nums):
            with_cache_result = []
            without_cache_result = []
            for slf in range(1, 17):
                ret = run_motivation(
                    True, slf, flow_num=flow_num, count=cnts[idx])
                with_cache_result.append(ret)

                ret = run_motivation(
                    False, slf, flow_num=flow_num,  count=cnts[idx])
                without_cache_result.append(ret)

            generate_fig(with_cached=with_cache_result,
                         without_cached=without_cache_result, filename_prefix="flow_num"+str(flow_num))


if __name__ == "__main__":
    main()
