#! /bin/python
import subprocess
import argparse
import re
from run_evaluation import print_figure
import json


def write_json(filename, obj):
    json_str = json.dumps(obj)
    with open(filename, 'w') as f:
        f.write(json_str)

def run_motivation(enable_cache, slf):
    filename = f"synthetic_slf{slf}_flow_num10000_count1_seed42.pcap"
    
    cmd = f"perf stat -e L1-dcache-load-misses,L1-dcache-load taskset -c 0 ./motivation/nat --enable-cache {1 if enable_cache else 0} --pcap {filename}"
    cmd = cmd.split()
   
    per_packet_ns = 0.0
    miss_percent = 0.0
    repeat = 1
    for _ in range(repeat):
        reuslt = subprocess.run(cmd, text=True, capture_output=True, check=True)
        print(reuslt.stdout)
        print(reuslt.stderr)
        lines = reuslt.stdout.split('\n')

        for line in lines:
            ret = re.findall(r'Average time per packet: (\S+)', line)

            if len(ret)==1:
                per_packet_ns += float(ret[0])

        lines = reuslt.stderr.split('\n')

        for line in lines:
            ret = re.findall(r'(\S+)% of all L1-dcache hits', line)

            if len(ret)==1:
                miss_percent += float(ret[0])

    per_packet_ns /= repeat
    miss_percent /= repeat

    result={}
    result['per_packet_ns'] =per_packet_ns
    result['miss_percent'] = miss_percent
    return result
                


def run_prepare():
    flow_num = 10000
    for slf in range(1, 17):
        cmd = f"./scripts/generate_synthetic_flow.py --slf {slf} --slf-group-count 1 --flow-num {flow_num}"
        print(cmd)
        cmd = cmd.split()
        subprocess.run(cmd)
        print("Done!")


def generate_fig(with_cached,without_cached):

    x = range(1, 17)
    y1 = [e['per_packet_ns'] for e in with_cached]
    y2 = [e['per_packet_ns'] for e in without_cached]

    print_figure(x, y1, "w/ cache", y2, "w/o cache", '', 'F',
                 'Average Processing Time Per Packet (ns)', 'per_packet.png')
    
    y1 = [e['miss_percent'] for e in with_cached]
    y2 = [e['miss_percent'] for e in without_cached]
    print_figure(x, y1, "w/ cache", y2, "w/o cache", '', 'F',
                 'L1-dcache Load Misses Rate (%)', 'miss_rate.png')
    



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
        for slf in  range(1,17):
            ret = run_motivation(True, slf)
            with_cache_result.append(ret)

            ret = run_motivation(False,slf)
            without_cache_result.append(ret)

        generate_fig(with_cached=with_cache_result,
                     without_cached=without_cache_result)

        write_json('motivation_with_cache.json',with_cache_result)
        write_json('motivation_without_cache.json', without_cache_result)
            
     

if __name__ =="__main__":
    main()