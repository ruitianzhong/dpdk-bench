#! /bin/python
import subprocess
import argparse


def run_motivation(enable_cache, slf):
    filename = f"synthetic_slf{slf}_flow_num10000_count1_seed42.pcap"
    
    cmd = f"perf stat -e L1-dcache-load-misses,L1-dcache-load taskset -c 0 ./motivation/nat --enable-cache {1 if enable_cache else 0} --pcap {filename}"
    cmd = cmd.split()
    reuslt = subprocess.run(cmd, text=True, capture_output=True, check=True)
    print(reuslt.stdout)
    print(reuslt.stderr)

    lines = reuslt.stdout.split('\n')
    for line in lines:
        pass


def run_prepare():
    flow_num = 10000
    for slf in range(1, 17):
        cmd = f"./scripts/generate_synthetic_flow.py --slf {slf} --slf-group-count 1 --flow-num {flow_num}"
        print(cmd)
        cmd = cmd.split()
        subprocess.run(cmd)
        print("Done!")


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", default=False, action="store_true")
    parser.add_argument("--run", action="store_true", default=False)
    
    args = parser.parse_args()
    print(args.prepare)
    if args.prepare:
        run_prepare()

    if args.run:
        run_motivation(False, 1)
     

if __name__ =="__main__":
    main()