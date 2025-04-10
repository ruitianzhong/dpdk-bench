#! /bin/python

import matplotlib
import re
import subprocess
from matplotlib import pyplot as plt
from util import write_json, FIG_PATH, JSON_PATH
import argparse
#  Avoid warning here
matplotlib.use('Agg')


def run_back2back(app_name, gbps, enable_aggregator, enable_ablation=0, delay_cycle=0, access_byte_per_packet=0, max_batch=32, buffer_time_us=16):
    # reasonable offered load
    assert (1 <= gbps <= 40)

    assert (not (delay_cycle != 0 and access_byte_per_packet != 0))

    cmdline = f"./aggregator/build/back2back --  " \
        f" --app {app_name} " \
        " --pcap_file ./synthetic_flow_num10000_seed42.pcap " \
        " --fw_rules ./fw-testing-10000.rules " \
        f" --enable-aggregator {1 if enable_aggregator else 0} " \
        f" --gbps {str(gbps)} " \
        f" --ablation {1 if enable_ablation else 0} "   \
        f" --delay-cycle {delay_cycle} "    \
        f" --access-byte-per-packet {access_byte_per_packet} "  \
        f" --max-batch {max_batch} " \
        f" --buffer-time {buffer_time_us} "

    print(cmdline)
    cmdline = cmdline.split()
    repeat = 3
    xput = 0.0
    latency = 0.0
    cycle = 0.0

    try:
        for _ in range(0, repeat):

            result = subprocess.run(cmdline, check=True,
                                    capture_output=True, text=True)
            # print(result)
            lines = result.stdout.split("\n")
            for line in lines:
                ret = re.findall(r"average latency: (\S+)", line)

                if len(ret) == 1:
                    print(line)
                    latency += float(ret[0])

                ret = re.findall(r"Throughput: (\S+)", line)

                if len(ret) == 1:
                    xput += float(ret[0])

                ret = re.findall(r"average cycle (\S+)", line)

                if len(ret) == 1:
                    cycle += float(ret[0])

        result = {}
        result['latency'] = latency/float(repeat)
        result['throughput'] = xput/float(repeat)
        result['cycle'] = cycle/float(repeat)
        print(f'Done! {result}')

        return result

    except subprocess.CalledProcessError as e:
        print(f'Failed to run command:{e}')
        raise Exception("faied to run command")


def print_figure(x, y1, y1_label, y2, y2_label, figname, xlabel, ylabel, filename):

    plt.figure(figsize=(8, 4))
    plt.minorticks_on()
    # Setup Grid
    plt.grid(True, which="major", linestyle="--", color="gray", linewidth=0.75)
    plt.grid(True, which="minor", linestyle=":",
             color="lightgray", linewidth=0.7)
    plt.title(figname)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.scatter(x, y1, c='red', s=30, marker='x', label=y1_label)
    plt.scatter(x, y2, c='blue', s=30, marker='*', label=y2_label)

    plt.legend()
    plt.savefig(FIG_PATH+filename)
    print(f'Saving {filename}')
    plt.close()


def print_multiple_figure(x, y, y_label,  figname, xlabel, ylabel, filename):
    color = ['r', 'b', 'g']
    shape = ['x', '*', ',']
    plt.figure(figsize=(8, 4))
    plt.minorticks_on()
    # Setup Grid
    plt.grid(True, which="major", linestyle="--", color="gray", linewidth=0.75)
    plt.grid(True, which="minor", linestyle=":",
             color="lightgray", linewidth=0.7)
    plt.title(figname)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    for idx, _ in enumerate(y):
        plt.scatter(x, y[idx], c=color[idx],
                    label=y_label[idx], marker=shape[idx])

    plt.legend()
    plt.savefig(FIG_PATH+filename)
    print(f'Saving {filename}')
    plt.close()


def generate_throughput_figure(with_agg_results, without_agg_results):
    x = [result[0] for result in with_agg_results]
    with_agg_y = [result[1]['throughput'] for result in with_agg_results]
    without_agg_y = [result[1]['throughput'] for result in without_agg_results]
    print_figure(x, with_agg_y, "w/ aggregator", without_agg_y, 'w/o aggregator', '',
                 'Offered Load (Gbps)', 'Network Function Throughput (Gbps)', 'throughput.png')


def generate_latency_figure(with_agg_results, without_agg_results):
    x = [result[0] for result in with_agg_results]
    with_agg_y = [result[1]['latency'] for result in with_agg_results]
    without_agg_y = [result[1]['latency'] for result in without_agg_results]
    print_figure(x, with_agg_y, "w/ aggregator", without_agg_y, 'w/o aggregator', '',
                 'Offered Load (Gbps)', 'Average Latency Per Packet (us)', 'latency.png')


def generate_cycle_figure(with_agg_results, without_agg_results):
    x = [result[0] for result in with_agg_results]
    with_agg_y = [result[1]['cycle'] for result in with_agg_results]
    without_agg_y = [result[1]['cycle'] for result in without_agg_results]
    print_figure(x, with_agg_y, "w/ aggregator", without_agg_y, 'w/o aggregator', '',
                 'Offered Load (Gbps)', 'Average CPU Cycles Per Packet', 'cycle.png')


def do_preparation():
    cmdline = "./scripts/generate_testing_flow"
    cmdline = cmdline.split()
    subprocess.run(cmdline, check=True)
    print("Preparation done!")


def do_miss_penalty_ablation():
    with_agg = []
    without_agg = []
    x = range(0, 1700, 100)
    for miss_penalty_cycle in x:
       ret = run_back2back(app_name="chain", gbps=30, enable_aggregator=True,
                           enable_ablation=True, delay_cycle=miss_penalty_cycle)

       with_agg.append(ret)
       ret = run_back2back(app_name="chain", gbps=30, enable_aggregator=False,
                           enable_ablation=True, delay_cycle=miss_penalty_cycle)
       without_agg.append(ret)

    # cycle
    y1 = [e['cycle'] for e in with_agg]
    y2 = [e['cycle'] for e in without_agg]
    prefix = "ablation_miss_penalty"

    print_figure(x, y1, 'w/ aggregator', y2, 'w/o aggregator', '',
                 'Miss Penalty (cycle)', 'Average CPU Cycle Per Packet', prefix + '_cycle.png')

    #  latency
    y1 = [e['latency'] for e in with_agg]
    y2 = [e['latency'] for e in without_agg]

    print_figure(x, y1, 'w/ aggregator', y2, 'w/o aggregator', '',
                 'Miss Penalty (cycle)', 'Average Latency Per Packet (us)', prefix+'_latency.png')

    y1 = [e['throughput'] for e in with_agg]
    y2 = [e['throughput'] for e in without_agg]

    print_figure(x, y1, 'w/ aggregator', y2, 'w/o aggregator', '',
                 'Miss Penalty (cycle)', 'Throughput (Gbps)', prefix+'_throughput.png')

    write_json(JSON_PATH+prefix+'_with_agg.json', with_agg)
    write_json(JSON_PATH+prefix+'_without_agg.json', without_agg)


def do_burst_time_ablation():
    x = range(25, 34)
    buffer_time = [16, 32, 48]
    results = []
    for _ in range(len(buffer_time)):
        results.append([])

    for gbps in x:
        for idx, t in enumerate(buffer_time):
            ret = run_back2back(app_name="chain", gbps=gbps, enable_aggregator=True,
                                enable_ablation=False, access_byte_per_packet=0, max_batch=32, buffer_time_us=t)
            results[idx].append(ret)
    print(results)
    write_json("buffer_time.json", results)

    y_label = [f"buffer time {t} us" for t in buffer_time]
    y_latency = []
    y_throughput = []
    y_cycle = []

    for idx in range(len(buffer_time)):
        y_latency.append([m['latency'] for m in results[idx]])
        y_cycle.append([m['cycle'] for m in results[idx]])
        y_throughput.append([m['throughput'] for m in results[idx]])

    PREFIX = "buffer_time"
    x_axis = "Offered Load (Gbps)"

    print_multiple_figure(x, y_latency, y_label, "", x_axis,
                          "Latency (us)",  PREFIX+"_latency.png")
    print_multiple_figure(x, y_throughput, y_label, "", x_axis,
                          "Throughput (Gbps)",  PREFIX+"_throughput.png")
    print_multiple_figure(x, y_cycle, y_label, "", x_axis,
                          "Processing Time Per Packet (cycle)",  PREFIX+"_cycle.png")


def do_cache_ablation():
    with_agg = []
    without_agg = []
    x = range(0, 1000+1, 100)
    for access_mem_size in x:
       ret = run_back2back(app_name="chain", gbps=30, enable_aggregator=True,
                           enable_ablation=True, access_byte_per_packet=access_mem_size)

       with_agg.append(ret)
       ret = run_back2back(app_name="chain", gbps=30, enable_aggregator=False,
                           enable_ablation=True, access_byte_per_packet=access_mem_size)
       without_agg.append(ret)

    # cycle
    y1 = [e['cycle'] for e in with_agg]
    y2 = [e['cycle'] for e in without_agg]
    prefix = "ablation_mem_access"
    x_axis_name = "Memory Access Per Packet (byte)"

    print_figure(x, y1, 'w/ aggregator', y2, 'w/o aggregator', '',
                 x_axis_name, 'Average CPU Cycle Per Packet', prefix + '_cycle.png')

    #  latency
    y1 = [e['latency'] for e in with_agg]
    y2 = [e['latency'] for e in without_agg]

    print_figure(x, y1, 'w/ aggregator', y2, 'w/o aggregator', '',
                 x_axis_name, 'Average Latency Per Packet (us)', prefix+'_latency.png')

    y1 = [e['throughput'] for e in with_agg]
    y2 = [e['throughput'] for e in without_agg]

    print_figure(x, y1, 'w/ aggregator', y2, 'w/o aggregator', '',
                 x_axis_name, 'Throughput (Gbps)', prefix+'_throughput.png')

    write_json(JSON_PATH+prefix+'_with_agg.json', with_agg)
    write_json(JSON_PATH+prefix+'_without_agg.json', without_agg)


def do_ablation():
    do_miss_penalty_ablation()
    do_cache_ablation()


def do_evaluation():
    print(run_back2back("chain", 25, True))
    # print(run_back2back("chain", 25, True))

    with_agg_results = []
    without_agg_results = []

    for i in range(1, 34):
       result = run_back2back("chain", i, True)
       with_agg_results.append((i, result))
       result = run_back2back("chain", i, False)
       without_agg_results.append((i, result))

    generate_throughput_figure(with_agg_results, without_agg_results)
    generate_latency_figure(with_agg_results, without_agg_results)
    generate_cycle_figure(with_agg_results, without_agg_results)

    write_json(JSON_PATH+"eval_with_agg.json", with_agg_results)
    write_json(JSON_PATH+"eval_without_agg.json", without_agg_results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--prepare", action="store_true", default=False)
    parser.add_argument("--run", action="store_true", default=False)
    parser.add_argument("--ablation", action="store_true", default=False)
    parser.add_argument("--buffer-time", action="store_true", default=False)
    args = parser.parse_args()
    if args.prepare:
        do_preparation()
    if args.run:
        do_evaluation()
    if args.ablation:
        do_ablation()
    if args.buffer_time:
        do_burst_time_ablation()
