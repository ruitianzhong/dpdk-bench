#! /bin/python

import subprocess
import re
import matplotlib
from matplotlib import pyplot as plt
from matplotlib.ticker import MultipleLocator

def run_back2back(app_name, gbps, enable_aggregator):
    assert (1 <= gbps <= 40)

    cmdline = f"./aggregator/build/back2back --  " \
        " --app chain " \
        " --pcap_file ./synthetic_flow_num10000_seed42.pcap " \
        " --fw_rules ./fw-testing-10000.rules " \
        f" --enable-aggregator {1 if enable_aggregator else 0} " \
        f" --gbps {str(gbps)}"

    print(cmdline)
    cmdline = cmdline.split()
    repeat = 1
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

    plt.figure(figsize=(6, 3.5))
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
    plt.savefig(filename)
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
                 'Offered Load (Gbps)', '', 'latency.png')


def generate_cycle_figure(with_agg_results, without_agg_results):
    x = [result[0] for result in with_agg_results]
    with_agg_y = [result[1]['cycle'] for result in with_agg_results]
    without_agg_y = [result[1]['cycle'] for result in without_agg_results]
    print_figure(x, with_agg_y, "w/ aggregator", without_agg_y, 'w/o aggregator', '',
                 'Offered Load (Gbps)', 'Average CPU Cycles Per Packet', 'cycle.png')


def generate_back2back_figure():
    pass


def main():
    print(run_back2back("chain", 25, True))
    # print(run_back2back("chain", 25, True))

    with_agg_results = []
    without_agg_results = []

    for i in range(1, 30):
       result = run_back2back("chain", i, True)
       with_agg_results.append((i, result))
       result = run_back2back("chain", i, False)
       without_agg_results.append((i, result))

    generate_throughput_figure(with_agg_results, without_agg_results)
    generate_latency_figure(with_agg_results, without_agg_results)
    generate_cycle_figure(with_agg_results, without_agg_results)


if __name__ == "__main__":
    main()
