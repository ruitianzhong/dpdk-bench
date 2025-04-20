#! /bin/python
import subprocess
import re

from matplotlib import pyplot as plt


def run_fastclick(slf, flow_num, group_count):

    filename = f"synthetic_slf{slf}_flow_num{flow_num}_count{group_count}_seed42.pcap"

    cmd = f"../fastclick/bin/click pcap_name={filename} ./perf.click"

    result = subprocess.run(cmd.split(), check=True,
                            capture_output=True, text=True)

    lines = result.stdout.split("/n")
    for line in lines:
        ret = re.findall(r"RESULT-DUT-CYCLES-PP (\S+)", line)

        if len(ret) == 1:
            return int(ret[0])

    raise Exception("Not Found")


def print_single(x, y, filename):

    pass


if __name__ == "__main__":
    flow_nums = [32, 128, 512, 1000, 10000]
    cnts = [300, 75, 19, 10, 1]
    # print(run_fastclick(1, 10000, 1))

    for idx, flow_num in enumerate(flow_nums):
        result = []
        x = range(1, 17)
        for i in x:
            repeat = 6
            total = 0

            for _ in range(repeat):
               ret = run_fastclick(slf=i, flow_num=flow_num,
                                   group_count=cnts[idx])
               total += ret

            result.append(float(total)/float(repeat))

        plt.scatter(x, result)
        plt.xlabel("F")
        plt.ylabel("Average Cycle Per Packet")
        plt.title(f"Flow Num {flow_num}")
        plt.savefig(f"result/fig/click_flownum{flow_num}_all.png")
        plt.close()
        print(f"flow num {flow_num} Done!")
