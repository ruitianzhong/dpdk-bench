# Artifact Evaluation for Final Year Project (FYP)

## Overview

This repository is for artifact evaluation(i.e., 软硬件验收 in Chinese) of final year project(FYP) in Xidian University.

[Section 2](#setup-environment) contains necessary steps to set up the testbed to reproduce the result. [Section 3](#generate-packets-trace-and-configuration-file-for-firewall) gives instruction to generate the trace used in the evaluation. [Section 4](#reproducing-the-results) provides detailed instruction to reproduce the result in bachelor thesis.

## Setup environment

Testbed Overview:

![testbed overview](./platform_illustrate.png)


Install Dependencies:

```bash
pip install scapy
sudo apt-get install libpcap-dev linux-tools-5.4.0-214-generic
```

System configuration:

```bash
# for perf
cat /proc/sys/kernel/perf_event_paranoid
echo "-1" | sudo  tee /proc/sys/kernel/perf_event_paranoid
# disable turbo boost
cat /sys/devices/system/cpu/intel_pstate/no_turbo
echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Two NUMA node here
# Hugepage setup
echo 2048 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 2048 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
mkdir /mnt/huge
mount -t hugetlbfs pagesize=1GB /mnt/huge
```

All the programs are developed and tested with _DPDK 21.05_.


DPDK setup(Note that you must replaced the `0000:82:00.1` and `0000:04:00.1` with your configuration.): 

```bash
# add the NIC used in experiment
sudo dpdk-devbind.py -b vfio-pci 0000:82:00.1
sudo dpdk-devbind.py -b vfio-pci 0000:04:00.1
pkg-config --modversion libdpdk # show dpdk version
```

Compile the program used in motivation section:

```bash
make -C ./motivation
```

Compile the program used in evaluation section (including aggregator implementation):

```bash
make -C ./aggregator
```

## Generate packets trace and configuration file for firewall

Generate packets trace for motivation and evaluation:
```bash
# machine time: ~40 min (can be parallelized to speed up)
./scripts/run_motivation.py --prepare
# machine time: ~6 min
./scripts/run_evaluation.py --prepare
```

## Reproducing the results

### Results for motivation

```bash
# machine time: ~ 35 minutes
./scripts/run_motivation.py --run
```

All generated figures are under `result/fig`.

| Fig in Thesis | File Name |
| ----------- | ----------- |
| Fig 3-2 | flow_num10000per_packet.png |
| Fig 3-3 | flow_num10000miss_rate.png |
| Fig 3-4 | flow_num10000per_packet.png |
| Fig 3-5 | flow_num1000miss_rate.png |
| Fig 3-6 | flow_num32per_packet.png |

### Results for evaluation

```bash
# machine time: ~17 minutes
sudo ./scripts/run_evaluation.py --run --buffer-time
```

All generated figures are under `result/fig`.

| Fig in Thesis | File Name |
| ----------- | ----------- |
| Fig 4-3 | throughput.png |
| Fig 4-4 | latency.png |
| Fig 4-5 | cycle.png |
| Fig 4-6 | buffer_time_throughput.png |
| Fig 4-7 | buffer_time_latency.png |
| Fig 4-8 | buffer_time_cycle.png |

### Clean up all the results and traces

```bash
# remove results
rm -rf ./result
# remove traces 
rm -rf *.pcap
```