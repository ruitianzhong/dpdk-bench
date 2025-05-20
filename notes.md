# Notes

## Install Dependencies

```bash
pip install scapy
sudo apt-get install libpcap-dev
cat /proc/sys/kernel/perf_event_paranoid
echo -1 >> /proc/sys/kernel/perf_event_paranoid
# disable turbo boost
cat /sys/devices/system/cpu/intel_pstate/no_turbo
echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Two NUMA node here
echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 2048 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
mkdir /mnt/huge
mount -t hugetlbfs pagesize=1GB /mnt/huge
```

```bash
dpdk-devbind.py -b vfio-pci 0000:82:00.1
dpdk-devbind.py -b vfio-pci 0000:04:00.1
```
```bash
pkg-config --modversion libdpdk # show dpdk version
```

使用perf进行耗时的分析(对FastClick Element的分析)
```bash
perf  list #查看支持的事件
perf record -F 99 -a -g -- sleep 60
# 99 HZ 的采样频率
perf script > out.perf
perf record -F max --call-graph fp -- <program>
sudo perf record -F max --call-graph fp -o slow.data  --   ../fastclick/bin/click  perf.click 
sudo perf diff slow.data common.data
sudo dmidecode -t memory
cat /etc/os-release
```

```bash
sudo lspci -vv
make -C ./aggregator/ && sudo  ./aggregator/build/back2back --  --app firewall  --pcap_file ./synthetic_slf1_flow_num20000_seed42.pcap --fw_rules ./fw20000.rules
```

## Notes

Run app on specific core

```bash
taskset -c 0 <command>
```

Check process on CPU 0

```bash
bash -c 
```

Isolate one core on Ubuntu

```bash
vim /etc/default/grub
# GRUB_CMDLINE_LINUX="isolcpus=0"
# update grub (/boot/grub/grub.cfg)
sudo update-grub
# Verify it through /boot/grub/grub.cfg

# Check if CPU0 is really isolated (no user process at all)
ps -o pid,psr,comm -p <pid> # standard syntax (instead of BSD style)
ps -eo pid,psr,comm | awk  '($2 == 0)'
```
