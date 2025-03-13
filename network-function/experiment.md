# Experiment Setup & Result

## NAT

```bash
perf stat -e L1-dcache-load-misses,L1-dcache-load taskset -c 0 ./nat ./synthetic_slf8_flow_num10000_count1_seed42.pcap
```

### Result

Note: All experiment is based on commit 86dde003c09783f93e35aefdd3fefd9e55734ff1

Make sure you have run the following command

```bash
git checkout 86dde003c09783f93e35aefdd3fefd9e55734ff1
```

Understand the impact of the flow number and SLF:
Processing time per packet:

| SLF | clients=1000 |  clients=10000(Setup of POM experiment) |
| -------- | -------- | -------- |
| 1 | 12.34 (-0%) | 23.21 (-0%) |
| 2 |   N/A | 19.49(-16.02%) |
| 3 | N/A | 18.42 |
| 4 |  12.70 (+2.9%) | 17.28 (-25%) |
|5 | N/A |16.60 |
|6| N/A | 17.02 |
|7 | N/A | 16.60 |
| 8 |      11.85      |  16.04(-30.89%)         |
| 9 | N/A | 15.56 |
| 10 | N/A | 16.31 |
|11 | N/A | 15.88 |
|12 |      11.63      |    15.08(-35%)       |
| 13 |N/A | 15.45 |
|14|N/A | 15.05 |
|15 | N/A | 15.54 |
| 16 | 11.75 (-4.78%) | 14.94 (-35%) |
| 32 | 11.55 (-6.4%) | 15.65 (-32.5%) |

clients= 10000

|SLF| L1 dcache miss rate|
| -------- | -------- |
| 1 |  13.57% |
| 2 | 9.68% |
| 3 | 8.12%  |
| 4 | 7.23% |
| 5 | 6.71%|
| 6 | 6.31% |
| 7| 6.04% |
| 8 | 5.84% |
| 9 | 5.69% |
| 10 | 5.56% |
| 11 | 5.46% |
| 12 | 5.38% |
| 13 | 5.30% |
|14 | 5.24% |
|15 | 5.18% |
| 16 | 5.14% |
| 32 | 4.77% |

## Firewall(TBD)
