# Experiment Setup & Result

## NAT

### Result

Understand the impact of the flow number and SLF:
Processing time per packet:

| SLF | clients=1000 |  clients=10000(Setup of POM experiment) |
| -------- | -------- | -------- |
| 1 | 12.34 (-0%) | 23.21 (-0%) |
| 4 |  12.70 (+2.9%) | 17.28 (-25%) |
| 16 | 11.75 (-4.78%) | 14.94 (-35%) |
| 32 | 11.55 (-6.4%) | 15.65 (-32.5%) |

clients= 10000

|SLF| L1 dcache miss rate|
| -------- | -------- |
| slf=1 |  13.57% |
| slf=4 | 7.23% |
| slf=16 | 5.14% |
| slf=32 | 4.77% |

## Firewall(TBD)
