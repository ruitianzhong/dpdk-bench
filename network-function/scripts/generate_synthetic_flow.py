#! /usr/bin/python3
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--slf", help="spacial locality factor(SLF)", type=int, default=1)
    parser.add_argument(
        "--flow-num", help="total number of flow", type=int, default=50)
    parser.add_argument(
        "--packet-per-flow", help="configure the number of packet per flow", type=int, default=20)
    parser.add_argument(
        "--seed", help="seed for generating random number", type=int, default=42)
    args = parser.parse_args()
    print(args.seed)
