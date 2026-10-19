import argparse
import json
from src.dns_monitor import run_replay

def main():
    p=argparse.ArgumentParser(description='Offline DNS configuration incident replay')
    p.add_argument('--scenario',default='examples/dns_sweeps.json')
    args=p.parse_args()
    for event in run_replay(args.scenario):print(json.dumps(event,sort_keys=True))
if __name__=='__main__':main()
