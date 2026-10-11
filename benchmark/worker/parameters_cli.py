#!/usr/bin/env python3
"""Read-only: print the Console's brain-verified runtime parameters, the audited change log and
the dashboard's observation timeline as one JSON document, recording a new observation for each
policy whose values, generation or verdicts changed. Never writes to the cluster."""
import argparse
import json
import sys

import parameters
from runner import Console


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['snapshot'])
    parser.add_argument('--data', required=True)
    args = parser.parse_args()
    console = Console()
    try:
        record = parameters.capture(console)
    finally:
        console.close()
    if record.get('runtime'):
        parameters.observe(args.data, record)
    record['observations'] = parameters.recent_observations(args.data)
    print(json.dumps(record, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
