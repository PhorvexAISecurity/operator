#!/usr/bin/env python3
"""M100 product-copy gate; historical reports, tests and catalog labels excluded.

Scan current dashboard components and audit/console Go.
Exact legacy `contained` wire tokens remain compatible; prose using that word
is rejected. Source comments and self-contained (software composition) are not
outcome claims. This gate does not certify mathematical or security validity.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
BAD = re.compile(r"\b(contained|secured|eliminated)\b|Contained the threat|Cleared injected state|SLO never broken|Zero-day foothold eviction|no data or job loss", re.I)

def violations(text):
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(('//', '*', '/*', '{/*')):
            continue
        line = line.replace('self-contained', '')
        # Only the exact historical protocol value, never a sentence.
        line = line.replace('"contained"', '')
        if BAD.search(line):
            yield number

def main():
    files = list((ROOT / 'dashboard-web/components').rglob('*.tsx'))
    for part in ('audit', 'console'):
        files += list((ROOT / f'phorvex/internal/{part}').rglob('*.go'))
    files = sorted(p for p in files if not p.name.endswith('_test.go'))
    errors = [f'{p.relative_to(ROOT)}:{n}: unqualified outcome language' for p in files for n in violations(p.read_text())]
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'M100 claim-language gate passed ({len(files)} current product source files)')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
