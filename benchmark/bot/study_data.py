"""Validate/install a normalized recorded trace for declarative studies.

This imports existing evidence. It cannot reconstruct missing ledgers from legacy
snapshots. The operator, not a Telegram request, chooses the data directory.
"""
import argparse
import json
import os
from pathlib import Path
import tempfile

from study import digest
from study_schema import POLICY, StudyError, strict_json, trace_validate


def install(source, data_dir, policy):
    if not POLICY.fullmatch(policy):
        raise StudyError('policy must be namespace/name')
    source = Path(source)
    if source.stat().st_size > 2*1024*1024:
        raise StudyError('trace exceeds 2 MiB')
    trace = strict_json(source.read_text())
    trace_validate(trace)
    if trace['evidence'] != 'recorded':
        raise StudyError('only recorded evidence may be installed as the recorded dataset')
    target = Path(data_dir)/'mathlab'/'study-traces'/(policy+'.json')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix='.study-trace-', dir=target.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(trace, f, ensure_ascii=False, allow_nan=False)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return {'path': str(target), 'trace_sha256': digest(trace), 'ticks': len(trace['ticks'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace')
    parser.add_argument('--data-dir', required=True)
    parser.add_argument('--policy', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(install(args.trace, args.data_dir, args.policy)))
    except (ValueError, OSError) as err:
        parser.exit(2, 'study-data: %s\n' % err)


if __name__ == '__main__':
    main()
