"""Verify final author receipts without executing or relabelling their checks."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys

repo = Path(__file__).resolve().parents[5]
fix = repo / 'workflow/fixes/BENCH-SELFSERVE'
sys.path.insert(0, str(repo / 'workflow/tools'))
import preflight

base = 'c3174a516bee6bf8eae39749825051c3cfcb8cc6'
head = 'a5d8d6121ed7a285d79f76b5aba4f7dad506725e'
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip() == head
status = json.loads((fix / 'evidence/final-source/final-checks-status.json').read_text())
assert status['state'] == 'DONE' and status['exit_code'] == 0 and status['source_sha'] == head
assert len(status['results']) == 2 and all(row['exit_code'] == 0 and not row['timed_out'] for row in status['results'])
receipt_path = fix / 'evidence/preflight/receipt.json'
receipt = preflight.validate_receipt(repo, receipt_path, base, head, require_worktree=True)
manifest_path = fix / 'evidence/final-source/integrated-source-inputs-v3.json'
manifest = json.loads(manifest_path.read_text())
for row in manifest['paths']:
    raw = subprocess.check_output(['git', 'show', head + ':' + row['path']], cwd=repo)
    assert hashlib.sha256(raw).hexdigest() == row['sha256'], row['path']
    assert (repo / row['path']).read_bytes() == raw, row['path']
suites = {}
for name, expected_suites in [('l1', 2), ('l2', 3)]:
    raw = (fix / ('evidence/final-source/' + name + '.txt')).read_text()
    assert raw.startswith(head + '\nPython 3.12.15\n'), name
    counts = [int(n) for n in re.findall(r'^Ran (\d+) tests? in ', raw, re.M)]
    assert len(counts) == expected_suites and all(counts), (name, counts)
    assert len(re.findall(r'^OK$', raw, re.M)) == expected_suites, name
    assert 'skipped=' not in raw and '\nFAILED ' not in raw, name
    suites[name] = counts
record = {'result': 'PASS', 'source_base': base, 'source_head': head,
          'strict_worktree_validation': True, 'preflight_checks': len(receipt['results']),
          'runtime_source_blobs_verified': len(manifest['paths']), 'author_suites': suites,
          'preflight_sha256': hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
          'reference': 'Current committed-source local checks only; independent review and live acceptance are separate.'}
print(json.dumps(record, indent=2))
