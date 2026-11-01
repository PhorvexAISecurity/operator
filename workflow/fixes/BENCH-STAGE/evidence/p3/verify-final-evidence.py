"""Verify final review inputs; does not rerun or replace recorded producer tests."""
import datetime
import hashlib
import json
import pathlib
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[5]
FIX = REPO / 'workflow/fixes/BENCH-STAGE'
EVIDENCE = FIX / 'evidence'
HEAD = 'ec310e276e45e6a218f7520880e22c6c1c687817'


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


receipt_path = EVIDENCE / 'preflight/receipt.json'
receipt = read(receipt_path)
assert receipt['result'] == 'PASS'
assert receipt['plan']['head_sha'] == HEAD
assert receipt['plan']['base_sha'] == '9b5a3eb0e9b1b5a033290cee1302aa6b5059cf40'
patch = subprocess.check_output(['git', '-C', str(REPO), 'diff', '--binary', '--full-index',
                                 '--no-color', '--no-ext-diff', '--no-textconv',
                                 receipt['plan']['base_sha'], HEAD])
assert (FIX / '04-diff.patch').read_bytes() == patch
assert len(receipt['results']) == len(receipt['plan']['jobs']) == 18
assert {r['id'] for r in receipt['results']} == {j['id'] for j in receipt['plan']['jobs']}
for row in receipt['results']:
    assert row['result'] == 'PASS' and row['exit_code'] == 0, row
    assert sha(receipt_path.parent / row['log']) == row['sha256'], row['id']

status = read(EVIDENCE / 'final-source/preflight-ec310e27-final-status.json')
assert status['state'] == 'DONE' and status['exit_code'] == 0, status
assert status['source_sha'] == HEAD
acceptance = {}
for name in ['l1.txt', 'l2.txt']:
    path = EVIDENCE / 'final-source' / name
    data = path.read_text()
    assert '--- PASS:' in data and '\nok ' in '\n' + data, name
    assert '--- FAIL:' not in data and '\nFAIL' not in data, name
    acceptance[name] = {'sha256': sha(path), 'passed_test_rows': data.count('--- PASS:')}

bindings = read(EVIDENCE / 'p3/incident-evidence-bindings.json')
assert bindings['source_sha'] == HEAD
for name, digest in bindings['evidence'].items():
    assert sha(REPO / name) == digest, name
handover = read(EVIDENCE / 'live/final-status.json')
assert handover['result'] == 'PASS_SCOPED_STAGE_HANDOVER'
assert handover['source_tip'] == HEAD
for name, row in handover['artifacts'].items():
    path = EVIDENCE / name
    assert sha(path) == row['sha256'] and path.stat().st_size == row['bytes'], name
operational = read(EVIDENCE / 'peer-review/final-handover/operational-review.json')
assert str(operational['result']).startswith('PASS'), operational['result']
recovery = read(EVIDENCE / 'peer-review/final-handover/recovery-independent-review.json')
assert recovery['result'] == 'PASS_AUTOMATIC_POST_GAP_RECOVERY_64'
assert recovery['baseline_receipt_count'] == 64
assert recovery['raw_cohort']['snapshots_hash_header_clock_verified'] == 64
assert recovery['moves']['open'] == recovery['moves']['censored'] == 0
assert recovery['moves']['external_eviction_attributed'] is False

delivery = read(EVIDENCE / 'peer-review/code-retry/replay-delivery-review.json')
assert delivery['result'] == 'PASS_REAL_CODE_REPLAY_AND_FINAL_DELIVERY'
assert delivery['exact_reproduced_by_all_three_arms'] == 64
assert delivery['pending'] == delivery['omitted'] == 0
user_zip = pathlib.Path('/workspace/benchmark-delivery/2026-11-01-stage-brain/phorvex-stage-benchmark.zip')
assert sha(user_zip) == delivery['zip_sha256']

allowed_metadata = ('workflow/fixes/BENCH-STAGE/', 'workflow/campaigns/2026-10-31-stage-brain-benchmark/',
                    'workflow/intake/RPT-20261101-005200-stage-clock/',
                    'workflow/intake/RPT-20261101-005201-stage-vendored-chart/',
                    'workflow/intake/RPT-20261101-005202-stage-runtime-deadline/')
allowed_indexes = {'workflow/fixes/INDEX.yaml', 'workflow/campaigns/INDEX.yaml', 'workflow/intake/INDEX.yaml'}
delta = subprocess.check_output(['git', '-C', str(REPO), 'diff', '--name-only', HEAD], text=True).splitlines()
assert all(name in allowed_indexes or name.startswith(allowed_metadata) for name in delta), delta
result = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'by': 'bench-v3-lead',
          'source_sha': HEAD, 'result': 'PASS_FINAL_REVIEW_INPUTS',
          'scope': 'Input/hash and recorded-outcome verification; original producer executions retain their own commands and sources.',
          'preflight_sha256': sha(receipt_path), 'coherent_passed_gates': len(receipt['results']),
          'canonical_patch_sha256': hashlib.sha256(patch).hexdigest(),
          'acceptance': acceptance, 'incident_bindings_verified': len(bindings['evidence']),
          'operational_bindings_verified': len(handover['artifacts']),
          'recovery_review_sha256': sha(EVIDENCE / 'peer-review/final-handover/recovery-independent-review.json'),
          'user_zip_sha256': sha(user_zip), 'metadata_only_worktree_delta': delta}
(EVIDENCE / 'p3/review-input-verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'result': result['result'], 'gates': result['coherent_passed_gates'],
                  'source': HEAD, 'l1_l2': acceptance}))
