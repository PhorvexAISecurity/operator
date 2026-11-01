"""Actual pin flock control; external replay/cluster transports use declared fixtures."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

root = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(root / 'benchmark/worker'))
from test_endpoint_refresh import RefreshTests
from mathlab import stage_scope

case = RefreshTests('test_real_normalization_latest64_true_sourcepins_and_atomic_generation')
case.setUp()
child = None
try:
    positive = case.run_refresh()
    assert positive['state'] == 'READY' and positive['ticks'] == 64
    pointer_before = case.pointer().read_bytes()
    status = case.data / 'mathlab/endpoint-refresh' / (case.policy + '.status.json')
    status_before = status.read_bytes()
    case.sync.reset_mock()
    child = subprocess.Popen([sys.executable, '-c',
        'import fcntl,sys; f=open(sys.argv[1],"a"); fcntl.flock(f,fcntl.LOCK_EX); print("LOCKED",flush=True); sys.stdin.read()',
        str(case.data / 'mathlab/stage.lock')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert child.stdout.readline().strip() == 'LOCKED'
    start = time.monotonic()
    try:
        case.run_refresh()
    except stage_scope.StageError as exc:
        error = str(exc)
        assert error == 'stage pin is busy with active jobs or reconciliation; retry after it completes'
    else:
        raise AssertionError('Expected original unhandled lease timeout')
    elapsed = time.monotonic() - start
    assert elapsed >= 19 and status.read_bytes() == status_before and case.pointer().read_bytes() == pointer_before
    case.sync.assert_not_called()
    result = {'source': subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
              'result': 'EXPECTED_RED', 'real_process_exclusive_flock': True,
              'positive_control': {'state': positive['state'], 'ticks': positive['ticks']},
              'negative': {'error_type': 'StageError', 'error': error, 'elapsed_seconds': elapsed,
                           'status_stale': True, 'pointer_unchanged': True, 'sync_calls': 0},
              'status_sha256': hashlib.sha256(status_before).hexdigest(),
              'pointer_sha256': hashlib.sha256(pointer_before).hexdigest(),
              'limit': 'Real journal/normalizer/PXMS and actual OS lock; external cluster and replay CLI are explicit existing test transports, not live-brain proof.'}
    print(json.dumps(result,indent=2))
finally:
    if child is not None:
        child.stdin.close()
        child.wait(timeout=5)
    case.doCleanups()
