"""Offline doubles shared by the bot tests (not a test module itself).

- make_repo: a tiny operator repository whose brain decides by
  `const RotateThreshold = N` in phorvex/internal/decision/decision.go, with a
  release tag at its first commit.
- make_snapshot: a Math Lab snapshot file (PXMLSNP1 + header + payload), named by
  its own sha256 as the real corpus is; the payload holds the tick's risk and
  the decision production recorded.
- write_fake_replay: a stand-in brain-replay with the real CLI (-version,
  -snapshots/-arms/-out/-summary, -allow-cross-version) and output schema. It
  selects a move when risk > its compiled threshold, and refuses snapshots of
  another revision (VERSION_MISMATCH) unless -allow-cross-version is given.
- write_fake_go: a stand-in `go build ./cmd/brain-replay` that "compiles" the
  threshold it finds in the source into a fake brain-replay. So a candidate
  diff to decision.go really changes the decisions.
"""
import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path

GIT_ENV = {'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_AUTHOR_NAME': 'seed', 'GIT_AUTHOR_EMAIL': 'seed@example.invalid',
           'GIT_COMMITTER_NAME': 'seed', 'GIT_COMMITTER_EMAIL': 'seed@example.invalid'}
DECISION = 'phorvex/internal/decision/decision.go'

FAKE_REPLAY = r'''#!/usr/bin/env python3
import json, pathlib, struct, sys
GIT_SHA = %(git_sha)r
THRESHOLD = %(threshold)d
args = sys.argv[1:]
if '-version' in args:
    print(json.dumps({'gitSHA': GIT_SHA, 'brainImage': 'local', 'snapshotSchema': 'math-lab.snapshot.v1',
                      'replaySchema': 'math-lab.replay.v1', 'overridableParameters': ['P-OBJ-003', 'P-FEA-006']}))
    sys.exit(0)
def opt(name):
    return args[args.index(name) + 1]
cross = '-allow-cross-version' in args
arms = json.load(open(opt('-arms')))
lines, by_status = [], {}
for path in sorted(pathlib.Path(opt('-snapshots')).glob('*.pxms')):
    raw = path.read_bytes()
    size = struct.unpack('>I', raw[8:12])[0]
    header, payload = json.loads(raw[12:12 + size]), json.loads(raw[12 + size:])
    other = header['gitSHA'] != GIT_SHA
    for i, arm in enumerate(arms):
        base = {'snapshot': {'snapshot_digest': path.stem, 'captured_at': header['capturedAt']}, 'arm_id': arm['arm_id'],
                'cross_version': other and cross, 'replay_git_sha': GIT_SHA}
        if other and not cross:
            line = {**base, 'status': 'VERSION_MISMATCH', 'reasons': ['VERSION_MISMATCH: recorded by ' + header['gitSHA']]}
        else:
            selected = payload['risk'] > THRESHOLD
            line = {**base, 'status': 'OK', 'selected_set': ['vllm/a:rotate'] if selected else [],
                    'estimated_objective_m_p18': 1.0 if selected else 0.0, 'replay_seconds': 0.01, 'arm_max_moves_per_tick': 1,
                    'decisions': [{'asset': 'vllm/a', 'action': 'rotate', 'selected': selected, 'attack_backed': True,
                                   'common_weight_covered': 2.0 if selected else 0, 'expected_cost': 0.3,
                                   'noop_reason': '' if selected else 'FEASIBLE_NONPOSITIVE_GAIN'}],
                    'funnel': {'assets': 1, 'attack_backed_assets': 1, 'enabled_pairs': 4, 'admitted': 2, 'scored': 2,
                               'positive_gain': 2 if selected else 0, 'selected': int(selected), 'noop_by_reason': {},
                               'first_veto_by_gate': {'G9-chi-ceiling': 2}, 'complete_feasible_evidence': True,
                               'attack_backed_assets_with_positive_gain_feasible': int(selected), 'g9_categories': {'G9_PASS': 2},
                               'unassessed_gate_pairs': 1, 'applicable_gate_pairs': 10}}
            if i == 0:
                line['baseline_check'] = {'reproduced': (not other) and selected == payload['recorded_selected']}
        by_status[line['status']] = by_status.get(line['status'], 0) + 1
        lines.append(line)
with open(opt('-out'), 'w') as f:
    f.writelines(json.dumps(l) + '\n' for l in lines)
if '-summary' in args:
    json.dump({'schema_version': 'math-lab.replay-summary.v1', 'replay_git_sha': GIT_SHA, 'results_by_status': by_status},
              open(opt('-summary'), 'w'))
'''

FAKE_GO = r'''#!/usr/bin/env python3
import os, re, sys, pathlib
args = sys.argv[1:]
if args[:1] == ['version']:
    print('go version go1.26.4 linux/amd64'); sys.exit(0)
if os.environ.get('FAKE_GO_FAIL'):
    print('fake go: build failed', file=sys.stderr); sys.exit(1)
assert args[0] == 'build' and args[-1] == './cmd/brain-replay', args
assert os.environ.get('GOFLAGS') == '-mod=readonly -buildvcs=false' and os.environ.get('CGO_ENABLED') == '0', os.environ
sha = re.search(r'linkedGitSHA=([0-9a-f]{40})', ' '.join(args)).group(1)
out = args[args.index('-o') + 1]
threshold = int(re.search(r'RotateThreshold = (\d+)', pathlib.Path('internal/decision/decision.go').read_text()).group(1))
pathlib.Path(out).write_text(open(os.environ['FAKE_REPLAY_TEMPLATE']).read() % {'git_sha': sha, 'threshold': threshold})
os.chmod(out, 0o755)
'''


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, text=True, capture_output=True,
                          env={**os.environ, **GIT_ENV}).stdout.strip()


def make_repo(path, threshold=3, tag='manager-v0.12.0'):
    path = Path(path)
    (path / 'phorvex/internal/decision').mkdir(parents=True)
    (path / 'phorvex/cmd/brain-replay').mkdir(parents=True)
    (path / DECISION).write_text('package decision\n\nconst RotateThreshold = %d\n' % threshold)
    (path / 'phorvex/cmd/brain-replay/main.go').write_text('package main\n')
    (path / 'phorvex/go.mod').write_text('module github.com/phorvex/phorvex\n\ngo 1.26.1\n')
    git(path, 'init', '-q', '-b', 'main')
    git(path, 'add', '-A')
    git(path, 'commit', '-q', '-m', 'base')
    git(path, 'tag', '-a', '-m', 'release', tag)
    return git(path, 'rev-parse', 'HEAD')


def threshold_diff(old, new):
    return ('--- a/%s\n+++ b/%s\n@@ -1,3 +1,3 @@\n package decision\n \n-const RotateThreshold = %d\n+const RotateThreshold = %d\n'
            % (DECISION, DECISION, old, new))


def make_snapshot(directory, git_sha, risk, recorded_selected, captured_at):
    header = json.dumps({'schema': 'math-lab.snapshot.v1', 'capturedAt': captured_at, 'gitSHA': git_sha, 'namespace': 'vllm',
                         'policyName': 'vllm-defense', 'policyUID': 'u', 'economicsMode': 'legacy-runtime-lambda-v1',
                         'processConfigHash': 'p', 'parameterManifestHash': 'm', 'policyOverridesHash': 'o',
                         'finalized': True}).encode()
    data = b'PXMLSNP1' + struct.pack('>I', len(header)) + header + json.dumps(
        {'risk': risk, 'recorded_selected': recorded_selected}).encode()
    digest = hashlib.sha256(data).hexdigest()
    Path(directory).mkdir(parents=True, exist_ok=True)
    (Path(directory) / (digest + '.pxms')).write_bytes(data)
    return digest


def make_corpus(data_dir, git_sha, risks=(1, 2, 3, 4, 5, 6), recorded_threshold=3):
    """A dashboard Math Lab data directory holding recorded vllm/vllm-defense ticks."""
    directory = Path(data_dir) / 'mathlab' / 'snapshots' / 'vllm' / 'vllm-defense'
    return [make_snapshot(directory, git_sha, r, r > recorded_threshold, '2026-10-28T00:00:%02dZ' % i)
            for i, r in enumerate(risks)]


def write_fake_replay(path, git_sha, threshold):
    path = Path(path)
    path.write_text(FAKE_REPLAY % {'git_sha': git_sha, 'threshold': threshold})
    path.chmod(0o755)
    return path


def write_fake_go(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    template = directory / 'replay.template'
    template.write_text(FAKE_REPLAY)
    go = directory / 'go'
    go.write_text(FAKE_GO)
    go.chmod(0o755)
    return go, template
