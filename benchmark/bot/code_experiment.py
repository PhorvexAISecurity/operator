"""Compare a candidate brain's decisions with the deployed brain's on recorded ticks.

A Math Lab replay experiment, but the arms are brain builds, not parameter values:

  control     the deployed brain-replay; a tick counts only if it reproduces
              production byte for byte.
  base-local  the deployed commit, built here. A toolchain-fidelity check: it
              must decide exactly like control (M-P21 = 0), or the local
              build cannot be trusted to stand for the candidate either.
  candidate   the candidate commit, built here. Replayed with
              -allow-cross-version, so every result is observational.

Snapshots are read from the dashboard's Math Lab data directory, which is never
written; the cohort is frozen into this experiment's own directory. The
analysis, metrics and exports are the Math Lab worker's own, unchanged. Like
all replay, this measures decision sensitivity on recorded states, not defense
or SLO outcomes.
"""
import shutil
import sys
from pathlib import Path

WORKER = Path(__file__).resolve().parents[1] / 'worker'
sys.path.insert(0, str(WORKER))
from mathlab import analysis, binary, exports  # noqa: E402
from mathlab.common import read_json, sha256_file, sha256_json, utc, write_json  # noqa: E402
from mathlab.experiment import select_cohort  # noqa: E402
from mathlab.snapshots import corpus_summary, local_index  # noqa: E402

ARMS = ('control', 'base-local', 'candidate')
HEADLINE = ('M-P21', 'M-P26', 'M-P19', 'M-P22', 'M-P25', 'M-P28')


class CodeExperimentError(Exception):
    pass


def _status(root, stage, message, state='RUNNING'):
    write_json(Path(root) / 'status.json', {'state': state, 'stage': stage, 'message': message, 'updated_at': utc()})


def run(data_dir, root, request, control, base_local, candidate, timeout=3600):
    """request: experiment_id, title, namespace, policy, cohort, base_commit,
    candidate_commit and provenance. control, base_local and candidate are
    binary identities (binary.local_identity, or the deployed current.json)."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    write_json(root / 'request.json', request)
    _status(root, 'checks', 'checking the cohort and the three builds')
    cohort = select_cohort(data_dir, request)
    if not cohort:
        raise CodeExperimentError('no recorded ticks for %s/%s; sync the policy first' % (request['namespace'], request['policy']))
    shas = {e['header'].get('gitSHA') for e in cohort}
    if len(shas) != 1:
        raise CodeExperimentError('the cohort mixes source revisions %s; narrow it to one release' % sorted(map(str, shas)))
    recorded = shas.pop()
    if control.get('git_sha') != recorded:
        raise CodeExperimentError('the deployed brain-replay is %s but the ticks were recorded by %s; re-sync after the deploy'
                                  % (control.get('git_sha'), recorded))
    if base_local.get('git_sha') != request['base_commit'] or request['base_commit'] != recorded:
        raise CodeExperimentError('the base build %s is not the recorded revision %s' % (base_local.get('git_sha'), recorded))
    if candidate.get('git_sha') != request['candidate_commit']:
        raise CodeExperimentError('the candidate build carries %s, not %s' % (candidate.get('git_sha'), request['candidate_commit']))

    _status(root, 'cohort', 'freezing %d ticks' % len(cohort))
    src = Path(data_dir).resolve() / 'mathlab' / 'snapshots' / request['namespace'] / request['policy']
    cohort_dir = root / 'cohort'
    cohort_dir.mkdir(exist_ok=True)
    for e in cohort:
        dst = cohort_dir / (e['digest'] + '.pxms')
        shutil.copy2(src / dst.name, dst)
        if sha256_file(dst) != e['digest']:
            raise CodeExperimentError('snapshot %s failed its content check' % e['digest'])

    identities = {'control': control, 'base-local': base_local, 'candidate': candidate}
    with open(root / 'replay.jsonl', 'w') as merged:
        for arm in ARMS:
            _status(root, 'replay', 'replaying %d ticks with %s' % (len(cohort), arm))
            write_json(root / ('arms-%s.json' % arm), [{'arm_id': arm, 'overrides': []}])
            out = root / ('replay-%s.jsonl' % arm)
            cmd = [identities[arm]['path'], '-snapshots', str(cohort_dir), '-arms', str(root / ('arms-%s.json' % arm)),
                   '-out', str(out), '-summary', str(root / ('replay-summary-%s.json' % arm))]
            if arm == 'candidate':
                cmd.append('-allow-cross-version')
            binary.run_isolated(cmd, timeout=timeout)
            merged.write(out.read_text())

    _status(root, 'analysis', 'computing metrics')
    policy = request['namespace'] + '/' + request['policy']
    labels = {'control': 'deployed brain-replay (recorded production)', 'base-local': 'deployed commit built here',
              'candidate': 'candidate brain'}
    values = {'control': request['base_commit'], 'base-local': request['base_commit'], 'candidate': request['candidate_commit']}
    ctx = {'experiment_id': request['experiment_id'], 'arms': list(ARMS), 'control': 'control', 'parameter_id': 'CODE',
           'policy': policy, 'seed': 20261009, 'comparison_status': 'OBSERVATIONAL',
           'arm_values': {a: {'value': values[a][:12], 'label': labels[a]} for a in ARMS}}
    lines = exports.stream_replay(root, request['experiment_id'], root / 'replay.jsonl')
    rows, plots, population = analysis.analyze(lines, ctx)

    base_rows = [r for r in rows if r['arm_id'] == 'base-local' and r['metric_id'] == 'M-P21']
    base_changed = base_rows[0]['value'] if base_rows else None
    matched = population['matched_by_arm']
    if population['control_eligible'] and matched.get('base-local') == population['control_eligible'] and base_changed == 0:
        fidelity = 'EXACT'
    else:
        fidelity = 'DIVERGED'
    if not population['control_eligible']:
        state = 'INVALID'
    elif matched.get('candidate') == population['control_eligible'] == len(cohort):
        state = 'COMPLETE'
    else:
        state = 'PARTIAL'
    manifest = {
        'schema_version': 'phorvex-bench.code-experiment-manifest.v1', 'experiment_id': request['experiment_id'],
        'title': request.get('title'), 'mode': 'CODE_REPLAY', 'hypothesis': request.get('hypothesis'),
        'parameter': {'param_id': 'CODE', 'name': 'brain source change', 'config_key': 'candidate %s' % request['candidate_commit'][:12]},
        'arms': [{'arm_id': a, 'label': labels[a], 'commit': values[a]} for a in ARMS], 'policy': policy,
        'cohort': {'snapshot_digests': [e['digest'] for e in cohort], 'digests_sha256': sha256_json([e['digest'] for e in cohort]),
                   'summary': corpus_summary(cohort), 'selection': request.get('cohort')},
        'replay_binary': control, 'builds': identities, 'provenance': request.get('provenance'),
        'limitations': [
            'Replay measures immediate decision sensitivity on recorded states; it does not observe defense, SLO impact or future-state effects.',
            'The candidate is a different source revision: every candidate result is cross-version and observational.',
            'After the candidate diverges from the control, later recorded states no longer follow from its decisions.',
            'Base-local fidelity %s: the deployed commit built here %s the deployed brain.' % (
                fidelity, 'decides exactly like' if fidelity == 'EXACT' else 'does NOT decide exactly like')],
        'tests': request.get('tests'), 'started_at': request.get('created_at'), 'finished_at': utc()}
    result = {'schema_version': 'phorvex-bench.code-experiment-result.v1', 'experiment_id': request['experiment_id'],
              'state': state, 'cohort_size': len(cohort),
              'comparison_status': 'OBSERVATIONAL', 'toolchain_fidelity': fidelity, 'population': population,
              'tests': request.get('tests'),
              'arm_values': ctx['arm_values'], 'replay_summaries': {a: read_json(root / ('replay-summary-%s.json' % a)) for a in ARMS},
              'finished_at': utc()}
    write_json(root / 'experiment_manifest.json', manifest)
    write_json(root / 'metrics.json', rows)
    write_json(root / 'plots.json', plots)
    write_json(root / 'result.json', result)
    _status(root, 'export', 'writing evidence')
    exports.write_all(root, manifest, rows, plots, result)
    _status(root, 'done', 'finished', state=state)
    return result, rows


def identity(path):
    """The identity of a brain-replay built here."""
    return binary.local_identity(path)

