"""Local stage-backed parameter/sync adapter; never routes to a legacy dashboard."""
import json
import shutil
import uuid
from pathlib import Path

from mathlab import experiment, stage_scope
from mathlab.common import read_json, write_json, utc
from mathlab.snapshots import cache_lock, freeze_cohort
from stage_cli import sync_stage, readiness


class StageRuntime:
    def __init__(self, cfg):
        self.cfg = cfg
        self.requests = {}

    def policies(self):
        pin = stage_scope.load(self.cfg.data, repo=self.cfg.repo)
        return {'policies': [{'policy': p} for p in sorted(pin['policies'])]}

    def request_readiness(self, requested):
        import request_readiness
        return request_readiness.inspect(self.cfg.data, self.cfg.repo, requested)

    def sync(self, policy):
        sync_stage(self.cfg.data, self.cfg.repo, policy)
        return None  # Synchronous bounded collection; no legacy API queue.

    def prepare(self, request):
        request = dict(request)
        ns, name = stage_scope.policy(request['policy'])
        pin = stage_scope.load(self.cfg.data, request['policy'], self.cfg.repo)
        ident = stage_scope.identity(self.cfg.data, pin)
        request.update(schema_version='math-lab.experiment.v1', namespace=ns, policy=name)
        request['cohort'] = {**request.get('cohort', {}), **stage_scope.cohort_filter(pin, ns + '/' + name)}
        entries = experiment.select_cohort(self.cfg.data, request)
        wanted = request['cohort'].get('max_snapshots')
        if wanted is not None and len(entries) != wanted:
            raise stage_scope.StageError('stage cohort changed or contains fewer snapshots than requested; sync and retry the full requested cohort')
        request['stage_provenance'] = stage_scope.cohort(pin, ns + '/' + name, entries)
        request['cohort']['digests'] = [e['digest'] for e in entries]
        return request, ident, entries

    def preflight(self, request):
        # The bot queues one task at a time. Keep at most one uncreated frozen
        # request; never clean a created experiment or its retained results.
        for pending in self.requests.values():
            self.discard_prepared(pending)
        self.requests.clear()
        ns, name = stage_scope.policy(request['policy'])
        with cache_lock(self.cfg.data, ns, name):
            prepared, ident, entries = self.prepare(request)
            result = experiment.preflight(self.cfg.data, prepared, ident, cohort_entries=entries)
            # Freeze while selecting, before any queued create or cache prune.
            if result['status'] == 'PASS':
                prepared.update(experiment_id=str(uuid.uuid4()), created_at=utc())
                try:
                    freeze_cohort(self.cfg.data, ns, name, entries, self.root(prepared['experiment_id'])/'cohort')
                except Exception:
                    self.discard_prepared(prepared)
                    raise
                self.requests[json.dumps(request, sort_keys=True)] = prepared
        return result

    def discard_prepared(self, prepared):
        root = self.root(prepared['experiment_id'])
        if root.is_dir() and not (root/'request.json').exists():
            shutil.rmtree(root)

    def create(self, request):
        prepared = self.requests.pop(json.dumps(request, sort_keys=True), None)
        if prepared is None:
            raise stage_scope.StageError('stage request must pass preflight before creation')
        try:
            pin = stage_scope.load(self.cfg.data, request['policy'], self.cfg.repo)
            ident = stage_scope.identity(self.cfg.data, pin)
            from mathlab.common import sha256_json
            if sha256_json(pin) != prepared['stage_provenance']['pin_sha256']:
                raise stage_scope.StageError('stage pin changed after preflight; submit again')
            if ident['git_sha'] != prepared['cohort']['git_sha']:
                raise stage_scope.StageError('stage source changed after preflight; submit again')
        except Exception:
            self.discard_prepared(prepared)
            raise
        eid = prepared['experiment_id']
        write_json(self.root(eid) / 'request.json', prepared)
        return {'id': eid}

    def wait_experiment(self, eid, cancelled=lambda: False, progress=None, **unused):
        if cancelled():
            return {'status': 'INTERRUPTED', 'message': 'cancelled before replay'}
        if progress:
            progress('replaying the pinned stage brain on the frozen recorded cohort')
        state = experiment.run(self.cfg.data, eid, stage_scope.identity(self.cfg.data))
        root = self.root(eid)
        return {'status': state, 'result': read_json(root / 'result.json', {}),
                'manifest': read_json(root / 'experiment_manifest.json', {}),
                'message': (read_json(root / 'status.json', {}) or {}).get('message')}

    def root(self, eid):
        if str(uuid.UUID(eid)) != eid:
            raise stage_scope.StageError('invalid stage experiment id')
        return Path(self.cfg.data) / 'mathlab/experiments' / eid

    def metrics(self, eid):
        return read_json(self.root(eid) / 'metrics.json')

    def artifact(self, eid, name):
        if name not in ('report.md', 'result.json', 'experiment_manifest.json', 'evidence.zip'):
            raise stage_scope.StageError('unsupported stage artifact')
        return (self.root(eid) / name).read_bytes()
