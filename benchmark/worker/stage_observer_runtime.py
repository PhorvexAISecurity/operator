#!/usr/bin/env python3
"""Supervise one read-only, exact-source fixture observer; retain every old journal."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import stage_cli
from mathlab import stage_scope
from mathlab.common import read_json, sha256_file, sha256_json, utc
from stage_reconcile import capacity, observe
from benchmark.stage.observe import Kube, discover
from benchmark.stage.evidence import EvidenceError

POLICY = 'phorvex-staging-demo/stage-bench-defense'
SCHEMA = 'phorvex-bench.observer-runtime.v1'


def descriptor(data, repo, timeout=60):
    """Only exact allowlisted dryRun fixture identity may start a watch."""
    # Publication is one atomic file. Observe this immutable pin without the
    # job lease so a long, unchanged-source reconciliation does not manufacture
    # an observation gap. Starting a new child takes the lease separately.
    pin_path=Path(data)/'mathlab/stage.json'; before=sha256_file(pin_path)
    pin=stage_scope.load(data,POLICY)
    if pin.get('kube_context') != stage_scope.STAGE_CONTEXT or pin.get('service_namespace') != stage_scope.STAGE_NAMESPACE:
        raise stage_scope.StageError('OBSERVER_STAGE_SCOPE_MISMATCH')
    actual=observe([POLICY],time.monotonic()+timeout)
    policy=actual['policies'][POLICY]
    if policy['mode']!='dryRun':raise stage_scope.StageError('ACTIVE_POLICY_OBSERVATION_UNSUPPORTED')
    keys=('git_sha','image','image_digest','deployment_uid')
    if (any(actual[c].get(k)!=pin.get(c,{}).get(k) for c in ('brain','manager') for k in keys) or
            policy!=pin['policies'][POLICY] or actual['capture']!=pin.get('capture')):
        raise stage_scope.StageError('OBSERVER_RUNTIME_NOT_READY: actual source/policy/workload differs from pin')
    ns,name=stage_scope.policy(POLICY)
    scope=discover(Kube(stage_scope.STAGE_CONTEXT),ns,name,'stage-bench-api','stage-bench-api',
                   pin['brain']['git_sha'],pin['brain']['image_digest'])
    if (scope['policy_uid']!=policy['uid'] or scope['workload_uid']!=policy['workload_uid'] or
            scope['service_uid']!=policy['service_uid']):
        raise stage_scope.StageError('OBSERVER_SCOPE_CHANGED_DURING_DISCOVERY')
    if sha256_file(pin_path)!=before:raise stage_scope.StageError('OBSERVER_PIN_CHANGED_DURING_DISCOVERY')
    # Generations live outside scope.v1; old journal hashes remain unchanged.
    return {'schema':SCHEMA,'policy':POLICY,'scope':scope,'policy_generation':policy['generation'],
            'workload_generation':policy['workload_generation'],
            'manager':{k:pin['manager'][k] for k in keys},'brain_deployment_uid':pin['brain']['deployment_uid']}


def resolve_journal(data, pin, policy):
    if policy != POLICY:
        raise stage_scope.StageError('managed endpoint observation is available only for the isolated dryRun fixture')
    pointer = read_json(Path(data)/'mathlab/observer-current.json') or {}
    if pointer.get('schema') != SCHEMA or pointer.get('state') != 'RUNNING':
        raise stage_scope.StageError('managed fixture observer is not running; retain the requested window and wait for observation')
    desc = pointer.get('descriptor') or {}; scope = desc.get('scope') or {}
    expected = pin['policies'].get(policy) or {}
    if (desc.get('policy') != policy or scope.get('source_revision') != pin['brain']['git_sha'] or
            scope.get('image_digest') != pin['brain']['image_digest'] or scope.get('policy_uid') != expected.get('uid') or
            scope.get('workload_uid') != expected.get('workload_uid') or desc.get('policy_generation') != expected.get('generation') or
            scope.get('service_uid') != expected.get('service_uid') or
            desc.get('workload_generation') != expected.get('workload_generation') or expected.get('mode') != 'dryRun'):
        raise stage_scope.StageError('managed observer scope differs from current stage pin; no old history is reused')
    if (desc.get('brain_deployment_uid') != pin['brain'].get('deployment_uid') or
            desc.get('manager') != {k:pin.get('manager',{}).get(k) for k in ('git_sha','image','image_digest','deployment_uid')}):
        raise stage_scope.StageError('managed observer producer identity differs from current stage pin')
    root = Path(data).resolve()/'observer/managed'/sha256_json(desc)
    path = root/'compressed-evidence.db'
    if pointer.get('journal') != str(path) or not path.is_file() or path.is_symlink():
        raise stage_scope.StageError('managed observer journal identity is unavailable')
    if read_json(root/'descriptor.json') != desc or read_json(root/'scope.json') != scope:
        raise stage_scope.StageError('managed observer immutable scope changed')
    return path


class Supervisor:
    def __init__(self, data, repo, *, max_bytes=4 << 30, poll_seconds=30, scan_timeout=120):
        if not 64 << 20 <= max_bytes <= 16 << 30 or not 10 <= poll_seconds <= 300 or not 1 <= scan_timeout <= 1800:
            raise ValueError('observer capacity/poll/scan bounds are invalid')
        self.data, self.repo = Path(data).resolve(), Path(repo).resolve()
        self.max_bytes, self.poll_seconds, self.scan_timeout = max_bytes, poll_seconds, scan_timeout
        self.child, self.current = None, None
        self.pointer = self.data/'mathlab/observer-current.json'

    def stop_child(self):
        if self.child is not None and self.child.poll() is None:
            # Only this supervisor's Popen handle; never PID discovery/killall.
            self.child.terminate()
            try: self.child.wait(timeout=25)
            except subprocess.TimeoutExpired:
                self.child.kill(); self.child.wait(timeout=5)
        self.child = None

    def step(self):
        try:
            wanted = descriptor(self.data, self.repo)
            if self.child is not None and self.child.poll() is not None:
                self.child = None
            if wanted != self.current:
                self.stop_child()
                self.current = None
            if self.child is None:
                capacity(self.data, 16 << 20)
                root = self.data/'observer/managed'/sha256_json(wanted)
                root.mkdir(parents=True, exist_ok=True)
                for name,value in (('descriptor.json',wanted), ('scope.json',wanted['scope'])):
                    path=root/name
                    if path.exists() and read_json(path) != value:
                        raise stage_scope.StageError('immutable observer identity changed')
                    if not path.exists(): stage_cli.durable_json(path,value)
                # Confirm after file preparation before starting the child; a
                # pin transition between probes cannot launch old-scope history.
                command=[sys.executable,'-m','benchmark.stage.observe','watch','--scope',str(root/'scope.json'),
                         '--journal',str(root/'compressed-evidence.db'),'--seconds','31536000','--encoding','zlib-v1',
                         '--max-bytes',str(self.max_bytes),'--scan-timeout',str(self.scan_timeout)]
                with stage_scope.pin_lock(self.data,readonly=True) as leased:
                    if not leased or descriptor(self.data,self.repo) != wanted:
                        raise stage_scope.StageError('OBSERVER_IDENTITY_CHANGED_BEFORE_START')
                    self.child=subprocess.Popen(command, cwd=Path(__file__).resolve().parents[2], stdin=subprocess.DEVNULL)
                    self.current=wanted
            result={'schema':SCHEMA,'state':'RUNNING','at':utc(),'descriptor':wanted,
                    'journal':str(self.data/'observer/managed'/sha256_json(wanted)/'compressed-evidence.db'),
                    'owned_pid':self.child.pid, 'capacity':capacity(self.data),
                    'continuity':'Actual journal watch segments only; restart/source changes never bridge history.'}
        except (stage_scope.StageError,EvidenceError,OSError,ValueError,subprocess.TimeoutExpired) as error:
            self.stop_child()
            result={'schema':SCHEMA,'state':'BLOCKED','at':utc(),'reason':str(error),
                    'descriptor':self.current,'continuity':'Old journals retained; unavailable observation is not counted.'}
        except BaseException as error:
            self.stop_child()
            stage_cli.durable_json(self.pointer,{'schema':SCHEMA,'state':'FAILED','at':utc(),
                                               'reason':type(error).__name__+':'+str(error)})
            raise
        stage_cli.durable_json(self.pointer,result)
        return result

    def run(self, stop):
        self.pointer.parent.mkdir(parents=True,exist_ok=True)
        lease=(self.pointer.parent/'observer-supervisor.lock').open('a')
        try:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            lease.close()
            raise stage_scope.StageError('another owned observer supervisor is running')
        try:
            while not stop.is_set():
                self.step()
                stop.wait(self.poll_seconds)
        finally:
            self.stop_child()
            if stop.is_set():
                stage_cli.durable_json(self.pointer, {'schema':SCHEMA,'state':'STOPPED','at':utc(), 'descriptor':self.current})
            lease.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data',required=True); parser.add_argument('--repo',required=True)
    parser.add_argument('--max-bytes',type=int,default=4 << 30)
    parser.add_argument('--poll-seconds',type=int,default=30)
    parser.add_argument('--scan-timeout',type=int,default=120)
    args=parser.parse_args(); stop=threading.Event()
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_:stop.set())
    Supervisor(args.data,args.repo,max_bytes=args.max_bytes,poll_seconds=args.poll_seconds,scan_timeout=args.scan_timeout).run(stop)


if __name__=='__main__': main()
