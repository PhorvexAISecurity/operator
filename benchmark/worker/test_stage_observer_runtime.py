"""Supervisor identity and real owned-process lifecycle controls, no live API writes."""
import copy
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parents[1]))
import stage_cli
import stage_reconcile
import stage_observer_runtime as observer
from mathlab import binary,stage_scope
from mathlab.common import read_json,sha256_file
from benchmark.worker.test_stage_reconcile import Producer
from benchmark.stage.evidence import Journal
from benchmark.stage import test_evidence as observed
from benchmark.stage.normalize import normalize
from benchmark.bot import testkit

CHILD='''import json,sys,time
from benchmark.stage.evidence import Journal
journal=Journal(sys.argv[1],json.load(open(sys.argv[2])),encoding='zlib-v1',max_bytes=67108864)
journal.append('session',{'id':'actual-child-session'})
time.sleep(60)
'''


class ObserverTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name);self.p=Producer(self.root)
        for patch in (mock.patch.object(stage_cli,'kube',side_effect=self.p.kube),mock.patch.object(binary,'ensure_binary',side_effect=self.p.ensure),
                      mock.patch('runner.Console',side_effect=self.p.console),mock.patch.object(observer.Kube,'get',side_effect=self.get)):
            patch.start();self.addCleanup(patch.stop)
        result=stage_reconcile.reconcile(self.p.data,self.p.repo,ticks=2,timeout=30)
        self.assertEqual(result['status'],'READY',result)
        self.supervisor=observer.Supervisor(self.p.data,self.p.repo,max_bytes=64<<20)
        self.addCleanup(self.supervisor.stop_child)
        original=subprocess.Popen
        def child(command,**kwargs):
            if command[1:4] != ['-m','benchmark.stage.observe','watch']:
                return original(command,**kwargs)
            self.assertEqual(command[1:4],['-m','benchmark.stage.observe','watch'])
            self.assertNotIn('calibrate',command)
            path=command[command.index('--journal')+1];scope=command[command.index('--scope')+1]
            return original([sys.executable,'-c',CHILD,path,scope],env={**os.environ,'PYTHONPATH':str(HERE.parents[1])},**kwargs)
        patch=mock.patch.object(observer.subprocess,'Popen',side_effect=child);patch.start();self.addCleanup(patch.stop)
    def get(self,path):
        if '/phorvexpolicies/' in path:return copy.deepcopy(self.p.policies['stage-bench-defense'])
        if '/deployments/' in path:return copy.deepcopy(self.p.workloads['stage-bench-api'])
        if '/services/' in path:return copy.deepcopy(self.p.services['stage-bench-api'])
        raise AssertionError(path)
    def started(self):
        before={str(path):self.event_count(path) for path in (self.p.data/'observer/managed').glob('*/compressed-evidence.db')}
        result=self.supervisor.step();self.assertEqual(result['state'],'RUNNING',result)
        for _ in range(100):
            if self.event_count(result['journal']) > before.get(result['journal'],0):break
            time.sleep(.01)
        self.assertGreater(self.event_count(result['journal']),before.get(result['journal'],0));return result
    def event_count(self,path):
        try:
            with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True) as db:
                return db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        except sqlite3.Error:return 0
    def test_true_scope_generation_transition_retains_old_journal_and_stops_owned_child(self):
        first=self.started();child=self.supervisor.child;old=Path(first['journal']);old_scope=read_json(old.parent/'scope.json')
        self.p.workloads['stage-bench-api']['metadata']['generation']=2
        unavailable=self.supervisor.step();self.assertEqual(unavailable['state'],'BLOCKED');self.assertIsNotNone(child.poll())
        self.assertEqual(read_json(old.parent/'scope.json'),old_scope)
        result=stage_reconcile.reconcile(self.p.data,self.p.repo,ticks=2,timeout=30);self.assertEqual(result['status'],'READY',result)
        second=self.started();self.assertNotEqual(second['journal'],first['journal']);self.assertTrue(old.is_file())
        self.assertEqual(second['descriptor']['workload_generation'],2)
        current=observer.resolve_journal(self.p.data,stage_scope.load(self.p.data),observer.POLICY)
        self.assertEqual(current,Path(second['journal']))
    def test_active_fixture_is_blocked_and_current_pointer_cannot_serve_old_history(self):
        self.started();child=self.supervisor.child
        self.p.policies['stage-bench-defense']['spec']['mode']='active'
        result=self.supervisor.step();self.assertEqual(result['state'],'BLOCKED');self.assertIn('ACTIVE_POLICY',result['reason'])
        self.assertIsNotNone(child.poll())
        with self.assertRaises(stage_scope.StageError):observer.resolve_journal(self.p.data,stage_scope.load(self.p.data),observer.POLICY)
        with self.assertRaises(stage_scope.StageError):observer.resolve_journal(self.p.data,stage_scope.load(self.p.data),stage_scope.ALLOWED_POLICIES[0])
    def test_manager_transition_and_pointer_tamper_are_not_reused(self):
        self.started();pin=stage_scope.load(self.p.data)
        altered=copy.deepcopy(pin);altered['manager']['image_digest']='sha256:'+'a'*64
        with self.assertRaisesRegex(stage_scope.StageError,'producer identity'):observer.resolve_journal(self.p.data,altered,observer.POLICY)
        pointer=self.p.data/'mathlab/observer-current.json';value=read_json(pointer);value['journal']='/tmp/unrelated.db';stage_cli.durable_json(pointer,value)
        with self.assertRaises(stage_scope.StageError):observer.resolve_journal(self.p.data,pin,observer.POLICY)
    def test_discovery_uid_race_never_starts_child(self):
        original=self.get
        def changed(path):
            value=original(path)
            if '/deployments/' in path:value['metadata']['uid']='recreated-during-discovery'
            return value
        with mock.patch.object(observer.Kube,'get',side_effect=changed):result=self.supervisor.step()
        self.assertEqual(result['state'],'BLOCKED');self.assertIn('SCOPE_CHANGED_DURING_DISCOVERY',result['reason'])
        self.assertIsNone(self.supervisor.child)
    def test_child_restart_is_new_journal_session_not_backdated_continuity(self):
        first=self.started();self.supervisor.stop_child()
        second=self.started();self.assertEqual(first['journal'],second['journal'])
        journal=Journal(second['journal']);self.addCleanup(journal.close)
        sessions=[r for r in journal.records() if r['kind']=='session']
        self.assertEqual(len(sessions),2);self.assertGreater(sessions[1]['at'],sessions[0]['at'])

    def test_unchanged_observation_continues_while_reconciler_holds_exclusive_lease(self):
        self.started();child=self.supervisor.child;ready=threading.Event();release=threading.Event()
        def lease():
            with stage_scope.pin_lock(self.p.data,exclusive=True):ready.set();release.wait(5)
        thread=threading.Thread(target=lease);thread.start();self.assertTrue(ready.wait(2))
        try:
            result=self.supervisor.step();self.assertEqual(result['state'],'RUNNING',result)
            self.assertIs(self.supervisor.child,child);self.assertIsNone(child.poll())
        finally:release.set();thread.join()

    def test_real_new_git_source_establishes_new_scope_without_old_history(self):
        first=self.started();old_source=self.p.source;old=Path(first['journal'])
        testkit.git(self.p.repo,'commit','--allow-empty','-qm','new exact source')
        self.p.source=testkit.git(self.p.repo,'rev-parse','HEAD')
        self.p.executable.write_text(self.p.executable.read_text().replace(old_source,self.p.source))
        self.p.digests={'brain':'a'*64,'manager':'b'*64};self.p.make_records()
        self.assertEqual(self.supervisor.step()['state'],'BLOCKED')
        result=stage_reconcile.reconcile(self.p.data,self.p.repo,ticks=2,timeout=30)
        self.assertEqual(result['status'],'READY',result)
        second=self.started();self.assertNotEqual(first['journal'],second['journal'])
        self.assertEqual(read_json(old.parent/'scope.json')['source_revision'],old_source)
        self.assertEqual(second['descriptor']['scope']['source_revision'],self.p.source)
        journal=Journal(second['journal']);self.addCleanup(journal.close)
        self.assertEqual(len(list(journal.records())),1)


class GenerationBindingTests(unittest.TestCase):
    def test_actual_asof_reducer_and_normalizer_bind_observed_generations(self):
        with tempfile.TemporaryDirectory() as root:
            journal=Journal(Path(root)/'evidence.db',observed.scope());self.addCleanup(journal.close)
            observed.seed(journal);observed.rotate(journal);observed.seal(journal,100)
            snapshot=observed.asof(journal,100)
            self.assertEqual(snapshot['policy_generation'],1);self.assertEqual(snapshot['workload_generation'],1)
            # The normalizer's existing actual export fixtures exercise all
            # pricing fields; assert additive provenance at their same tick.
            row=observed.export(90)
            trace,metadata=normalize(journal.scope,journal.records,[row],.9,60,60,0)
            self.assertEqual(metadata['bindings'][0]['policy_generation'],1)
            self.assertEqual(metadata['bindings'][0]['workload_generation'],1)


if __name__=='__main__':unittest.main()
