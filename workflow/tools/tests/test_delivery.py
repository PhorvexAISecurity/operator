from __future__ import annotations

import argparse
import copy
import contextlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from test_operations import sandbox, workflow as w, run
from test_contracts import ready_snapshot
import delivery
import preflight


def setup(repo, baseline):
    fix, status = ready_snapshot(repo, baseline)
    status['state'] = 'AGREED'; status['delivery_version'] = 1
    w.write_yaml(fix/'STATUS.yaml',status)
    return fix


def revision(fix): return w.load_yaml(fix/'STATUS.yaml')['revision']


def receipt(repo, fix):
    s=w.load_yaml(fix/'STATUS.yaml');impl=s['implementation']
    path=fix/'evidence/preflight/receipt.json'
    selected=preflight.plan(repo,impl['base_sha'],impl['head_sha'])
    result=preflight.run_plan(repo,selected,path,argparse.Namespace(python=None,helm=None,timeout=30))
    assert result['result']=='PASS',result
    return str(path.relative_to(fix))


def package(fix, receipt_path):
    s=w.load_yaml(fix/'STATUS.yaml')
    checks={}
    for key in ['implementation','l0','l1','l2','positive_control']:
        checks[key]={'artifact':s['checks'][key]['artifact'],'command':'synthetic fixture command'}
    checks['l0']['inputs']=['widget.txt']
    return {'checks':checks,'preflight':receipt_path}


def submit(fix, data, by='author', expect=None):
    file=fix/'submit.yaml';w.write_yaml(file,data)
    return w.cmd_submit_review(argparse.Namespace(fix_id=fix.name,file=str(file),by=by,
        expect_revision=revision(fix) if expect is None else expect,no_notify=True))


def review(fix, *, result='PASS', approve=False, by='reviewer', reuse=None):
    path=fix/'evidence/p3/verdict.md';path.write_text('Independent current delta review: '+result+'\n')
    data={'checks':{'p3':{'artifact':'evidence/p3/verdict.md','result':result,'command':'review current delta and incident'}}}
    if reuse:data['reuse']=reuse
    elif result=='PASS':data['checks']['incident']={'artifact':'evidence/incident.md','command':'independent real producer reproduction'}
    if approve:data['approve_reuse']=['l0']
    file=fix/'review.yaml';w.write_yaml(file,data)
    return w.cmd_review_verdict(argparse.Namespace(fix_id=fix.name,file=str(file),by=by,
        result=result,expect_revision=revision(fix),no_notify=True))


class DeliveryTests(unittest.TestCase):
    def test_role_batches_advance_once_and_reviewer_can_own_red(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline)
            self.assertEqual(w.cmd_record_check(argparse.Namespace(fix_id=fix.name,check='red',by='reviewer',
                artifact='evidence/red.txt',result='PASS',command='baseline negative control',approval_ref=None,
                rationale=None,expect_revision=revision(fix))),0)
            before=revision(fix)
            self.assertEqual(submit(fix,package(fix,receipt(repo,fix))),0)
            s=w.load_yaml(fix/'STATUS.yaml')
            self.assertEqual((s['revision'],s['state'],s['checks']['red']['by']),(before+1,'OFFLINE_VERIFIED','reviewer'))
            before=revision(fix)
            self.assertEqual(review(fix,approve=True),0)
            s=w.load_yaml(fix/'STATUS.yaml')
            self.assertEqual((s['revision'],s['state']),(before+1,'PR_READY'))
            self.assertEqual(s['reuse_approvals']['l0']['by'],'reviewer')
            self.assertNotIn('merge',s['approvals'])

    def test_existing_current_checks_and_authorized_waiver_need_no_resigning(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline)
            self.assertEqual(w.cmd_record_check(argparse.Namespace(fix_id=fix.name,check='l2',by='owner',
                artifact='evidence/l2.txt',result='NOT_REQUIRED',command='record explicit scoped waiver',
                approval_ref='fixture:approved',rationale='Synthetic stateless fixture has no multi-tick behavior.',
                expect_revision=revision(fix))),0)
            before=w.load_yaml(fix/'STATUS.yaml')['checks']['l2']
            self.assertEqual(submit(fix,{'preflight':receipt(repo,fix),'checks':{}}),0)
            self.assertEqual(w.load_yaml(fix/'STATUS.yaml')['checks']['l2'],before)

    def test_submit_keeps_matching_patch_bytes_and_renders_full_index_when_stale(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline);impl=w.load_yaml(fix/'STATUS.yaml')['implementation']
            abbreviated=subprocess.check_output(['git','-c','core.abbrev=8','diff','--binary',impl['base_sha'],impl['head_sha']],cwd=repo)
            canonical=subprocess.check_output(['git','diff','--binary','--full-index',impl['base_sha'],impl['head_sha']],cwd=repo)
            self.assertNotEqual(abbreviated,canonical)
            (fix/'04-diff.patch').write_bytes(abbreviated)
            self.assertEqual(w.cmd_record_check(argparse.Namespace(fix_id=fix.name,check='implementation',by='author',
                artifact='04-diff.patch',result='PASS',command='git diff --binary base head',approval_ref=None,rationale=None,
                inputs=None,expect_revision=revision(fix))),0)
            signed=w.load_yaml(fix/'STATUS.yaml')['checks']['implementation']
            self.assertEqual(submit(fix,{'preflight':receipt(repo,fix),'checks':{}}),0)
            self.assertEqual((fix/'04-diff.patch').read_bytes(),abbreviated)
            self.assertEqual(w.load_yaml(fix/'STATUS.yaml')['checks']['implementation'],signed)
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline);impl=w.load_yaml(fix/'STATUS.yaml')['implementation']
            (fix/'04-diff.patch').write_bytes(b'stale artifact\n')
            data=package(fix,receipt(repo,fix))
            self.assertEqual(submit(fix,data),0)
            self.assertEqual((fix/'04-diff.patch').read_bytes(),
                subprocess.check_output(['git','diff','--binary','--full-index',impl['base_sha'],impl['head_sha']],cwd=repo))
            self.assertEqual(w.load_yaml(fix/'STATUS.yaml')['checks']['implementation']['sha256'],w.sha256(fix/'04-diff.patch'))

    def test_partial_batch_rolls_back_files_and_pin_updates(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline);data=package(fix,receipt(repo,fix))
            data['checks']['l2']['artifact']='evidence/missing.log'
            paths=[fix/'STATUS.yaml',fix/'04-diff.patch',fix/'evidence/manifest.yaml',w.FIXES/'INDEX.yaml',w.ISSUES/'MASTER_ISSUES.md']
            before={p:p.read_bytes() for p in paths}
            self.assertEqual(submit(fix,data),1)
            self.assertEqual(before,{p:p.read_bytes() for p in paths})

    def test_late_scope_approval_failure_rolls_back_review_transitions(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline)
            self.assertEqual(submit(fix,package(fix,receipt(repo,fix))),0)
            data={'checks':{
                'incident':{'artifact':'evidence/incident.md','command':'independent reproduction'},
                'p3':{'artifact':'evidence/p3/verdict.md','command':'independent review','result':'PASS'}},
                'approve_reuse':['implementation']}
            file=fix/'review.yaml';w.write_yaml(file,data)
            paths=[fix/'STATUS.yaml',fix/'evidence/manifest.yaml',w.FIXES/'INDEX.yaml',w.ISSUES/'MASTER_ISSUES.md']
            before={path:path.read_bytes() for path in paths}
            self.assertEqual(w.cmd_review_verdict(argparse.Namespace(fix_id=fix.name,file=str(file),by='reviewer',
                result='PASS',expect_revision=revision(fix),no_notify=True)),1)
            self.assertEqual(before,{path:path.read_bytes() for path in paths})

    def test_author_cannot_review_and_reviewer_cannot_submit(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline)
            self.assertEqual(submit(fix,package(fix,receipt(repo,fix)),by='reviewer'),1)
            self.assertEqual(review(fix,by='author'),1)
            self.assertEqual(submit(fix,{'checks':{'p3':{'artifact':'evidence/p3/verdict.md','command':'forge'}}}),1)

    def test_stale_revision_and_missing_preflight_fail_closed(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline);data=package(fix,receipt(repo,fix))
            self.assertEqual(submit(fix,data,expect=revision(fix)-1),1)
            data.pop('preflight')
            self.assertEqual(submit(fix,data),1)

    def test_failed_review_returns_to_implementer(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline)
            self.assertEqual(submit(fix,package(fix,receipt(repo,fix))),0)
            self.assertEqual(review(fix,result='FAIL'),0)
            s=w.load_yaml(fix/'STATUS.yaml')
            self.assertEqual(s['state'],'IMPLEMENTED');self.assertEqual(s['next_action']['owner'],'implementer')

    def test_passing_review_cannot_bypass_missing_incident(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline)
            self.assertEqual(submit(fix,package(fix,receipt(repo,fix))),0)
            (fix/'evidence/incident.md').unlink()
            before=revision(fix)
            self.assertEqual(review(fix),1)
            self.assertEqual(revision(fix),before)

    def test_reuse_requires_review_and_rejects_changed_dependency(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline)
            self.assertEqual(submit(fix,package(fix,receipt(repo,fix))),0)
            with self.assertRaises(ValueError):w.evidence_scope.prepare_reuse(w,fix,w.load_yaml(fix/'STATUS.yaml'),'l0','author')
            self.assertEqual(review(fix,approve=True),0)
            original=w.load_yaml(fix/'STATUS.yaml')
            (repo/'packaging.txt').write_text('new packaging\n');run(['git','add','packaging.txt'],repo);run(['git','commit','-m','packaging'],repo)
            s=copy.deepcopy(original);s['state']='IN_PR';s['implementation']['head_sha']=run(['git','rev-parse','HEAD'],repo);w.write_yaml(fix/'STATUS.yaml',s)
            data=package(fix,receipt(repo,fix));data['checks'].pop('l0');data['reuse']=['l0']
            self.assertEqual(submit(fix,data),0)
            s=w.load_yaml(fix/'STATUS.yaml');self.assertIn('reused_from',s['checks']['l0'])
            self.assertEqual(w.gates.check_errors(root,fix,s,'l0'),[])
            self.assertEqual(review(fix,approve=True),0)
            (repo/'widget.txt').write_text('changed relevant dependency\n');run(['git','add','widget.txt'],repo);run(['git','commit','-m','behavior'],repo)
            s=w.load_yaml(fix/'STATUS.yaml');s['implementation']['head_sha']=run(['git','rev-parse','HEAD'],repo);w.write_yaml(fix/'STATUS.yaml',s)
            with self.assertRaises(ValueError):w.evidence_scope.prepare_reuse(w,fix,s,'l0','author')

    def test_delta_packet_respects_blind_seal(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline);s=w.load_yaml(fix/'STATUS.yaml');s['blind_derivation']['status']='pending';w.write_yaml(fix/'STATUS.yaml',s)
            self.assertEqual(w.cmd_review_delta(argparse.Namespace(fix_id=fix.name,agent='reviewer')),1)

    def test_missing_log_and_dirty_code_invalidate_preflight(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline);path=fix/receipt(repo,fix);s=w.load_yaml(fix/'STATUS.yaml')['implementation']
            preflight.validate_receipt(repo,path,s['base_sha'],s['head_sha'])
            (repo/'widget.txt').write_text('uncommitted change\n')
            with self.assertRaises(ValueError):preflight.validate_receipt(repo,path,s['base_sha'],s['head_sha'])
            run(['git','checkout','--','widget.txt'],repo)
            raw=json.loads(path.read_text());(path.parent/raw['results'][0]['log']).write_text('altered')
            with self.assertRaises(ValueError):preflight.validate_receipt(repo,path,s['base_sha'],s['head_sha'])

    def test_notification_failure_commits_state_and_retry_does_not_resign(self):
        with sandbox() as (repo,root,baseline):
            fix=setup(repo,baseline);data=package(fix,receipt(repo,fix));file=fix/'submit.yaml';w.write_yaml(file,data)
            with patch.object(delivery,'notification',side_effect=ValueError('state committed; notification unavailable')):
                self.assertEqual(w.cmd_submit_review(argparse.Namespace(fix_id=fix.name,file=str(file),by='author',expect_revision=revision(fix),no_notify=False)),1)
            self.assertEqual(w.load_yaml(fix/'STATUS.yaml')['state'],'OFFLINE_VERIFIED')
            before=(fix/'STATUS.yaml').read_bytes()
            with patch.object(delivery.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'queued-message.md\n','')) as send:
                # git root lookup uses check_output, which also calls subprocess.run.
                with patch.object(preflight,'git',return_value=str(repo/'.git').encode()):
                    self.assertIn('queued-message',delivery.notification(w,fix.name,'author'))
                    self.assertIn('already queued',delivery.notification(w,fix.name,'author'))
                    self.assertEqual(send.call_count,1)
            self.assertEqual((fix/'STATUS.yaml').read_bytes(),before)


if __name__=='__main__': unittest.main()
