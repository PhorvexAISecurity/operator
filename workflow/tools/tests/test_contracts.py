from __future__ import annotations

import argparse
import contextlib
import io
import threading
import unittest
from pathlib import Path

from test_operations import sandbox, workflow as w, run, prepare_fix_evidence


def transition(fix, target, *, revision=0, by='coordinator', force=False):
    return w.cmd_transition(argparse.Namespace(fix_id=fix, target=target, expect_revision=revision,
        by=by, next_owner='coordinator', next_action='Continue the synthetic review.', artifact=None,
        note=None, approval_ref='fixture:approved', force=force))


def assign(fix):
    path=w.FIXES/fix/'STATUS.yaml'; status=w.load_yaml(path)
    status['roles'] = {'human_owner':'owner', 'proposer':'author', 'implementer':'author',
                      'skeptic':'reviewer', 'live_verifier':'reviewer', 'coordinator':'coordinator'}
    w.write_yaml(path,status)
    return status


def ready_snapshot(repo, baseline):
    (repo/'widget.txt').write_text('fixed\n')
    run(['git','add','widget.txt'],repo);run(['git','commit','-m','widget correction'],repo)
    head=run(['git','rev-parse','HEAD'],repo)
    w.create_fix_record('FIX-TEST',['M-1'])
    status=assign('FIX-TEST')
    status['state']='DEPLOYED'
    status['implementation'].update(branch='fix/widget',base_sha=baseline,head_sha=head)
    status['pull_request'].update(url='https://example.invalid/pr/1', reviewed_head=head,merge_sha=head,checks='PASS')
    status['deployment'].update(image='widget:test',digest='sha256:fixture',git_sha=head,rolled_out_at=w.utcnow())
    status['verification']['required']=['L0','L1','L2','L3']
    w.write_yaml(w.FIXES/'FIX-TEST/STATUS.yaml',status)
    prepare_fix_evidence('FIX-TEST',repo)
    return w.FIXES/'FIX-TEST',w.load_yaml(w.FIXES/'FIX-TEST/STATUS.yaml')


class HarnessContracts(unittest.TestCase):
    def test_every_forward_stage_rejects_empty_template(self):
        with sandbox():
            w.create_fix_record('FIX-TEST',['M-1']);status=assign('FIX-TEST')
            for target in w.gates.STAGES[1:]:
                with self.subTest(target=target):
                    self.assertTrue(w.transition_prerequisites(w.FIXES/'FIX-TEST',status,target))
            status['verification']['p3']='PASS';status['implementation']['head_sha']='a'*40
            self.assertTrue(w.transition_prerequisites(w.FIXES/'FIX-TEST',status,'PR_READY'))

    def test_duplicate_transition_is_rejected_without_lost_history(self):
        with sandbox():
            w.create_fix_record('FIX-TEST',['M-1']);assign('FIX-TEST')
            barrier=threading.Barrier(2); results=[]
            def attempt():
                barrier.wait();results.append(transition('FIX-TEST','HELD'))
            threads=[threading.Thread(target=attempt) for _ in range(2)]
            for t in threads:t.start()
            for t in threads:t.join(timeout=10)
            self.assertFalse(any(t.is_alive() for t in threads))
            self.assertEqual(sorted(results),[0,1])
            status=w.load_yaml(w.FIXES/'FIX-TEST/STATUS.yaml')
            self.assertEqual(status['revision'],1)
            self.assertEqual(len(status['transitions']),1)

    def test_force_cannot_bypass_any_forward_gate(self):
        with sandbox():
            w.create_fix_record('FIX-TEST',['M-1']);assign('FIX-TEST')
            for target in w.gates.STAGES[1:]:
                self.assertEqual(transition('FIX-TEST',target,force=True),1)

    def test_blind_packet_omits_implementation_and_proposal(self):
        with sandbox():
            w.create_fix_record('FIX-TEST',['M-1']);status=assign('FIX-TEST')
            status['implementation']['branch']='SECRET-PROPOSAL-BRANCH'
            w.write_yaml(w.FIXES/'FIX-TEST/STATUS.yaml',status)
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(w.cmd_brief(argparse.Namespace(identifier='FIX-TEST',agent='reviewer')),0)
            packet=w.yaml.safe_load(out.getvalue())
            self.assertNotIn('SECRET-PROPOSAL-BRANCH',out.getvalue())
            self.assertNotIn('implementation',packet)
            self.assertFalse(any('01-proposal' in name or '04-diff' in name for name in packet['read']))
            self.assertEqual(packet['write_scope'],['fixes/FIX-TEST/02A-blind-derivation.md'])

    def test_seal_is_owned_revision_checked_and_immutable(self):
        with sandbox() as (_,_,baseline):
            fix=w.create_fix_record('FIX-TEST',['M-1']);status=assign('FIX-TEST')
            status['state']='DESIGNING';status['baseline']['code_sha']=baseline
            w.write_yaml(fix/'STATUS.yaml',status)
            (fix/'02A-blind-derivation.md').write_text('Independent model derived from baseline code.\n')
            args=argparse.Namespace(fix_id='FIX-TEST',by='author',expect_revision=0,force=False,approval_ref=None)
            self.assertEqual(w.cmd_seal(args),1)
            args.by='reviewer';self.assertEqual(w.cmd_seal(args),0)
            self.assertEqual(w.cmd_seal(args),1)
            signed=w.load_yaml(fix/'STATUS.yaml')
            self.assertEqual(signed['revision'],1)
            self.assertEqual(signed['blind_derivation']['by'],'reviewer')
            (fix/'02A-blind-derivation.md').write_text('Changed after reading proposal.\n')
            errors=w.gates.prerequisites(w.ROOT,fix,signed,'CRITIQUED')
            self.assertTrue(any('blind derivation' in e for e in errors))

    def test_new_evidence_manifest_conforms_to_schema(self):
        with sandbox() as (repo,root,baseline):
            fix,_=ready_snapshot(repo,baseline)
            errors=[]
            w.validate_schema_instance('evidence-manifest.schema.json',w.load_yaml(fix/'evidence/manifest.yaml'),'fixture',errors)
            self.assertEqual(errors,[])

    def test_new_fix_does_not_ship_a_final_verdict(self):
        with sandbox():
            fix=w.create_fix_record('FIX-TEST',['M-1'])
            self.assertFalse((fix/'06-verdict.md').exists())

    def test_fresh_cycle_reaches_open_pr_without_another_human_gate(self):
        with sandbox() as (repo,root,baseline):
            fix=w.create_fix_record('FIX-TEST',['M-1'])
            configuration=root/'inputs.yaml'
            roles={'human_owner':'owner','proposer':'author','implementer':'author',
                   'skeptic':'reviewer','live_verifier':'reviewer','coordinator':'coordinator'}
            w.write_yaml(configuration,{'roles':roles,'baseline':{'code_sha':baseline},'change_class':'A',
                                       'verification':{'required':['L0','L1','L2'],'live_required':False,'soak_required':False}})
            self.assertEqual(w.cmd_configure(argparse.Namespace(fix_id='FIX-TEST',file=str(configuration),
                              by='coordinator',expect_revision=0,approval_ref=None)),0)
            def revision():return w.load_yaml(fix/'STATUS.yaml')['revision']
            def advance(target):self.assertEqual(transition('FIX-TEST',target,revision=revision()),0)
            def sign(key,artifact):
                self.assertEqual(w.cmd_record_check(argparse.Namespace(fix_id='FIX-TEST',check=key,
                    by=roles[w.gates.CHECK_ROLES[key]],artifact=artifact,result='PASS',command='synthetic fixture check',
                    approval_ref=None,rationale=None,expect_revision=revision())),0)
            (fix/'00-intake.md').write_text('Scoped widget change, assigned roles, frozen source and verification plan.\n')
            advance('DESIGNING')
            (fix/'02A-blind-derivation.md').write_text('Independent widget model and falsifying counterexample.\n')
            self.assertEqual(w.cmd_seal(argparse.Namespace(fix_id='FIX-TEST',by='reviewer',expect_revision=revision(),
                             force=False,approval_ref=None)),0)
            (fix/'01-proposal.md').write_text('Widget proposal with exact delta and controls.\n')
            (fix/'02B-critique.md').write_text('Counterexample rejected by baseline test; design critique PASS.\n')
            sign('critique','02B-critique.md');advance('CRITIQUED')
            (fix/'03-decision.md').write_text('Agreed widget delta and invariant; all other outputs unchanged.\n')
            sign('decision','03-decision.md');advance('AGREED')
            (repo/'widget.txt').write_text('fixed\n');run(['git','add','widget.txt'],repo)
            run(['git','commit','-m','widget correction'],repo);head=run(['git','rev-parse','HEAD'],repo)
            w.write_yaml(configuration,{'implementation':{'branch':'fix/widget','base_sha':baseline,'head_sha':head}})
            self.assertEqual(w.cmd_configure(argparse.Namespace(fix_id='FIX-TEST',file=str(configuration),
                              by='coordinator',expect_revision=revision(),approval_ref=None)),0)
            import subprocess
            (fix/'04-diff.patch').write_bytes(subprocess.check_output(['git','diff','--binary',baseline,head],cwd=repo))
            sign('implementation','04-diff.patch');advance('IMPLEMENTED')
            (fix/'05-evidence.md').write_text('Each widget criterion maps to its retained control and run.\n')
            for key in ['red','l0','l1','l2','positive_control']:
                artifact=f'evidence/{key}.txt';(fix/artifact).write_text('Synthetic fixture instrument output.\n')
                sign(key,artifact)
            advance('OFFLINE_VERIFIED')
            (fix/'evidence/incident.md').write_text('Widget input traverses the real parser: dropped on baseline, retained at head; healthy input preserved. Independent reproduction PASS.\n')
            sign('incident','evidence/incident.md')
            (fix/'evidence/p3').mkdir();(fix/'evidence/p3/verdict.md').write_text('Verdict: PASS\nIndependent counterexample attempt.\n')
            sign('p3','evidence/p3/verdict.md');advance('DIFF_REVIEW_PASSED');advance('PR_READY')
            self.assertEqual(w.load_yaml(fix/'STATUS.yaml')['state'],'PR_READY')
            w.write_yaml(configuration,{'pull_request':{'url':'https://example.invalid/pr/42','reviewed_head':head}})
            self.assertEqual(w.cmd_configure(argparse.Namespace(fix_id='FIX-TEST',file=str(configuration),
                              by='coordinator',expect_revision=revision(),approval_ref=None)),0)
            self.assertEqual(w.cmd_transition(argparse.Namespace(fix_id='FIX-TEST',target='IN_PR',
                by='coordinator',expect_revision=revision(),next_owner='human_owner',next_action='PR delivered; await merge scope.',
                artifact=None,note=None,approval_ref=None,force=False)),0)
            final=w.load_yaml(fix/'STATUS.yaml')
            self.assertEqual(final['state'],'IN_PR')
            self.assertEqual(final['transitions'][-1]['approval_ref'],'operations/AUTONOMY.md')
            self.assertNotIn('merge',final['approvals'])
            self.assertNotIn('deploy',final['approvals'])

    def test_valid_snapshot_passes_and_tampering_fails(self):
        with sandbox() as (repo,root,baseline):
            fix,status=ready_snapshot(repo,baseline)
            self.assertEqual(w.gates.prerequisites(root,fix,status,'CLOSED',finalizing=True),[])
            (fix/'03-decision.md').write_text('New prediction after seeing results\n')
            self.assertTrue(any('artifact changed' in x for x in w.gates.prerequisites(root,fix,status,'PR_READY')))

    def test_changed_verification_plan_invalidates_decision(self):
        with sandbox() as (repo,root,baseline):
            fix,status=ready_snapshot(repo,baseline)
            status['verification']['live_required']=False
            self.assertTrue(any('plan changed' in x for x in w.gates.prerequisites(root,fix,status,'PR_READY')))

    def test_green_checks_without_incident_cannot_pass_p3_or_pr_gate(self):
        with sandbox() as (repo,root,baseline):
            fix,status=ready_snapshot(repo,baseline)
            del status['checks']['incident']
            w.write_yaml(fix/'STATUS.yaml',status)
            errors=w.gates.prerequisites(root,fix,status,'PR_READY')
            self.assertTrue(any('checks.incident' in e for e in errors))
            args=argparse.Namespace(fix_id='FIX-TEST',check='p3',by='reviewer',
                artifact='evidence/p3/verdict.md',result='PASS',command='independent diff review',
                approval_ref=None,rationale=None,expect_revision=status['revision'])
            self.assertEqual(w.cmd_record_check(args),1)
            self.assertEqual(w.load_yaml(fix/'STATUS.yaml')['revision'],status['revision'])

    def test_incident_requires_independent_signer_and_cannot_be_waived(self):
        with sandbox() as (repo,root,baseline):
            fix,status=ready_snapshot(repo,baseline)
            args=argparse.Namespace(fix_id='FIX-TEST',check='incident',by='author',
                artifact='evidence/incident.md',result='PASS',command='reproduce incident',
                approval_ref=None,rationale=None,expect_revision=status['revision'])
            self.assertEqual(w.cmd_record_check(args),1)
            # Even a conflicting assignment cannot turn the implementer into an independent reviewer.
            status['roles']['skeptic']='author';w.write_yaml(fix/'STATUS.yaml',status)
            self.assertEqual(w.cmd_record_check(args),1)
            args.by='owner';args.result='NOT_REQUIRED';args.approval_ref='fixture:approval'
            args.rationale='Unit tests are green.'
            self.assertEqual(w.cmd_record_check(args),1)

    def test_incident_pins_both_sources_and_changed_evidence_requires_new_p3(self):
        with sandbox() as (repo,root,baseline):
            fix,status=ready_snapshot(repo,baseline)
            status['baseline']['code_sha']='a'*40
            self.assertTrue(any('baseline differs' in e for e in w.gates.check_errors(root,fix,status,'incident')))
            status=w.load_yaml(fix/'STATUS.yaml');status['implementation']['head_sha']='b'*40
            self.assertTrue(any('source_sha differs' in e for e in w.gates.check_errors(root,fix,status,'incident')))
            status=w.load_yaml(fix/'STATUS.yaml')
            (fix/'evidence/incident.md').write_text('Expanded reproduction includes the formerly missed predicate arm; baseline fails and head passes.\n')
            self.assertTrue(any('artifact changed' in e for e in w.gates.check_errors(root,fix,status,'incident')))
            args=argparse.Namespace(fix_id='FIX-TEST',check='incident',by='reviewer',
                artifact='evidence/incident.md',result='PASS',command='reproduce expanded incident',
                approval_ref=None,rationale=None,expect_revision=status['revision'])
            self.assertEqual(w.cmd_record_check(args),0)
            status=w.load_yaml(fix/'STATUS.yaml')
            self.assertTrue(any('incident evidence changed' in e for e in w.gates.prerequisites(root,fix,status,'PR_READY')))
            args.check='p3';args.artifact='evidence/p3/verdict.md';args.expect_revision=status['revision']
            self.assertEqual(w.cmd_record_check(args),0)
            status=w.load_yaml(fix/'STATUS.yaml')
            self.assertEqual(w.gates.prerequisites(root,fix,status,'PR_READY'),[])

    def test_same_author_and_old_build_evidence_cannot_close(self):
        with sandbox() as (repo,root,baseline):
            fix,status=ready_snapshot(repo,baseline)
            status['roles']['skeptic']='author'
            self.assertTrue(any('skeptic must differ' in x for x in w.gates.prerequisites(root,fix,status,'CLOSED',finalizing=True)))
            status['roles']['skeptic']='reviewer'
            status['deployment']['git_sha']=baseline
            errors=w.gates.prerequisites(root,fix,status,'CLOSED',finalizing=True)
            self.assertTrue(any('source_sha differs' in x for x in errors))
            self.assertTrue(any('does not contain recorded merge' in x for x in errors))

    def test_unindexed_or_changed_patch_is_not_evidence(self):
        with sandbox() as (repo,root,baseline):
            fix,status=ready_snapshot(repo,baseline)
            manifest=w.load_yaml(fix/'evidence/manifest.yaml')
            manifest['artifacts']=[a for a in manifest['artifacts'] if a['id']!='check-p3']
            w.write_yaml(fix/'evidence/manifest.yaml',manifest)
            self.assertTrue(any('not indexed' in x for x in w.gates.prerequisites(root,fix,status,'PR_READY')))
            (fix/'04-diff.patch').write_text('not the reviewed diff\n')
            self.assertTrue(any('git diff --binary' in x for x in w.gates.prerequisites(root,fix,status,'PR_READY')))

    def test_configure_cannot_forge_state_or_checks(self):
        with sandbox() as (_,root,_):
            w.create_fix_record('FIX-TEST',['M-1']);assign('FIX-TEST')
            update=root/'configuration.yaml'
            for forbidden in ['state','checks','profile','revision','blind_derivation']:
                w.write_yaml(update,{forbidden:'forged'})
                args=argparse.Namespace(fix_id='FIX-TEST',file=str(update),by='coordinator',expect_revision=0,approval_ref=None)
                self.assertEqual(w.cmd_configure(args),1)
            w.write_yaml(update,{'title':'Scoped input update'})
            self.assertEqual(w.cmd_configure(args),0)
            self.assertEqual(w.cmd_configure(args),1)

    def test_register_header_uses_metadata_not_historical_claim(self):
        with sandbox():
            path=w.ISSUES/'entries/M-001.md';meta,body=w.parse_entry(path)
            meta['workflow_state']='REOPENED';meta['title']='Current title'
            w.write_entry(path,meta,body)
            result=w.render_master()
            self.assertIn('M-1 · Current title · **REOPENED**',result)
            self.assertIn('| REOPENED | 1 |',result)
            self.assertNotIn('### M-1 · Widget drops signals',result)

    def test_new_fix_records_only_pr_open_from_standing_scope(self):
        with sandbox():
            fix=w.create_fix_record('FIX-TEST',['M-1'])
            status=w.load_yaml(fix/'STATUS.yaml')
            self.assertEqual(status['approvals'],{'pr_open':'operations/AUTONOMY.md'})
            self.assertEqual(status['state'],'TRIAGED')

    def test_start_preserves_gates_and_does_not_resume_held_work(self):
        with sandbox():
            fix=w.create_fix_record('FIX-TEST',['M-1']);status=assign('FIX-TEST')
            status['approvals']={};w.write_yaml(fix/'STATUS.yaml',status)
            args=argparse.Namespace(fix_id='FIX-TEST',by='coordinator',expect_revision=0)
            self.assertEqual(w.cmd_start(args),0)
            after=w.load_yaml(fix/'STATUS.yaml')
            self.assertEqual(after['state'],'TRIAGED');self.assertEqual(after['checks'],{})
            self.assertEqual(set(after['approvals']),{'pr_open'})
            self.assertEqual(w.cmd_start(args),1)  # stale revision
            after['state']='HELD';w.write_yaml(fix/'STATUS.yaml',after)
            args.expect_revision=after['revision']
            self.assertEqual(w.cmd_start(args),1)

    def test_invalid_configuration_is_rejected_without_writing(self):
        with sandbox() as (_,root,_):
            fix=w.create_fix_record('FIX-TEST',['M-1']);assign('FIX-TEST')
            before=(fix/'STATUS.yaml').read_bytes();index=(root/'fixes/INDEX.yaml').read_bytes()
            update=root/'configuration.yaml'
            for value in [{'approvals':{'sec_1':'not-a-supported-scope'}},{'change_class':'INVALID'}]:
                w.write_yaml(update,value)
                args=argparse.Namespace(fix_id='FIX-TEST',file=str(update),by='coordinator',expect_revision=0,approval_ref='fixture:approval')
                self.assertEqual(w.cmd_configure(args),1)
                self.assertEqual((fix/'STATUS.yaml').read_bytes(),before)
                self.assertEqual((root/'fixes/INDEX.yaml').read_bytes(),index)

    def test_implementer_can_pin_commits_but_cannot_grant_authority(self):
        with sandbox() as (_,root,baseline):
            fix=w.create_fix_record('FIX-TEST',['M-1']);status=assign('FIX-TEST')
            status['state']='AGREED';w.write_yaml(fix/'STATUS.yaml',status)
            update=root/'configuration.yaml'
            args=argparse.Namespace(fix_id='FIX-TEST',file=str(update),by='author',expect_revision=0,approval_ref='fixture:approval')
            for value in [{'roles':{'skeptic':'author'}},{'approvals':{'deploy':'yes'}},
                          {'verification':{'required':['L0']}},{'implementation':{'stacked_on':[]}},
                          {'implementation':{'head_sha':'f'*40}}]:
                w.write_yaml(update,value);self.assertEqual(w.cmd_configure(args),1)
            w.write_yaml(update,{'implementation':{'branch':'fix/widget','base_sha':baseline,'head_sha':baseline}})
            self.assertEqual(w.cmd_configure(args),0)
            self.assertEqual(w.load_yaml(fix/'STATUS.yaml')['implementation']['head_sha'],baseline)

    def test_base_review_is_independent_and_binds_both_sources(self):
        with sandbox() as (repo,root,baseline):
            fix,status=ready_snapshot(repo,baseline)
            newbase=status['implementation']['head_sha']
            status['implementation']['base_sha']=newbase;w.write_yaml(fix/'STATUS.yaml',status)
            artifact=fix/'evidence/base-review.md';artifact.write_text('Independent integration review; relevant producer unchanged and new path covered.\n')
            args=argparse.Namespace(fix_id='FIX-TEST',check='base_review',by='author',artifact='evidence/base-review.md',
                result='PASS',command='Compare original baseline to rebased producer and integration paths',
                approval_ref=None,rationale=None,expect_revision=status['revision'])
            self.assertEqual(w.cmd_record_check(args),1)
            args.by='reviewer';self.assertEqual(w.cmd_record_check(args),0)
            signed=w.load_yaml(fix/'STATUS.yaml')
            self.assertEqual(w.gates.check_errors(root,fix,signed,'base_review'),[])
            self.assertEqual(signed['checks']['base_review']['baseline_sha'],baseline)
            self.assertEqual(signed['checks']['base_review']['source_sha'],newbase)
            signed['implementation']['base_sha']=baseline
            self.assertTrue(w.gates.check_errors(root,fix,signed,'base_review'))
            signed['implementation']['base_sha']=newbase;signed['baseline']['code_sha']=newbase
            self.assertTrue(w.gates.check_errors(root,fix,signed,'base_review'))
            artifact.write_text('Changed review')
            self.assertTrue(w.gates.check_errors(root,fix,w.load_yaml(fix/'STATUS.yaml'),'base_review'))

    def test_agreed_brief_routes_implementer_to_verification(self):
        with sandbox():
            fix=w.create_fix_record('FIX-TEST',['M-1']);status=assign('FIX-TEST');status['state']='AGREED'
            w.write_yaml(fix/'STATUS.yaml',status)
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                w.cmd_brief(argparse.Namespace(identifier='FIX-TEST',agent='author'))
            packet=w.yaml.safe_load(out.getvalue())
            self.assertIn('stages/verify.md',packet['read'])
            self.assertIn('implementation code/tests',packet['write_scope'])

    def test_startup_context_budget(self):
        root=Path(__file__).resolve().parents[2]
        startup=(root/'AGENTS.md').read_text()
        self.assertLessEqual(len(startup.split()),500)
        common=sum(len((root/p).read_text().split()) for p in ['AGENTS.md','OPERATIONS.md','operations/FIX.md'])
        for stage in (root/'stages').glob('*.md'):
            self.assertLessEqual(common+len(stage.read_text().split()),1250)


if __name__=='__main__':
    unittest.main()
