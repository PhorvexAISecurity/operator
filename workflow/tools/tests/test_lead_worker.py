from __future__ import annotations

import argparse
import contextlib
import io
import unittest

from test_operations import sandbox, workflow as w, SOURCE_ROOT, run
from test_contracts import assign
from test_delivery import setup, revision, receipt, package, submit, review


def lead_snapshot(repo, baseline):
    fix = setup(repo, baseline)
    status = w.load_yaml(fix / 'STATUS.yaml')
    status['fix_loop'] = 'lead_worker'
    status['roles'].update(proposer='reviewer', coordinator='reviewer')
    status['blind_derivation'] = {'status': 'pending'}
    for name in ('01-proposal.md', '02A-blind-derivation.md', '02B-critique.md'):
        (fix / name).unlink()
    status['checks'].pop('critique')
    w.write_yaml(fix / 'STATUS.yaml', status)
    assert sign(fix, 'decision', 'reviewer', approval='fixture:user-lead-worker') == 0
    return fix


def sign(fix, key, by, approval=None):
    status = w.load_yaml(fix / 'STATUS.yaml')
    artifact = w.gates.REVIEW_FILES.get(key, status.get('checks', {}).get(key, {}).get('artifact'))
    return w.cmd_record_check(argparse.Namespace(
        fix_id=fix.name, check=key, by=by, artifact=artifact, result='PASS',
        command='synthetic fixture evidence', approval_ref=approval, rationale=None,
        expect_revision=revision(fix)))


class LeadWorkerTests(unittest.TestCase):
    def test_new_template_defaults_to_lead_worker(self):
        self.assertEqual(w.load_yaml(SOURCE_ROOT / 'fixes/_template/STATUS.yaml')['fix_loop'], 'lead_worker')

    def test_review_rejection_revision_acceptance_and_live_gate(self):
        with sandbox() as (repo, root, baseline):
            fix = lead_snapshot(repo, baseline)
            self.assertEqual(submit(fix, package(fix, receipt(repo, fix))), 0)
            self.assertEqual(review(fix, by='author'), 1)
            self.assertEqual(review(fix, result='FAIL'), 0)
            status = w.load_yaml(fix / 'STATUS.yaml')
            self.assertEqual((status['state'], status['next_action']['owner']), ('IMPLEMENTED', 'implementer'))
            self.assertTrue(w.gates.prerequisites(root, fix, status, 'PR_READY'))
            (repo / 'widget.txt').write_text('revised fix\n')
            run(['git', 'add', 'widget.txt'], repo)
            run(['git', 'commit', '-m', 'address reviewer finding'], repo)
            data = package(fix, 'unused')
            data['source'] = dict(status['implementation'], head_sha=run(['git', 'rev-parse', 'HEAD'], repo))
            data['source'].pop('stacked_on', None)
            # Preflight must be generated for the new pinned head before submission.
            status['implementation'].update(data['source'])
            w.write_yaml(fix / 'STATUS.yaml', status)
            data['preflight'] = receipt(repo, fix)
            self.assertEqual(submit(fix, data), 0)
            self.assertEqual(review(fix), 0)
            status = w.load_yaml(fix / 'STATUS.yaml')
            self.assertEqual(status['state'], 'PR_READY')
            self.assertEqual(w.gates.prerequisites(root, fix, status, 'PR_READY'), [])
            self.assertTrue(w.gates.prerequisites(root, fix, status, 'LIVE_VERIFIED'))
            self.assertTrue(any(x.get('check') == 'p3' and x['result'] == 'FAIL' for x in status['check_history']))

    def test_plan_required_and_tampering_invalidates_acceptance(self):
        with sandbox() as (repo, root, baseline):
            fix = lead_snapshot(repo, baseline)
            status = w.load_yaml(fix / 'STATUS.yaml')
            self.assertEqual(w.gates.prerequisites(root, fix, status, 'AGREED'), [])
            (fix / '03-decision.md').write_text('Changed plan after signing.\n')
            self.assertTrue(any('artifact changed' in x for x in w.gates.prerequisites(root, fix, status, 'AGREED')))
            self.assertEqual(submit(fix, package(fix, receipt(repo, fix))), 1)

    def test_lead_brief_and_delta_do_not_require_blind_exposure(self):
        with sandbox() as (repo, root, baseline):
            fix = lead_snapshot(repo, baseline)
            status = w.load_yaml(fix / 'STATUS.yaml')
            status['state'] = 'DESIGNING'
            w.write_yaml(fix / 'STATUS.yaml', status)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(w.cmd_brief(argparse.Namespace(identifier=fix.name, agent='reviewer')), 0)
            packet = w.yaml.safe_load(output.getvalue())
            self.assertEqual(packet['do_not_read'], [])
            self.assertIn('AGREED', packet['allowed_transitions'])
            self.assertNotIn('CRITIQUED', packet['allowed_transitions'])
            self.assertIn('03-decision.md', packet['write_scope'])
            self.assertEqual(w.cmd_review_delta(argparse.Namespace(fix_id=fix.name, agent='reviewer')), 0)

    def test_worker_cannot_self_review_even_if_reassigned_reviewer_or_live_role(self):
        with sandbox() as (repo, root, baseline):
            fix = lead_snapshot(repo, baseline)
            status = w.load_yaml(fix / 'STATUS.yaml')
            status['roles'].update(skeptic='author', live_verifier='author')
            w.write_yaml(fix / 'STATUS.yaml', status)
            for key in ('decision', 'base_review', 'incident', 'p3', 'l3', 'l4', 'final'):
                with self.subTest(key=key):
                    self.assertEqual(sign(fix, key, 'author'), 1)
            status['checks']['l3']['by'] = 'author'
            self.assertTrue(any('cannot sign' in x for x in w.gates.check_errors(root, fix, status, 'l3')))

    def test_migration_requires_user_reference_and_cannot_change_after_agreement(self):
        with sandbox():
            fix = w.create_fix_record('FIX-TEST', ['M-1'])
            assign(fix.name)
            file = fix / 'migration.yaml'
            w.write_yaml(file, {'fix_loop': 'lead_worker', 'roles': {
                'proposer': 'coordinator', 'skeptic': 'coordinator', 'live_verifier': 'coordinator'}})
            args = argparse.Namespace(fix_id=fix.name, file=str(file), by='coordinator',
                                      expect_revision=revision(fix), approval_ref=None)
            self.assertEqual(w.cmd_configure(args), 1)
            args.approval_ref = 'fixture:user-instruction'
            self.assertEqual(w.cmd_configure(args), 0)
            status = w.load_yaml(fix / 'STATUS.yaml')
            status['state'] = 'AGREED'
            w.write_yaml(fix / 'STATUS.yaml', status)
            w.write_yaml(file, {'fix_loop': 'blind_peer'})
            args.expect_revision = revision(fix)
            self.assertEqual(w.cmd_configure(args), 1)


if __name__ == '__main__':
    unittest.main()
