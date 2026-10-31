from __future__ import annotations
import argparse
import json
import hashlib
import os
import shutil
from pathlib import Path
import tempfile
import unittest
import yaml
from unittest.mock import patch
import sys

from test_operations import sandbox, run, workflow as w, SOURCE_ROOT
import preflight


class PreflightTests(unittest.TestCase):
    def test_plan_selects_ci_versions_but_never_shared_jobs(self):
        with sandbox() as (repo,root,baseline):
            ci=repo/'.github/workflows';ci.mkdir(parents=True)
            w.write_yaml(ci/'workflow-harness.yml',{'jobs':{'harness':{'steps':[
                {'uses':'actions/setup-python@v5','with':{'python-version':'3.11'}},
                {'run':'python -m pip install -r workflow/requirements.txt'},
                {'run':'bash workflow/tools/check.sh'}]}}})
            w.write_yaml(ci/'ci.yml',{'jobs':{
                'chart-sync':{'steps':[{'uses':'azure/setup-helm@v4','with':{'version':'v3.16.4'}},{'run':'echo local chart check'}]},
                'e2e':{'steps':[{'run':'DO_NOT_RUN_SHARED_CLUSTER_MUTATION'}]},
                'deploy':{'steps':[{'run':'DO_NOT_DEPLOY'}]}}})
            run(['git','add','.github'],repo);run(['git','commit','-m','CI configuration'],repo)
            selected=preflight.plan(repo,baseline,run(['git','rev-parse','HEAD'],repo))
            jobs=selected['jobs']
            self.assertEqual(next(j['version'] for j in jobs if j['id']=='workflow'),'3.11')
            self.assertEqual(next(j['version'] for j in jobs if j['tool']=='helm'),'v3.16.4')
            self.assertNotIn('DO_NOT_',json.dumps(jobs))
            pinned_head = selected['head_sha']
            (ci/'workflow-harness.yml').write_text('invalid: later-checkout-config')
            (ci/'ci.yml').unlink()
            (ci/'pr-validation.yml').write_text('invalid: current-checkout-is-not-historical-authority')
            run(['git', 'add', '.github'], repo)
            run(['git', 'commit', '-m', 'Change CI on later main'], repo)
            self.assertEqual(preflight.plan(repo, baseline, pinned_head, pinned=True), selected)


    def test_current_ci_authority_retains_every_chart_check_and_pinned_setup(self):
        with sandbox() as (repo, root, baseline):
            ci = repo/'.github/workflows'; ci.mkdir(parents=True)
            for name in ('workflow-harness.yml', 'pr-validation.yml'):
                shutil.copy2(SOURCE_ROOT.parent/'.github/workflows'/name, ci/name)
            (repo/'tools').mkdir()
            shutil.copy2(SOURCE_ROOT.parent/'tools/provision-python.sh', repo/'tools/provision-python.sh')
            run(['git', 'add', '.github', 'tools'], repo)
            run(['git', 'commit', '-m', 'Current source-validation authority'], repo)
            head = run(['git', 'rev-parse', 'HEAD'], repo)
            selected = preflight.plan(repo, baseline, head)
            self.assertFalse((ci/'ci.yml').exists())
            charts = [j for j in selected['jobs'] if j['id'].startswith('chart-')]
            config = yaml.safe_load((ci/'pr-validation.yml').read_text())
            expected = [step['run'] for step in config['jobs']['charts']['steps']
                        if 'run' in step and 'tools/provision-python.sh' not in step['run']]
            self.assertEqual([j['script'] for j in charts], expected)
            self.assertTrue(charts)
            for job in charts:
                self.assertEqual(job['version'], 'v3.16.4')
                self.assertEqual(job['python_version'], '3.12.15')
                self.assertEqual(job['ci_sha256'], hashlib.sha256((ci/'pr-validation.yml').read_bytes()).hexdigest())
                self.assertEqual(job['python_provision_sha256'], hashlib.sha256((repo/'tools/provision-python.sh').read_bytes()).hexdigest())
            harness = next(j for j in selected['jobs'] if j['id'] == 'workflow')
            self.assertEqual(harness['version'], '3.11.17')
            self.assertEqual(harness['script'], 'bash workflow/tools/check.sh')
            self.assertEqual(preflight.plan(repo, baseline, head, pinned=True), selected)
            # Both authority selection and the provision recipe come from the
            # receipt's commit, never a different checkout's present files.
            (ci/'pr-validation.yml').unlink()
            (ci/'ci.yml').write_text('invalid: later-main')
            (repo/'tools/provision-python.sh').write_text('invalid: later-provisioner')
            self.assertEqual(preflight.plan(repo, baseline, head, pinned=True), selected)

    def test_pinned_python_requires_exact_patch_and_version_specific_binary(self):
        args = argparse.Namespace(python='/generic/python', helm=None)
        with patch.dict(os.environ, {'PREFLIGHT_PYTHON_3_12': '/matching/python'}), \
             patch.object(preflight.subprocess, 'check_output', return_value='3.12.14\n') as check:
            with self.assertRaisesRegex(ValueError, 'differs from CI 3.12.15'):
                preflight.environment({'tool':'python', 'version':'3.12.15'}, Path('/tmp'), args)
            self.assertEqual(check.call_args.args[0][0], '/matching/python')

    def test_pinned_receipt_survives_new_checkout_but_submission_and_tampering_fail(self):
        with sandbox() as (repo, root, baseline):
            head = run(['git', 'rev-parse', 'HEAD'], repo)
            output = root/'fixes/FIX-TEST/evidence/preflight/pinned.json'
            selected = preflight.plan(repo, baseline, head)
            receipt = preflight.run_plan(repo, selected, output,
                argparse.Namespace(python=None, helm=None, timeout=10))
            self.assertEqual(receipt['result'], 'PASS')
            preflight.validate_receipt(repo, output, baseline, head)
            # A later main/merge checkout has different code and CI configuration.
            (repo/'later-code.txt').write_text('new main code')
            ci = repo/'.github/workflows'; ci.mkdir(parents=True, exist_ok=True)
            (ci/'workflow-harness.yml').write_text('new incompatible CI configuration')
            run(['git', 'add', 'later-code.txt', '.github'], repo)
            run(['git', 'commit', '-m', 'Later main'], repo)
            preflight.validate_receipt(repo, output, baseline, head, require_worktree=False)
            with self.assertRaisesRegex(ValueError, 'worktree must match'):
                preflight.validate_receipt(repo, output, baseline, head)
            log = output.parent/receipt['results'][0]['log']
            log.write_text('tampered')
            with self.assertRaisesRegex(ValueError, 'raw output missing or changed'):
                preflight.validate_receipt(repo, output, baseline, head, require_worktree=False)

    def test_wrong_tool_versions_are_not_silently_accepted(self):
        args=argparse.Namespace(python=sys.executable,helm='/tmp/helm')
        with patch.object(preflight.subprocess,'check_output',return_value='3.12\n'):
            with self.assertRaisesRegex(ValueError,'differs from CI'):
                preflight.environment({'tool':'python','version':'3.11'},Path('/tmp'),args)
        with patch.object(preflight.subprocess,'check_output',return_value='v3.16.2'):
            with self.assertRaisesRegex(ValueError,'differs from CI'):
                preflight.environment({'tool':'helm','version':'v3.16.4'},Path('/tmp'),args)

    def test_command_failure_is_retained_and_cannot_be_a_pass(self):
        with sandbox() as (repo,root,baseline):
            output=root/'fixes/FIX-TEST/evidence/preflight/receipt.json'
            plan={'jobs':[{'id':'fail','cwd':'.','tool':None,'script':'echo decisive failure; exit 4'}]}
            result=preflight.run_plan(repo,plan,output,argparse.Namespace(python=None,helm=None,timeout=10))
            self.assertEqual(result['result'],'FAIL')
            self.assertEqual(result['results'][0]['exit_code'],4)
            self.assertIn('decisive failure',(output.parent/result['results'][0]['log']).read_text())

    def test_templates_are_code_but_mutable_evidence_is_not(self):
        self.assertFalse(preflight.evidence_path('workflow/fixes/_template/STATUS.yaml'))
        self.assertFalse(preflight.evidence_path('workflow/campaigns/_template/STATUS.yaml'))
        self.assertTrue(preflight.evidence_path('workflow/fixes/M-6/STATUS.yaml'))

    def test_unknown_workflow_ci_command_requires_adapter_update(self):
        with sandbox() as (repo,root,baseline):
            ci=repo/'.github/workflows';ci.mkdir(parents=True)
            w.write_yaml(ci/'workflow-harness.yml',{'jobs':{'harness':{'steps':[
                {'uses':'actions/setup-python@v5','with':{'python-version':'3.11'}},
                {'run':'new meaningful check that must not silently disappear'}]}}})
            run(['git','add','.github'],repo);run(['git','commit','-m','new CI step'],repo)
            with self.assertRaisesRegex(ValueError,'adapter'):
                preflight.plan(repo,baseline,run(['git','rev-parse','HEAD'],repo))


if __name__=='__main__':unittest.main()
