from __future__ import annotations
import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

from test_operations import sandbox, run, workflow as w
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
