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


def current_ci(repo):
    ci = repo/'.github/workflows'; ci.mkdir(parents=True)
    for name in ('workflow-harness.yml', 'pr-validation.yml'):
        shutil.copy2(SOURCE_ROOT.parent/'.github/workflows'/name, ci/name)
    for name in ('tools/provision-python.sh', 'tools/benchmark-test-requirements.txt',
                 'tools/test_benchmark_regressions.py', 'build/test-harness/go.mod', 'phorvex/go.mod'):
        path = repo/name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE_ROOT.parent/name, path)
    return ci


class PreflightTests(unittest.TestCase):
    def test_benchmark_only_change_selects_current_pinned_gating_recipe(self):
        with sandbox() as (repo, root, baseline):
            current_ci(repo)
            run(['git', 'add', '.'], repo)
            run(['git', 'commit', '-m', 'Current benchmark CI authority'], repo)
            base = run(['git', 'rev-parse', 'HEAD'], repo)
            file = repo/'benchmark/bot/service.py'
            file.parent.mkdir(parents=True)
            file.write_text('# benchmark-only change\n')
            run(['git', 'add', 'benchmark'], repo)
            run(['git', 'commit', '-m', 'Change only benchmark source'], repo)
            head = run(['git', 'rev-parse', 'HEAD'], repo)
            selected = preflight.plan(repo, base, head, pinned=True)
            self.assertEqual(selected['changed_paths'], ['benchmark/bot/service.py'])
            charts = [j for j in selected['jobs'] if j['id'].startswith('chart-')]
            self.assertTrue(charts)
            self.assertTrue(any("python -m unittest discover -s tools -p 'test_*.py' -v" == j['script'].strip() for j in charts))
            self.assertTrue(all('benchmark_wrapper_sha256' in j for j in charts))
            self.assertEqual([j['id'] for j in preflight.plan(repo, base, head, pinned=True, recipe_version=1)['jobs']], ['diff'])
            # Current capability cannot silently pass when its wrapper is gone.
            (repo/'tools/test_benchmark_regressions.py').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'benchmark gating wrapper missing'):
                preflight.plan(repo, base, head)
            # A later broken checkout does not reinterpret the pinned receipt.
            self.assertEqual(preflight.plan(repo, base, head, pinned=True), selected)

    def test_benchmark_only_historical_source_does_not_gain_new_jobs(self):
        with sandbox() as (repo, root, baseline):
            ci = current_ci(repo)
            file = ci/'pr-validation.yml'
            current = file.read_text()
            historical = yaml.safe_load(current)
            steps = historical['jobs']['charts']['steps']
            historical['jobs']['charts']['steps'] = [s for s in steps if not s.get('uses', '').startswith('actions/setup-go@')]
            for step in historical['jobs']['charts']['steps']:
                if 'benchmark-test-requirements.txt' in step.get('run', ''):
                    step['run'] = 'python -m pip install PyYAML==6.0.2'
            file.write_text(yaml.safe_dump(historical))
            (repo/'tools/test_benchmark_regressions.py').unlink()
            run(['git', 'add', '.'], repo)
            run(['git', 'commit', '-m', 'Historical chart authority'], repo)
            base = run(['git', 'rev-parse', 'HEAD'], repo)
            benchmark = repo/'benchmark/bot/service.py'
            benchmark.parent.mkdir(parents=True)
            benchmark.write_text('# historical benchmark change\n')
            run(['git', 'add', 'benchmark'], repo)
            run(['git', 'commit', '-m', 'Historical benchmark-only change'], repo)
            head = run(['git', 'rev-parse', 'HEAD'], repo)
            selected = preflight.plan(repo, base, head, pinned=True)
            self.assertEqual([j['id'] for j in selected['jobs']], ['diff'])
            current_ci_file = SOURCE_ROOT.parent/'tools/test_benchmark_regressions.py'
            shutil.copy2(current_ci_file, repo/'tools/test_benchmark_regressions.py')
            file.write_text(current)
            self.assertEqual(preflight.plan(repo, base, head, pinned=True), selected)
            self.assertTrue(any(j['id'].startswith('chart-') for j in preflight.plan(repo, base, head)['jobs']))

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
            ci = current_ci(repo)
            run(['git', 'add', '.github', 'tools', 'build', 'phorvex'], repo)
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
                self.assertEqual(job['benchmark_go_version'], '1.26.3')
                self.assertEqual(job['benchmark_go_version_file_sha256'], hashlib.sha256((repo/'build/test-harness/go.mod').read_bytes()).hexdigest())
                self.assertEqual(job['benchmark_wrapper_sha256'], hashlib.sha256((repo/'tools/test_benchmark_regressions.py').read_bytes()).hexdigest())
            harness = next(j for j in selected['jobs'] if j['id'] == 'workflow')
            self.assertEqual(harness['version'], '3.11.17')
            self.assertEqual(harness['script'], 'bash workflow/tools/check.sh')
            go_jobs = [j for j in selected['jobs'] if j['id'].startswith('go-unit-')]
            ci_go = config['jobs']['go-unit']
            self.assertEqual([j['script'] for j in go_jobs], [s['run'] for s in ci_go['steps']
                             if 'run' in s and ' test ' in s['run']])
            self.assertEqual(len(go_jobs), 7)
            for job in go_jobs:
                self.assertEqual(job['version'], '1.26.3')
                self.assertEqual(job['toolchain'], 'local')
                self.assertEqual(job['env'], ci_go['env'])
                self.assertEqual(job['helm_version'], 'v3.16.4')
                self.assertEqual(job['go_version_file'], 'build/test-harness/go.mod')
                self.assertEqual(job['go_version_file_sha256'], hashlib.sha256((repo/'build/test-harness/go.mod').read_bytes()).hexdigest())
            summary = next(j for j in selected['jobs'] if j['id'] == 'go-affected-services')
            self.assertNotIn('$GITHUB_', summary['script'])
            self.assertIn('$GITHUB_STEP_SUMMARY', summary['ci_script'])
            self.assertIn('--base ' + selected['base_sha'], summary['script'])
            self.assertNotIn('HEAD^1', summary['script'])
            self.assertIn('go-envtest', ' '.join(selected['external']))
            self.assertEqual(preflight.plan(repo, baseline, head, pinned=True), selected)
            # Both authority selection and the provision recipe come from the
            # receipt's commit, never a different checkout's present files.
            (ci/'pr-validation.yml').unlink()
            (ci/'ci.yml').write_text('invalid: later-main')
            (repo/'tools/provision-python.sh').write_text('invalid: later-provisioner')
            (repo/'build/test-harness/go.mod').write_text('invalid: later-Go-authority')
            self.assertEqual(preflight.plan(repo, baseline, head, pinned=True), selected)

    def test_legacy_receipt_keeps_old_go_recipe_but_cannot_satisfy_current_submission(self):
        with sandbox() as (repo, root, baseline):
            current_ci(repo)
            run(['git', 'add', '.github', 'tools', 'build', 'phorvex'], repo)
            run(['git', 'commit', '-m', 'Current CI with legacy receipt semantics'], repo)
            head = run(['git', 'rev-parse', 'HEAD'], repo)
            old = preflight.plan(repo, baseline, head, pinned=True, recipe_version=1)
            self.assertEqual(next(j['version'] for j in old['jobs'] if j['id'] == 'go-phorvex'), '1.26.1')
            self.assertFalse(any(j['id'].startswith('go-unit-') for j in old['jobs']))
            # Synthetic receipt fixture tests historical verification, not real
            # execution of repository commands in this miniature repository.
            output = root/'fixes/FIX-TEST/evidence/preflight/legacy.json'
            output.parent.mkdir(parents=True, exist_ok=True)
            rows = []
            for job in old['jobs']:
                log = output.parent/(job['id'] + '.log')
                log.write_text('synthetic historical verification fixture\n')
                rows.append({'id':job['id'], 'log':log.name, 'result':'PASS', 'exit_code':0,
                             'sha256':hashlib.sha256(log.read_bytes()).hexdigest()})
            receipt = {'schema_version':1, 'plan':old, 'plan_sha256':preflight.digest(old),
                       'worktree_sha256':preflight.worktree(repo), 'results':rows, 'result':'PASS'}
            output.write_text(json.dumps(receipt))
            preflight.validate_receipt(repo, output, baseline, head, require_worktree=False)
            with self.assertRaisesRegex(ValueError, 'legacy preflight recipe'):
                preflight.validate_receipt(repo, output, baseline, head)
            current = preflight.plan(repo, baseline, head, pinned=True)
            self.assertEqual(current['schema_version'], 2)
            self.assertEqual(next(j['version'] for j in current['jobs'] if j['id']=='go-unit-phorvex'), '1.26.3')
            # Changing only the envelope version cannot upgrade old incomplete
            # commands into the new complete CI authority.
            receipt['plan']['schema_version'] = 2
            receipt['plan_sha256'] = preflight.digest(receipt['plan'])
            output.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, 'missing, failed or stale'):
                preflight.validate_receipt(repo, output, baseline, head)

    def test_current_go_rejects_changed_commands_context_and_nonlocal_binary(self):
        with sandbox() as (repo, root, baseline):
            ci = current_ci(repo)
            file = ci/'pr-validation.yml'
            original = yaml.safe_load(file.read_text())
            for kind in ('command', 'environment', 'setup', 'path'):
                config = yaml.safe_load(yaml.safe_dump(original))
                job = config['jobs']['go-unit']
                if kind == 'command':
                    next(s for s in job['steps'] if 'run' in s)['run'] += ' -run SelectedOnly'
                elif kind == 'environment':
                    job['env']['USE_EXISTING_CLUSTER'] = 'true'
                elif kind == 'setup':
                    next(s for s in job['steps'] if s.get('uses','').startswith('actions/setup-go@'))['if'] = 'some condition'
                else:
                    next(s for s in job['steps'] if s.get('uses','').startswith('actions/setup-go@'))['with']['go-version-file'] = '../outside/go.mod'
                file.write_text(yaml.safe_dump(config))
                with self.assertRaisesRegex(ValueError, 'adapter'):
                    preflight.current_go_unit_jobs(repo, lambda p: p.read_bytes(), baseline)
            file.write_text(yaml.safe_dump(original))
            job = preflight.current_go_unit_jobs(repo, lambda p: p.read_bytes(), baseline)[0]
            args = argparse.Namespace(python=None, helm='/exact/helm')
            with patch.dict(os.environ, {'GO_BIN':'/exact/go', 'GOTOOLCHAIN':'auto', 'USE_EXISTING_CLUSTER':'true'}), \
                 patch.object(preflight.subprocess, 'check_output', side_effect=['go version go1.26.3 linux/amd64\n', 'v3.16.4']) as check:
                _, env = preflight.environment(job, repo, args)
                self.assertEqual(env['GOTOOLCHAIN'], 'local')
                self.assertEqual(env['USE_EXISTING_CLUSTER'], 'false')
                self.assertEqual(check.call_args_list[0].kwargs['env']['GOTOOLCHAIN'], 'local')
            with patch.dict(os.environ, {'GO_BIN':'/wrong/go'}), \
                 patch.object(preflight.subprocess, 'check_output', return_value='go version go1.26.1 linux/amd64\n'):
                with self.assertRaisesRegex(ValueError, 'differs from CI 1.26.3'):
                    preflight.environment(job, repo, args)

    def test_current_summary_uses_full_proposal_base_after_docs_only_tip(self):
        with sandbox() as (repo, root, baseline):
            current_ci(repo)
            run(['git', 'add', '.github', 'tools', 'build', 'phorvex'], repo)
            run(['git', 'commit', '-m', 'Source and CI authority change'], repo)
            source_commit = run(['git', 'rev-parse', 'HEAD'], repo)
            (repo/'review-note.md').write_text('Review metadata after source commit\n')
            run(['git', 'add', 'review-note.md'], repo)
            run(['git', 'commit', '-m', 'Documentation only tip'], repo)
            head = run(['git', 'rev-parse', 'HEAD'], repo)
            selected = preflight.plan(repo, baseline, head, pinned=True)
            summary = next(j for j in selected['jobs'] if j['id']=='go-affected-services')
            self.assertEqual(run(['git', 'rev-parse', 'HEAD^1'], repo), source_commit)
            self.assertNotEqual(selected['base_sha'], source_commit)
            self.assertIn('--base ' + selected['base_sha'], summary['script'])
            self.assertNotIn('HEAD^1', summary['script'])
            self.assertIn('--base HEAD^1', summary['ci_script'])
            self.assertIn('pinned plan base', summary['adaptation'])

    def test_pinned_python_requires_exact_patch_and_version_specific_binary(self):
        args = argparse.Namespace(python='/generic/python', helm=None)
        with patch.dict(os.environ, {'PREFLIGHT_PYTHON_3_12': '/matching/python'}), \
             patch.object(preflight.subprocess, 'check_output', return_value='3.12.14\n') as check:
            with self.assertRaisesRegex(ValueError, 'differs from CI 3.12.15'):
                preflight.environment({'tool':'python', 'version':'3.12.15'}, Path('/tmp'), args)
            self.assertEqual(check.call_args.args[0][0], '/matching/python')

    def test_chart_benchmark_rejects_missing_recipe_and_pins_wrapper_hash(self):
        with sandbox() as (repo, root, baseline):
            ci = current_ci(repo)
            original = yaml.safe_load((ci/'pr-validation.yml').read_text())['jobs']['charts']['steps']
            read = lambda p: p.read_bytes()
            want = preflight.chart_benchmark_setup(repo, original, read)
            for kind in ('setup', 'command', 'version-file', 'dependency', 'wrapper'):
                steps = yaml.safe_load(yaml.safe_dump(original))
                dependencies = (repo/'tools/benchmark-test-requirements.txt').read_bytes()
                wrapper = (repo/'tools/test_benchmark_regressions.py').read_bytes()
                try:
                    if kind == 'setup':
                        steps = [s for s in steps if not s.get('uses', '').startswith('actions/setup-go@')]
                    elif kind == 'command':
                        steps = [s for s in steps if s.get('run') != "python -m unittest discover -s tools -p 'test_*.py' -v"]
                    elif kind == 'version-file':
                        next(s for s in steps if s.get('uses', '').startswith('actions/setup-go@'))['with']['go-version-file'] = 'phorvex/go.mod'
                    elif kind == 'dependency':
                        (repo/'tools/benchmark-test-requirements.txt').write_text('openpyxl>=3.1\n')
                    else:
                        (repo/'tools/test_benchmark_regressions.py').write_bytes(b'')
                    with self.assertRaisesRegex(ValueError, 'adapter'):
                        preflight.chart_benchmark_setup(repo, steps, read)
                finally:
                    (repo/'tools/benchmark-test-requirements.txt').write_bytes(dependencies)
                    (repo/'tools/test_benchmark_regressions.py').write_bytes(wrapper)
            (repo/'tools/test_benchmark_regressions.py').write_bytes(wrapper + b'\n# changed wrapper\n')
            changed = preflight.chart_benchmark_setup(repo, original, read)
            self.assertNotEqual(want['benchmark_wrapper_sha256'], changed['benchmark_wrapper_sha256'])

    def test_chart_benchmark_requires_exact_local_go(self):
        job = {'tool': 'helm', 'version': 'v3.16.4', 'benchmark_go_version': '1.26.3'}
        args = argparse.Namespace(python=None, helm='/exact/helm')
        with patch.dict(os.environ, {'GO_BIN': '/exact/go', 'GOTOOLCHAIN': 'auto'}), \
             patch.object(preflight.subprocess, 'check_output', side_effect=['v3.16.4', 'go version go1.26.3 linux/amd64']) as check:
            _, env = preflight.environment(job, Path('/tmp'), args)
            self.assertEqual(env['GOTOOLCHAIN'], 'local')
            self.assertEqual(env['GO_BIN'], '/exact/go')
            self.assertEqual(check.call_args_list[-1].kwargs['env']['GOTOOLCHAIN'], 'local')
        with patch.dict(os.environ, {'GO_BIN': '/wrong/go'}), \
             patch.object(preflight.subprocess, 'check_output', side_effect=['v3.16.4', 'go version go1.26.1 linux/amd64']):
            with self.assertRaisesRegex(ValueError, 'differs from chart CI 1.26.3'):
                preflight.environment(job, Path('/tmp'), args)

    def test_historical_chart_without_benchmark_setup_retains_its_plan(self):
        with sandbox() as (repo, root, baseline):
            ci = current_ci(repo)
            file = ci/'pr-validation.yml'
            current = file.read_bytes()
            old = yaml.safe_load(current)
            old['jobs']['charts']['steps'] = [s for s in old['jobs']['charts']['steps']
                                              if not s.get('uses', '').startswith('actions/setup-go@')]
            for step in old['jobs']['charts']['steps']:
                if 'benchmark-test-requirements.txt' in step.get('run', ''):
                    step['run'] = 'python -m pip install PyYAML==6.0.2'
            file.write_text(yaml.safe_dump(old))
            run(['git', 'add', '.github', 'tools', 'build', 'phorvex'], repo)
            run(['git', 'commit', '-m', 'Historical chart authority'], repo)
            head = run(['git', 'rev-parse', 'HEAD'], repo)
            selected = preflight.plan(repo, baseline, head, pinned=True)
            self.assertTrue([j for j in selected['jobs'] if j['tool'] == 'helm'])
            self.assertFalse(any('benchmark_go_version' in j for j in selected['jobs']))
            file.write_bytes(current)
            self.assertEqual(preflight.plan(repo, baseline, head, pinned=True), selected)
            updated = preflight.plan(repo, baseline, head)
            self.assertTrue(any(j.get('benchmark_go_version') == '1.26.3' for j in updated['jobs']))

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
