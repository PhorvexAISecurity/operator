"""Tests for benchmark/lab/teardown-by-tag.sh (ticket Part 2 P8, TP-5).

The script runs against a stateful fake account (tests/teardown_stubs): a full
lab for the run under test, a second concurrent lab, the dev cluster, prod
resources and a look-alike lab whose name merely extends the run's. Every test
checks the one safety rule: nothing that is not the run's is ever touched, and
every delete names a resource of the run.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parents[1]
SCRIPT = LAB_DIR / 'teardown-by-tag.sh'
STUBS = Path(__file__).resolve().parent / 'teardown_stubs'
ACCT = '753556437180'
RUN, OTHER = 'abc123', 'def456'
MUTATING = {'delete-stack', 'delete-load-balancer', 'delete-network-interface', 'delete-security-group',
            'delete-open-id-connect-provider', 'delete-log-group', 'delete-volume', 'delete-repository'}


def arn(service, resource):
    return f'arn:aws:{service}:us-east-2:{ACCT}:{resource}'


def lab_items(run, lab=None):
    """A lab as eksctl, the in-cluster controllers and build-image.sh leave it."""
    lab = lab or f'phorvex-281-lab-{run}'
    runtag = {'phorvex.ai/lab-run': run, 'phorvex.ai/benchmark': 'true'}
    alpha = {'alpha.eksctl.io/cluster-name': lab}
    k8s = {f'kubernetes.io/cluster/{lab}': 'owned'}
    cs, ng_sys, ng_gpu = f'eksctl-{lab}-cluster', f'eksctl-{lab}-nodegroup-system', f'eksctl-{lab}-nodegroup-gpu'
    addon = f'eksctl-{lab}-addon-iamserviceaccount-kube-system-ebs-csi-controller-sa'
    vpc = f'vpc-{run}'

    def stack(name):
        return {'kind': 'stack', 'name': name, 'cluster': lab, 'state': 'CREATE_COMPLETE',
                'arn': arn('cloudformation', f'stack/{name}/{run}'), 'tags': {**runtag, **alpha}}

    def ec2(kind, rid, res, **extra):
        return {'kind': kind, 'id': rid, 'arn': arn('ec2', f'{res}/{rid}'), **extra}

    items = [
        {'kind': 'cluster', 'name': lab, 'arn': arn('eks', f'cluster/{lab}'), 'tags': dict(runtag), 'owner': cs},
        stack(cs), stack(ng_sys), stack(ng_gpu), stack(addon),
        ec2('vpc', vpc, 'vpc', tags={**alpha, **runtag}, owner=cs),
        ec2('nat', f'nat-{run}', 'natgateway', state='available', vpc=vpc, tags={**alpha, **runtag}, owner=cs),
        ec2('eip', f'eipalloc-{run}', 'elastic-ip', tags={**alpha, **runtag}, owner=cs),
        ec2('sg', f'sg-cp-{run}', 'security-group', vpc=vpc, tags={**alpha, **runtag}, owner=cs),
        ec2('instance', f'i-sys-{run}', 'instance', state='running', vpc=vpc,
            tags={'eks:cluster-name': lab, **runtag}, owner=ng_sys),
        ec2('instance', f'i-gpu-{run}', 'instance', state='running', vpc=vpc,
            tags={'eks:cluster-name': lab, **runtag}, owner=ng_gpu),
        ec2('eni', f'eni-primary-{run}', 'network-interface', state='in-use', vpc=vpc,
            groups=[f'sg-cp-{run}'], attached_to=f'i-sys-{run}', tags={}),
        # Controller-made: a classic ELB, its security group, a CNI ENI that leaks.
        {'kind': 'elb', 'name': f'a{run}elb', 'arn': arn('elasticloadbalancing', f'loadbalancer/a{run}elb'),
         'vpc': vpc, 'tags': dict(k8s)},
        ec2('sg', f'sg-elb-{run}', 'security-group', vpc=vpc, tags=dict(k8s)),
        ec2('eni', f'eni-leak-{run}', 'network-interface', state='in-use', vpc=vpc, leaks=True,
            groups=[f'sg-elb-{run}'], attached_to=f'i-sys-{run}',
            tags={'cluster.k8s.amazonaws.com/name': lab}),
        # A PVC's volume, attached until its node goes.
        ec2('volume', f'vol-{run}', 'volume', state='in-use', attached_to=f'i-gpu-{run}', tags={**runtag, **k8s}),
        {'kind': 'oidc', 'arn': f'arn:aws:iam::{ACCT}:oidc-provider/oidc.eks.us-east-2.amazonaws.com/id/{run.upper()}',
         'tags': dict(alpha)},
        {'kind': 'loggroup', 'name': f'/aws/eks/{lab}/cluster', 'arn': arn('logs', f'log-group:/aws/eks/{lab}/cluster'),
         'tags': {}},
        {'kind': 'ecr', 'name': f'phorvex-281-temp-{run}', 'arn': arn('ecr', f'repository/phorvex-281-temp-{run}'),
         'tags': dict(runtag)},
    ]
    for it in items:
        it['run'] = run  # test bookkeeping; the stubs ignore it
    return items


def bystander_items():
    """Dev, prod and a look-alike lab: none of it may ever change."""
    dev = 'phorvex-dev-eks'
    items = [
        {'kind': 'cluster', 'name': dev, 'arn': arn('eks', f'cluster/{dev}'), 'tags': {}},
        {'kind': 'stack', 'name': f'eksctl-{dev}-cluster', 'cluster': dev, 'state': 'CREATE_COMPLETE',
         'arn': arn('cloudformation', f'stack/eksctl-{dev}-cluster/dev'), 'tags': {'alpha.eksctl.io/cluster-name': dev}},
        {'kind': 'ecr', 'name': 'phorvex/brain', 'arn': arn('ecr', 'repository/phorvex/brain'), 'tags': {}},
        {'kind': 'volume', 'id': 'vol-prod', 'arn': arn('ec2', 'volume/vol-prod'), 'state': 'available',
         'tags': {f'kubernetes.io/cluster/{dev}': 'owned'}},
        {'kind': 'sg', 'id': 'sg-prod', 'arn': arn('ec2', 'security-group/sg-prod'), 'vpc': 'vpc-dev',
         'tags': {f'kubernetes.io/cluster/{dev}': 'owned'}},
    ]
    for it in items:
        it['run'] = 'bystander'
    lookalike = lab_items('abc1234', lab=f'phorvex-281-lab-{RUN}4')
    for it in lookalike:
        it['run'] = 'lookalike'
    return items + lookalike


class TeardownTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='teardown-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.world = self.tmp / 'world.json'
        self.log = self.tmp / 'calls.log'
        self.proof = self.tmp / 'TEARDOWN-PROOF.txt'
        self.scratch = self.tmp / 'scratch'
        self.home = self.tmp / 'home'
        self.scratch.mkdir()
        (self.home / '.kube').mkdir(parents=True)
        (self.home / '.kube' / 'config').write_text('real kubeconfig sentinel\n')
        self.write_world(lab_items(RUN) + lab_items(OTHER) + bystander_items())

    def write_world(self, items):
        self.world.write_text(json.dumps({'account': ACCT, 'items': items}))

    def items(self):
        return json.loads(self.world.read_text())['items']

    def teardown(self, *extra, run=RUN, proof=True, **stub):
        args = ['--run-id', run, '--account', ACCT, '--region', 'us-east-2']
        if proof:
            args += ['--proof', str(self.proof)]
        env = {**{k: v for k, v in os.environ.items() if not k.startswith(('AWS_', 'STUB_', 'TEARDOWN_'))},
               'PATH': f'{STUBS}:{os.environ["PATH"]}', 'HOME': str(self.home), 'TMPDIR': str(self.scratch),
               'STUB_WORLD': str(self.world), 'STUB_LOG': str(self.log),
               'TEARDOWN_WAIT_STACKS': '5', 'TEARDOWN_WAIT_ELB': '5', 'TEARDOWN_WAIT_SG': '5', 'TEARDOWN_POLL': '0',
               **stub}
        return subprocess.run(['bash', str(SCRIPT), *args, *extra], text=True, capture_output=True, env=env)

    def calls(self):
        if not self.log.exists():
            return []
        return [line.split('\t') for line in self.log.read_text().splitlines()]

    def mutations(self):
        return [c for c in self.calls() if c[0] == 'eksctl' or (c[0] == 'aws' and set(c) & MUTATING)]

    def gone(self, it):
        return it.get('deleted') or it.get('state') in ('terminated', 'DELETE_COMPLETE', 'deleted')

    def assert_run_gone(self, run=RUN):
        alive = [(it['kind'], it.get('id') or it.get('name') or it['arn']) for it in self.items()
                 if it['run'] == run and not self.gone(it)]
        self.assertEqual(alive, [], f'resources of {run} left behind')

    def assert_only_run_touched(self, before, run=RUN):
        """Everything not of `run` is unchanged, and every delete names a resource of `run`."""
        after = {json.dumps(it, sort_keys=True) for it in self.items() if it['run'] != run}
        self.assertEqual(after, {json.dumps(it, sort_keys=True) for it in before if it['run'] != run})
        owners = {}
        for it in before:
            for key in ('arn', 'name', 'id'):
                if it.get(key):
                    owners[it[key]] = it['run']
        for call in self.mutations():
            if call[0] == 'eksctl':
                self.assertIn(f'phorvex-281-lab-{run}', call)
                continue
            targets = {owners[a] for a in call if a in owners}
            self.assertEqual(targets, {run}, f'delete outside the run: {call}')

    def assert_pass(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], 'PASS')
        self.assertEqual(self.proof.read_text().splitlines()[-1], 'PASS')

    # TP-5 main path: eksctl gets part of the way; the sweeps and stack retry finish it.
    def test_partial_eksctl_converges_to_pass(self):
        before = self.items()
        result = self.teardown()
        self.assert_pass(result)
        self.assert_run_gone()
        self.assert_only_run_touched(before)
        self.assertIn('DELETE_FAILED', self.proof.read_text(), 'eksctl left the cluster stack failed')
        # eksctl got a throwaway kubeconfig; the real one and the scratch dir are clean.
        (kubeconfig,) = [c[1] for c in self.calls() if c[0] == 'eksctl-kubeconfig']
        self.assertTrue(kubeconfig.startswith(str(self.scratch)), kubeconfig)
        self.assertEqual((self.home / '.kube' / 'config').read_text(), 'real kubeconfig sentinel\n')
        self.assertEqual(list(self.scratch.iterdir()), [])
        (eksctl,) = [c for c in self.calls() if c[0] == 'eksctl']
        self.assertEqual(eksctl[1:], ['delete', 'cluster', '--name', f'phorvex-281-lab-{RUN}', '--region', 'us-east-2',
                                      '--disable-nodegroup-eviction', '--wait'])

    def test_clean_eksctl(self):
        before = self.items()
        self.assert_pass(self.teardown(STUB_EKSCTL='clean'))
        self.assert_run_gone()
        self.assert_only_run_touched(before)

    # Step 3 note: with the API unreachable, steps 4-9 still converge, in stack order.
    def test_api_unreachable_still_converges(self):
        before = self.items()
        self.assert_pass(self.teardown(STUB_EKSCTL='fail'))
        self.assert_run_gone()
        self.assert_only_run_touched(before)
        deleted = [c[c.index('--stack-name') + 1] for c in self.calls() if 'delete-stack' in c]
        lab = f'phorvex-281-lab-{RUN}'
        kinds = ['nodegroup' if '-nodegroup-' in s else 'addon' if '-addon-' in s else 'cluster'
                 for s in deleted if s.startswith(f'eksctl-{lab}-')]
        self.assertEqual(kinds, sorted(kinds, key=['nodegroup', 'addon', 'cluster'].index))
        self.assertEqual(kinds[-1], 'cluster')

    def test_no_eksctl_on_path_still_converges(self):
        bare = self.tmp / 'bin'
        bare.mkdir()
        for tool in ('aws', 'world.py'):
            (bare / tool).symlink_to(STUBS / tool)
        before = self.items()
        self.assert_pass(self.teardown(PATH=f'{bare}:/usr/bin:/bin'))
        self.assertIn('eksctl is not on PATH', self.proof.read_text())
        self.assert_run_gone()
        self.assert_only_run_touched(before)

    # TP-S4: a re-run after PASS deletes nothing and passes again.
    def test_rerun_is_idempotent(self):
        self.assert_pass(self.teardown())
        self.log.unlink()
        before = self.items()
        self.assert_pass(self.teardown())
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.items(), before)

    # TP-S4: two labs side by side, each torn down on its own.
    def test_concurrent_labs_are_independent(self):
        before = self.items()
        self.assert_pass(self.teardown())
        self.assert_only_run_touched(before)
        mid = self.items()
        self.log.unlink()
        self.assert_pass(self.teardown(run=OTHER))
        self.assert_run_gone(OTHER)
        self.assert_only_run_touched(mid, run=OTHER)

    # TP-S1: --plan deletes nothing.
    def test_plan_deletes_nothing(self):
        before = self.items()
        result = self.teardown('--plan')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.items(), before)
        text = self.proof.read_text()
        self.assertIn(f'PLAN: eksctl delete cluster --name phorvex-281-lab-{RUN}', text)
        self.assertIn(f'PLAN: aws ecr delete-repository --repository-name phorvex-281-temp-{RUN} --force', text)
        self.assertIn('PRESENT EKS cluster', result.stdout)

    # TP-S1: a malformed id, and credentials for another account.
    def test_refusals(self):
        for bad in ('ABC123', 'abc12', 'abc1234', '../x'):
            with self.subTest(run=bad):
                result = self.teardown(run=bad)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(self.calls(), [])
        result = self.teardown(STUB_CALLER_ACCOUNT='111111111111')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('account 111111111111, not --account', result.stderr)
        self.assertEqual([c[1:3] for c in self.calls()], [['--region', 'us-east-2']])
        self.assertEqual(self.mutations(), [])

    # TP-S1: a resource with the derived name but without the run tag is never deleted.
    def test_derived_names_without_the_run_tag_are_never_deleted(self):
        items = [it for it in self.items()]
        for it in items:
            if it['run'] == RUN and it['kind'] in ('cluster', 'stack', 'ecr'):
                it['tags'].pop('phorvex.ai/lab-run')
                it['run'] = 'untagged'
        self.write_world(items)
        before = self.items()
        result = self.teardown()
        self.assertEqual(result.returncode, 70, result.stdout)
        for it in self.items():
            if it['run'] == 'untagged':
                self.assertFalse(self.gone(it), f'untagged {it["kind"]} {it.get("name")} was deleted')
        self.assertNotIn('eksctl', {c[0] for c in self.calls()})
        self.assertIn(f'LEFTOVER EKS cluster phorvex-281-lab-{RUN}', result.stdout)
        self.assertIn(f'LEFTOVER ECR repository phorvex-281-temp-{RUN}', result.stdout)
        self.assertIn('is not tagged phorvex.ai/lab-run=abc123; not deleting it', self.proof.read_text())
        after = {json.dumps(it, sort_keys=True) for it in self.items() if it['run'] not in (RUN, 'untagged')}
        self.assertEqual(after, {json.dumps(it, sort_keys=True) for it in before if it['run'] not in (RUN, 'untagged')})

    # R7-2: a failed step does not stop the others, and a re-run converges.
    def test_failed_step_is_best_effort_and_rerun_converges(self):
        result = self.teardown(STUB_EKSCTL='fail', STUB_FAIL='elb:delete-load-balancer')
        self.assertEqual(result.returncode, 70, result.stdout)
        self.assertIn(f'LEFTOVER load balancer: {arn("elasticloadbalancing", f"loadbalancer/a{RUN}elb")}', result.stdout)
        self.assertIn('did not complete; continuing', self.proof.read_text())
        ecr = next(it for it in self.items() if it['kind'] == 'ecr' and it['run'] == RUN)
        self.assertTrue(ecr.get('deleted'), 'later steps still ran')
        self.assert_pass(self.teardown())
        self.assert_run_gone()

    def test_check_that_cannot_run_is_a_leftover(self):
        result = self.teardown(STUB_FAIL='ec2:describe-addresses')
        self.assertEqual(result.returncode, 70, result.stdout)
        self.assertIn('LEFTOVER Elastic IP: could not be checked', result.stdout)

    def test_missing_dev_cluster_is_not_a_pass(self):
        self.write_world([it for it in self.items() if it.get('name') != 'phorvex-dev-eks'])
        result = self.teardown()
        self.assertEqual(result.returncode, 70, result.stdout)
        self.assertIn('LEFTOVER dev cluster phorvex-dev-eks is not visible', result.stdout)

    def test_stale_tagging_hits_are_confirmed_by_describe(self):
        self.assert_pass(self.teardown(STUB_TAGGING_STALE='1'))

    def test_unknown_tagged_type_is_reported_not_ignored(self):
        queue = arn('sqs', f'queue-{RUN}')
        self.write_world(self.items() + [{'kind': 'other', 'arn': queue, 'run': RUN,
                                          'tags': {'phorvex.ai/lab-run': RUN}}])
        result = self.teardown()
        self.assertEqual(result.returncode, 70, result.stdout)
        self.assertIn(f'LEFTOVER tagged phorvex.ai/lab-run={RUN}: {queue}', result.stdout)

    # Step 2: an eksctl create still in progress is waited for.
    def test_in_progress_stack_is_waited_for(self):
        items = self.items()
        late = f'eksctl-phorvex-281-lab-{RUN}-nodegroup-late'
        items.append({'kind': 'stack', 'name': late, 'cluster': f'phorvex-281-lab-{RUN}', 'state': 'CREATE_IN_PROGRESS',
                      'settle_after': 3, 'arn': arn('cloudformation', f'stack/{late}/x'), 'run': RUN,
                      'tags': {'phorvex.ai/lab-run': RUN}})
        self.write_world(items)
        self.assert_pass(self.teardown())
        lists = [c for c in self.calls() if 'list-stacks' in c]
        self.assertGreaterEqual(len(lists), 3, 'polled until the create finished')

    # No internal retry: a node still shutting down fails this run; a re-run passes.
    def test_shutting_down_instance_is_a_leftover_without_retry(self):
        items = self.items()
        items.append({'kind': 'instance', 'id': f'i-late-{RUN}', 'arn': arn('ec2', f'instance/i-late-{RUN}'),
                      'state': 'shutting-down', 'run': RUN, 'tags': {'eks:cluster-name': f'phorvex-281-lab-{RUN}'}})
        self.write_world(items)
        result = self.teardown()
        self.assertEqual(result.returncode, 70, result.stdout)
        self.assertIn(f'LEFTOVER EC2 instance: i-late-{RUN} shutting-down', result.stdout)
        self.assertIn('run this command again', self.proof.read_text())


class StaticChecksTest(unittest.TestCase):
    def test_bash_syntax_and_executable(self):
        subprocess.run(['bash', '-n', str(SCRIPT)], check=True)
        for path in (SCRIPT, STUBS / 'aws', STUBS / 'eksctl'):
            self.assertTrue(os.access(path, os.X_OK), path)

    def test_no_set_x(self):
        self.assertNotRegex(SCRIPT.read_text(), r'(?m)^\s*set -[a-zA-Z]*x')

    @unittest.skipUnless(shutil.which('shellcheck'), 'shellcheck not installed')
    def test_shellcheck(self):
        subprocess.run(['shellcheck', str(SCRIPT)], check=True)


if __name__ == '__main__':
    unittest.main()
