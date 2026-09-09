"""Run selected LOCAL checks with CI's tool versions; never run deploy/E2E jobs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import signal
import time
import yaml


def git(repo, *args):
    return subprocess.check_output(['git', *args], cwd=repo)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def evidence_path(name):
    if '/_template/' in name: return False  # templates are executable workflow configuration
    return name == 'workflow/.workflow.lock' or name.startswith(('workflow/fixes/', 'workflow/issues/', 'workflow/releases/',
                            'workflow/anatomy/', 'workflow/intake/', 'workflow/campaigns/', 'workflow/coordination/inbox/',
                            'workflow/coordination/archive/', 'workflow/coordination/.runtime/'))


def code_tree(repo, source):
    entries = git(repo, 'ls-tree', '-rz', '--full-tree', source).decode().split('\0')
    return digest([row for row in entries if row and not evidence_path(row.split('\t', 1)[1])])


def worktree(repo):
    # Mutable fix records are checked by workflow gates, not mistaken for code edits.
    paths = git(repo, 'diff', '--name-only', 'HEAD').decode().splitlines()
    paths += git(repo, 'ls-files', '--others', '--exclude-standard').decode().splitlines()
    dirty = {}
    for name in sorted(set(paths)):
        if evidence_path(name):
            continue
        p = repo / name
        dirty[name] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else 'deleted'
    return digest({'code_tree': code_tree(repo, 'HEAD'), 'dirty': dirty})


def plan(repo: Path, base: str, head: str) -> dict:
    # A newer main must not make unrelated upstream changes look like this PR's delta.
    base = git(repo, 'merge-base', base, head).decode().strip()
    paths = set(git(repo, 'diff', '--name-only', base, head).decode().splitlines())
    paths.update(p for p in git(repo, 'diff', '--name-only', 'HEAD').decode().splitlines() if not evidence_path(p))
    paths.update(p for p in git(repo, 'ls-files', '--others', '--exclude-standard').decode().splitlines() if not evidence_path(p))
    jobs = [{'id': 'diff', 'cwd': '.', 'script': f'git diff --check {base} {head}\ngit diff --check HEAD', 'tool': None}]
    if any(p.startswith(('workflow/', 'AGENTS.md', '.github/workflows/workflow-harness')) for p in paths):
        file = repo / '.github/workflows/workflow-harness.yml'
        config = yaml.safe_load(file.read_text())
        steps = config['jobs']['harness']['steps']
        version = next(str(s['with']['python-version']) for s in steps if str(s.get('uses', '')).startswith('actions/setup-python@'))
        runs = [s['run'].strip() for s in steps if 'run' in s]
        if runs != ['python -m pip install -r workflow/requirements.txt', 'bash workflow/tools/check.sh']:
            raise ValueError('workflow CI commands changed: update the local preflight adapter explicitly')
        jobs.append({'id': 'workflow', 'cwd': '.', 'script': runs[-1], 'tool': 'python', 'version': version,
                     'ci_sha256': hashlib.sha256(file.read_bytes()).hexdigest()})
    chart_paths = ('phorvex/', 'deploy/helm/', 'build/phoenix-extended/charts/', 'tools/', 'End-to-End/', '.github/workflows/ci.yml', '.github/workflows/e2e-contract.yml')
    if any(p.startswith(chart_paths) for p in paths):
        file = repo / '.github/workflows/ci.yml'
        job = yaml.safe_load(file.read_text())['jobs']['chart-sync']
        if job.get('env') or job.get('container'): raise ValueError('chart-sync now needs CI environment setup; review adapter')
        steps = job['steps']
        if any('uses' in step and not step['uses'].startswith(('actions/checkout@', 'azure/setup-helm@')) for step in steps):
            raise ValueError('new chart-sync setup action requires explicit local adapter support')
        version = next(str(s['with']['version']) for s in steps if str(s.get('uses', '')).startswith('azure/setup-helm@'))
        for i, step in enumerate(steps):
            if 'run' not in step:
                continue
            if '${{' in step['run'] or step.get('if') or step.get('env'):
                raise ValueError('chart-sync now depends on CI context; review the adapter before running')
            jobs.append({'id': f'chart-{i}', 'name': step.get('name'), 'cwd': step.get('working-directory', '.'),
                         'script': step['run'], 'tool': 'helm', 'version': version,
                         'ci_sha256': hashlib.sha256(file.read_bytes()).hexdigest()})
    for module in ['phorvex', 'build/phoenix-extended']:
        if any(p.startswith(module + '/') and p.endswith(('.go', 'go.mod', 'go.sum')) for p in paths):
            lines = (repo / module / 'go.mod').read_text().splitlines()
            version = next(line.split()[1] for line in lines if line.startswith('go '))
            jobs.append({'id': 'go-' + module.replace('/', '-'), 'cwd': module, 'tool': 'go',
                         'version': version, 'script': 'go build ./...\ngo test ./...\ngo vet ./...'})
    return {'schema_version': 1, 'base_sha': base, 'head_sha': head, 'changed_paths': sorted(paths), 'jobs': jobs,
            'external': ['Shared-cluster E2E, image builds/deployment and live verification are separate; local PASS does not sign them.']}


def environment(job, repo, args):
    env = dict(os.environ)
    if args.helm: env['HELM_BIN'] = args.helm
    prefix = []
    tool = job['tool']
    if tool == 'python':
        binary = args.python or os.environ.get('WORKFLOW_PYTHON') or shutil.which('python' + job['version'])
        if binary:
            got = subprocess.check_output([binary, '-c', 'import sys;print(".".join(map(str,sys.version_info[:2])))'], text=True, timeout=15).strip()
            if got != job['version']:
                raise ValueError(f'Python {got} differs from CI {job["version"]}')
            # Both python and python3 in check.sh must use the selected environment.
            binary = shutil.which(binary) or binary
            env['PATH'] = str(Path(binary).absolute().parent) + os.pathsep + env['PATH']
            subprocess.run([binary, '-c', 'import yaml,jsonschema'], check=True, capture_output=True, timeout=15)
        elif shutil.which('uv'):
            prefix = ['uv', 'run', '--python', job['version'], '--with-requirements', str(repo/'workflow/requirements.txt')]
        else:
            raise ValueError(f'install Python {job["version"]} with workflow/requirements.txt, or uv; no version fallback')
    elif tool == 'helm':
        binary = args.helm or os.environ.get('HELM_BIN') or shutil.which('helm')
        if not binary:
            raise ValueError(f'Helm {job["version"]} required by CI; set --helm or HELM_BIN')
        got = subprocess.check_output([binary, 'version', '--template', '{{.Version}}'], text=True, timeout=15).strip()
        if got != job['version']:
            raise ValueError(f'Helm {got} differs from CI {job["version"]}; provide the matching binary')
        env['PATH'] = str(Path(binary).absolute().parent) + os.pathsep + env['PATH']
    elif tool == 'go':
        binary = os.environ.get('GO_BIN') or shutil.which('go')
        if not binary:
            raise ValueError('Go required; set GO_BIN or PATH')
        env['PATH'] = str(Path(binary).absolute().parent) + os.pathsep + env['PATH']
        env['GOTOOLCHAIN'] = 'go' + job['version']
    return prefix, env


def run_plan(repo, selected, output, args):
    before = worktree(repo)
    log_dir = output.parent / ('run-' + str(time.time_ns()))
    log_dir.mkdir(parents=True)
    results = []
    for job in selected['jobs']:
        log = log_dir / (job['id'] + '.log')
        started = time.monotonic()
        result = {'id': job['id'], 'log': str(log.relative_to(output.parent))}
        try:
            prefix, env = environment(job, repo, args)
            cwd = (repo / job['cwd']).resolve()
            if cwd != repo.resolve() and repo.resolve() not in cwd.parents:
                raise ValueError('check working directory escapes repository')
            with log.open('w') as stream:
                proc = subprocess.Popen(prefix + ['bash', '-e', '-o', 'pipefail', '-c', job['script']],
                                        cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                        start_new_session=True)
                try:
                    proc.wait(timeout=args.timeout)
                except BaseException:
                    # Cancel the whole owned local test process tree, not only its shell.
                    try: os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    proc.wait()
                    raise
            result.update(result='PASS' if proc.returncode == 0 else 'FAIL', exit_code=proc.returncode)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            if not log.exists(): log.write_text(str(exc) + '\n')
            result.update(result='UNAVAILABLE', error=str(exc))
        result.update(seconds=round(time.monotonic()-started, 3), sha256=hashlib.sha256(log.read_bytes()).hexdigest())
        results.append(result)
        print(f'{job["id"]}: {result["result"]}', flush=True)
    after = worktree(repo)
    receipt = {'schema_version': 1, 'plan': selected, 'plan_sha256': digest(selected),
               'worktree_sha256': before, 'results': results,
               'result': 'PASS' if before == after and all(x['result'] == 'PASS' for x in results) else 'FAIL'}
    if before != after: receipt['error'] = 'code changed during checks; rerun preflight'
    output.write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


def validate_receipt(repo, path, base, head):
    receipt = json.loads(path.read_text())
    if worktree(repo) != digest({'code_tree': code_tree(repo, head), 'dirty': {}}):
        raise ValueError('commit code before final preflight; worktree must match the pinned implementation')
    selected = plan(repo, base, head)
    if (receipt.get('result') != 'PASS' or receipt.get('plan_sha256') != digest(selected)
            or receipt.get('worktree_sha256') != worktree(repo)):
        raise ValueError('preflight missing, failed or stale; rerun for this source/worktree')
    expected = {x['id'] for x in selected['jobs']}
    rows = receipt.get('results', [])
    if len(rows) != len(expected) or {x.get('id') for x in rows} != expected:
        raise ValueError('preflight did not run every selected local check')
    for row in rows:
        log = (path.parent / row['log']).resolve()
        if (path.parent.resolve() not in log.parents or row.get('result') != 'PASS'
                or row.get('exit_code') != 0 or not log.is_file()
                or hashlib.sha256(log.read_bytes()).hexdigest() != row.get('sha256')):
            raise ValueError('preflight raw output missing or changed')
    return receipt
