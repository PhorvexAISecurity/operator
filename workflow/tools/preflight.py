"""Run selected LOCAL checks with CI's tool versions; never run deploy/E2E jobs."""
from __future__ import annotations

import hashlib
import json
import os
import re
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


def python_setup(repo, steps, source_bytes):
    """Resolve supported CI provisioning without executing GitHub-only setup."""
    found = []
    for i, step in enumerate(steps):
        if str(step.get('uses', '')).startswith('actions/setup-python@'):
            if step.get('if') or step.get('env'):
                raise ValueError('conditional Python setup requires local adapter support')
            found.append((str(step['with']['python-version']), i, None))
        for minor in ('3.11', '3.12'):
            expected = ('bin="$(bash tools/provision-python.sh ' + minor + ' "$RUNNER_TEMP/python")"\n'
                        'echo "$bin" >> "$GITHUB_PATH"')
            if step.get('run', '').strip() == expected:
                if any(step.get(key) for key in ('if', 'env', 'shell', 'working-directory')):
                    raise ValueError('custom pinned Python setup requires local adapter support')
                raw = source_bytes(repo / 'tools/provision-python.sh')
                match = re.search(r'^\s*' + re.escape(minor) + r'\) VERSION=(\d+\.\d+\.\d+) SHA256=[0-9a-f]{64} ;;$', raw.decode(), re.M)
                if match is None or not match[1].startswith(minor + '.'):
                    raise ValueError('pinned Python provision recipe changed: update local adapter')
                found.append((match[1], i, hashlib.sha256(raw).hexdigest()))
    if len(found) != 1:
        raise ValueError('CI Python setup missing or ambiguous: update local adapter')
    return found[0]


GO_UNIT_MODULES = (
    ('phorvex', '15m'), ('build/metricvalidity', '5m'), ('build/test-harness', '15m'),
    ('build/phoenix-extended', '15m'), ('libs/logging', '5m'),
    ('build/integrations/epss-ecr-auth-runtime', '5m'), ('farm-fixtures/agentsim', '5m'),
)
GO_UNIT_ENV = {'KUBECONFIG': '/dev/null', 'KUBEBUILDER_ASSETS': '',
               'USE_EXISTING_CLUSTER': 'false', 'GOTOOLCHAIN': 'local'}


def current_go_unit_jobs(repo, source_bytes, base):
    """Adapt only the pinned, non-cluster go-unit authority, never other CI jobs."""
    file = repo / '.github/workflows/pr-validation.yml'
    raw = source_bytes(file)
    job = yaml.safe_load(raw)['jobs']['go-unit']
    if job.get('env') != GO_UNIT_ENV or any(job.get(k) for k in ('container', 'services', 'defaults', 'strategy', 'if')):
        raise ValueError('Go unit CI environment changed: update local adapter')
    steps = job['steps']
    if any('uses' in s and not s['uses'].startswith(('actions/checkout@', 'actions/setup-go@', 'azure/setup-helm@')) for s in steps):
        raise ValueError('new Go setup action requires explicit local adapter support')
    if any(any(s.get(k) for k in ('if', 'env', 'shell', 'working-directory')) for s in steps):
        raise ValueError('custom Go unit step context requires local adapter support')
    setups = [s for s in steps if s.get('uses', '').startswith('actions/setup-go@')]
    helms = [s for s in steps if s.get('uses', '').startswith('azure/setup-helm@')]
    if len(setups) != 1 or len(helms) != 1:
        raise ValueError('Go/Helm unit setup missing or ambiguous: update local adapter')
    setup = setups[0].get('with', {})
    version_file = setup.get('go-version-file', '')
    if (set(setup) - {'go-version-file', 'cache-dependency-path'}
            or not re.fullmatch(r'(?:[A-Za-z0-9_-]+/)*go\.mod', version_file)):
        raise ValueError('Go version-file setup changed: update local adapter')
    version_raw = source_bytes(repo / version_file)
    versions = re.findall(r'^go (\d+\.\d+\.\d+)$', version_raw.decode(), re.M)
    if len(versions) != 1 or set(helms[0].get('with', {})) != {'version'}:
        raise ValueError('Go/Helm unit version recipe changed: update local adapter')
    common = {'cwd': '.', 'tool': 'go', 'version': versions[0], 'toolchain': 'local',
              'env': dict(GO_UNIT_ENV), 'helm_version': str(helms[0]['with']['version']),
              'ci_sha256': hashlib.sha256(raw).hexdigest(), 'go_version_file': version_file,
              'go_version_file_sha256': hashlib.sha256(version_raw).hexdigest()}
    summary = 'go -C phorvex run ./tools/servicerelease affected --base HEAD^1 --markdown >> "$GITHUB_STEP_SUMMARY"'
    tests = [f'go -C {module} test -mod=readonly -count=1 -timeout={timeout} ./...'
             for module, timeout in GO_UNIT_MODULES]
    expected = [tests[0], summary, *tests[1:]]
    runs = [s['run'].strip() for s in steps if 'run' in s]
    if runs != expected:
        raise ValueError('Go unit CI commands changed: update local adapter explicitly')
    jobs = []
    for script in runs:
        if script == summary:
            local_script = script.split(' >> ')[0].replace('--base HEAD^1', '--base ' + base)
            jobs.append(dict(common, id='go-affected-services', script=local_script,
                             adaptation='GitHub informational step-summary output is captured in this job log; the pinned plan base replaces the CI merge-parent base',
                             ci_script=script))
        else:
            module = script.split()[2]
            jobs.append(dict(common, id='go-unit-' + module.replace('/', '-'), script=script))
    return jobs


def chart_benchmark_setup(repo, steps, source_bytes):
    """Recognize the exact additional tool contract; old chart plans stay unchanged."""
    setups = [s for s in steps if s.get('uses', '').startswith('actions/setup-go@')]
    if not setups:
        if any('benchmark-test-requirements.txt' in s.get('run', '') for s in steps):
            raise ValueError('chart benchmark Go setup missing: update local adapter')
        return {}
    expected = {'go-version-file': 'build/test-harness/go.mod', 'cache-dependency-path': 'phorvex/go.sum'}
    if (len(setups) != 1 or setups[0].get('with') != expected
            or any(setups[0].get(k) for k in ('if', 'env', 'shell', 'working-directory'))):
        raise ValueError('chart benchmark Go setup changed: update local adapter')
    runs = [s.get('run', '').strip() for s in steps]
    required = ('python -m pip install PyYAML==6.0.2 -r tools/benchmark-test-requirements.txt',
                "python -m unittest discover -s tools -p 'test_*.py' -v")
    if any(command not in runs for command in required):
        raise ValueError('chart benchmark gating command missing: update local adapter')
    version_file = expected['go-version-file']
    raw = source_bytes(repo / version_file)
    versions = re.findall(r'^go (\d+\.\d+\.\d+)$', raw.decode(), re.M)
    if len(versions) != 1:
        raise ValueError('chart benchmark Go version changed: update local adapter')
    requirements = source_bytes(repo / 'tools/benchmark-test-requirements.txt')
    if requirements.decode().splitlines() != ['openpyxl==3.1.5', 'et_xmlfile==2.0.0']:
        raise ValueError('chart benchmark Python dependency recipe changed: update local adapter')
    wrapper = source_bytes(repo / 'tools/test_benchmark_regressions.py')
    if not wrapper.strip():
        raise ValueError('chart benchmark gating wrapper missing: update local adapter')
    return {'benchmark_go_version': versions[0], 'benchmark_go_version_file': version_file,
            'benchmark_go_version_file_sha256': hashlib.sha256(raw).hexdigest(),
            'benchmark_requirements_sha256': hashlib.sha256(requirements).hexdigest(),
            'benchmark_wrapper_sha256': hashlib.sha256(wrapper).hexdigest()}


def plan(repo: Path, base: str, head: str, *, pinned: bool = False, recipe_version: int = 2) -> dict:
    if recipe_version not in (1, 2):
        raise ValueError('unsupported preflight recipe version')
    # A newer main must not make unrelated upstream changes look like this PR's delta.
    base = git(repo, 'merge-base', base, head).decode().strip()
    paths = set(git(repo, 'diff', '--name-only', base, head).decode().splitlines())
    if not pinned:
        paths.update(p for p in git(repo, 'diff', '--name-only', 'HEAD').decode().splitlines() if not evidence_path(p))
        paths.update(p for p in git(repo, 'ls-files', '--others', '--exclude-standard').decode().splitlines() if not evidence_path(p))
    def source_bytes(file):
        return git(repo, 'show', head + ':' + file.relative_to(repo).as_posix()) if pinned else file.read_bytes()
    jobs = [{'id': 'diff', 'cwd': '.', 'script': f'git diff --check {base} {head}\ngit diff --check HEAD', 'tool': None}]
    if any(p.startswith(('workflow/', 'AGENTS.md', '.github/workflows/workflow-harness')) for p in paths):
        file = repo / '.github/workflows/workflow-harness.yml'
        config = yaml.safe_load(source_bytes(file))
        steps = config['jobs']['harness']['steps']
        version, setup_index, provision_hash = python_setup(repo, steps, source_bytes)
        runs = [s['run'].strip() for i, s in enumerate(steps) if 'run' in s and i != setup_index]
        if runs != ['python -m pip install -r workflow/requirements.txt', 'bash workflow/tools/check.sh']:
            raise ValueError('workflow CI commands changed: update the local preflight adapter explicitly')
        jobs.append({'id': 'workflow', 'cwd': '.', 'script': runs[-1], 'tool': 'python', 'version': version,
                     'ci_sha256': hashlib.sha256(source_bytes(file)).hexdigest()})
        if provision_hash:
            jobs[-1]['python_provision_sha256'] = provision_hash
    chart_paths = ('phorvex/', 'deploy/helm/', 'build/phoenix-extended/charts/', 'tools/', 'End-to-End/', '.github/workflows/ci.yml', '.github/workflows/pr-validation.yml', '.github/workflows/e2e-contract.yml')
    if any(p.startswith(chart_paths) for p in paths):
        legacy = repo / '.github/workflows/ci.yml'
        exists = bool(git(repo, 'ls-tree', '--name-only', head, '.github/workflows/ci.yml').strip()) if pinned else legacy.is_file()
        file = legacy if exists else repo / '.github/workflows/pr-validation.yml'
        job_name = 'chart-sync' if exists else 'charts'
        raw = source_bytes(file)
        job = yaml.safe_load(raw)['jobs'][job_name]
        if job.get('env') or job.get('container'): raise ValueError('chart checks now need CI environment setup; review adapter')
        steps = job['steps']
        allowed = ('actions/checkout@', 'azure/setup-helm@') if exists else ('actions/checkout@', 'azure/setup-helm@', 'actions/setup-python@', 'actions/setup-go@')
        if any('uses' in step and not step['uses'].startswith(allowed) for step in steps):
            raise ValueError('new chart setup action requires explicit local adapter support')
        version = next(str(s['with']['version']) for s in steps if str(s.get('uses', '')).startswith('azure/setup-helm@'))
        python_version, setup_index, provision_hash = (None, None, None) if exists else python_setup(repo, steps, source_bytes)
        benchmark_setup = {} if exists else chart_benchmark_setup(repo, steps, source_bytes)
        for i, step in enumerate(steps):
            if 'run' not in step or i == setup_index:
                continue
            if any(token in step['run'] for token in ('${{', '$RUNNER_TEMP', '$GITHUB_')) or step.get('if') or step.get('env'):
                raise ValueError('chart checks now depend on CI context; review the adapter before running')
            item = {'id': f'chart-{i}', 'name': step.get('name'), 'cwd': step.get('working-directory', '.'),
                    'script': step['run'], 'tool': 'helm', 'version': version,
                    'ci_sha256': hashlib.sha256(raw).hexdigest()}
            if python_version:
                item['python_version'] = python_version
                if provision_hash: item['python_provision_sha256'] = provision_hash
            item.update(benchmark_setup)
            jobs.append(item)
    affected = []
    for module in ['phorvex', 'build/phoenix-extended']:
        if any(p.startswith(module + '/') and p.endswith(('.go', 'go.mod', 'go.sum')) for p in paths):
            affected.append(module)
    legacy_exists = bool(git(repo, 'ls-tree', '--name-only', head, '.github/workflows/ci.yml').strip()) if pinned else (repo / '.github/workflows/ci.yml').is_file()
    current_go = recipe_version == 2 and not legacy_exists and (
        '.github/workflows/pr-validation.yml' in paths or any(
            p.startswith(module + '/') and p.endswith(('.go', 'go.mod', 'go.sum'))
            for p in paths for module, _ in GO_UNIT_MODULES))
    if current_go:
        current_jobs = current_go_unit_jobs(repo, source_bytes, base)
        jobs.extend(current_jobs)
        # Preserve the pre-existing additional build/vet coverage for changed
        # product modules; current CI's seven unit commands run separately above.
        for module in affected:
            item = dict(current_jobs[0], id='go-build-vet-' + module.replace('/', '-'),
                        script=f'go -C {module} build ./...\ngo -C {module} vet ./...')
            jobs.append(item)
    else:
        for module in affected:
            lines = source_bytes(repo / module / 'go.mod').decode().splitlines()
            version = next(line.split()[1] for line in lines if line.startswith('go '))
            jobs.append({'id': 'go-' + module.replace('/', '-'), 'cwd': module, 'tool': 'go',
                         'version': version, 'script': 'go build ./...\ngo test ./...\ngo vet ./...'})
    external = ['Shared-cluster E2E, image builds/deployment and live verification are separate; local PASS does not sign them.']
    if recipe_version == 2:
        external.append('Remote go-envtest with local Kubernetes API binaries and other remote CI jobs remain separate and unexecuted here; local PASS is not all remote CI passing.')
    return {'schema_version': recipe_version, 'base_sha': base, 'head_sha': head, 'changed_paths': sorted(paths), 'jobs': jobs,
            'external': external}


def python_environment(version, args, env, repo, *, imports='yaml,jsonschema'):
    # One preflight can require both workflow Python 3.11 and chart Python 3.12.
    minor = '.'.join(version.split('.')[:2])
    specific = os.environ.get('PREFLIGHT_PYTHON_' + minor.replace('.', '_'))
    binary = specific or args.python or os.environ.get('WORKFLOW_PYTHON') or shutil.which('python' + minor)
    prefix = []
    if binary:
        expression = 'import platform;print(platform.python_version())' if version.count('.') == 2 else 'import sys;print(".".join(map(str,sys.version_info[:2])))'
        got = subprocess.check_output([binary, '-c', expression], text=True, timeout=15).strip()
        if got != version:
            raise ValueError(f'Python {got} differs from CI {version}')
        binary = shutil.which(binary) or binary
        env['PATH'] = str(Path(binary).absolute().parent) + os.pathsep + env['PATH']
        subprocess.run([binary, '-c', 'import ' + imports], check=True, capture_output=True, timeout=15)
    elif shutil.which('uv'):
        prefix = ['uv', 'run', '--python', version, '--with-requirements', str(repo/'workflow/requirements.txt')]
    else:
        raise ValueError(f'install Python {version} with workflow/requirements.txt, or uv; no version fallback')
    return prefix, env


def environment(job, repo, args):
    env = dict(os.environ)
    if args.helm: env['HELM_BIN'] = args.helm
    prefix = []
    tool = job['tool']
    if tool == 'python':
        prefix, env = python_environment(job['version'], args, env, repo)
    elif tool == 'helm':
        binary = args.helm or os.environ.get('HELM_BIN') or shutil.which('helm')
        if not binary:
            raise ValueError(f'Helm {job["version"]} required by CI; set --helm or HELM_BIN')
        got = subprocess.check_output([binary, 'version', '--template', '{{.Version}}'], text=True, timeout=15).strip()
        if got != job['version']:
            raise ValueError(f'Helm {got} differs from CI {job["version"]}; provide the matching binary')
        env['PATH'] = str(Path(binary).absolute().parent) + os.pathsep + env['PATH']
        if job.get('python_version'):
            prefix, env = python_environment(job['python_version'], args, env, repo, imports='yaml')
        if job.get('benchmark_go_version'):
            binary = os.environ.get('GO_BIN') or shutil.which('go')
            if not binary:
                raise ValueError('Go required by chart benchmark integrations; set GO_BIN or PATH')
            binary = shutil.which(binary) or binary
            env['GOTOOLCHAIN'] = 'local'
            got = subprocess.check_output([binary, 'version'], env=env, text=True, timeout=15).strip()
            if not got.startswith('go version go' + job['benchmark_go_version'] + ' '):
                raise ValueError(f'Go {got} differs from chart CI {job["benchmark_go_version"]}')
            env['GO_BIN'] = binary
            env['PATH'] = str(Path(binary).absolute().parent) + os.pathsep + env['PATH']
    elif tool == 'go':
        binary = os.environ.get('GO_BIN') or shutil.which('go')
        if not binary:
            raise ValueError('Go required; set GO_BIN or PATH')
        binary = shutil.which(binary) or binary
        env['PATH'] = str(Path(binary).absolute().parent) + os.pathsep + env['PATH']
        if job.get('toolchain') == 'local':
            env.update(job['env'])
            got = subprocess.check_output([binary, 'version'], env=env, text=True, timeout=15).strip()
            if not got.startswith('go version go' + job['version'] + ' '):
                raise ValueError(f'Go {got} differs from CI {job["version"]}; provide the exact binary with GO_BIN')
            helm = args.helm or os.environ.get('HELM_BIN') or shutil.which('helm')
            if not helm:
                raise ValueError(f'Helm {job["helm_version"]} required by Go unit CI')
            got = subprocess.check_output([helm, 'version', '--template', '{{.Version}}'], text=True, timeout=15).strip()
            if got != job['helm_version']:
                raise ValueError(f'Helm {got} differs from Go unit CI {job["helm_version"]}')
            env['HELM_BIN'] = helm
            env['PATH'] = str(Path(binary).absolute().parent) + os.pathsep + str(Path(helm).absolute().parent) + os.pathsep + env['PATH']
        else:
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


def validate_receipt(repo, path, base, head, *, require_worktree=True):
    # Submission binds the current checkout. Historical attestations bind their pinned
    # source, even when doctor runs on a newer main or GitHub's synthetic merge checkout.
    receipt = json.loads(path.read_text())
    pinned_worktree = digest({'code_tree': code_tree(repo, head), 'dirty': {}})
    if require_worktree and worktree(repo) != pinned_worktree:
        raise ValueError('commit code before final preflight; worktree must match the pinned implementation')
    recipe_version = receipt.get('plan', {}).get('schema_version', 1)
    if require_worktree and recipe_version != 2:
        raise ValueError('legacy preflight recipe cannot satisfy current submission; rerun preflight')
    selected = plan(repo, base, head, pinned=True, recipe_version=recipe_version)
    if (receipt.get('result') != 'PASS' or receipt.get('plan_sha256') != digest(selected)
            or receipt.get('worktree_sha256') != pinned_worktree):
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
