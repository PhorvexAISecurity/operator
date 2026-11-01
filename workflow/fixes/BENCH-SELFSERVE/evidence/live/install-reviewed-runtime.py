"""Operator deployment of one reviewed source; no cluster writes or global symlink change.

Invoke on jh: python install-reviewed-runtime.py SOURCE MANIFEST_SHA256.
The release archive and reviewed source manifest are staged before this operation.
"""
from pathlib import Path
import datetime, hashlib, json, os, re, shutil, subprocess, sys, time

source, manifest_sha = sys.argv[1:]
assert re.fullmatch('[0-9a-f]{40}', source)
root = Path('/home/hami/phorvex-benchmark')
release = root / 'releases' / ('stage-selfserve-' + source[:12])
data = root / 'stage-data'
units = Path.home() / '.config/systemd/user'
out = data / 'deployment' / ('selfserve-' + source[:12])
assert not out.exists(), 'retain each previous deployment attempt'
out.mkdir(parents=True, mode=0o700)
os.umask(0o077)
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
def run(args, **kw): return subprocess.run(args, check=True, text=True, capture_output=True, **kw)
def system(*args): return run(['systemctl', '--user', *args])
def show(name):
    raw = system('show', name, '--property=MainPID,ActiveState,SubState,WorkingDirectory,UnitFileState,NRestarts').stdout
    return dict(x.split('=', 1) for x in raw.splitlines() if '=' in x)
def write(name, value): (out/name).write_text(json.dumps(value, indent=2)+'\n')
manifest = release/'reviewed-source-manifest.json'
assert digest(manifest) == manifest_sha
for row in json.loads(manifest.read_text())['paths']:
    assert digest(release/row['path']) == row['sha256'], row['path']
assert json.loads((release/'release-origin.json').read_text())['commit'] == source
expected_units = {
    'phorvex-benchmark-bot.service': 'a5d38dfa9cf504514b149f8705e90a8f6164c4c14a9e20cb0f4302e665afbbb9',
    'phorvex-stage-observer.service': 'd67049d417541279a1c6b03497530fb8b9813037bd7bbad596fd4afa7a88906c',
    'phorvex-stage-endpoint-refresh.service': 'aa7b7a634c930c1b22c6f1c3c11d9be3cb5931fd85d5351b61e0a2aebc0ca0a8',
    'phorvex-stage-endpoint-refresh.timer': '23e380d0ffcdf61e6a4785870c385e174a46c0ba996c8ac4889ace301d60c4f1'}
new_names = ['phorvex-stage-reconcile.service', 'phorvex-stage-reconcile.timer']
for name, sha in expected_units.items(): assert digest(units/name) == sha, 'concurrent unit change: '+name
for name in new_names: assert not (units/name).exists(), 'preserve existing unowned unit'
assert shutil.disk_usage(root).free >= 4 * 1024**3 + 512 * 1024**2
sys.path[:0]=[str(release/'benchmark/worker'),str(release)]
from stage_reconcile import observe, same_observation
from mathlab import stage_scope
observed=observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+120)
reviewed_probe=root/'stage-data/live/selfserve-install-inputs/runtime-probe-b3d55bdd.json'
assert digest(reviewed_probe)=='b080a773ed58b7cf1adeec3a6caea27e189204293949c5569a6f354e05d6f95c'
reviewed=json.loads(reviewed_probe.read_text())['probes']
reviewed_policies={}
for p,row in reviewed.items():
    policy=dict(row['result']['policy'])
    assert policy.pop('dry_run')==(policy['mode']=='dryRun')
    reviewed_policies[p]=policy
assert observed['policies']==reviewed_policies, 'reviewed policy/workload/Service identity changed'
assert observed['capture']==next(iter(reviewed.values()))['result']['capture'], 'reviewed capture scope changed'
for component,uid,digest_value in (
    ('brain','4057afaa-f682-47ef-bdda-ea754316aa09','sha256:ebb6d245afc52528155eee999e130972c1aa78f14f03a19b86118508acefd1bf'),
    ('manager','2c18eb3a-779e-467e-8b59-42fa5e4d05e7','sha256:da27f8d92181003872b73d09f88e4540d56f598deabeed66bbca2cf5f4160f33')):
    assert observed[component]['git_sha']=='61e83673b8d4f143fca67e17b8a54dc4712f9b28'
    assert observed[component]['deployment_uid']==uid and observed[component]['image_digest']==digest_value
for name,uid,mode in [('demo-api-defense','6485e0b3-0f36-4737-b0f5-7e846375da9f','active'),
                      ('stage-bench-defense','621c056d-ae10-452c-8828-b2dd0bbb5cb3','dryRun')]:
    assert observed['policies']['phorvex-staging-demo/'+name]['uid']==uid
    assert observed['policies']['phorvex-staging-demo/'+name]['mode']==mode
protected = [root/'config/bot.env', root/'bot/owner.json', root/'bot/members.json', data/'mathlab/bin/current.json']
before_hashes = {str(p): digest(p) for p in protected}
current_link = str((root/'current').resolve())
other_names = ['phorvex-benchmark-'+n+'.service' for n in ('api','proxy','web')]
other_before = {n: show(n) for n in other_names}
def idle():
    raw = run(['journalctl','--user','-u','phorvex-benchmark-bot.service','--since','2026-11-01 00:00:00','-o','cat','--no-pager']).stdout
    queued = set(re.findall(r'queued \w+ job ([a-f0-9]{12}) from',raw))
    history = [json.loads(x) for x in (root/'bot/history.jsonl').read_text().splitlines() if x.strip()]
    pending = queued-{x['id'] for x in history}
    assert not pending, 'bot has uncompleted accepted jobs: '+repr(sorted(pending))
    return {'queued_ids_not_in_terminal_history':sorted(pending),'terminal_records':len(history)}
receipt = {'source':source,'manifest_sha256':manifest_sha,'state':'PREPARED',
    'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'idle_before':idle(),
    'protected_hashes_before':before_hashes,'unrelated_units_before':other_before,'current_link_before':current_link,
    'stage_observation_before':observed}
backup = out/'unit-backups'; backup.mkdir(mode=0o700)
for name in expected_units: shutil.copy2(units/name, backup/name)
shutil.copy2(data/'mathlab/stage.json',out/'stage-pin-before.json')
proposed = out/'proposed-units';proposed.mkdir(mode=0o700)
bot = (units/'phorvex-benchmark-bot.service').read_text()
oldwd = 'WorkingDirectory='+str(root/'releases/stage-bot-3e11f4e7/benchmark/bot')
assert bot.count(oldwd) == 1
(proposed/'phorvex-benchmark-bot.service').write_text(bot.replace(oldwd,'WorkingDirectory='+str(release/'benchmark/bot')))
for template in (release/'benchmark/worker/deploy').glob('*.example'):
    name = template.name.removesuffix('.example')
    assert name in set(expected_units)|set(new_names)
    (proposed/name).write_text(template.read_text().replace('REVIEWED_SOURCE',release.name))
assert {p.name for p in proposed.iterdir()} == set(expected_units)|set(new_names)
receipt['proposed_unit_hashes']={p.name:digest(p) for p in proposed.iterdir()}
write('receipt.json',receipt)
stopped = False
try:
    assert same_observation(observed,observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+120)), 'stage changed before stop'
    receipt['idle_immediately_before_stop']=idle();write('receipt.json',receipt)
    system('stop','phorvex-benchmark-bot.service');stopped=True
    receipt['idle_after_stop']=idle();write('receipt.json',receipt)
    system('stop','phorvex-stage-endpoint-refresh.timer','phorvex-stage-endpoint-refresh.service','phorvex-stage-observer.service')
    env = os.environ.copy();env.update(PYTHONPATH=str(release/'benchmark/worker')+':'+str(release),PYTHONDONTWRITEBYTECODE='1')
    with (out/'initial-reconcile.log').open('w') as stream:
        result = subprocess.run([str(root/'runtime/python/bin/python'),'-B','benchmark/worker/stage_reconcile.py',
            '--data',str(data),'--repo',str(root/'operator-refactored'),'--ticks','64','--timeout','900',
            '--max-work-bytes','268435456','--max-corpus-bytes','2147483648'],
            cwd=release,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=950)
    receipt['reconcile_returncode']=result.returncode
    receipt['reconcile_status']=json.loads((data/'mathlab/reconcile-status.json').read_text())
    assert result.returncode == 0 and receipt['reconcile_status']['status']=='READY', 'initial reconciliation unavailable'
    assert json.loads((data/'mathlab/stage.json').read_text())['brain']['git_sha']=='61e83673b8d4f143fca67e17b8a54dc4712f9b28'
    assert same_observation(observed,observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+120)), 'stage changed during installation'
    for p in proposed.iterdir(): shutil.copy2(p,units/p.name)
    system('daemon-reload')
    system('enable','phorvex-stage-observer.service','phorvex-stage-reconcile.timer','phorvex-stage-endpoint-refresh.timer')
    system('start','phorvex-stage-observer.service','phorvex-stage-reconcile.timer','phorvex-stage-endpoint-refresh.timer','phorvex-benchmark-bot.service')
    receipt['installed_units']={name:show(name) for name in set(expected_units)|set(new_names)}
    for name in ['phorvex-benchmark-bot.service','phorvex-stage-observer.service','phorvex-stage-reconcile.timer','phorvex-stage-endpoint-refresh.timer']:
        assert receipt['installed_units'][name]['ActiveState']=='active',name
    receipt['protected_hashes_after']={str(p):digest(p) for p in protected}
    assert receipt['protected_hashes_after']==before_hashes
    assert str((root/'current').resolve())==current_link
    assert {n:show(n) for n in other_names}==other_before
    receipt['state']='INSTALLED_PENDING_BOT_ACCEPTANCE'
except BaseException as exc:
    receipt.update(state='INSTALLATION_ERROR',error_type=type(exc).__name__,error=str(exc))
    # Leave exact evidence/pins intact. Restore owned units only; no cluster rollback,
    # no journal removal, no global symlink change and no credential edits.
    if stopped:
        for name in ['phorvex-stage-reconcile.timer','phorvex-stage-reconcile.service','phorvex-stage-endpoint-refresh.timer','phorvex-stage-endpoint-refresh.service','phorvex-stage-observer.service','phorvex-benchmark-bot.service']:
            subprocess.run(['systemctl','--user','stop',name],capture_output=True)
        for name in expected_units: shutil.copy2(backup/name,units/name)
        for name in new_names:
            subprocess.run(['systemctl','--user','disable',name],capture_output=True)
            (units/name).unlink(missing_ok=True)
        system('daemon-reload')
        system('start','phorvex-benchmark-bot.service','phorvex-stage-observer.service','phorvex-stage-endpoint-refresh.timer')
        receipt['recovery']='Previous owned units restored; pin/evidence preserved for diagnosis. This does not claim old runtime readiness.'
    raise
finally:
    receipt['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();write('receipt.json',receipt)
    print(json.dumps({'state':receipt['state'],'receipt':str(out/'receipt.json'),'sha256':digest(out/'receipt.json')}),flush=True)
