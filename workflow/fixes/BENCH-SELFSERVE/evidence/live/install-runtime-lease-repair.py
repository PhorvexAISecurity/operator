"""Reviewed immutable runtime update; preserves cluster, global link and all journals."""
import datetime, hashlib, json, os, re, shutil, subprocess, sys, time
from pathlib import Path

source, manifest_sha = sys.argv[1:]
assert re.fullmatch('[a-f0-9]{40}', source)
root=Path('/home/hami/phorvex-benchmark'); data=root/'stage-data'
old_release=root/'releases/stage-selfserve-a5d8d6121ed7'
release=root/'releases'/('stage-selfserve-'+source[:12])
units=Path.home()/'.config/systemd/user'
out=data/'deployment'/('selfserve-'+source[:12])
assert not out.exists(), 'retain every prior attempt'
os.umask(0o077);out.mkdir(parents=True,mode=0o700)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
def run(args, **kwargs):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=kwargs.pop('timeout',40),**kwargs)
def system(*args):return run(['systemctl','--user',*args],timeout=120)
def show(name):
    raw=system('show',name,'--property=MainPID,ActiveState,SubState,WorkingDirectory,UnitFileState,NRestarts').stdout
    return dict(x.split('=',1) for x in raw.splitlines() if '=' in x)
def save():
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
expected_units={
 'phorvex-stage-reconcile.service':'e721d297aa35b2b908ab25e705022792c4b26d386cd3c66b9254110aad55ab7d',
 'phorvex-stage-reconcile.timer':'61a408ab2e4a0a1827bc55dfd8a0ea54754a249afad2e7e36f65843c430074c1',
 'phorvex-stage-endpoint-refresh.timer':'f128a13ebf3160841a2a937194c2c4228760ec8774f9b1cd594bf0be0e3f9ab2',
 'phorvex-benchmark-bot.service':'9ed310744fb7bc2a36157d5e24d9cdaf7d3e8da49b3d2f575eeb76bb327522e5',
 'phorvex-stage-observer.service':'ca6bad303577f7b4aa9f7c06142631e1343eff8cd84be2164ce940d8cd1f0019',
 'phorvex-stage-endpoint-refresh.service':'2280075784ec49acc49a8bb98c4b298285863361eb36541b27fa281b11a09ddd'}
for name,value in expected_units.items():assert digest(units/name)==value,'concurrent owned unit change'
assert digest(release/'reviewed-source-manifest.json')==manifest_sha
manifest=json.loads((release/'reviewed-source-manifest.json').read_text())
for item in manifest['paths']:assert digest(release/item['path'])==item['sha256'],item['path']
assert json.loads((release/'release-origin.json').read_text())['commit']==source
assert shutil.disk_usage(root).free >= (4<<30)+(512<<20)
sys.path[:0]=[str(release/'benchmark/worker'),str(release)]
from stage_reconcile import observe,same_observation
from mathlab import stage_scope
pin=stage_scope.load(data,stage_scope.ALLOWED_POLICIES[0],root/'operator-refactored')
assert pin['brain']['git_sha']=='bee9caccf3bae388d412e72adfe50ca9de41a486'
stage_scope.native_study_engine(data,pin)
observed=observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+120)
assert same_observation(pin,observed),'actual stage differs from verified pin'
assert observed['brain']['image_digest']=='sha256:3200cb0e57130468ebdf73ba22b02d4e531d2cf25fe92cc7fb895672659aa2bf'
assert observed['manager']['image_digest']=='sha256:b1ac09d66a0651360252806b8f39925c45a677f63c320d9a5773ec7935163044'
for policy,uid,mode in [('demo-api-defense','6485e0b3-0f36-4737-b0f5-7e846375da9f','active'),('stage-bench-defense','621c056d-ae10-452c-8828-b2dd0bbb5cb3','dryRun')]:
    item=observed['policies']['phorvex-staging-demo/'+policy]
    assert item['uid']==uid and item['mode']==mode
protected=[root/'config/bot.env',root/'bot/owner.json',root/'bot/members.json',data/'mathlab/bin/current.json',root/'operator-refactored/.git/config']
assert (root/'operator-refactored/.git/config').is_file()
before_hashes={str(p):digest(p) for p in protected}
checkout=run(['git','-C',str(root/'operator-refactored'),'rev-parse','HEAD']).stdout.strip()
current_link=str((root/'current').resolve())
others=['phorvex-benchmark-'+x+'.service' for x in ('api','proxy','web')]
other_before={name:show(name) for name in others}
bot='phorvex-benchmark-bot.service';observer='phorvex-stage-observer.service'
timers=['phorvex-stage-reconcile.timer','phorvex-stage-endpoint-refresh.timer']
active=[bot,observer]+timers
before_units={name:show(name) for name in expected_units}
assert all(before_units[name]['ActiveState']=='active' for name in active)
assert before_units[bot]['WorkingDirectory']==str(old_release/'benchmark/bot')
def idle():
    raw=run(['journalctl','--user','-u',bot,'--since','2026-11-01 00:00:00','-o','cat','--no-pager']).stdout
    queued=set(re.findall(r'queued \w+ job ([a-f0-9]{12}) from',raw))
    history=[json.loads(x) for x in (root/'bot/history.jsonl').read_text().splitlines() if x.strip()]
    assert not queued-{x['id'] for x in history},'accepted bot work is pending'
    return {'pending':0,'terminal_records':len(history)}
receipt={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':source,'manifest_sha256':manifest_sha,'state':'PREPARED',
 'stage_before':observed,'units_before':before_units,'protected_before':before_hashes,'unrelated_before':other_before,
 'checkout_before':checkout,'current_link_before':current_link,'idle_before':idle(),
 'observer_continuity':'Owned observer restart closes the old segment. All journals retained; qualify fresh continuous history after restart.'}
backup=out/'unit-backups';backup.mkdir(mode=0o700)
for name in expected_units:shutil.copy2(units/name,backup/name)
shutil.copy2(data/'mathlab/stage.json',out/'stage-pin-before.json')
if (data/'mathlab/observer-current.json').exists():shutil.copy2(data/'mathlab/observer-current.json',out/'observer-before.json')
proposed=out/'proposed-units';proposed.mkdir(mode=0o700)
text=(units/bot).read_text();oldwd='WorkingDirectory='+str(old_release/'benchmark/bot')
assert text.count(oldwd)==1
(proposed/bot).write_text(text.replace(oldwd,'WorkingDirectory='+str(release/'benchmark/bot')))
for template in (release/'benchmark/worker/deploy').glob('*.example'):
    name=template.name.removesuffix('.example');assert name in expected_units
    (proposed/name).write_text(template.read_text().replace('REVIEWED_SOURCE',release.name))
assert {p.name for p in proposed.iterdir()}==set(expected_units)
receipt['proposed_unit_hashes']={p.name:digest(p) for p in proposed.iterdir()};save()
stopped=[];mutated=False
try:
    for name in timers:stopped.append(name);system('stop',name)
    deadline=time.monotonic()+950
    while any(show(name)['ActiveState'] in ('active','activating','deactivating') for name in ['phorvex-stage-reconcile.service','phorvex-stage-endpoint-refresh.service']):
        assert time.monotonic()<deadline,'existing maintenance exceeded bounded wait'
        time.sleep(5)
    assert same_observation(observed,observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+120))
    receipt['idle_before_stop']=idle();save()
    stopped.append(bot);system('stop',bot);receipt['idle_after_stop']=idle()
    stopped.append(observer);system('stop',observer)
    receipt['observer_stopped_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
    for name,value in expected_units.items():assert digest(units/name)==value,'concurrent unit modification before installation'
    mutated=True
    for p in proposed.iterdir():shutil.copy2(p,units/p.name)
    system('daemon-reload')
    for name in [observer,bot]+timers:system('start',name)
    receipt['units_after']={name:show(name) for name in expected_units}
    assert all(receipt['units_after'][name]['ActiveState']=='active' for name in active)
    assert receipt['units_after'][bot]['WorkingDirectory']==str(release/'benchmark/bot')
    assert receipt['units_after'][observer]['WorkingDirectory']==str(release)
    assert same_observation(observed,observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+120))
    receipt['protected_after']={str(p):digest(p) for p in protected};assert receipt['protected_after']==before_hashes
    assert str((root/'current').resolve())==current_link
    assert run(['git','-C',str(root/'operator-refactored'),'rev-parse','HEAD']).stdout.strip()==checkout
    assert {name:show(name) for name in others}==other_before
    receipt['state']='INSTALLED_PENDING_LIVE_ACCEPTANCE'
except BaseException as exc:
    receipt.update(state='INSTALLATION_ERROR',error_type=type(exc).__name__,error=str(exc))
    recovery_errors=[]
    def recover_system(action,name=None):
        args=['systemctl','--user',action]+([name] if name else [])
        try:
            result=subprocess.run(args,capture_output=True,timeout=120)
            if result.returncode:recovery_errors.append({'action':action,'unit':name,'exit_code':result.returncode})
        except (OSError,subprocess.SubprocessError) as failure:
            recovery_errors.append({'action':action,'unit':name,'error_type':type(failure).__name__})
    if mutated:
        for name in active+['phorvex-stage-reconcile.service','phorvex-stage-endpoint-refresh.service']:recover_system('stop',name)
        for name in expected_units:
            try:shutil.copy2(backup/name,units/name)
            except OSError as failure:recovery_errors.append({'action':'restore-unit-file','unit':name,'error_type':type(failure).__name__})
        recover_system('daemon-reload')
    for name in active if mutated else stopped:
        recover_system('start',name)
        try:
            if show(name)['ActiveState']!='active':recovery_errors.append({'action':'verify-active','unit':name})
        except (OSError,subprocess.SubprocessError) as failure:
            recovery_errors.append({'action':'verify-active','unit':name,'error_type':type(failure).__name__})
    receipt['recovery_errors']=recovery_errors
    if recovery_errors:
        receipt['state']='RESTORATION_FAILED'
        receipt['recovery']='Restoration attempted for owned units; explicit failures remain. Do not claim restored runtime.'
    else:
        receipt['recovery']='Previous owned units restored; all pin/history evidence retained. No current readiness claim.'
    raise
finally:
    receipt['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
    print(json.dumps({'state':receipt['state'],'receipt':str(out/'receipt.json'),'sha256':digest(out/'receipt.json')}),flush=True)
