import copy,datetime,hashlib,io,json,os,pathlib,subprocess,tarfile,tempfile
import yaml
R=pathlib.Path('/workspace/operator-benchmark-selfserve');E=R/'workflow/fixes/BENCH-SELFSERVE/evidence';O=E/'peer-review/upstream-565';BASE='565c3ea44387d45641d36a4ace9615de62f59fa9';PRIOR='0288e00ffe51c2a23f30742b4f6dcd2b8a733d65'
sha=lambda b:hashlib.sha256(b).hexdigest();git=lambda *a:subprocess.check_output(['git',*a],cwd=R)
m=E/'upstream-565/composition-inputs.json';assert sha(m.read_bytes())=='7ba803782e93e15487bb5217efd2eb84f395d760b498ab12eacba5363180de8b'
man=json.loads(m.read_bytes());paths=man['component_paths'];assert len(paths)==10
assert git('diff','--cached','--name-only').decode().splitlines()==sorted(x['path'] for x in paths)
for p in paths:
 assert sha((R/p['path']).read_bytes())==p['sha256'];assert sha(git('show',':'+p['path']))==p['sha256']
rt=json.loads((E/'final-source/integrated-source-inputs-v3.json').read_bytes());print('runtime manifest keys',list(rt))
# The final runtime receipt contains exactly the author-reviewed 43 independent paths.
rows=next(v for v in rt.values() if isinstance(v,list) and len(v)==43 and isinstance(v[0],dict) and 'path' in v[0])
for p in rows:assert sha((R/p['path']).read_bytes())==p['sha256']==sha(git('show',PRIOR+':'+p['path']))
for p in paths:
 name=p['path']
 if name in ['deploy/environments/staging/actuator.yaml','deploy/environments/staging/attacks.yaml','deploy/environments/staging/catalogue-family.yaml','deploy/environments/staging/sensor.yaml','release/staging-batch.json']:assert (R/name).read_bytes()==git('show',BASE+':'+name)
 if name in ['deploy/environments/staging/brain.yaml','deploy/environments/staging/manager.yaml','deploy/environments/staging/console.yaml']:
  new=yaml.safe_load((R/name).read_bytes());prior=yaml.safe_load(git('show',PRIOR+':'+name));up=yaml.safe_load(git('show',BASE+':'+name))
  if name.endswith('/brain.yaml'):
   assert new['phorvex']==prior['phorvex'];assert new['mathLabStore']==prior['mathLabStore'];new.pop('phorvex');new.pop('mathLabStore')
  elif name.endswith('/manager.yaml'):
   assert new['phorvex']['mathLab']==prior['phorvex']['mathLab'];new['phorvex'].pop('mathLab')
  else:
   assert new['phorvex']['console']['auth']==prior['phorvex']['console']['auth'];new['phorvex']['console'].pop('auth')
  assert new==up,name
values='phorvex/charts/phorvex/values.yaml';before=git('show',PRIOR+':'+values);after=(R/values).read_bytes();assert after==before.replace(b'        profile: ""\n        cleanupPolicy: Delete',b'        profile: ""\n        namespaceUID: ""\n        cleanupPolicy: Delete')
archive='deploy/helm/phorvex-stack/charts/phorvex-0.1.4.tgz'
def members(raw):
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:return {x.name:t.extractfile(x).read() for x in t if x.isfile()}
a=members(git('show',PRIOR+':'+archive));b=members((R/archive).read_bytes());assert a.keys()==b.keys() and len(b)==76
changed=[k for k in a if a[k]!=b[k]];assert changed==['phorvex/values.yaml'];assert yaml.safe_load(b['phorvex/values.yaml'])==yaml.safe_load(after)
old=yaml.safe_load(a['phorvex/values.yaml']);new=yaml.safe_load(b['phorvex/values.yaml']);assert new['phorvex']['console']['attackCatalog']['familyFixtures'].pop('namespaceUID')=='';assert new==old
names=['test_service_charts.AttacksServiceTests.test_its_defaults_are_the_managers','test_service_charts.ConsoleChartTests.test_its_defaults_are_the_managers','test_service_charts.SensorChartTests.test_its_defaults_are_the_managers']
command=['/workspace/.phorvex-tools/python312/python/bin/python3.12','-m','unittest',*names,'-v'];env=dict(os.environ,PATH='/workspace/.phorvex-tools:'+os.environ['PATH'],PYTHONDONTWRITEBYTECODE='1')
inputs=['tools/test_service_charts.py','phorvex/charts/phorvex/values.yaml',*[f'deploy/charts/phorvex-{c}/values.yaml' for c in ['attacks','console','sensor']]]
with tempfile.TemporaryDirectory(dir='/workspace/.phorvex-test-tmp',prefix='565-parity-peer-') as tmp:
 root=pathlib.Path(tmp)
 for f in inputs:(root/f).parent.mkdir(parents=True,exist_ok=True);(root/f).write_bytes(git('show',BASE+':'+f))
 red=subprocess.run(command,cwd=root/'tools',env=env,capture_output=True,text=True);(O/'baseline-565-tests.txt').write_text(red.stdout+red.stderr)
 assert red.returncode==1 and 'FAILED (failures=2)' in red.stderr and '(test_service_charts.SensorChartTests.test_its_defaults_are_the_managers) ... ok' in red.stderr and 'skipped' not in red.stderr
 green=subprocess.run(command,cwd=R/'tools',env=env,capture_output=True,text=True);(O/'current-default-tests.txt').write_text(green.stdout+green.stderr)
 assert green.returncode==0 and 'Ran 3 tests' in green.stderr and 'skipped' not in green.stderr
report={'schema':'phorvex-bench.independent-composition.v1','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'reviewer':'stage-review','upstream':BASE,'previous_head':PRIOR,'manifest_sha256':sha(m.read_bytes()),'staged_and_working_paths_verified':10,'runtime_unchanged_paths':43,'upstream_exact_paths':5,'capture_settings_unchanged_paths':3,'namespace_default_delta':'Exactly one empty namespaceUID default, no test changes.','archive':{'sha256':sha((R/archive).read_bytes()),'members':76,'changed_vs_0288':changed,'other_75_members_byte_identical':True},'actual_565_baseline':{'tests':3,'expected_failures':2,'positive_controls':1,'exit_code':red.returncode},'current_same_three_tests':{'tests':3,'failures':0,'skips':0,'exit_code':green.returncode},'verdict':'PASS'}
(O/'independent-composition.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
