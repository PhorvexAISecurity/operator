import ast,hashlib,json,pathlib,subprocess,sys,tempfile,textwrap,types
root=pathlib.Path('/workspace/operator-benchmark-selfserve');sys.path[:0]=[str(root/'benchmark/bot'),str(root/'benchmark/worker')]
import service,testkit,code_experiment
from mathlab import stage_scope
src=subprocess.check_output(['git','show','6ae89857369468d4ca39a6856d9fd55c3b5debd3:benchmark/bot/service.py'],cwd=root,text=True)
node=next(x for cls in ast.parse(src).body if isinstance(cls,ast.ClassDef) and cls.name=='BenchBot' for x in cls.body if isinstance(x,ast.FunctionDef) and x.name=='recorded_window')
method=textwrap.dedent(ast.get_source_segment(src,node));namespace={'Path':pathlib.Path,'json':json,'JobError':service.JobError,'code_experiment':code_experiment};exec(compile(method,'actual-6ae-recorded-window','exec'),namespace)
r={'schema':'phorvex-bench.legacy-pointer-counterexample.v1','scope':'Actual unchanged pre-repair recorded_window method against the new atomic pin contract. Real PXMS-format headers and identity file checks; fake binary only supplies identity fixture, no kernel execution or empirical stage claim.','method_source':'6ae89857369468d4ca39a6856d9fd55c3b5debd3:benchmark/bot/service.py:BenchBot.recorded_window','method_sha256':hashlib.sha256(method.encode()).hexdigest(),'cases':[]}
with tempfile.TemporaryDirectory(prefix='legacy-pointer-',dir='/workspace/.phorvex-test-tmp') as td:
 data=pathlib.Path(td);sha='b'*40;policy='phorvex-staging-demo/demo-api-defense'
 pin=testkit.write_stage_pin(data,sha);pin['identity_binding']='stage-pin.replay.v1';pin['policies'][policy]['generation']=9
 (data/'mathlab/stage.json').write_text(json.dumps(pin));binary=testkit.write_fake_replay(data/'mathlab/bin/legacy-replay','a'*40,3)
 for i in range(6):testkit.make_snapshot(data/'mathlab/snapshots'/policy,sha,3,False,'2026-11-01T18:00:%02dZ'%i,policy_generation=9)
 bot=types.SimpleNamespace(cfg=types.SimpleNamespace(data=str(data)))
 current=data/'mathlab/bin/current.json'
 for name in ['matching-legacy-positive','stale-legacy-negative','missing-legacy-negative']:
  if name.startswith('matching'):current.write_text(json.dumps(pin['replay']))
  elif name.startswith('stale'):current.write_text(json.dumps({**pin['replay'],'git_sha':'a'*40,'path':str(binary)}))
  else:current.unlink()
  actual=stage_scope.identity(data,stage_scope.load(data,policy));assert actual['git_sha']==sha
  row={'case':name,'atomic_pin_identity_valid':True,'atomic_pin_source':actual['git_sha']}
  try:row.update(result='RETURNED',window=namespace['recorded_window'](bot,policy))
  except Exception as e:row.update(result='ERROR',error_type=type(e).__name__,message=str(e))
  r['cases'].append(row)
assert r['cases'][0]['result']=='RETURNED' and r['cases'][0]['window']['git_sha']=='b'*40
assert all(x['result']=='ERROR' and x['atomic_pin_identity_valid'] for x in r['cases'][1:])
r['verdict']='RED_REPRODUCED_WITH_POSITIVE_CONTROL'
print(json.dumps(r,indent=2))
