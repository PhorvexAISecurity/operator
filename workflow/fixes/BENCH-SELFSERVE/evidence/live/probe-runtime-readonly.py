from pathlib import Path
import datetime,hashlib,json,sys,time
root=Path('/home/hami/phorvex-benchmark');source=root/'releases/selfserve-helper-probe-449fec50'
manifest=source/'probe-source-manifest.json';expected='449fec50b24fc1eeef9686b584e930a8e815245b50a53f048560f84dd7e2cbcb'
assert hashlib.sha256(manifest.read_bytes()).hexdigest()==expected
for row in json.loads(manifest.read_text())['files']:assert hashlib.sha256((source/row['path']).read_bytes()).hexdigest()==row['sha256']
sys.path[:0]=[str(source/'benchmark/worker'),str(source)]
from mathlab import binary,stage_scope
import stage_cli,stage_reconcile
out=root/'stage-data/live/selfserve-runtime-probe-449fec50';out.mkdir(parents=True,exist_ok=True)
def fingerprint(path):return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
protected=[root/'stage-data/mathlab/stage.json',root/'stage-data/mathlab/bin/current.json']
before={str(p):fingerprint(p) for p in protected}
r={'schema':'phorvex-bench.actual-readonly-runtime-probe.v1','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'state':'RUNNING','source_manifest_sha256':expected,'scope':'actual live identities, isolated scratch pin built from actual observe and verified native binary; active pins/services untouched','probes':{}}
def save():(out/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
save()
try:
 t=time.monotonic();observed=stage_reconcile.observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+240)
 r['observe_seconds']=time.monotonic()-t
 assert observed['brain']['git_sha']=='61e83673b8d4f143fca67e17b8a54dc4712f9b28'
 ident=json.loads((root/'stage-data/live/selfserve-native-control-2/receipt.json').read_text())['binary']
 actual=binary.local_identity(ident['path']);assert actual['binary_sha256']==ident['binary_sha256'] and actual['git_sha']==observed['brain']['git_sha']
 ident.update(endpoint_study_mode=actual['endpoint_study_mode'],study_candidates_schema=actual['study_candidates_schema'])
 with stage_scope.pin_lock(out,exclusive=True):stage_cli.publish_pin(out,stage_reconcile.new_pin(observed,ident))
 r['setup']='Actual observe/new_pin in isolated scratch only; this is not an active deployment or synthetic READY fixture.';save()
 for policy in stage_scope.ALLOWED_POLICIES:
  t=time.monotonic();result=stage_cli.probe_runtime(out,root/'operator-refactored',policy,timeout=60)
  r['probes'][policy]={'seconds':time.monotonic()-t,'result':result};save()
  print(json.dumps({'policy':policy,'status':result['status'],'seconds':r['probes'][policy]['seconds'],'reason_codes':[x['code'] for x in result['reasons']]}),flush=True)
 after={str(p):fingerprint(p) for p in protected};assert after==before
 r['active_pin_hashes_unchanged']=after
 r['state']='PASS' if all(x['result']['status']=='READY' for x in r['probes'].values()) else 'FAIL';save()
except Exception as exc:r['state']='ERROR';r['error_type']=type(exc).__name__;r['error']=str(exc);save();raise
print(json.dumps({'state':r['state'],'observe_seconds':r['observe_seconds'],'receipt':str(out/'receipt.json'),'sha256':fingerprint(out/'receipt.json')}),flush=True)
