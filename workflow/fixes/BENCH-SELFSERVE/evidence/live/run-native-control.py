from pathlib import Path
import datetime,hashlib,json,shutil,sys,time
root=Path('/home/hami/phorvex-benchmark');release=root/'releases/stage-bot-3e11f4e7'
sys.path.insert(0,str(release/'benchmark/worker'))
from runner import Console
from mathlab import binary,snapshots
from mathlab.common import sha256_file
import stage_cli
from endpoint_refresh import run_replay,json_lines,exact_baseline
ctx='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
out=root/'stage-data/live/selfserve-native-control';out.mkdir(parents=True,exist_ok=True)
assert not (out/'receipt.json').exists(), 'new control must not overwrite existing result'
assert shutil.disk_usage(root).free>4.5*1024**3
brain=stage_cli.running_image(ctx,'phorvex-staging','staging-brain','brain')
assert brain['git_sha']=='61e83673b8d4f143fca67e17b8a54dc4712f9b28'
assert brain['digest']=='sha256:ebb6d245afc52528155eee999e130972c1aa78f14f03a19b86118508acefd1bf'
ident=binary.ensure_binary(out,brain)
assert ident['binary_sha256']=='739b43a24c79ee7599ea02aab84ade4e23081d1881dd9db225d0e4c8ea192f86'
assert ident['git_sha']==brain['git_sha']
version=json.loads(binary.run_isolated([ident['path'],'-version'],timeout=30))
assert version['endpointStudyMode']=='PAIRED_BRAIN_REPLAY' and version['studyCandidatesSchema']=='math-lab.study-candidates.v1'
r={'schema':'phorvex-bench.independent-native-replay.v1','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'state':'RUNNING','authority':'lead executed actual image-native replay over isolated downloaded current-source cohort; not a bot submission','brain':brain,'binary':ident,'actual_version':version,'policies':{}}
def save():
 (out/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
save()
c=Console(kube_context=ctx,namespace='phorvex-staging',service='staging-phorvex-console',token_service_account='staging-brain-benchmark',service_port=80,use_environment=False,token_audience='phorvex-staging-console',token_duration='10m')
try:
 for name,uid,generation in [('demo-api-defense','6485e0b3-0f36-4737-b0f5-7e846375da9f',9),('stage-bench-defense','621c056d-ae10-452c-8828-b2dd0bbb5cb3',1)]:
  expected={'gitSHA':brain['git_sha'],'brainImage':brain['image'],'policyUID':uid}
  sync=snapshots.sync(out,'phorvex-staging-demo',name,c,since='2026-11-01T17:59:00Z',limit=256,expected_header=expected,max_bytes=64<<20)
  entries=[e for e in snapshots.local_index(out,'phorvex-staging-demo',name,expected) if e['header'].get('finalized') is True and not e['header'].get('unreplayableFields') and e['header'].get('policyGeneration')==generation][-64:]
  assert len(entries)==64, 'not yet64 exact finalized current-policy ticks'
  work=out/name;work.mkdir(exist_ok=True);frozen=work/'cohort';snapshots.freeze_cohort(out,'phorvex-staging-demo',name,entries,frozen)
  digests=[e['digest'] for e in entries]
  run_replay([ident['path'],'-snapshots',str(frozen),'-out',str(work/'replay.jsonl'),'-summary',str(work/'summary.json')],work,time.monotonic()+300,128<<20)
  rows=json_lines(work/'replay.jsonl');exact_baseline(rows,digests,name)
  r['policies'][name]={'state':'PASS','snapshots':len(entries),'exact_baselines':len(rows),'snapshot_digests':digests,'first_captured_at':entries[0]['header']['capturedAt'],'last_captured_at':entries[-1]['header']['capturedAt'],'downloaded':sync['downloaded'],'sync_rejections':sync['rejected'],'replay_sha256':sha256_file(work/'replay.jsonl'),'summary':json.loads((work/'summary.json').read_text())};save()
  print(json.dumps({'policy':name,'state':'PASS','exact_baselines':len(rows)}),flush=True)
 actual=stage_cli.running_image(ctx,'phorvex-staging','staging-brain','brain')
 assert all(actual.get(k)==brain.get(k) for k in ['git_sha','image','digest','deployment_uid'])
 r['state']='PASS';r['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
except Exception as exc:
 r['state']='FAIL';r['error_type']=type(exc).__name__;r['error']=str(exc);save();raise
finally:c.close()
print(json.dumps({'state':r['state'],'receipt_sha256':sha256_file(out/'receipt.json'),'path':str(out/'receipt.json')}),flush=True)
