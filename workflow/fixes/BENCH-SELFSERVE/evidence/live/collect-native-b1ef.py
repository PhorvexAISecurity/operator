import pathlib,json,hashlib,datetime
r=pathlib.Path('/home/hami/phorvex-benchmark/stage-data/mathlab');p=r/'stage.json';pin=json.loads(p.read_text());rec=json.loads((r/'reconcile-status.json').read_text());src='b1ef9ccdb258f0a94b0dad575a17cc3a4c25cab0'
assert rec['status']=='READY' and pin['brain']['git_sha']==pin['manager']['git_sha']==src
assert pin['native_study']['source_revision']==src and pin['replay']['git_sha']==src
assert hashlib.sha256(pathlib.Path(pin['replay']['path']).read_bytes()).hexdigest()==pin['replay']['binary_sha256']==pin['native_study']['binary_sha256']
policies={'phorvex-staging-demo/demo-api-defense','phorvex-staging-demo/stage-bench-defense'};baselines=[]
for entry in pin['native_study']['baseline_evidence']:
 f=pathlib.Path(entry['path']);assert hashlib.sha256(f.read_bytes()).hexdigest()==entry['sha256'];d=json.loads(f.read_text())
 assert d['source_revision']==src and d['image_digest']==pin['brain']['image_digest']
 assert d['binary_sha256']==pin['replay']['binary_sha256'] and d['policy_uid']==pin['policies'][d['policy']]['uid']
 assert len(d['rows'])==len(d['snapshot_digests'])==len(set(d['snapshot_digests']))==64
 assert all(x['status']=='OK' and x['baseline_check']['reproduced'] is True and x['replay_git_sha']==src for x in d['rows'])
 baselines.append({'path':str(f),'sha256':entry['sha256'],'policy':d['policy'],'ticks':len(d['rows']),'binary_sha256':d['binary_sha256'],'snapshot_digests':d['snapshot_digests']})
assert {x['policy'] for x in baselines}==policies
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'result':'PASS_NATIVE_BASELINES_NOT_BOT_ACCEPTANCE','stage_pin':pin,'reconciliation':rec,'baselines':baselines,'stage_pin_sha256':hashlib.sha256(p.read_bytes()).hexdigest()},indent=2))
