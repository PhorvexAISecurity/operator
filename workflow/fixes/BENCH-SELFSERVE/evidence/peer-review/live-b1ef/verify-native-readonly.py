import datetime,hashlib,json,os,pathlib,sys,time
sys.dont_write_bytecode=True
root=pathlib.Path('/home/hami/phorvex-benchmark');release=root/'releases/stage-selfserve-225877a8ecb4';data=root/'stage-data';source='b1ef9ccdb258f0a94b0dad575a17cc3a4c25cab0';image='sha256:d208a9a53acd16cc146dce4c72b26d7614620862f2e1cecc1f526259033a1903';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sys.path[:0]=[str(release/'benchmark/worker'),str(release)]
from mathlab import stage_scope,snapshots
from stage_reconcile import observe,same_observation
manifest=json.loads((release/'reviewed-source-manifest.json').read_text())
for item in manifest['paths']:
 if item['path'] in ['benchmark/worker/mathlab/stage_scope.py','benchmark/worker/mathlab/binary.py','benchmark/worker/mathlab/snapshots.py','benchmark/worker/stage_reconcile.py','benchmark/worker/stage_cli.py']:assert sha(release/item['path'])==item['sha256']
status_path=data/'mathlab/reconcile-status.json';status=json.loads(status_path.read_text());assert status['status']=='READY',status.get('reasons');assert status['phase']=='COMPLETE'
with stage_scope.pin_lock(data,readonly=True,timeout=10) as held:
 assert held
 pin_path=data/'mathlab/stage.json';pin_sha=sha(pin_path);pin=json.loads(pin_path.read_text());assert pin['brain']['git_sha']==pin['manager']['git_sha']==source and pin['brain']['image_digest']==image
 assert pin['study_engine_lane']=='native-stage-image';engine=stage_scope.native_study_engine(data,pin,timeout=10);assert engine['source_revision']==engine['base_source']==source
 binary=pathlib.Path(pin['replay']['path']);assert sha(binary)==pin['replay']['binary_sha256']==pin['native_study']['binary_sha256']
 observed=observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+60);assert same_observation(pin,observed),'actual live scope differs from installed native pin'
 baselines=[]
 for ref in pin['native_study']['baseline_evidence']:
  path=pathlib.Path(ref['path']);assert sha(path)==ref['sha256'];receipt=json.loads(path.read_text());digests=receipt['snapshot_digests'];assert len(digests)==len(set(digests))==len(receipt['rows'])==64;assert receipt['source_revision']==source and receipt['image_digest']==image and receipt['binary_sha256']==sha(binary);assert receipt['policy_uid']==pin['policies'][receipt['policy']]['uid']
  rows=[];headers=[]
  for row in receipt['rows']:
   digest=row['snapshot']['snapshot_digest'];assert digest in digests and row['status']=='OK' and row['baseline_check']['reproduced'] is True;raw=pathlib.Path(receipt['cohort_path'])/(digest+'.pxms');assert sha(raw)==digest;header=snapshots.read_header(raw);assert all(header.get(k)==v for k,v in stage_scope.snapshot_header(pin,receipt['policy']).items());assert header.get('finalized') is True
   rows.append({'snapshot_digest':digest,'status':row['status'],'baseline_check':row['baseline_check'],'full_row_canonical_sha256':hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()});headers.append({'snapshot_digest':digest,'header_canonical_sha256':hashlib.sha256(json.dumps(header,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'captured_at':header.get('captured_at'),'decided_at':header.get('decided_at'),'policy_uid':header.get('policy_uid'),'git_sha':header.get('git_sha'),'finalized':header.get('finalized')})
  baselines.append({'policy':receipt['policy'],'policy_uid':receipt['policy_uid'],'path':ref['path'],'sha256':ref['sha256'],'cohort_path':receipt['cohort_path'],'ticks':len(digests),'distinct_snapshot_digests':digests,'rows':rows,'headers':headers})
 assert {b['policy'] for b in baselines}==set(stage_scope.ALLOWED_POLICIES);assert sha(pin_path)==pin_sha
 print(json.dumps({'verdict':'PASS_CURRENT_NATIVE_BASELINES_64_EACH','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'runtime_source':'225877a8ecb4c11eb39980ba932c114f7a8068a4','capture_source':source,'capture_image_digest':image,'pin_sha256':pin_sha,'reconciliation_status_sha256':sha(status_path),'reconciliation_started_at':status.get('started_at'),'reconciliation_finished_at':status.get('finished_at'),'reconciliation_baseline_ticks':status.get('baseline_ticks'),'native_binary_path':str(binary),'native_binary_sha256':sha(binary),'engine_classification':engine['classification'],'actual_stage_observation':observed,'baseline_evidence':baselines,'limits':['Read-only source/identity/liveKube observation and all128 retainedrawhash/header/actualreplayrow validation; no newreconciliation orbenchmark dispatched.','This proves exactnativebaseline fidelity,not endpointobservedhistory, securityefficacy, original10dayresult,or terminalbotacceptance.','Actualsource rechecked duringthisread; later release/scope changes invalidatecurrentreadiness.']},indent=2))
