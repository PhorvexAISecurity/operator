"""Independent local producer controls. No live access or product file edits.
Git/Console/Kubernetes test transports are explicit; no product engine claim.
"""
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs,urlsplit
from datetime import datetime,timezone
import tempfile,time,json,struct,hashlib,io,subprocess,os
from benchmark.worker.test_stage_reconcile import Producer
from test_request_readiness import EndpointHistoryReadinessTests
from mathlab import binary,snapshots,stage_scope
import stage_cli,stage_reconcile as reconcile

OUT=Path('workflow/fixes/BENCH-SELFSERVE/evidence/peer-review/runtime-final')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def tree(p):return {str(f.relative_to(p)):digest(f) for f in p.rglob('*') if f.is_file()}
def git(p,*args,env=None):
 return subprocess.run(['git','-C',str(p),*args],capture_output=True,env=env,text=True,check=True).stdout.strip()
def hydration():
 root=Path(tempfile.mkdtemp(prefix='peer-source-hydrated-',dir='/workspace/.phorvex-test-tmp'));source=root/'remote';source.mkdir()
 for args in [('init','-q'),('config','user.name','Peer control'),('config','user.email','peer@example.invalid'),('config','uploadpack.allowFilter','true'),('config','uploadpack.allowAnySHA1InWant','true')]:git(source,*args)
 (source/'phorvex').mkdir();(source/'phorvex/main.go').write_text('package main\nfunc main() {}\n');git(source,'add','.');git(source,'commit','-qm','old exact source');old=git(source,'rev-parse','HEAD')
 partial=root/'partial';subprocess.run(['git','clone','-q','--filter=blob:none','--no-checkout','file://'+str(source),str(partial)],check=True)
 git(partial,'remote','set-url','origin',stage_scope.REPOSITORY)
 for i in range(270):(source/('blob%03d'%i)).write_text('required blob '+str(i))
 git(source,'add','.');git(source,'commit','-qm','new deployed source');sha=git(source,'rev-parse','HEAD');config=(partial/'.git/config').read_bytes();before=tree(partial/'.git')
 try:stage_scope.repository(partial,old,complete_tree=True)
 except stage_scope.StageError:blocked=True
 else:blocked=False
 assert blocked and before==tree(partial/'.git')
 original=subprocess.Popen;fetches=[]
 def transport(args,**kwargs):
  args=list(args)
  if 'fetch' in args:
   assert 'origin' in args;fetches.append(list(args));args[args.index('fetch'):args.index('fetch')]=['-c','url.file://'+str(source)+'.insteadOf='+stage_scope.REPOSITORY]
  return original(args,**kwargs)
 with mock.patch.object(reconcile.subprocess,'Popen',side_effect=transport):result=reconcile.ensure_source(partial,sha,time.monotonic()+30)
 assert result['fetched'] and git(partial,'rev-parse','HEAD')==old and (partial/'.git/config').read_bytes()==config
 assert not (partial/'.git/FETCH_HEAD').exists()
 stable=tree(partial/'.git');stage_scope.repository(partial,sha,complete_tree=True)
 actual=subprocess.run(['git','-C',str(partial),'archive','--format=tar',sha],capture_output=True,env=stage_scope.observation_git_env(),check=True).stdout
 expected=subprocess.run(['git','-C',str(source),'archive','--format=tar',sha],capture_output=True,check=True).stdout
 assert actual==expected and stable==tree(partial/'.git')
 return {'producer':'Real partial Git clone and explicit local transport substitution only for authorized fetch. No network.','initial_complete_tree_readonly_refused':blocked,'explicit_fetches':len(fetches),'result':result,'offline_archive_sha256':hashlib.sha256(actual).hexdigest(),'offline_archive_equal':True,'readonly_git_unchanged':True,'head_config_and_fetch_head_preserved':True}
def cold():
 root=Path(tempfile.mkdtemp(prefix='peer-cold-fixed-',dir='/workspace/.phorvex-test-tmp'));p=Producer(root);p.raw={};now=time.time();queries=[]
 latest={}
 for policy in stage_scope.ALLOWED_POLICIES:
  ns,name=policy.split('/');last=[]
  for index in range(470):
   epoch=now-6000+index*5 if index<400 else now-350+(index-400)*5
   at=datetime.fromtimestamp(epoch,timezone.utc).isoformat().replace('+00:00','Z');header={'schema':'math-lab.snapshot.v1','capturedAt':at,'decidedAt':at,'gitSHA':p.source,'namespace':ns,'policyName':name,'policyUID':p.policies[name]['metadata']['uid'],'policyGeneration':1,'brainImage':p.image('brain'),'captureIdentitySource':'recorder-process','finalized':True}
   h=json.dumps(header).encode();raw=snapshots.MAGIC+struct.pack('>I',len(h))+h+json.dumps({'risk':4,'recorded_selected':True}).encode();d=hashlib.sha256(raw).hexdigest();p.raw[d]=raw;last.append(d)
  latest[policy]=last[-64:]
 def console(**kwargs):
  class C:
   def request(self,path):
    q=parse_qs(urlsplit(path).query);lo=snapshots._clock(q.get('since',[None])[0]);hi=snapshots._clock(q.get('until',[None])[0]);name=q['policy'][0];limit=int(q['limit'][0]);rows=[{'digest':d,'header':snapshots.read_header(raw)} for d,raw in p.raw.items() if snapshots.read_header(raw)['policyName']==name];rows.sort(key=lambda r:(r['header']['capturedAt'],r['digest']));rows=[r for r in rows if (lo is None or snapshots._clock(r['header']['capturedAt'])>=lo) and (hi is None or snapshots._clock(r['header']['capturedAt'])<hi)];queries.append(q);return {'entries':rows[:limit]}
   def open(self,path,**kwargs):return io.BytesIO(p.raw[parse_qs(urlsplit(path).query)['digest'][0]])
   def close(self):pass
  return C()
 with mock.patch.object(stage_cli,'kube',side_effect=p.kube),mock.patch.object(binary,'ensure_binary',side_effect=p.ensure),mock.patch('runner.Console',side_effect=console):
  result=reconcile.reconcile(p.data,p.repo,ticks=64,timeout=30)
  assert result['status']=='READY',result
  pin=stage_scope.load(p.data)
  for policy in stage_scope.ALLOWED_POLICIES:assert [e['digest'] for e in reconcile.selected_entries(p.data,pin,policy,64)]==latest[policy]
 return {'producer':'Actual470 final hash-addressed PXMS per policy and actual sync/reconcile/native receipt plumbing; Kubernetes/Console/image extraction scripted boundaries and executable fixture are not product engine proof.','status':result['status'],'requested_ticks':64,'per_policy':{'old':400,'fresh':70},'both_selected_actual_latest64':True,'queries':len(queries),'all_queries_upper_bounded':all('until' in q for q in queries),'source':p.source,'pin_sha256':digest(p.data/'mathlab/stage.json')}
def service():
 case=EndpointHistoryReadinessTests('test_real_history_qualifies_but_missing_engine_still_refuses_ready');case.setUp()
 try:
  meta=json.loads(case.pointer.read_text());scope=meta['normalization']['scope'];positive=dict(case.actual,service_uid=scope['service_uid']);codes={}
  for label,actual in [('matching',positive),('recreated',dict(positive,service_uid='recreated')),('missing',{k:v for k,v in positive.items() if k!='service_uid'})]:codes[label]=[r['code'] for r in case.inspect(actual=actual)['reasons']]
  assert 'ENDPOINT_SERVICE_UNVERIFIED' not in codes['matching']
  assert all('ENDPOINT_SERVICE_UNVERIFIED' in codes[k] for k in ('recreated','missing'))
  assert all('ENDPOINT_ENGINE_UNAVAILABLE' in c for c in codes.values())
  return {'producer':'Real Journal/reducer/normalizer. Current Service supplied at observation boundary. Unrelated missing-engine refusal remains; no mock PASS.','codes':codes,'immutable_manifest_unchanged':case.pointer.read_text()==case.original}
 finally:case.doCleanups()
record={'schema':'phorvex-bench.independent-four-repair-controls.v1','reviewer':'stage-review','hydration':hydration(),'cold_backlog':cold(),'service_uid':service(),'source_hashes':{n:digest(Path(n)) for n in ('benchmark/worker/stage_reconcile.py','benchmark/worker/stage_cli.py','benchmark/worker/mathlab/stage_scope.py','benchmark/worker/mathlab/snapshots.py','benchmark/worker/mathlab/recent_snapshots.py','benchmark/bot/request_readiness.py')}}
(OUT/'four-repairs-producer-results.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
