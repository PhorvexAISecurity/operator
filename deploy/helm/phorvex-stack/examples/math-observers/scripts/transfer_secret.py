#!/usr/bin/env python3
"""UID-pinned Secret transfer. Prints metadata and digests only; never Secret data."""
import argparse, base64, datetime, hashlib, json, os, pathlib, re, subprocess, sys
SCHEMA='phorvex.secure-secret-transfer.v1'; MARKER='m106-v5'; MAX_TTL=datetime.timedelta(hours=22)
def die(msg): raise ValueError(msg)
def parse_time(v):
 try:return datetime.datetime.fromisoformat(v.replace('Z','+00:00')).astimezone(datetime.timezone.utc)
 except Exception:die('time is not RFC3339')
def kubectl(binary,args,input_bytes=None):
 try:p=subprocess.run([binary,'--request-timeout=15s',*args],input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
 except subprocess.TimeoutExpired:die('kubectl command timed out')
 if p.returncode:die('kubectl command failed: '+' '.join(args[:4])+f' (exit {p.returncode})')
 return p.stdout
def get_json(k,args,allow_empty=False):
 raw=kubectl(k,[*args,'-o','json'])
 if allow_empty and not raw.strip():return None
 try:return json.loads(raw)
 except Exception:die('kubectl returned non-JSON')
def digest_data(data):
 out={}
 for key,value in data.items():
  try:decoded=base64.b64decode(value,validate=True)
  except Exception:die(f'invalid base64 for data key {key}')
  out[key]=hashlib.sha256(decoded).hexdigest()
 return out
def check_hex(v):return isinstance(v,str) and re.fullmatch(r'[0-9a-f]{64}',v) is not None
def save(path,result):
 path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_name(path.name+'.tmp')
 tmp.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');os.chmod(tmp,0o600);os.replace(tmp,path)
def check_transfer(k,t,now):
 src=t['source'];dst=t['destination'];expected=t['dataSHA256']
 for side in (src,dst):
  for key in ('namespace','namespaceUID','name'):
   if not side.get(key) or str(side[key]).startswith('REPLACE_WITH_'):die(f'{key} is not pinned')
 if not src.get('uid') or str(src['uid']).startswith('REPLACE_WITH_'):die('source Secret UID is not pinned')
 if not expected or any(not check_hex(v) for v in expected.values()):die('dataSHA256 is incomplete')
 expiry=parse_time(src['expiresAt'])
 if expiry<=now:die('transfer Secret expired')
 if expiry-now>MAX_TTL:die('transfer Secret TTL exceeds 22 hours')
 if 'certificateNotAfter' in t:
  cert_expiry=parse_time(t['certificateNotAfter'])
  if expiry>cert_expiry or cert_expiry<=now:die('transfer expiry exceeds certificate validity')
 for side in (src,dst):
  ns=get_json(k,['get','namespace',side['namespace']])
  if ns['metadata']['uid']!=side['namespaceUID']:die(f"namespace UID differs for {side['namespace']}")
 secret=get_json(k,['get','secret',src['name'],'-n',src['namespace']]);m=secret['metadata'];ann=m.get('annotations',{});labels=m.get('labels',{})
 if m.get('namespace')!=src['namespace'] or m.get('name')!=src['name'] or m.get('uid')!=src['uid'] or m.get('deletionTimestamp') is not None:die('source Secret identity differs')
 if secret.get('immutable') is not True:die('source Secret is not immutable')
 if labels.get('phorvex.ai/secure-transfer')!=MARKER:die('source transfer marker differs')
 if ann.get('phorvex.ai/expires-at')!=src['expiresAt']:die('source expiry annotation differs')
 if ann.get('phorvex.ai/transfer-destination')!=f"{dst['namespace']}/{dst['name']}":die('source destination annotation differs')
 if secret.get('type','Opaque')!=t['type']:die('source Secret type differs')
 actual=digest_data(secret.get('data',{}))
 if actual!=expected:die('source Secret key set or digest differs')
 return secret,actual,expiry
def ref(obj):return {'namespace':obj['namespace'],'name':obj['name'],'uid':obj['uid'],'generation':obj.get('generation')}
def controller_ref(obj,kind):
 rows=[x for x in obj.get('metadata',{}).get('ownerReferences',[]) if x.get('controller') is True and x.get('kind')==kind]
 if len(rows)!=1:die(f'exact {kind} controller unavailable')
 return rows[0]
def validate_startup_authority(k,pin,source):
 try:cfg=json.loads(base64.b64decode(source['data']['startup.json'],validate=True))
 except Exception:die('startup.json is unavailable or invalid')
 a=pin.get('startupAuthority',{});prep=cfg.get('prepare',{})
 observed={'policy':prep.get('policy'),'workload':prep.get('workload'),'targetName':prep.get('targetName'),'targetUID':prep.get('targetUID'),'targetTerminationGraceSeconds':prep.get('targetTerminationGraceSeconds')}
 expected={key:a.get(key) for key in observed}
 if observed!=expected:die('startup authority differs from public pin')
 workload=a['workload'];scope=hashlib.sha256(json.dumps(workload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 old,replacement=prep.get('old',{}),prep.get('replacement',{})
 if old.get('targetUID')!=a['targetUID'] or old.get('workloadScopeSHA256')!=scope or replacement.get('workloadScopeSHA256')!=scope or replacement.get('targetUID') not in ('',None):die('startup session/workload binding differs')
 if any(not x.get('url','').startswith('https://') or not x.get('sessionID') or not x.get('challenge') for x in (old,replacement)):die('startup session authority incomplete')
 pol=a['policy'];livepol=get_json(k,['get','phorvexpolicy',pol['name'],'-n',pol['namespace']]);pm=livepol['metadata']
 if pm['uid']!=pol['uid'] or pm['generation']!=pol['generation'] or livepol.get('status',{}).get('observedGeneration')!=pol['generation'] or livepol.get('spec',{}).get('mode')!=a.get('policyMode'):die('live policy authority differs')
 pod=get_json(k,['get','pod',a['targetName'],'-n',workload['namespace']]);m=pod['metadata']
 if m['uid']!=a['targetUID'] or m.get('deletionTimestamp') is not None or pod['spec'].get('terminationGracePeriodSeconds')!=a['targetTerminationGraceSeconds'] or any(m.get('labels',{}).get(k)!=v for k,v in a.get('targetLabels',{}).items()):die('live target authority differs')
 if not any(c.get('type')=='Ready' and c.get('status')=='True' for c in pod.get('status',{}).get('conditions',[])):die('live target is not Ready')
 rsref=controller_ref(pod,'ReplicaSet');rs=get_json(k,['get','replicaset',rsref['name'],'-n',workload['namespace']])
 if rs['metadata']['uid']!=rsref['uid']:die('live ReplicaSet authority differs')
 dref=controller_ref(rs,'Deployment');dep=get_json(k,['get','deployment',workload['ownerName'],'-n',workload['namespace']])
 if workload.get('ownerKind')!='Deployment' or dep['metadata']['uid']!=workload['ownerUID'] or dref['uid']!=workload['ownerUID'] or dref['name']!=workload['ownerName']:die('live Deployment authority differs')
 return {'policy':pol,'workload':workload,'targetName':a['targetName'],'targetUID':a['targetUID'],'workloadScopeSHA256':scope}
def destination(k,t):
 d=t['destination'];return get_json(k,['get','secret',d['name'],'-n',d['namespace'],'--ignore-not-found'],allow_empty=True)
def desired(t,source):
 s=t['source'];d=t['destination'];hashes=t['dataSHA256']
 return {'apiVersion':'v1','kind':'Secret','metadata':{'name':d['name'],'namespace':d['namespace'],'labels':{'app.kubernetes.io/part-of':'phorvex-math-verification','phorvex.ai/secure-transfer':MARKER},'annotations':{'phorvex.ai/materialized-from':f"{s['namespace']}/{s['name']}",'phorvex.ai/materialized-from-uid':s['uid'],'phorvex.ai/transfer-expires-at':s['expiresAt'],'phorvex.ai/data-sha256':json.dumps(hashes,sort_keys=True,separators=(',',':'))}},'immutable':True,'type':t['type'],'data':source['data']}
def exact_destination(obj,want):
 return obj is not None and obj.get('immutable') is True and obj.get('type','Opaque')==want['type'] and obj.get('metadata',{}).get('annotations',{})==want['metadata']['annotations'] and obj.get('metadata',{}).get('labels',{})==want['metadata']['labels'] and digest_data(obj.get('data',{}))==digest_data(want['data'])
def execute(mode,pin_path,k,receipt_path):
 now=datetime.datetime.now(datetime.timezone.utc);result={'schema':'phorvex.secure-secret-transfer.receipt.v1','mode':mode,'startedAt':now.isoformat(),'status':'PREFLIGHTING','transfers':[]};save(receipt_path,result)
 checked=[]
 try:
  pin=json.loads(pathlib.Path(pin_path).read_text())
  if pin.get('schema')!=SCHEMA or len(pin.get('transfers',[]))!=2:die('pin schema/count differs')
  for t in pin['transfers']:
   source,hashes,expiry=check_transfer(k,t,now)
   if destination(k,t) is not None:die('destination Secret already exists; refusing all writes')
   checked.append((t,source,hashes,expiry))
   result['transfers'].append({'state':'CHECKED','sourceNamespace':t['source']['namespace'],'sourceName':t['source']['name'],'sourceUID':t['source']['uid'],'destinationNamespace':t['destination']['namespace'],'destinationName':t['destination']['name'],'dataSHA256':hashes,'expiresAt':t['source']['expiresAt']})
  config=next((s for t,s,_,_ in checked if set(t['dataSHA256'])=={'startup.json'}),None)
  if config is None:die('exact startup config transfer unavailable')
  result['startupAuthority']=validate_startup_authority(k,pin,config)
  result['status']='CHECKED_NO_MUTATION' if mode=='check' else 'APPLYING';save(receipt_path,result)
  if mode=='apply':
   for i,(t,source,hashes,expiry) in enumerate(checked):
    validate_startup_authority(k,pin,config)
    result['transfers'][i]['state']='CREATE_ATTEMPTING';save(receipt_path,result)
    want=desired(t,source);body=json.dumps(want,separators=(',',':')).encode()
    try:kubectl(k,['create','-f','-','-o','name'],body)
    except ValueError:
     observed=destination(k,t)
     if not exact_destination(observed,want):raise
    observed=destination(k,t)
    if not exact_destination(observed,want):die('destination readback differs')
    result['transfers'][i].update({'state':'CREATED','destinationUID':observed['metadata']['uid'],'destinationResourceVersion':observed['metadata']['resourceVersion']});save(receipt_path,result)
   result['status']='COMPLETE'
  result['finishedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat();save(receipt_path,result);return 0,result
 except Exception as e:
  possible_write=any(x.get('state') in ('CREATE_ATTEMPTING','CREATED') for x in result['transfers'])
  result['status']='PARTIAL' if possible_write else 'REFUSED'
  if possible_write:result['unsafeToRetry']=True
  result['error']=str(e);result['finishedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat();save(receipt_path,result);return 1,result
def main():
 ap=argparse.ArgumentParser();ap.add_argument('mode',choices=('check','apply'));ap.add_argument('--pin',required=True);ap.add_argument('--kubectl',default='kubectl');ap.add_argument('--receipt',required=True);a=ap.parse_args()
 rc,result=execute(a.mode,a.pin,a.kubectl,a.receipt);print(json.dumps({'status':result['status'],'receipt':a.receipt,'transfers':len(result['transfers'])},sort_keys=True));sys.exit(rc)
if __name__=='__main__':main()
