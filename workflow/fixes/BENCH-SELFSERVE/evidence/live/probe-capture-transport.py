from pathlib import Path
import datetime,hashlib,json,sys,urllib.parse
root=Path('/home/hami/phorvex-benchmark');release=root/'releases/stage-bot-3e11f4e7'
sys.path.insert(0,str(release/'benchmark/worker'))
from runner import Console,error_details
from mathlab.snapshots import read_header
out=root/'stage-data/live/selfserve-capture-v2';out.mkdir(parents=True,exist_ok=True)
r={'schema':'phorvex-bench.capture-transport.v1','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'reader_module_release':'3e11f4e7','authority':'actual authenticated Console index and blob GET; no cache/pin mutation','policies':{}}
c=Console(kube_context='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks',namespace='phorvex-staging',service='staging-phorvex-console',token_service_account='staging-brain-benchmark',service_port=80,use_environment=False,token_audience='phorvex-staging-console',token_duration='10m')
try:
 for name,uid in [('demo-api-defense','6485e0b3-0f36-4737-b0f5-7e846375da9f'),('stage-bench-defense','621c056d-ae10-452c-8828-b2dd0bbb5cb3')]:
  try:
   query=urllib.parse.urlencode({'namespace':'phorvex-staging-demo','policy':name,'policyUID':uid,'limit':256,'since':'2026-11-01T17:59:00Z'})
   data=c.request('/api/math-lab/snapshots?'+query);entries=data.get('entries') or []
   row={'listed':len(entries),'index_sha256':hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()};r['policies'][name]=row
   if entries:
    entry=entries[-1];digest=entry['digest']
    with c.open('/api/math-lab/snapshot?'+urllib.parse.urlencode({'namespace':'phorvex-staging-demo','digest':digest})) as response:raw=response.read(64*1024*1024+1)
    assert len(raw)<=64*1024*1024 and hashlib.sha256(raw).hexdigest()==digest
    header=read_header(raw)
    assert header['gitSHA']=='61e83673b8d4f143fca67e17b8a54dc4712f9b28' and header['policyUID']==uid and header['namespace']=='phorvex-staging-demo' and header['policyName']==name
    (out/(name+'-'+digest+'.pxms')).write_bytes(raw)
    row.update(sample_digest=digest,sample_bytes=len(raw),sample_header=header,status='PASS')
   else:row['status']='CAPTURE_ACCUMULATING'
  except Exception as exc:r['policies'][name]={'status':'FAIL','error':error_details(exc)}
finally:c.close()
(out/'capture-transport.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
