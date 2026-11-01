import json,pathlib,subprocess,time,datetime,hashlib
root=pathlib.Path('/home/hami/phorvex-benchmark/stage-data/deployment/relay-ef94fad3')
review=json.loads((root/'relay-oci-review.json').read_text());assert review['result']=='PASS_FOR_AUTHORIZED_STAGE_ROLLOUT'
patch=root/'applicationset-patch.json'
key='workflow/fixes/BENCH-STAGE/evidence/deployment/relay-ef94fad3/applicationset-patch.json'
assert hashlib.sha256(patch.read_bytes()).hexdigest()==review['evidence'][key]
for _ in range(120):
 status=json.loads((root/'publish-status.json').read_text())
 if status['state']!='RUNNING':break
 time.sleep(1)
assert status['state']=='DONE' and status['exit_code']==0,status
published=json.loads((root/'publish-receipt.json').read_text())
assert set(published['images'])=={'brain','manager'}
for service,v in published['images'].items():assert v['digest']==review['images'][service]['digest']
k=['kubectl','--context','arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks','--request-timeout=60s']
def run(args):return subprocess.check_output(k+args,timeout=90,text=True)
print(run(['-n','argocd','patch','applicationset','phorvex-services','--type=json','--patch-file',str(patch)]),flush=True)
with (root.parent.parent/'mutations.jsonl').open('a') as f:f.write(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'action':'reviewed-stage-relay-appset-patch','source':published['source'],'images':published['images'],'review_sha256':hashlib.sha256((root/'relay-oci-review.json').read_bytes()).hexdigest()})+'\n')
expected={s:v['tag']+'@'+v['digest'] for s,v in published['images'].items()};result={}
end=time.monotonic()+600
while time.monotonic()<end:
 for service,name in [('brain','staging-brain'),('manager','staging-phorvex')]:
  if service in result:continue
  dep=json.loads(run(['-n','phorvex-staging','get','deployment',name,'-o','json']));st=dep.get('status',{});wanted=dep['spec'].get('replicas',1)
  container=next(x for x in dep['spec']['template']['spec']['containers'] if x['name']==service)
  if container['image']!=expected[service] or st.get('observedGeneration',0)<dep['metadata']['generation'] or any(st.get(x,0)!=wanted for x in ['replicas','updatedReplicas','readyReplicas','availableReplicas']):continue
  selector=','.join(k+'='+v for k,v in dep['spec']['selector']['matchLabels'].items());pods=json.loads(run(['-n','phorvex-staging','get','pods','-l',selector,'-o','json']))['items'];actual=[]
  for pod in pods:
   if pod['metadata'].get('deletionTimestamp'):continue
   cs=next((x for x in pod.get('status',{}).get('containerStatuses',[]) if x['name']==service),{})
   if not cs.get('ready') or not cs.get('imageID','').endswith('@'+published['images'][service]['digest']):continue
   version=json.loads(run(['-n','phorvex-staging','exec',pod['metadata']['name'],'-c',service,'--','/service' if service=='brain' else '/manager','--version']))
   assert version['gitSHA']==published['source'] and version['service']==service
   actual.append({'name':pod['metadata']['name'],'uid':pod['metadata']['uid'],'image_id':cs['imageID'],'embedded_version':version})
  if len(actual)!=wanted:continue
  if service=='brain':assert {v['name']:v.get('value') for v in container.get('env',[])}['PHORVEX_BRAIN_IMAGE']==expected[service]
  result[service]={'deployment':name,'uid':dep['metadata']['uid'],'image':expected[service],'pods':actual,'status':st}
  print('READY',service,published['source'],flush=True)
 if len(result)==2:break
 time.sleep(5)
assert len(result)==2,'stage rollout did not reach both exact source/digest readiness'
receipt={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':published['source'],'result':'PASS','services':result,'context':k[2]}
(root/'runtime-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('PASS actual stage relay runtime identity',flush=True)
