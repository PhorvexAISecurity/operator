import concurrent.futures, datetime, hashlib, json, shutil, subprocess
ctx='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
def get(item):
 key,kind,name,ns=item
 p=subprocess.run(['kubectl','--context',ctx,'-n',ns,'get',kind,name,'-o','json','--request-timeout=20s'],capture_output=True,text=True,timeout=30)
 return key, json.loads(p.stdout) if p.returncode==0 else {'error':'kubectl failed','rc':p.returncode,'stderr':p.stderr[-1000:]}
items=[('appset','applicationset','phorvex-services','argocd')]
for x in ['brain','manager','console']: items.append(('app-'+x,'application','phorvex-'+x+'-staging','argocd'))
for x in ['staging-brain','staging-phorvex','staging-phorvex-console']:items.append((x,'deployment',x,'phorvex-staging'))
items.extend([('grants','configmap','staging-phorvex-console-grants','phorvex-staging'),('pvc','pvc','staging-brain-mathlab','phorvex-staging')])
for x in ['demo-api-defense','stage-bench-defense']:items.append((x,'phorvexpolicy',x,'phorvex-staging-demo'))
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex: results=dict(ex.map(get,items))
r={'schema':'phorvex-bench.capture-rollout-inspection.v1','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'free_bytes':shutil.disk_usage('/home/hami/phorvex-benchmark').free}
def identity(x):return {k:x.get('metadata',{}).get(k) for k in ['name','uid','generation','resourceVersion']}
for k,o in results.items():
 if 'error' in o:r[k]=o;continue
 if k.startswith('app-'):r[k]={'identity':identity(o),'sources':o['spec']['sources'],'health':o.get('status',{}).get('health'),'sync_status':o.get('status',{}).get('sync',{}).get('status'),'revisions':o.get('status',{}).get('sync',{}).get('revisions'),'operation':o.get('status',{}).get('operationState',{}).get('phase'),'conditions':o.get('status',{}).get('conditions'),'outofsync_resources':[x for x in o.get('status',{}).get('resources',[]) if x.get('status')=='OutOfSync']}
 elif k=='appset':r[k]={'identity':identity(o),'templatePatch_sha256':hashlib.sha256(o['spec'].get('templatePatch','').encode()).hexdigest(),'status':o.get('status',{})}
 elif k.startswith('staging-'):
  pod=o['spec']['template']['spec'];r[k]={'identity':identity(o),'status':o['status'],'securityContext':pod.get('securityContext'),'volumes':pod.get('volumes'),'containers':[{'name':c['name'],'image':c['image'],'args':c.get('args',[]),'volumeMounts':c.get('volumeMounts'),'identity_env':[e for e in c.get('env',[]) if e['name']=='PHORVEX_BRAIN_IMAGE']} for c in pod['containers']]}
 elif k=='grants':r[k]={'identity':identity(o),'sha256':hashlib.sha256(o['data']['grants.json'].encode()).hexdigest(),'data':json.loads(o['data']['grants.json'])}
 elif k=='pvc':r[k]={'identity':identity(o),'status':o['status']}
 else:r[k]={'identity':identity(o),'mode':o['spec'].get('mode')}
print(json.dumps(r,indent=2))
