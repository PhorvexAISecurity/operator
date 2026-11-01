"""Read-only current-stage proposal preconditions and embedded producer versions."""
import concurrent.futures,subprocess,json,datetime,sys,time
from pathlib import Path
ctx='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
items=[('appset','applicationset','phorvex-services','argocd')]
for n in ['staging-brain','staging-phorvex','staging-phorvex-console']:items.append((n,'deployment',n,'phorvex-staging'))
for n in ['demo-api-defense','stage-bench-defense']:items.append((n,'phorvexpolicy',n,'phorvex-staging-demo'))
for n in ['demo-api','stage-bench-api']:
    items.append(('workload-'+n,'deployment',n,'phorvex-staging-demo'));items.append(('service-'+n,'service',n,'phorvex-staging-demo'))
for n in ['brain','manager','console']:items.append(('app-'+n,'application','phorvex-'+n+'-staging','argocd'))
def get(row):
    key,kind,name,ns=row
    r=subprocess.run(['kubectl','--context',ctx,'-n',ns,'get',kind,name,'-o','json','--request-timeout=20s'],capture_output=True,text=True,timeout=30)
    if r.returncode:return key,{'read_error':{'kind':kind,'name':name,'namespace':ns,'returncode':r.returncode,'stderr':r.stderr[-2000:]}}
    return key,json.loads(r.stdout)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:rows=dict(ex.map(get,items))
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'context':ctx,
        'expected':{'deployments':[],'policies':[],'workloads':[],'services':[]},'apps':{}}
errors={k:v['read_error'] for k,v in rows.items() if 'read_error' in v}
if errors:
    result.update(status='READ_FAILED_NO_PRECONDITIONS',errors=errors)
    print(json.dumps(result,indent=2));raise SystemExit(2)
for key,x in rows.items():
    m=x['metadata'];base={k:m.get(k) for k in ['name','uid','generation','resourceVersion']}
    if key=='appset':result['expected']['appset_spec']=x['spec'];result['appset_identity']=base
    elif key.startswith('staging-'):
        base.update(ready=x['status'].get('readyReplicas'),containers=[{k:c.get(k,[]) for k in ['name','image','args']} for c in x['spec']['template']['spec']['containers']]);result['expected']['deployments'].append(base)
    elif key.startswith('app-'):result['apps'][key]={'health':x.get('status',{}).get('health'),'operation':x.get('status',{}).get('operationState',{}).get('phase'),'revisions':x.get('status',{}).get('sync',{}).get('revisions'),'sources':x['spec']['sources']}
    elif key.startswith('workload-'):
        base.update(selector=x['spec']['selector'],replicas=x['spec']['replicas']);result['expected']['workloads'].append(base)
    elif key.startswith('service-'):
        base.update(selector=x['spec'].get('selector'));result['expected']['services'].append(base)
    else:base['mode']=x['spec'].get('mode');result['expected']['policies'].append(base)
source=Path('/home/hami/phorvex-benchmark/releases/stage-selfserve-225877a8ecb4')
sys.path[:0]=[str(source/'benchmark/worker'),str(source)]
import stage_cli
deadline=time.monotonic()+120
inventory=stage_cli.runtime_inventory(deadline)
result['embedded']={}
for name,deploy in [('brain','staging-brain'),('manager','staging-phorvex')]:
    result['embedded'][name]=stage_cli.running_image(ctx,'phorvex-staging',deploy,name,deadline=deadline,inventory=inventory)
brain=result['embedded']['brain']
v=subprocess.run(['kubectl','--context',ctx,'-n','phorvex-staging','exec',brain['pods'][0]['name'],'-c','brain','--','/brain-replay','-version'],capture_output=True,text=True,check=True,timeout=30)
result['native_replay_version']=json.loads(v.stdout)
print(json.dumps(result,indent=2))
