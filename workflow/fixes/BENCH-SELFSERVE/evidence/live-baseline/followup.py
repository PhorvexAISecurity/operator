"""Read-only manager/RBAC/registry/tool follow-up; never prints credentials."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

CTX='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
commands=[]
def run(args, timeout=35):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    commands.append({'argv':args,'rc':p.returncode})
    return p
def kube(*args):
    p=run(['kubectl','--context',CTX,*args,'--request-timeout=20s'])
    return json.loads(p.stdout) if not p.returncode else {'error':p.stderr[-1000:]}
def ident(o):
    return {k:o['metadata'].get(k)for k in ('name','namespace','uid','generation','resourceVersion')}
out={'read_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
deployments=kube('get','deployments','-n','phorvex-staging','-o','json')
out['deployments']=[]
names=[]
for d in deployments.get('items',[]):
    cs=d['spec']['template']['spec']['containers']
    if not any('/phorvex/staging/manager:' in c['image'] or '/phorvex/staging/console:' in c['image']for c in cs):continue
    names.append(d['metadata']['name'])
    s=d['spec']['template']['spec']
    out['deployments'].append({'identity':ident(d),'readyReplicas':d.get('status',{}).get('readyReplicas'),'replicas':d['spec'].get('replicas'),'serviceAccountName':s.get('serviceAccountName'),'volumes':s.get('volumes'),'containers':[{'name':c['name'],'image':c['image'],'args_count':len(c.get('args',[])),'capture_args':[a for a in c.get('args',[])if any(k in a for k in ('math-lab','brain-endpoint','brain-service'))],'volumeMounts':c.get('volumeMounts')}for c in cs]})
pods=kube('get','pods','-n','phorvex-staging','-o','json')
out['pods']=[]
for p in pods.get('items',[]):
    if not any(p['metadata']['name'].startswith(n+'-')for n in names):continue
    obj={'identity':ident(p),'phase':p.get('status',{}).get('phase'),'containers':[{k:c.get(k)for k in ('name','image','imageID','ready','restartCount')}for c in p.get('status',{}).get('containerStatuses',[])]}
    manager=next((c for c in p['spec']['containers']if '/phorvex/staging/manager:'in c['image']),None)
    if manager:
        v=run(['kubectl','--context',CTX,'-n','phorvex-staging','exec',p['metadata']['name'],'-c',manager['name'],'--','/manager','-version'])
        obj['embedded_version']={'rc':v.returncode,'stdout':v.stdout,'stderr':v.stderr[-1000:]}
    out['pods'].append(obj)
bindings=kube('get','clusterrolebindings','-o','json')
out['benchmark_clusterrolebindings']=[]
for b in bindings.get('items',[]):
    if any(s.get('name')=='staging-brain-benchmark'and s.get('namespace')=='phorvex-staging'for s in b.get('subjects',[])):
        out['benchmark_clusterrolebindings'].append({'identity':ident(b),'subjects':b.get('subjects'),'roleRef':b.get('roleRef')})
out['benchmark_roles']=[]
for b in out['benchmark_clusterrolebindings']:
    role=kube('get','clusterrole',b['roleRef']['name'],'-o','json')
    out['benchmark_roles'].append({'identity':ident(role),'rules':role.get('rules')})
out['known_tool_locations']={p:Path(p).is_file()for p in ['/home/hami/.local/bin/crane','/home/hami/go/bin/crane','/home/hami/phorvex-benchmark/runtime/bin/crane','/home/hami/phorvex-benchmark/tools/crane','/usr/local/bin/crane','/usr/bin/docker','/usr/local/bin/aws']}
docker=run(['/usr/bin/docker','version','--format','{{json .Server.Version}}'])
out['docker_server_read']={'rc':docker.returncode,'stdout':docker.stdout,'stderr':docker.stderr[-1000:]}
digest='sha256:ebb6d245afc52528155eee999e130972c1aa78f14f03a19b86118508acefd1bf'
args=['aws','ecr','batch-get-image','--registry-id','753556437180','--repository-name','phorvex/staging/brain','--image-ids','imageDigest='+digest,'--region','us-east-2','--output','json']
p=run(args,90)
if p.returncode:out['brain_manifest']={'rc':p.returncode,'error':p.stderr[-1000:]}
else:
    response=json.loads(p.stdout);item=response['images'][0];raw=item['imageManifest'];m=json.loads(raw)
    out['brain_manifest']={'rc':0,'requested_digest':digest,'sha256':'sha256:'+hashlib.sha256(raw.encode()).hexdigest(),'mediaType':m.get('mediaType'),'config':m.get('config'),'layers':m.get('layers'),'manifests':m.get('manifests')}
out['units']=run(['systemctl','--user','show','phorvex-benchmark-bot.service','phorvex-stage-observer.service','phorvex-stage-endpoint-refresh.service','--property=Id,ActiveState,SubState,NRestarts,ExecStart']).stdout
out['commands']=commands
print(json.dumps(out,sort_keys=True))
