"""Independent read-only main handover collector: no sync, replay, service or cluster writes."""
import concurrent.futures,datetime,hashlib,json,os,pathlib,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
BASE=pathlib.Path('/home/hami/phorvex-benchmark'); DATA=BASE/'stage-data'; RELEASE=BASE/'releases/stage-selfserve-225877a8ecb4'
CTX='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def run(args,timeout=30):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError('read-only command failed: rc='+str(p.returncode))
    return p.stdout
def ident(x):return {k:x['metadata'].get(k) for k in ('name','uid','generation','resourceVersion')}
items=[('appset','applicationset','phorvex-services','argocd'),('pvc','pvc','staging-brain-mathlab','phorvex-staging'),('grants','configmap','staging-phorvex-console-grants','phorvex-staging')]
items +=[(n,'deployment',n,'phorvex-staging') for n in ('staging-brain','staging-phorvex','staging-phorvex-console')]
items +=[('app-'+n,'application','phorvex-'+n+'-staging','argocd') for n in ('brain','manager','console')]
items +=[(n,'phorvexpolicy',n,'phorvex-staging-demo') for n in ('demo-api-defense','stage-bench-defense')]
for n in ('demo-api','stage-bench-api'):
    items += [('workload-'+n,'deployment',n,'phorvex-staging-demo'),('service-'+n,'service',n,'phorvex-staging-demo')]
def get(row):
    key,kind,name,ns=row
    return key,json.loads(run(['kubectl','--context',CTX,'-n',ns,'get',kind,name,'-o','json','--request-timeout=20s']))
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:raw=dict(ex.map(get,items))
out={'schema':'phorvex-bench.peer-post-main-readonly.v1','started_at':started,'context':CTX,'objects':{},'runtime':{}}
for k,x in raw.items():
    y={'identity':ident(x)}
    if k=='appset': y['spec']=x['spec']
    elif k.startswith('app-'):
        st=x.get('status',{}); y.update(sources=x['spec']['sources'],health=st.get('health'),operation=st.get('operationState',{}).get('phase'),sync=st.get('sync'),conditions=st.get('conditions',[]),outofsync_resources=[r for r in st.get('resources',[]) if r.get('status')!='Synced'])
    elif k=='grants':
        assert set(x['data'])=={'grants.json'}
        y.update(data=json.loads(x['data']['grants.json']),sha256=hashlib.sha256(x['data']['grants.json'].encode()).hexdigest())
    elif k=='pvc':y.update(status=x['status'],spec=x['spec'])
    elif k.startswith('service-'):y['selector']=x['spec'].get('selector')
    elif k.startswith('staging-') or k.startswith('workload-'):
        sp=x['spec'];pod=sp['template']['spec'];y.update(replicas=sp.get('replicas'),selector=sp['selector'],status=x['status'],securityContext=pod.get('securityContext'),volumes=pod.get('volumes',[]),containers=[{a:c.get(a,[]) for a in ('name','image','args','volumeMounts')} for c in pod['containers']])
    else:y.update(mode=x['spec'].get('mode'),selector=x['spec'].get('selector'))
    out['objects'][k]=y
for unit in ('phorvex-stage-observer.service','phorvex-benchmark-bot.service','phorvex-stage-endpoint-refresh.timer','phorvex-stage-endpoint-refresh.service','phorvex-stage-reconcile.timer','phorvex-stage-reconcile.service','phorvex-benchmark-api.service','phorvex-benchmark-proxy.service','phorvex-benchmark-web.service'):
    v=run(['systemctl','--user','show',unit,'--property=MainPID,ActiveState,SubState,Result,ExecMainStatus,NRestarts,WorkingDirectory,UnitFileState'])
    out['runtime'][unit]=dict(line.split('=',1) for line in v.splitlines() if '=' in line)
for key,p in {'observer':DATA/'mathlab/observer-current.json','pin':DATA/'mathlab/stage.json','refresh':DATA/'mathlab/endpoint-refresh/phorvex-staging-demo/stage-bench-defense.status.json','dataset':DATA/'mathlab/endpoint-traces/phorvex-staging-demo/stage-bench-defense.manifest.json'}.items():
    out['runtime'][key]={'sha256':sha(p),'value':json.loads(p.read_text())}
out['runtime']['protected_hashes']={str(p):sha(p) for p in [BASE/'config/bot.env',BASE/'bot/owner.json',BASE/'bot/members.json',DATA/'mathlab/bin/current.json',BASE/'operator-refactored/.git/config']}
out['runtime']['checkout_head']=run(['git','-C',str(BASE/'operator-refactored'),'rev-parse','HEAD']).strip()
out['runtime']['current_link']=os.readlink(BASE/'current')
out['free_bytes']=shutil.disk_usage(BASE).free
sys.path[:0]=[str(RELEASE/'benchmark/worker'),str(RELEASE)]
import stage_cli
from stage_reconcile import observe,same_observation
from mathlab import stage_scope
out['live_observation']=observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+60)
out['pin_matches_observation']=same_observation(out['runtime']['pin']['value'],out['live_observation'])
pin=out['runtime']['pin']['value'];binary=pathlib.Path(pin['replay']['path'])
if not binary.is_absolute():binary=DATA/binary
out['replay_binary']={'path':str(binary),'sha256':sha(binary),'version':json.loads(run([str(binary),'-version']))}
out['completed_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
print(json.dumps(out,indent=2))
