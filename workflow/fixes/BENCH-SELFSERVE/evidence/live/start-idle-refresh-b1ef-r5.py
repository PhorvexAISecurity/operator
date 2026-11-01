# Lead-owned start of the already reviewed read-only refresh unit in an idle interval.
import pathlib,json,subprocess,hashlib,shutil,datetime
r=pathlib.Path('/home/hami/phorvex-benchmark');p=json.loads((r/'stage-data/mathlab/stage.json').read_text())
assert p['brain']['git_sha']==p['manager']['git_sha']=='b1ef9ccdb258f0a94b0dad575a17cc3a4c25cab0'
assert shutil.disk_usage(r).free>4*1024**3
units=['phorvex-stage-reconcile.service','phorvex-stage-endpoint-refresh.service']
for n in units:
 s=subprocess.run(['systemctl','--user','show',n,'--property=ActiveState','--value'],capture_output=True,text=True,check=True,timeout=15).stdout.strip();assert s=='inactive',(n,s)
ctx='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
a=json.loads(subprocess.run(['kubectl','--context',ctx,'-n','argocd','get','applicationset','phorvex-services','-o','json','--request-timeout=20s'],capture_output=True,text=True,check=True,timeout=30).stdout)
assert a['metadata']['uid']=='e55f3b21-b600-423b-9f10-1faa1c09f6b5'
assert hashlib.sha256(a['spec']['templatePatch'].encode()).hexdigest()=='bf3a66c31a2468fad2a2afea721ca3a3970281b075be770eb855583e22df256b'
subprocess.run(['systemctl','--user','start','--no-block','phorvex-stage-endpoint-refresh.service'],check=True,capture_output=True,text=True,timeout=20)
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'state':'START_REQUESTED','unit':'phorvex-stage-endpoint-refresh.service','source':p['brain']['git_sha'],'observer_restart':False,'expected_existing_unit_only':True}))
